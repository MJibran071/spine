// RPC health checking + failover for anything that spawns a fork or reads
// infra state. Public endpoints go down (publicnode died mid-hunt on 2026-09-11);
// a 24/7 agent must fail over instead of stalling on a corpse.
// Read-only usage only: eth_chainId probes, fork sources. Nothing broadcasts.
// Fork-capable endpoints verified 2026-09-12 (eth_getBlockByNumber + eth_getStorageAt at -2000 blocks).
// Dead/rate-limited endpoints removed: cloudflare-eth.com (-32046), publicnode (archive paywall),
// ankr (auth required), 0xrpc.io (historical state error), meowrpc (429).
export const ETHEREUM_FORK_FALLBACKS = [
  // Operator-provided Alchemy first (config reads LAB_FORK_URL; the literal
  // here is the failover-list default so a fleet restarted WITHOUT .env still
  // prefers the private endpoint if the env var ever goes missing). Verified
  // live 2026-09-28: chainId 0x1, archive state, full anvil fork boot.
  ...(process.env.LAB_FORK_URL?.includes("g.alchemy.com") ? [process.env.LAB_FORK_URL.trim()] : []),
  "https://eth-mainnet.public.blastapi.io", // verified fork-grade 2026-09-12
  "https://public.1rpc.io/eth",             // verified fork-grade 2026-09-12
  "https://ethereum-public.nodies.app",     // verified fork-grade 2026-09-12
  "https://mainnet.gateway.tenderly.co",    // verified fork-grade 2026-09-12
  "https://api.zan.top/eth-mainnet",        // verified fork-grade 2026-09-12
  "https://rpc.mevblocker.io",              // verified fork-grade 2026-09-12
  "https://rpc.flashbots.net",              // verified fork-grade 2026-09-12
  "https://eth.drpc.org",                   // verified fork-grade 2026-09-12
];

/** First endpoint that answers eth_chainId within `timeoutMs`, or null.
 * If `expectedChainId` is given (hex), the endpoint must report that chain —
 * this is what makes mainnet fallbacks safe to attempt blindly. */
export async function pickHealthyRpc(
  candidates: string[],
  timeoutMs = 5_000,
  expectedChainId?: string
): Promise<string | null> {
  for (const url of candidates) {
    if (!url || !/^https?:\/\//.test(url)) continue;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) continue;
      const json: any = await res.json();
      if (typeof json?.result !== "string" || !json.result.startsWith("0x")) continue;
      if (expectedChainId && json.result.toLowerCase() !== expectedChainId.toLowerCase()) continue;
      return url;
    } catch {
      // dead/slow endpoint — try the next
    }
  }
  return null;
}

// Failover state for the daemon's long run: remember the working endpoint and
// only re-probe when it stops answering. Fallbacks are restricted to
// chainId 0x1 so a dead custom-chain RPC can never be silently swapped for
// the wrong chain.
let currentForkUrl: string | null = null;

/** Return a healthy version of `current` (or current itself if fine).
 * Falls back to a known-good mainnet endpoint ONLY when current is dead and
 * current is itself a mainnet endpoint (chainId 0x1 verified before use). */
export async function ensureHealthyRpc(current: string | null): Promise<string | null> {
  if (!current) return current;
  if (currentForkUrl === current) {
    const ok = await pickHealthyRpc([current], 3_000);
    if (ok) return current;
    currentForkUrl = null; // went dead mid-run
  }
  const ok = await pickHealthyRpc([current], 5_000);
  if (ok) {
    currentForkUrl = current;
    return current;
  }
  // Only mainnet gets automatic failover (the fallback list is mainnet).
  const isMainnet = await pickHealthyRpc([current], 5_000, "0x1");
  if (!isMainnet && !(await appearsMainnet(current))) {
    return current; // custom chain: keep the user's URL, errors surface per-probe
  }
  const fb = await pickHealthyRpc(ETHEREUM_FORK_FALLBACKS, 5_000, "0x1");
  if (fb) {
    console.log(`[rpc-health] ${current} is down — failing over to ${fb} (mainnet verified)`);
    currentForkUrl = fb;
    return fb;
  }
  return current;
}

async function appearsMainnet(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(5_000),
    });
    const json: any = await res.json();
    return json?.result === "0x1";
  } catch {
    return /ethereum|mainnet|\/eth/.test(url); // dead endpoint: judge by name
  }
}
