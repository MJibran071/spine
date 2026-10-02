// Live verified-source fetching for the scanner's "unknown shape" bucket.
// When a target's bytecode interface matches no template probe, its VERIFIED
// SOURCE still feeds the static detector suite — real signal instead of a
// dead end. Keyless public APIs (Blockscout instances, Sourcify repo), with
// optional Etherscan V2 when LAB_ETHERSCAN_KEY is set. Read-only HTTP GETs;
// results cached under reports/source-cache/.
// Every provider here was verified live before inclusion (2026-09-11).
import { mkdirSync, existsSync, readFileSync, writeFileSync, statSync, rmSync, renameSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const CACHE_DIR = join(REPORT_DIR, "source-cache");
const CACHE_TTL_MS = 7 * 24 * 3_600_000; // 7 days — re-fetch after contract upgrades

/** Keyless Blockscout instances per chain id (redirect-following). */
const BLOCKSCOUT: Record<string, string> = {
  "1": "https://eth.blockscout.com",
  "8453": "https://base.blockscout.com",
  "10": "https://optimism.blockscout.com",
  "100": "https://gnosis.blockscout.com",
  "42161": "https://arbitrum.blockscout.com",  // Arbitrum — verified Blockscout instance
  "137": "https://polygon.blockscout.com",     // Polygon — verified Blockscout instance
  "42114": "https://unichain.blockscout.com",   // Unichain — verified 2026-09-28 (live /api/v2/stats; v2 smart-contracts API)
};

/** Keyless Etherscan-V1-API instances per chain id (private-chain explorers
 * that keep the legacy /api?module=contract&action=getsourcecode endpoint
 * open WITHOUT a key). Probed 2026-09-28: the Etherscan-V2-family explorers
 * (berascan/sonicscan/blastscan/hyperevmscan/lineascan) have DEPRECATED V1
 * ("You are using a deprecated V1 endpoint") and their V2 requires a real
 * key — one LAB_ETHERSCAN_KEY unlocks ALL of them via api.etherscan.io/v2
 * with the chainid parameter. scrollscan answered V1 once then returned
 * empty bodies on every retry — too flaky to ship here by the fleet's own
 * "verified live before inclusion" rule. So: no reliable keyless explorer
 * API exists for these chains yet — the map stays empty until one is found. */
const KEYLESS_ETHSCAN_API: Record<string, string> = {};

// Etherscan-family V1 JSON: { status, result: [{ SourceCode }] } — same shape
// as the fromEtherscan V2 response, minus the key. Reuses the {{...}} unwrap.
async function fromKeylessEtherscanApi(chainId: string, address: string): Promise<string | null> {
  const host = KEYLESS_ETHSCAN_API[chainId];
  if (!host) return null;
  const j = await getJson(`${host}/api?module=contract&action=getsourcecode&address=${address}&apikey=`, 10_000);
  const item = (j as { result?: Array<{ SourceCode?: string }> })?.result?.[0];
  const src = typeof item?.SourceCode === "string" ? item.SourceCode : "";
  if (src.length < 32) return null;
  if (src.startsWith("{{")) {
    try {
      const inner = JSON.parse(src.slice(1, -1)) as Record<string, { content: string }>;
      return Object.entries(inner)
        .map(([path, f]) => `// file: ${path}\n${f.content}`)
        .join("\n\n");
    } catch {
      return src;
    }
  }
  return src;
}

async function getJson(url: string, timeoutMs: number): Promise<any | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// Blockscout v2: { source_code, additional_sources: [{source_code}] } — but
// some instances (base) flatten to { file_path, source_code }. Handle both.
async function fromBlockscout(host: string, chainId: string, address: string): Promise<string | null> {
  const url = `${host}/api/v2/smart-contracts/${address}`;
  const j = await getJson(url, 8_000);
  if (!j || typeof j.source_code !== "string" || j.source_code.length < 32) return null;
  const parts = [j.source_code as string];
  for (const extra of (j.additional_sources ?? []) as Array<{ source_code?: string }>) {
    if (typeof extra.source_code === "string" && extra.source_code.length > 32) {
      parts.push(extra.source_code);
    }
  }
  return parts.join("\n\n// ---- additional verified file ----\n\n");
}

// Sourcify: full match preferred, partial as fallback. Metadata lists all
// sources; fetch each Solidity file. WETH-style legacy contracts may be
// absent — that's fine, other providers cover them.
async function fromSourcify(chainId: string, address: string): Promise<string | null> {
  for (const match of ["full_match", "partial_match"]) {
    const meta = await getJson(
      `https://repo.sourcify.dev/contracts/${match}/${chainId}/${address}/metadata.json`,
      8_000
    );
    if (!meta?.sources) continue;
    const parts: string[] = [];
    for (const [path, info] of Object.entries(meta.sources as Record<string, { content?: string }>)) {
      if (typeof info?.content === "string" && info.content.length > 32) {
        parts.push(`// file: ${path}\n${info.content}`);
      }
    }
    if (parts.length > 0) return parts.join("\n\n");
  }
  return null;
}

// Etherscan V2 (chainid parameter) — only when the operator provides a key.
// FREE-TIER RATE LIMIT (~3-5 calls/s shared across ALL processes using the
// key): the 8-daemon fleet each fire fromEtherscan concurrently, so pacing
// MUST be shared. This is a cross-process token bucket via a lock file:
// each caller OAtimes a slot (O_EXCL create = the lock) and sleeps until its
// scheduled time. Bounded wait — if the queue is jammed, degrade to null (the
// caller falls through to blockscout/sourcify, and nothing retries blindly).
const ETHERSCAN_PACE_DIR = join(REPORT_DIR, "etherscan-pace");
const ETHERSCAN_MIN_INTERVAL_MS = 350; // ~3 calls/s (free tier, user-confirmed)
const ETHERSCAN_MAX_WAIT_MS = 8_000;

/**
 * Cross-process claim of the next free Etherscan slot. Atomic via rename:
 * each caller writes its OWN claim file `claim-<t>-<pid>-<rand>` where <t> is
 * the earliest time it may fire, then rename()s it to `current`. rename is
 * atomic — the winner is whoever renamed LAST, and it always read the true
 * previous claim first. Losers read the winner's time and re-claim after it.
 * No lock is ever held open, so a crashed process cannot wedge the queue.
 */
async function pacedEtherscanSlot(): Promise<boolean> {
  try {
    mkdirSync(ETHERSCAN_PACE_DIR, { recursive: true });
  } catch { /* exists */ }
  const currentPath = join(ETHERSCAN_PACE_DIR, "current");
  const start = Date.now();
  for (;;) {
    let lastFireAt = 0;
    try {
      // content is "<fireAt>|<pid>|<rand>" — the fireAt is field 0
      lastFireAt = Number(readFileSync(currentPath, "utf8").trim().split("|")[0]) || 0;
    } catch { /* no claim yet */ }
    const fireAt = Math.max(Date.now(), lastFireAt + ETHERSCAN_MIN_INTERVAL_MS);
    const token = `${process.pid}|${Math.random().toString(36).slice(2)}`;
    const myClaim = join(ETHERSCAN_PACE_DIR, `claim-${process.pid}-${Math.random().toString(36).slice(2)}`);
    try {
      // Claim file carries fireAt (for the next caller's watermark). The token
      // binds the current file to THIS caller so same-ms collisions resolve.
      writeFileSync(myClaim, `${fireAt}|${token}`);
      renameSync(myClaim, currentPath);
      const content = readFileSync(currentPath, "utf8");
      const winnerToken = content.trim(); // "<fireAt>|<pid>|<rand>" must equal ours
      if (winnerToken === `${fireAt}|${token}`) {
        const wait = fireAt - Date.now();
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
        return true; // our rename is current — we own this slot
      }
      // Lost: a later rename overwrote us. Loop; its fireAt pushes ours later.
    } catch {
      try { rmSync(myClaim, { force: true }); } catch { /* ignore */ }
    }
    if (Date.now() - start > ETHERSCAN_MAX_WAIT_MS) return false;
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function fromEtherscan(chainId: string, address: string): Promise<string | null> {
  const key = process.env.LAB_ETHERSCAN_KEY?.trim();
  if (!key) return null;
  if (!(await pacedEtherscanSlot())) return null; // queue jammed — other providers cover it
  const j = await getJson(
    `https://api.etherscan.io/v2/api?chainid=${chainId}&module=contract&action=getsourcecode&address=${address}&apikey=${key}`,
    15_000 // big sources: Sonic Balancer Vault is 300KB — 10s was too tight
  );
  const item = j?.result?.[0];
  const src = typeof item?.SourceCode === "string" ? item.SourceCode : "";
  if (src.length < 32) return null;
  // Etherscan wraps multi-file sources in {{...}} JSON; unwrap when present.
  if (src.startsWith("{{")) {
    try {
      const inner = JSON.parse(src.slice(1, -1)) as Record<string, { content: string }>;
      return Object.entries(inner)
        .map(([path, f]) => `// file: ${path}\n${f.content}`)
        .join("\n\n");
    } catch {
      return src;
    }
  }
  return src;
}

export interface LiveSourceResult {
  source: string | null;
  provider: string; // "blockscout" | "sourcify" | "etherscan" | "none"
}

/** Fetch verified source for a live contract, trying every provider and
 * caching the result. Returns null (provider "none") when nothing works. */
export async function fetchLiveSource(chainId: string, address: string): Promise<LiveSourceResult> {
  const addr = address.toLowerCase();
  const cachePath = join(CACHE_DIR, `${chainId}-${addr}.sol`);
  if (existsSync(cachePath)) {
    try {
      const cached = readFileSync(cachePath, "utf8");
      const age = Date.now() - (statSync(cachePath).mtimeMs ?? 0);
      if (cached.length > 32 && age < CACHE_TTL_MS) return { source: cached, provider: "cache" };
    } catch {
      // fall through to network
    }
  }  const providers: Array<[string, () => Promise<string | null>]> = [
    ["etherscan", () => fromEtherscan(chainId, addr)],
    ...(BLOCKSCOUT[chainId] ? ([['blockscout', () => fromBlockscout(BLOCKSCOUT[chainId]!, chainId, addr)]] as Array<[string, () => Promise<string | null>]>): []),
    // Keyless explorer APIs cover the newest fleet chains (bera/sonic/blast/
    // hyperevm/linea/scroll) where Blockscout has no instance and Sourcify
    // coverage is thin. Cheap: one GET, and only when the chain is listed.
    ...(KEYLESS_ETHSCAN_API[chainId] ? ([['explorer-api', () => fromKeylessEtherscanApi(chainId, addr)]] as Array<[string, () => Promise<string | null>]>): []),
    ["sourcify", () => fromSourcify(chainId, addr)],
  ];
  for (const [name, attempt] of providers) {
    try {
      const src = await attempt();
      if (src) {
        try {
          mkdirSync(CACHE_DIR, { recursive: true });
          writeFileSync(cachePath, src);
        } catch {
          // cache failure is non-fatal
        }
        return { source: src, provider: name };
      }
    } catch {
      // next provider
    }
  }
  return { source: null, provider: "none" };
}
