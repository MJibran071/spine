// Quick probe: which public Ethereum RPCs serve fork-grade archive reads?
// Usage: node check-rpcs.mjs
const CANDIDATES = [
  "https://eth-mainnet.public.blastapi.io",
  "https://public.1rpc.io/eth",
  "https://eth.meowrpc.com",
  "https://ethereum.public.blockpi.network/v1/rpc/public",
  "https://ethereum-public.nodies.app",
  "https://mainnet.gateway.tenderly.co",
  "https://api.zan.top/eth-mainnet",
  "https://rpc.mevblocker.io",
  "https://0xrpc.io/eth",
  "https://rpc.flashbots.net",
  "https://eth.drpc.org",
  "https://cloudflare-eth.com",
  "https://rpc.ankr.com/eth",
  "https://ethereum-rpc.publicnode.com",
];

async function rpc(url, method, params = []) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(8000),
  });
  const j = await res.json();
  if (j.error) throw Object.assign(new Error(j.error.message), { code: j.error.code });
  return j.result;
}

async function probe(url) {
  try {
    const blockHex = await rpc(url, "eth_blockNumber");
    const target = "0x" + (BigInt(blockHex) - 2000n).toString(16);
    // eth_getBlockByNumber deep in archive is the real test for fork capability
    const block = await rpc(url, "eth_getBlockByNumber", [target, false]);
    if (!block) return { url, status: "REFUSED", note: "null result" };
    // Also test eth_getStorageAt (anvil uses this heavily during fork)
    const storage = await rpc(url, "eth_getStorageAt", [
      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0x0", target
    ]);
    return { url, status: "FORK-OK", blockNum: parseInt(blockHex, 16) };
  } catch (e) {
    return { url, status: e.code === -32046 ? "RATE-LIMITED(-32046)" : `FAIL(${e.message?.slice(0, 60)})` };
  }
}

const results = await Promise.all(CANDIDATES.map(probe));
for (const r of results) {
  const icon = r.status === "FORK-OK" ? "✅" : "❌";
  console.log(`${icon} ${r.status.padEnd(25)} ${r.url}`);
}
console.log("\n--- Fork-capable endpoints (safe to use as LAB_FORK_URL) ---");
for (const r of results.filter(r => r.status === "FORK-OK")) {
  console.log(`  ${r.url}`);
}
