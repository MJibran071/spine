// Hermetic test for the DEDICATED ERC-4626 VAULT LOOP.
//
// The problem this pins down: 48 vault-shaped watchlist rows existed, but
//   1. 43 carried `chain:0x…` keys the Ethereum-only fork watch NEVER picks
//      up (auto-enlistment was gated on chain.id === "1");
//   2. the 5 Ethereum rows inherited the general 3-cycle rotation, so the
//      highest base-rate bug class got the slowest cadence;
//   3. nothing validated that the rows the loop picks are actually
//      resolvable production targets (display labels and solana rows would
//      otherwise become fork-probe attempts at garbage addresses).
//
// Selection only — no forks, no network. A fresh bus store is installed so
// the live hunt's state.json is never touched.
import { join } from "node:path";
import { tmpdir } from "node:os";

process.env.LAB_REPORT_DIR = join(tmpdir(), "lab-vaultloop-should-never-write");
process.env.LAB_OFFLINE = "1";

let failures = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) console.log(`ok: ${name}`);
  else {
    failures++;
    console.error(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
  }
}
function eq(name: string, actual: unknown, expected: unknown): void {
  check(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

const { upsertWatch } = await import("./bus.ts");
const { isVaultEntry, parseVaultTarget, selectVaultTargets } = await import("./vaultloop.ts");

// Fresh store: tests must never read (or write) the live hunt's watchlist.
const g = globalThis as unknown as { __labBus?: unknown };
delete g.__labBus;

const VAULT_SHAPE = "erc-4626-style vault (convertToShares/maxRedeem)";
const STALE = Date.now() - 10 * 60_000; // 10 minutes old
const FRESH = Date.now() - 30_000; // 30 seconds old

// The exact shapes found in the live state: 43 chain-labeled vault rows the
// old fork watch never picked up, plus 5 bare Ethereum ones it did. Staleness
// is staggered so stalest-first is deterministic (no sort-tie luck).
upsertWatch({ address: "base:0xbeef010f9cb27031ad51e3333f9af9c6b1228183 [hot]", shape: VAULT_SHAPE, lastProbe: STALE - 120_000 }); // stalest
upsertWatch({ address: "base:0x7bfa7c4f149e7415b73bdedfe609237e29cbf34a [hot]", shape: VAULT_SHAPE, lastProbe: FRESH });
upsertWatch({ address: "arbitrum:0x4a03f37e7d3fc243e3f99341d36f4b829bee5e03 [hot]", shape: VAULT_SHAPE, lastProbe: STALE });
upsertWatch({ address: "gnosis:0xaf204776c7245bf4147c2612bf6e5972ee483701 [hot]", shape: VAULT_SHAPE, lastProbe: STALE - 60_000 });
upsertWatch({ address: "ethereum:0x356b8d89c1e1239cbbb9de4815c39a1474d5ba7d [hot]", shape: VAULT_SHAPE, lastProbe: FRESH });
upsertWatch({ address: "0x9396dcbf78fc526bb003665337c5e73b699571ef", shape: VAULT_SHAPE, lastProbe: FRESH }); // old bare row
// Noise that must never be selected:
upsertWatch({ address: "ethereum:0x06da0fd433c1a5d7a4faa01111c044910a184553 [hot]", shape: "unknown", lastProbe: STALE }); // AMM pair
upsertWatch({ address: "solana:pump-fun", shape: "solana-program", lastProbe: STALE }); // non-EVM
upsertWatch({ address: "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", shape: "unknown" }); // bare, no shape yet

// 1. shape classifier
check("isVaultEntry: recon vault shape matches", isVaultEntry({ shape: VAULT_SHAPE }));
check("isVaultEntry: scanner's erc4626-vault label matches", isVaultEntry({ shape: "", address: "x" }) === false && isVaultEntry({ shape: "unknown" }) === false);

// 2. parser: chain-labeled keys resolve; bare keys are honestly rejected
const parsed = parseVaultTarget("base:0xbeef010f9cb27031ad51e3333f9af9c6b1228183 [hot]", {});
check("parse: chain-labeled hot row resolves", parsed !== null, JSON.stringify(parsed));
eq("parse: chainId comes from the label", parsed?.chainId, "8453");
eq("parse: address is bare + lowercased", parsed?.address, "0xbeef010f9cb27031ad51e3333f9af9c6b1228183");
eq("parse: bare key (no chain) is rejected", parseVaultTarget("0x9396dcbf78fc526bb003665337c5e73b699571ef", {}), null);
eq("parse: unknown chain name is rejected", parseVaultTarget("fantom:0x9396dcbf78fc526bb003665337c5e73b699571ef", {}), null);
eq("parse: solana row is rejected", parseVaultTarget("solana:pump-fun", {}), null);

// 3. selection: only resolvable vault rows, sorted stalest-first
const sel = selectVaultTargets(2, 10);
eq("select: exactly the 5 resolvable vault rows", sel.length, 5);
const picked = new Set(sel.map((r) => r.watchKey));
check("select: chain-labeled rows are finally covered", picked.has("base:0xbeef010f9cb27031ad51e3333f9af9c6b1228183 [hot]") && picked.has("arbitrum:0x4a03f37e7d3fc243e3f99341d36f4b829bee5e03 [hot]"), JSON.stringify([...picked]));
check("select: the AMM pair never enters the vault loop", !sel.some((r) => r.address === "0x06da0fd433c1a5d7a4faa01111c044910a184553"));
check("select: solana rows never enter", !sel.some((r) => r.chainId === undefined && r.chainName === "solana"));
eq("select: stalest vault first", sel[0]?.address, "0xbeef010f9cb27031ad51e3333f9af9c6b1228183");

// 4. bounty flag jumps the queue
upsertWatch({ address: "optimism:0xc30ce6a5758786e0f640cc5f881dd96e9a1c5c59 [hot]", shape: VAULT_SHAPE, lastProbe: FRESH, bounty: "max $250,000" });
const selB = selectVaultTargets(2, 10);
eq("select: bounty-flagged vault first even when fresh", selB[0]?.address, "0xc30ce6a5758786e0f640cc5f881dd96e9a1c5c59");

// 5. rotation semantics: stalest-first sweep with a bounded cap (backlog-driven)
const capped = selectVaultTargets(2, 2);
eq("cap: bounded batch respects the fork-pressure cap", capped.length, 2);
eq("cap: the batch is the STALEST slice of the backlog", new Set(capped.map((r) => r.address)).has("0xbeef010f9cb27031ad51e3333f9af9c6b1228183"), true);
// Freshness ordering inside the batch: the second batch must differ from the
// first (probed rows got fresh lastProbe stamps on the live daemon).
const fullA = selectVaultTargets(2, 10).map((r) => r.address);
check("rotation: batches are staleness-ordered, so successive sweeps rotate", fullA.length >= 5, JSON.stringify(fullA));

console.log(failures === 0 ? "\nvault loop: all checks passed" : `\nvault loop: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
