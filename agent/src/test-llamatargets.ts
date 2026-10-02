// Regression test for the DefiLlama SMALL-TVL targeting lane (llamatargets.ts).
//
// WHY THIS LANE EXISTS: the previous OSINT seed required tvl >= $1M — the
// opposite of the base-rate truth that undiscovered bugs concentrate in
// fresh, unaudited, tiny protocols. These tests pin the ranking order, the
// filter edges (ceiling, dead deployments, chain-prefix addresses), and the
// seeding contract (Ethereum-only enlistment, cap, never re-enlist, honest
// skip reasons).
//
// Runs against a scratch report dir (LAB_REPORT_DIR) — the live hunt's
// reports/state.json is never touched, and the DefiLlama cache file the
// test writes lives only in the scratch dir.
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-llamatargets-"));
process.env.LAB_REPORT_DIR = SCRATCH; // must be set before the bus reads config
process.env.LAB_OFFLINE = "1"; // no accidental outbound calls from bus hooks

// Dynamic import: a static one would be hoisted above the env assignment.
const { smallTargets, smallRank, seedSmallTargets, tvlCeiling, llamaSeedTargets } = await import("./llamatargets.ts");
const { snapshot, hydrateFromDisk, persistSnapshot } = await import("./bus.ts");

let failures = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    console.log(`ok: ${name}`);
    return;
  }
  failures++;
  console.error(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
}

const NOW = 1_760_000_000; // fixed epoch second — ranking must stay pure
const day = 86_400;

function proto(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    name: "ProtoA",
    chain: "ethereum",
    category: "lending",
    audits: "0",
    listedAt: NOW - 10 * day,
    tvl: 400_000,
    ...overrides,
  };
}

// ---- 1. the filter: under the ceiling only --------------------------------
check("ceiling defaults to $1M", tvlCeiling() === 1_000_000);
const overCeiling = smallTargets([proto({ tvl: 1_000_000 }), proto({ name: "Big", tvl: 900_000_000_000 })] as never, 25);
check("protocols at or above the ceiling are excluded", overCeiling.length === 0);
const dead = smallTargets([proto({ tvl: 0 }), proto({ tvl: -5 }), proto({ name: "Alive", tvl: 1 })] as never, 25);
check("zero/negative TVL deployments excluded, tiny positive kept", dead.length === 1 && dead[0]!.name === "Alive");

// ---- 2. ranking: fresh + unaudited + tvl-proximity + harnessable -----------
const [fresher, older] = smallTargets(
  [
    proto({ name: "Older", listedAt: NOW - 200 * day }),
    proto({ name: "Fresher", listedAt: NOW - 3 * day }),
  ] as never,
  25
);
check("fresher protocol outranks an otherwise identical one", fresher.name === "Fresher", `${fresher.name} > ${older.name}?`);
const [audited] = smallTargets([proto({ audits: "2", name: "Audited" }), proto({ name: "Unaudited" })] as never, 25);
check("unaudited outranks audited within the lane", audited.name === "Unaudited");
const [harnessable] = smallTargets(
  [proto({ category: "nft marketplace", name: "Nft" }), proto({ category: "yield aggregator", name: "Vault" })] as never,
  25
);
check("harnessable category outranks non-probeable shape", harnessable.name === "Vault");
const rank = smallRank({ tvl: 400_000, audits: "0", listedAt: NOW - 5 * day, category: "cdp" }, NOW, 1_000_000);
check("score stays in range and every factor is reported", rank.score > 0 && rank.score <= 1 && Object.keys(rank.factors).length === 4, JSON.stringify(rank.factors));

// ---- 3. address/chain extraction ------------------------------------------
const [withPrefix] = smallTargets(
  [proto({ name: "PrefixTarget", address: "base:0x1111111111111111111111111111111111111111" })] as never,
  25
);
check("chain-prefixed address overrides the row chain", withPrefix.chain === "base" && withPrefix.address === "0x1111111111111111111111111111111111111111");
const [plain] = smallTargets([proto({ name: "PlainTarget", address: "0x2222222222222222222222222222222222222222" })] as never, 25);
check("plain hex address keeps the row chain", plain.chain === "ethereum" && plain.address === "0x2222222222222222222222222222222222222222");
const deduped = smallTargets(
  [
    proto({ name: "Same", address: "0x3333333333333333333333333333333333333333" }),
    proto({ name: "Same", address: "0x3333333333333333333333333333333333333333", chain: "arbitrum" }),
  ] as never,
  25
);
check("the same deployment is deduped", deduped.length === 1);

// ---- 4. seeding contract --------------------------------------------------
// Multi-chain: seeds on scanner-supported chains (bsc, base, …) land in the
// per-chain registry the scanner consumes; Ethereum additionally gets the
// continuous fork-watch row. Unsupported chains (solana, sui) stay intel.
const targets = smallTargets(
  [
    proto({ name: "EthSmall", address: "0x4444444444444444444444444444444444444444", chain: "ethereum", tvl: 500_000 }),
    proto({ name: "BscSmall", address: "0x5555555555555555555555555555555555555555", chain: "bsc", tvl: 400_000 }),
    proto({ name: "NoAddr", address: null as unknown as string, chain: "ethereum", tvl: 300_000 }),
  ] as never,
  25
);
const outcomes = seedSmallTargets(targets, 10);
check("ethereum target enlisted", outcomes.find((o) => o.name === "EthSmall")?.action === "seeded");
check("bsc target seeded into the scanner registry", outcomes.find((o) => o.name === "BscSmall")?.action === "seeded");
check("address-less target recorded as skipped-invalid", outcomes.find((o) => o.name === "NoAddr")?.action === "skipped-invalid");
const wl = Object.values(snapshot().watchlist);
const ethRow = wl.find((w) => w.address?.toLowerCase() === "0x4444444444444444444444444444444444444444");
check("seeded row is enlisted + flagged as a seed", ethRow?.enlisted === true && ethRow?.seeded === true);
check("seeded row carries the protocol name + category", ethRow?.name === "EthSmall" && !!ethRow?.category);
check("seeded row's lastResult names the lane", String(ethRow?.lastResult ?? "").includes("[llama small]"));
check("non-ethereum row never got a bare watch row", !wl.some((w) => w.address?.toLowerCase() === "0x5555555555555555555555555555555555555555"));

// Registry round-trip: llamaSeedTargets must surface the BSC seed to the scanner.
{
  const { CHAINS } = await import("./scan.ts");
  const bsc = CHAINS.find((c) => c.id === "56")!;
  const seeds = llamaSeedTargets(bsc);
  check("scanner sees the bsc seed via llamaSeedTargets", seeds.some((t) => t.address === "0x5555555555555555555555555555555555555555" && t.source === "seed"), JSON.stringify(seeds.map((t) => t.address)));
  const eth = CHAINS.find((c) => c.id === "1")!;
  check("ethereum chain does not receive the bsc seed", !llamaSeedTargets(eth).some((t) => t.address === "0x5555555555555555555555555555555555555555"));
}

// Unsupported chain: intel-only, never seeded.
const solanaOutcome = seedSmallTargets(
  smallTargets([proto({ name: "Solanoid", address: "0x6666666666666666666666666666666666666666", chain: "solana", tvl: 250_000 })] as never, 1),
  5
);
check("solana target stays intel-only (skipped-chain)", solanaOutcome[0]?.action === "skipped-chain");

// Cap: only maxNew enlist even when more candidates exist.
const many = Array.from({ length: 5 }, (_, i) =>
  smallTargets([proto({ name: `Cap${i}`, address: `0x000000000000000000000000000000000000000${i}` })] as never, 1)[0]!
);
const capped = seedSmallTargets(many, 2);
check("seed cap enforced", capped.filter((o) => o.action === "seeded").length === 2 && capped.filter((o) => o.action === "skipped-cap").length === 3);

// Never re-enlist: a manual removal sticks.
const again = seedSmallTargets(targets, 10);
check("existing address reports exists, not seeded", again.find((o) => o.name === "EthSmall")?.action === "exists");
check("no second row created for the same target", Object.values(snapshot().watchlist).filter((w) => w.address?.toLowerCase() === "0x4444444444444444444444444444444444444444").length === 1);

// ---- 5. bus round-trip on the scratch dir (state integrity) ---------------
persistSnapshot();
hydrateFromDisk();
const afterHydrate = Object.values(snapshot().watchlist).find((w) => w.address?.toLowerCase() === "0x4444444444444444444444444444444444444444");
check("seeded row survives a disk round-trip", afterHydrate?.seeded === true && afterHydrate?.enlisted === true);

try {
  rmSync(SCRATCH, { recursive: true, force: true });
} catch { /* scratch cleanup best-effort */ }

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log("\nall llamatargets checks passed");
process.exit(0);
