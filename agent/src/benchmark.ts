// Fleet capability benchmark — "what are our agents actually capable of?"
//
// replay.ts answers "would the fleet have caught PAST hacks" (historical).
// This module answers the complementary, present-tense question: measured
// TODAY, what does the hunt pipeline achieve end-to-end, and where does it
// leak capability? Five sections, each on real production targets:
//
//   A. CHAIN MATRIX      per registered chain: reachable? hot pairs found?
//                        vaults found? factory targets? (discovery throughput)
//   B. FORK CAPABILITY   fork the top targets, run recon + template probes —
//                        how often does recon classify a shape, how often does
//                        a probe actually simulate?
//   C. FLEET OUTCOMES    the live watchlist's own lastResult histogram + triage
//                        health — what the 24/7 hunt really produces per hour.
//   D. E2E VAULT PROBE   one full pipeline run against a live ERC-4626 vault
//                        (the highest base-rate bug class) on its own chain.
//   E. SCORECARD         derived metrics + rule-based improvement flags.
//
// Read-only: discovery RPCs are the same allowlisted read-only calls the
// scanner uses; forks are local anvil only; nothing broadcasts. On-demand:
// `npm run benchmark [chainLimit]` — never scheduled alongside the hunt.
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, OFFLINE } from "./config.ts";
import {
  CHAINS,
  chainReachable,
  discoverHotPairs,
  discoverHotVaults,
  discoverAmmTargets,
  type ChainSpec,
} from "./scan.ts";
import { AnvilFork, reconPool, simulateOnFork, spawnForkWithFailover, type PoolRecon, type ForkFinding } from "./fork.ts";
import { triageHealth } from "./triage.ts";
import { triageQueueStats } from "./triageQueue.ts";
import { hydrateFromDisk, snapshot } from "./bus.ts";

const BENCH_DIR = join(REPORT_DIR, "benchmark");
const FORK_PORT_BASE = 8660; // away from the fleet (8550-8649) and replay (8640+)

// ------------------------------------------------------------------ types
export interface ChainBenchRow {
  chain: string;
  id: string;
  ms: number;
  reachable: boolean;
  hotPairs: number;
  topNativeReserveWei: string;
  vaults: number;
  factoryTargets: number | null; // null = no factory registered
  error?: string;
}

export interface ForkBenchRow {
  chain: string;
  target: string;
  shape: string;
  ms: number;
  forkOk: boolean;
  simulated: boolean;
  applicable: boolean;
  profitWei: string;
  technique: string;
  error?: string;
}

export interface FleetOutcomes {
  watchRows: number;
  probed: number;
  classified: number;
  findings: number;
  resultBuckets: Record<string, number>;
  events24h: Record<string, number>;
  triage: Record<string, unknown>;
  queue: Record<string, unknown>;
}

export interface E2EVaultProbe {
  chain: string;
  target: string;
  shape: string;
  ms: number;
  simulated: boolean;
  applicable: boolean;
  profitWei: string;
  note: string;
  ran: boolean;
  error?: string;
}

export interface CapabilityReport {
  at: string;
  offline: boolean;
  chainMatrix: ChainBenchRow[];
  forkCapability: ForkBenchRow[];
  fleet: FleetOutcomes;
  e2eVault: E2EVaultProbe;
  scorecard: Record<string, unknown>;
  improvements: string[];
}

// ------------------------------------------------------------- A. chains
async function benchChain(c: ChainSpec): Promise<ChainBenchRow> {
  const t0 = Date.now();
  const row: ChainBenchRow = {
    chain: c.name,
    id: c.id,
    ms: 0,
    reachable: false,
    hotPairs: 0,
    topNativeReserveWei: "0",
    vaults: 0,
    factoryTargets: c.factories.length > 0 ? 0 : null,
  };
  try {
    row.reachable = await chainReachable(c);
    if (!row.reachable) {
      row.ms = Date.now() - t0;
      return row;
    }
    const [hot, vaults, factory] = await Promise.all([
      discoverHotPairs(c, 30, 40, 8).catch(() => []),
      discoverHotVaults(c, 300, 8).catch(() => []),
      c.factories.length > 0 ? discoverAmmTargets(c, 100_000, 8).catch(() => []) : Promise.resolve([]),
    ]);
    row.hotPairs = hot.length;
    row.topNativeReserveWei = hot.length > 0 ? hot[0]!.nativeReserve.toString() : "0";
    row.vaults = vaults.length;
    if (c.factories.length > 0) row.factoryTargets = factory.length;
  } catch (e) {
    row.error = (e as Error).message.slice(0, 120);
  }
  row.ms = Date.now() - t0;
  return row;
}

// ------------------------------------------------- B. fork + recon + sim
function techniqueFor(shape: string): string {
  if (shape.includes("side-entrance")) return "side-entrance-reentrancy";
  if (shape.includes("erc-4626")) return "erc4626-share-inflation";
  return "manual-analysis-required";
}

async function benchFork(c: ChainSpec, target: string, port: number): Promise<ForkBenchRow> {
  const row: ForkBenchRow = {
    chain: c.name,
    target,
    shape: "",
    ms: 0,
    forkOk: false,
    simulated: false,
    applicable: false,
    profitWei: "0",
    technique: "",
  };
  const t0 = Date.now();
  let fork: AnvilFork | null = null;
  try {
    fork = await spawnForkWithFailover(c.rpcs[0]!, port, c.rpcs.slice(1));
    row.forkOk = true;
    const recon: PoolRecon = await reconPool(fork, target);
    row.shape = recon.shape;
    row.technique = techniqueFor(recon.shape);
    const f: ForkFinding = await simulateOnFork(fork, recon, row.technique);
    row.simulated = f.simulated;
    row.applicable = f.applicable;
    row.profitWei = f.profitWei;
  } catch (e) {
    row.error = (e as Error).message.slice(0, 140);
  } finally {
    try { fork?.stop(); } catch { /* already gone */ }
  }
  row.ms = Date.now() - t0;
  return row;
}

// ------------------------------------------------------- C. fleet truth
function bucketResult(r: string): string {
  const s = r.toLowerCase();
  if (s.startsWith("probe ran clean")) return "probe-clean";
  if (s.includes("probe finding") || s.includes("[finding]")) return "probe-signal";
  if (s.includes("probe reverted") || s.includes("custom error")) return "probe-reverted";
  if (s.includes("probe error") || s.includes("probe skipped")) return "probe-error";
  if (s.includes("triage deferred")) return "triage-deferred";
  if (s.includes("llm triage")) return "triaged";
  if (s.includes("no verified source")) return "unverified-source";
  if (s.includes("no drain")) return "no-drain";
  if (!r) return "unprobed";
  return "other";
}

function fleetOutcomes(): FleetOutcomes {
  const out: FleetOutcomes = {
    watchRows: 0,
    probed: 0,
    classified: 0,
    findings: 0,
    resultBuckets: {},
    events24h: {},
    triage: {},
    queue: {},
  };
  try {
    hydrateFromDisk(); // load the fleet's persisted shared state
    const s = snapshot();
    const rows = Object.values(s.watchlist ?? {}).filter((w) => String(w.address ?? "").indexOf("…") < 0);
    out.watchRows = rows.length;
    for (const w of rows) {
      if (w.lastProbe) out.probed++;
      if (w.shape && !String(w.shape).startsWith("unknown")) out.classified++;
      const b = bucketResult(String(w.lastResult ?? ""));
      out.resultBuckets[b] = (out.resultBuckets[b] ?? 0) + 1;
    }
    out.findings = (s.findings ?? []).length;
    const cutoff = Date.now() - 24 * 3600_000;
    for (const e of s.events ?? []) {
      if (e.t < cutoff) continue;
      out.events24h[e.kind] = (out.events24h[e.kind] ?? 0) + 1;
    }
  } catch { /* degraded but honest zeros */ }
  try {
    const th = triageHealth() as unknown as Record<string, unknown>;
    out.triage = {
      ok: th.ok,
      keys: th.keys,
      cooldownMs: th.cooldownMs,
      cooldownKeys: th.cooldownKeys,
      quarantined: th.quarantined,
      budget: th.budget,
      counts: th.counts,
    };
  } catch { /* cosmetic */ }
  try {
    out.queue = triageQueueStats() as unknown as Record<string, unknown>;
  } catch { /* cosmetic */ }
  return out;
}

// --------------------------------------------------- D. end-to-end vault
async function e2eVault(rows: ChainBenchRow[], port: number): Promise<E2EVaultProbe> {
  const empty: E2EVaultProbe = {
    chain: "", target: "", shape: "", ms: 0, simulated: false, applicable: false,
    profitWei: "0", note: "no live ERC-4626 vault reachable in this run", ran: false,
  };
  if (OFFLINE) return { ...empty, note: "offline mode — skipped" };
  // Prefer the fleet's own classified vault rows (hydrated in section C);
  // fall back to fresh discovery on the fastest reachable chains.
  let pick: { chain: ChainSpec; address: string } | null = null;
  try {
    const s = snapshot();
    for (const [key, w] of Object.entries(s.watchlist ?? {})) {
      const shape = String(w.shape ?? "");
      if (!shape.includes("4626") && !shape.toLowerCase().includes("vault")) continue;
      const m = key.replace(/\s+\[[^\]]*\]\s*$/, "").match(/^([a-z0-9]+):(0x[0-9a-f]{40})$/i);
      if (!m) continue;
      const chain = CHAINS.find((c) => c.name === m[1]!.toLowerCase());
      if (chain) { pick = { chain, address: m[2]! }; break; }
    }
  } catch { /* fall through to discovery */ }
  if (!pick) {
    for (const row of rows.filter((r) => r.reachable && r.vaults > 0).slice(0, 3)) {
      const chain = CHAINS.find((c) => c.name === row.chain)!;
      try {
        const vaults = await discoverHotVaults(chain, 300, 1);
        if (vaults.length > 0) { pick = { chain, address: vaults[0]!.address }; break; }
      } catch { /* next chain */ }
    }
  }
  if (!pick) return empty;

  const probe: E2EVaultProbe = {
    chain: pick.chain.name, target: pick.address, shape: "", ms: 0,
    simulated: false, applicable: false, profitWei: "0", note: "", ran: true,
  };
  const t0 = Date.now();
  let fork: AnvilFork | null = null;
  try {
    fork = await spawnForkWithFailover(pick.chain.rpcs[0]!, port, pick.chain.rpcs.slice(1));
    const recon = await reconPool(fork, pick.address);
    probe.shape = recon.shape;
    const technique = techniqueFor(recon.shape);
    const f = await simulateOnFork(fork, recon, technique);
    probe.simulated = f.simulated;
    probe.applicable = f.applicable;
    probe.profitWei = f.profitWei;
    probe.note = f.notes.slice(0, 200);
  } catch (e) {
    probe.error = (e as Error).message.slice(0, 160);
  } finally {
    try { fork?.stop(); } catch { /* gone */ }
  }
  probe.ms = Date.now() - t0;
  return probe;
}

// ------------------------------------------------------- E. scorecard
function derive(rows: ChainBenchRow[], forks: ForkBenchRow[], fleet: FleetOutcomes, e2e: E2EVaultProbe): {
  scorecard: Record<string, unknown>;
  improvements: string[];
} {
  const reachable = rows.filter((r) => r.reachable).length;
  const classifiedForks = forks.filter((f) => f.forkOk && f.shape && !f.shape.startsWith("unknown")).length;
  const simForks = forks.filter((f) => f.simulated).length;
  const attempted = Object.values(fleet.resultBuckets).reduce((a, b) => a + b, 0);
  const unprobed = fleet.resultBuckets["unprobed"] ?? 0;
  const clean = fleet.resultBuckets["probe-clean"] ?? 0;
  const reverted = fleet.resultBuckets["probe-reverted"] ?? 0;
  const unverified = fleet.resultBuckets["unverified-source"] ?? 0;
  const tri = fleet.triage as { ok?: number; keys?: number; cooldownKeys?: number; quarantined?: number; budget?: { max?: number; used?: number }; counts?: Record<string, number> };
  const triageCounts = tri?.counts ?? {};
  const triageAttempts = (tri?.ok ?? 0) + Object.entries(triageCounts).filter(([k]) => k !== "ok").reduce((a, [, v]) => a + (v as number), 0);
  const scorecard: Record<string, unknown> = {
    chainsReachable: `${reachable}/${rows.length}`,
    discoveryThroughput: {
      hotPairs: rows.reduce((a, r) => a + r.hotPairs, 0),
      vaults: rows.reduce((a, r) => a + r.vaults, 0),
      factoryTargets: rows.reduce((a, r) => a + (r.factoryTargets ?? 0), 0),
    },
    fork: {
      booted: forks.filter((f) => f.forkOk).length + (e2e.ran && !e2e.error ? 1 : 0),
      reconClassifiedPct: forks.length ? Math.round((classifiedForks / forks.length) * 100) : 0,
      probeSimulatedPct: forks.length ? Math.round((simForks / forks.length) * 100) : 0,
    },
    fleet: {
      probedPct: attempted ? Math.round(((attempted - unprobed) / attempted) * 100) : 0,
      classifiedPct: fleet.watchRows ? Math.round((fleet.classified / fleet.watchRows) * 100) : 0,
      cleanPct: attempted ? Math.round((clean / attempted) * 100) : 0,
      revertedPct: attempted ? Math.round((reverted / attempted) * 100) : 0,
      unverifiedSourcePct: attempted ? Math.round((unverified / attempted) * 100) : 0,
      findings: fleet.findings,
      events24h: fleet.events24h,
    },
    triage: {
      okPct: triageAttempts ? Math.round(((tri?.ok ?? 0) / triageAttempts) * 100) : null,
      keys: tri?.keys,
      cooldownKeys: tri?.cooldownKeys,
      quarantined: tri?.quarantined,
      budgetUsed: tri?.budget?.used,
      budgetMax: tri?.budget?.max,
      queueSize: (fleet.queue as { size?: number }).size,
    },
    e2eVault: e2e.ran
      ? { chain: e2e.chain, target: e2e.target, shape: e2e.shape, simulated: e2e.simulated, profitWei: e2e.profitWei, ok: !e2e.error }
      : { ran: false },
  };
  // Rule-based improvement flags — each maps to a concrete lever.
  const imp: string[] = [];
  const dead = rows.filter((r) => !r.reachable);
  if (dead.length) imp.push(`${dead.length} chain(s) unreachable (${dead.map((d) => d.chain).join(", ")}) — fix or drop their RPC lists; every dead chain is blind market share.`);
  const barren = rows.filter((r) => r.reachable && r.hotPairs === 0);
  if (barren.length) imp.push(`${barren.length} reachable chain(s) found 0 hot pairs (${barren.map((b) => b.chain).join(", ")}) — hot-pair discovery (chain-wide getLogs window) is being refused there; find endpoints that allow it or add factories.`);
  const noFactory = rows.filter((r) => r.reachable && r.factoryTargets === 0 && r.hotPairs === 0 && r.vaults === 0);
  if (noFactory.length) imp.push(`${noFactory.length} chain(s) produce nothing at all (${noFactory.map((n) => n.chain).join(", ")}) — highest-leverage RPC/factory work.`);
  if (forks.length && classifiedForks / forks.length < 0.5) imp.push(`recon classified only ${classifiedForks}/${forks.length} forked targets — shape detection (SELECTORS table) is missing the common patterns on these chains.`);
  if (forks.length && simForks / forks.length < 0.5) imp.push(`only ${simForks}/${forks.length} probes simulated — template-probe coverage gaps on newly discovered shapes (unknown shapes fall to manual-analysis).`);
  if (attempted && reverted / attempted > 0.25) imp.push(`${Math.round((reverted / attempted) * 100)}% of fleet probe results are reverts (custom errors) — the generic harness doesn't fit guarded vaults (Maple/MetaMorpho-style); add guard-aware probes or preflight simulation.`);
  if (attempted && unverified / attempted > 0.15) imp.push(`${Math.round((unverified / attempted) * 100)}% of targets have no verified source — livesrc providers (blockscout/sourcify/etherscan) don't cover those chains; source access = triage quality.`);
  if (tri?.keys != null && (tri.cooldownKeys ?? 0) > tri.keys / 2) imp.push(`${tri.cooldownKeys}/${tri.keys} triage keys in cooldown — upstream rate limits are the LLM bottleneck, not budget; consider another provider or slower burn.`);
  if (triageAttempts && (tri?.ok ?? 0) / triageAttempts < 0.5) imp.push(`LLM triage ok-rate under 50% — check the biggest failure reason in triage.counts.`);
  const q = fleet.queue as { size?: number; due?: number };
  if ((q?.due ?? 0) > 100) imp.push(`${q!.due} triage retries due now (queue ${q!.size}) — deferred verdicts starve targets of hypotheses; drain rate < arrival rate.`);
  if (e2e.ran && e2e.error) imp.push(`E2E vault probe errored (${e2e.error}) — the erc4626 path must stay proven end-to-end; investigate.`);
  if (e2e.ran && !e2e.error && !e2e.simulated) imp.push(`E2E vault probe did not simulate (shape "${e2e.shape}") — the highest base-rate class is not machine-probed on this vault; harness work needed.`);
  if (imp.length === 0) imp.push("no structural gaps flagged this run — raise targets per chain (top-N) and re-run for a harder read.");
  return { scorecard, improvements: imp };
}

// ------------------------------------------------------------- driver
function emptyE2e(): E2EVaultProbe {
  return { chain: "", target: "", shape: "", ms: 0, simulated: false, applicable: false, profitWei: "0", note: "segment without E2E probe (append run performs it)", ran: false };
}

export async function runCapabilityBenchmark(opts?: { chainLimit?: number; forkTargets?: number; chainOffset?: number; append?: boolean }): Promise<{ report: CapabilityReport; jsonPath: string; mdPath: string }> {
  const offset = Math.max(0, opts?.chainOffset ?? 0);
  const chainLimit = Math.max(1, Math.min(CHAINS.length - offset, opts?.chainLimit ?? CHAINS.length - offset));
  const forkTargets = Math.max(1, Math.min(8, opts?.forkTargets ?? 4));
  const chains = CHAINS.slice(offset, offset + chainLimit);

  // A. chain matrix (sequential — gentle on shared free endpoints)
  const chainRows: ChainBenchRow[] = [];
  for (const c of chains) {
    if (OFFLINE) break;
    chainRows.push(await benchChain(c));
  }

  // APPEND mode: merge this segment's rows into a previously written report
  // (lets a long matrix be measured across several foreground runs without
  // losing earlier segments).
  let mergedRows = chainRows;
  if (opts?.append) {
    try {
      const prev = JSON.parse(readFileSync(join(BENCH_DIR, "CAPABILITY.json"), "utf8")) as CapabilityReport;
      const byName = new Map(prev.chainMatrix.map((r) => [r.chain, r]));
      for (const r of chainRows) byName.set(r.chain, r);
      mergedRows = [...byName.values()];
    } catch { /* no previous report — this segment stands alone */ }
  }

  // B. fork capability on the juiciest discovered targets (top 2 chains)
  const forkRows: ForkBenchRow[] = [];
  let port = FORK_PORT_BASE;
  if (!OFFLINE && opts?.append) {
    const candidates = mergedRows
      .filter((r) => r.reachable && r.hotPairs > 0)
      .sort((a, b) => (BigInt(b.topNativeReserveWei) > BigInt(a.topNativeReserveWei) ? 1 : -1))
      .slice(0, 2);
    for (const row of candidates) {
      const chain = CHAINS.find((c) => c.name === row.chain);
      if (!chain) continue;
      try {
        const hot = await discoverHotPairs(chain, 30, 16, 8);
        for (const h of hot.slice(0, Math.ceil(forkTargets / candidates.length))) {
          forkRows.push(await benchFork(chain, h.address, port++));
        }
      } catch { /* skip chain */ }
    }
  }

  // C. fleet outcomes from the shared persisted state + live triage health
  const fleet = fleetOutcomes();

  // D. one end-to-end ERC-4626 probe (final segment only — it re-reads state)
  const e2e = opts?.append ? await e2eVault(mergedRows, port++) : emptyE2e();

  // E. scorecard + report
  const { scorecard, improvements } = derive(mergedRows, forkRows, fleet, e2e);
  const report: CapabilityReport = {
    at: new Date().toISOString(),
    offline: OFFLINE,
    chainMatrix: mergedRows,
    forkCapability: forkRows,
    fleet,
    e2eVault: e2e,
    scorecard,
    improvements,
  };

  mkdirSync(BENCH_DIR, { recursive: true });
  const jsonPath = join(BENCH_DIR, "CAPABILITY.json");
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) + "%" : "—");
  const md = [
    "# FLEET CAPABILITY BENCHMARK",
    "",
    `_generated ${report.at} — live read-only run; forks are local anvil only_`,
    "",
    "## A. Chain discovery matrix",
    "",
    "| chain | reachable | hot pairs | top native reserve | vaults | factory targets | ms |",
    "|---|---|---|---|---|---|---|",
    ...chainRows.map((r) =>
      `| ${r.chain} (${r.id}) | ${r.reachable ? "✓" : "✗"} | ${r.hotPairs} | ${r.topNativeReserveWei === "0" ? "—" : r.topNativeReserveWei} | ${r.vaults} | ${r.factoryTargets ?? "—"} | ${r.ms} |`
    ),
    "",
    "## B. Fork / recon / simulate capability",
    "",
    "| chain | target | shape | fork | simulated | technique | ms |",
    "|---|---|---|---|---|---|---|",
    ...(forkRows.length
      ? forkRows.map((f) => `| ${f.chain} | ${f.target.slice(0, 12)}… | ${f.shape.slice(0, 34) || (f.error ? `ERR: ${f.error.slice(0, 30)}` : "?")} | ${f.forkOk ? "✓" : "✗"} | ${f.simulated ? "✓" : "✗"} | ${f.technique} | ${f.ms} |`)
      : ["| — no fork rows (offline or no candidates) — |"]),
    "",
    "## C. Fleet outcomes (24/7 hunt, live state)",
    "",
    `- watchlist rows: **${fleet.watchRows}**, probed: ${pct(fleet.probed, fleet.watchRows)}, shape-classified: ${pct(fleet.classified, fleet.watchRows)}`,
    `- findings: **${fleet.findings}**`,
    `- lastResult buckets: ${Object.entries(fleet.resultBuckets).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(", ") || "none"}`,
    `- events (24h): ${Object.entries(fleet.events24h).map(([k, v]) => `${k}=${v}`).join(", ") || "none"}`,
    `- triage: ok=${(fleet.triage as { ok?: number }).ok ?? "?"} keys=${(fleet.triage as { keys?: number }).keys ?? "?"} budget=${JSON.stringify((fleet.triage as { budget?: unknown }).budget)} queue=${JSON.stringify(fleet.queue)}`,
    "",
    "## D. End-to-end ERC-4626 vault probe",
    "",
    e2e.ran
      ? `- ${e2e.chain}:${e2e.target} — shape "${e2e.shape}", simulated=${e2e.simulated}, profit=${e2e.profitWei} wei, ${e2e.ms}ms${e2e.error ? `, ERROR: ${e2e.error}` : ""}`
      : `- ${e2e.note}`,
    "",
    "## E. Scorecard + what to improve",
    "",
    "```json",
    JSON.stringify(scorecard, null, 2),
    "```",
    "",
    ...improvements.map((i) => `- [ ] ${i}`),
    "",
  ];
  const mdPath = join(BENCH_DIR, "CAPABILITY.md");
  writeFileSync(mdPath, md.join("\n"));
  return { report, jsonPath, mdPath };
}

// ---------------------------------------------------------------------------
const isMain = process.argv[1] && process.argv[1].endsWith("benchmark.ts");
if (isMain) {
  const chainLimit = parseInt(process.argv[2] ?? "0", 10) || undefined;
  const chainOffset = parseInt(process.argv[3] ?? "0", 10) || 0;
  const append = process.argv.includes("--append");
  runCapabilityBenchmark({ chainLimit, chainOffset, append })
    .then(({ mdPath }) => {
      console.log(`capability benchmark done — ${mdPath}`);
      process.exit(0);
    })
    .catch((e) => {
      console.error(`capability benchmark failed: ${(e as Error).message}`);
      process.exit(1);
    });
}
