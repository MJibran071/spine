// Persistent accumulating fuzz campaigns — the tool that turns "probe once,
// 64 runs, move on" into actual bug-finding pressure.
//
// THE GAP: the generic invariant engine ran each target ONCE with the default
// 64 fuzz runs and then self-skipped forever ("same verified source"). 64 runs
// is a smoke test, not a campaign — Foundry invariant campaigns that find real
// bugs run 50k+ sequences. This module:
//
//   1. records a CAMPAIGN for every target the generic engine harnesses;
//   2. the daemon runs ONE bounded slice per cycle (escalating runs, rotating
//      seed) on the highest-value targets first (canoncode class, then
//      least-recently-fuzzed);
//   3. any slice that violates an invariant is verified on a SECOND slice
//      with a different seed before it can become a finding (2/2 bar, same
//      philosophy as verify.ts) — a real violation reproduces across seeds;
//      a harness artifact does not.
//
// Safety: every slice runs through runTestContractOnFork (assertLocalRpc,
// no broadcast, forge self-repair). Nothing here talks to a remote chain.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { buildHarness, evaluateGenHarness, type GenEvaluation } from "./genharness.ts";
import { runTestContractOnFork } from "./runner.ts";
import { spawnForkWithFailover, toChecksumAddress, type AnvilFork } from "./fork.ts";
import { recordGenResult } from "./bus.ts";
import { recordViolation, recordHeld, recordGenError, recordDeadend, recordShapeFailureClass, recordShapeBackoff } from "./genlearn.ts";
import { captureProvenDrain } from "./techniques.ts";
import { learnFromProbe } from "./memory.ts";
import { fetchLiveSource } from "./livesrc.ts";
import { campaignPriority, getCanon } from "./canoncode.ts";

export interface Campaign {
  chainId: string;
  address: string; // lowercase
  shape: string;
  technique: string; // invariant harness label from the originating run
  /** Cumulative fuzz sequences thrown at this target across all slices. */
  runsSoFar: number;
  slices: number;
  lastSeed: string;
  lastSliceAt: number;
  /** Set when a slice violated an invariant; verified becomes a finding. */
  pendingViolation?: { invariant: string; path: string; profitWei: string | null; seed: string };
  violations: number;
  verifiedViolations: number;
  /** Set when the harness cannot even build/run for this target — campaigns
   * stop wasting slices after MAX_BUILD_FAILURES consecutive build errors. */
  consecutiveBuildErrors: number;
}

const STORE_PATH = join(REPORT_DIR, "campaigns.json");
const MAX_BUILD_FAILURES = 3;
/** Slice ladder: each successful slice escalates the run count. A campaign
 * crosses 50k sequences within ~6 slices — real campaign pressure. */
const SLICE_LADDER = [1024, 4096, 8192, 16384, 32768, 65536];

function loadStore(): Record<string, Campaign> {
  try {
    return JSON.parse(readFileSync(STORE_PATH, "utf8")) as Record<string, Campaign>;
  } catch {
    return {};
  }
}

function saveStore(s: Record<string, Campaign>): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(STORE_PATH, JSON.stringify(s));
  } catch {
    /* best-effort */
  }
}

export function keyOf(chainId: string, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}

/** Record (or refresh) a campaign after the generic engine builds a harness
 * for a target. Called from investigate.ts right after a successful build.
 * Optional patch fields apply ON TOP of the stored row — getCampaign returns
 * a fresh parse, so callers that mutate its result must persist via here. */
export function upsertCampaign(c: {
  chainId: string;
  address: string;
  shape: string;
  runsSoFar?: number;
  consecutiveBuildErrors?: number;
}): Campaign {
  const store = loadStore();
  const key = keyOf(c.chainId, c.address);
  const prev = store[key];
  const row: Campaign = prev ?? {
    chainId: c.chainId,
    address: c.address.toLowerCase(),
    shape: c.shape,
    technique: "generic-invariant",
    runsSoFar: 0,
    slices: 0,
    lastSeed: "",
    lastSliceAt: 0,
    violations: 0,
    verifiedViolations: 0,
    consecutiveBuildErrors: 0,
  };
  if (c.shape) row.shape = c.shape;
  if (typeof c.runsSoFar === "number") row.runsSoFar = Math.max(row.runsSoFar, c.runsSoFar);
  if (typeof c.consecutiveBuildErrors === "number") row.consecutiveBuildErrors = c.consecutiveBuildErrors;
  store[key] = row;
  saveStore(store);
  return row;
}

export function getCampaign(chainId: string, address: string): Campaign | null {
  return loadStore()[keyOf(chainId, address)] ?? null;
}

export function campaignStats(): { total: number; active: number; violations: number; verified: number; runsSoFar: number } {
  const all = Object.values(loadStore());
  return {
    total: all.length,
    active: all.filter((c) => c.consecutiveBuildErrors < MAX_BUILD_FAILURES).length,
    violations: all.reduce((a, c) => a + c.violations, 0),
    verified: all.reduce((a, c) => a + c.verifiedViolations, 0),
    runsSoFar: all.reduce((a, c) => a + c.runsSoFar, 0),
  };
}

/** Deterministic per-slice seed: same seed always explores the same sequences
 * (reproducibility), different slices explore different ones (coverage). */
function seedFor(c: Campaign, salt: number): string {
  return `0x${((c.slices + salt) * 2654435761 >>> 0).toString(16).padStart(8, "0")}`;
}

export interface SliceOptions {
  forkUrl?: string;
  forkPort: number;
  chainRpcs: string[];
  daemonId?: string;
  /** Verify a pending violation on a different seed instead of advancing. */
  verifyPending?: boolean;
}

export interface SliceResult {
  ran: boolean;
  note: string;
  discovered?: boolean;
  invariant?: string;
}

/** Persist ONE campaign row against a FRESH parse of the store: a slice runs
 * for minutes while sibling daemons advance OTHER campaigns' runsSoFar, so a
 * save of the slice-start snapshot would silently clobber their progress
 * (last-writer-wins — observed live: 12 fleet slices, runsSoFar unchanged).
 * Only the fields this process mutated are merged onto the fresh row. */
function commitCampaign(key: string, patch: Partial<Campaign>): void {
  const fresh = loadStore();
  const row = fresh[key];
  if (!row) return; // deleted meanwhile — nothing to merge
  Object.assign(row, patch);
  fresh[key] = row;
  saveStore(fresh);
}

/** Run ONE bounded campaign slice against a target on its own local fork.
 * Returns honestly when there is nothing runnable (no harness, build broken,
 * fork dead). A violation is only REPORTED as discovered after it reproduces
 * on a different seed (verifyPending path). */
export async function runCampaignSlice(chainId: string, address: string, opts: SliceOptions): Promise<SliceResult> {
  const store = loadStore();
  const key = keyOf(chainId, address);
  const c = store[key];
  if (!c) return { ran: false, note: "no campaign recorded for target" };
  if (c.consecutiveBuildErrors >= MAX_BUILD_FAILURES) {
    return { ran: false, note: `campaign suspended after ${c.consecutiveBuildErrors} consecutive build failures` };
  }

  // A pending violation must VERIFY on a different seed before it counts.
  if (c.pendingViolation && !opts.verifyPending) {
    return runCampaignSlice(chainId, address, { ...opts, verifyPending: true });
  }

  let fork: AnvilFork | null = null;
  const seed = opts.verifyPending ? (c.pendingViolation?.seed ?? "0xdeadbeef") : seedFor(c, 7);
  const runs = opts.verifyPending
    ? SLICE_LADDER[Math.min(1, SLICE_LADDER.length - 1)] // verification slice: small but seeded differently
    : SLICE_LADDER[Math.min(c.slices, SLICE_LADDER.length - 1)];
  const verifySeed = opts.verifyPending ? `0x${((c.slices + 991) * 2654435761 >>> 0).toString(16)}` : seed;

  try {
    fork = await spawnForkWithFailover(opts.forkUrl ?? opts.chainRpcs[0]!, opts.forkPort, opts.chainRpcs.slice(1));
    // The harness needs the verified SOURCE (shape detection parses it).
    // fetchLiveSource caches under agent/reports/src-cache, so slices after
    // the first are disk-cheap.
    let source = "";
    try {
      const live = await fetchLiveSource(chainId, c.address);
      source = live.source ?? "";
    } catch { /* source fetch is best-effort; build below reports honestly */ }
    const gen = buildHarness(
      { challengeName: `camp-${chainId}-${c.address.slice(0, 10)}`, sources: source ? [source] : [], mode: "address", bindAddress: toChecksumAddress(c.address), chainId },
      0
    );
    if (!gen) {
      commitCampaign(key, { consecutiveBuildErrors: c.consecutiveBuildErrors + 1 });
      return { ran: false, note: source ? "no harness for this target's shape (build returned null)" : "no verified source available to build a harness from" };
    }
    const gres = await runTestContractOnFork(gen.contractName, fork.localRpc, { fuzzRuns: runs, fuzzSeed: verifySeed, timeoutMs: Math.min(900_000, 240_000 + runs) });
    const ev: GenEvaluation = evaluateGenHarness(gres.output);
    c.lastSliceAt = Date.now();
    c.lastSeed = verifySeed;
    c.runsSoFar += runs;
    c.slices += 1;

    if (ev.discovered) {
      if (opts.verifyPending) {
        // 2/2 across seeds — this is a REAL, reproducible violation.
        commitCampaign(key, {
          pendingViolation: undefined,
          verifiedViolations: c.verifiedViolations + 1,
          violations: c.violations + 1,
          runsSoFar: c.runsSoFar + runs,
          slices: c.slices + 1,
          lastSliceAt: Date.now(),
          lastSeed: verifySeed,
        });
        recordViolation(gen.shape, { invariant: ev.invariant, path: ev.path, profitWei: ev.profitWei });
        recordGenResult(key, { shape: gen.shape, result: "discovered", invariant: ev.invariant });
        try {
          captureProvenDrain({
            origin: "generic-invariant",
            technique: `generic-invariant:${ev.invariant}`,
            shape: gen.shape,
            observation: `invariant "${ev.invariant}" violated and VERIFIED across seeds on a live fork campaign`,
            path: ev.path,
            profitWei: ev.profitWei,
            provenOn: c.address,
          });
          learnFromProbe(c.address, gen.shape, `generic-invariant:${ev.invariant}`, "drained", ev.path ? `verified violating path: ${ev.path}` : undefined);
        } catch { /* learning is best-effort */ }
        return { ran: true, discovered: true, invariant: ev.invariant, note: `VERIFIED violation of "${ev.invariant}" after ${c.runsSoFar} cumulative runs (${c.slices} slices)` };
      }
      // First sighting: hold for cross-seed verification. Do NOT report yet.
      commitCampaign(key, {
        pendingViolation: { invariant: ev.invariant, path: ev.path, profitWei: ev.profitWei, seed: verifySeed },
        violations: c.violations + 1,
        runsSoFar: c.runsSoFar + runs,
        slices: c.slices + 1,
        lastSliceAt: Date.now(),
        lastSeed: verifySeed,
      });
      return { ran: true, discovered: false, invariant: ev.invariant, note: `invariant "${ev.invariant}" violated on seed ${verifySeed} — verifying on a different seed next cycle` };
    }

    if (opts.verifyPending) {
      // Did NOT reproduce on a different seed: harness artifact, retire it.
      commitCampaign(key, { pendingViolation: undefined, runsSoFar: c.runsSoFar + runs, slices: c.slices + 1, lastSliceAt: Date.now(), lastSeed: verifySeed });
      recordHeld(gen.shape);
      return { ran: true, note: `pending violation did not reproduce on a different seed — retired as flaky` };
    }

    if (ev.compileError) {
      commitCampaign(key, { consecutiveBuildErrors: 0, runsSoFar: c.runsSoFar + runs, slices: c.slices + 1, lastSliceAt: Date.now(), lastSeed: verifySeed });
      recordGenError(gen.shape, "campaign slice failed to compile");
      recordShapeFailureClass(gen.shape, "compile", ev.compileErrorDetail ?? "compile error (no detail)");
      try { recordShapeBackoff(gen.shape); } catch { /* advisory */ }
      return { ran: true, note: "campaign slice hit a compile error" };
    }
    if (ev.setupFailed) {
      // setUp dead ends are PERMANENT for this target (live state cannot be
      // bootstrapped) — suspend the campaign rather than burn slices forever.
      commitCampaign(key, { consecutiveBuildErrors: MAX_BUILD_FAILURES, runsSoFar: c.runsSoFar + runs, slices: c.slices + 1, lastSliceAt: Date.now(), lastSeed: verifySeed });
      recordDeadend(gen.shape, "campaign setUp failed: live constructor/state could not be bootstrapped from the fork");
      return { ran: true, note: "campaign suspended: setUp cannot bootstrap this live target" };
    }
    commitCampaign(key, { consecutiveBuildErrors: 0, runsSoFar: c.runsSoFar + runs, slices: c.slices + 1, lastSliceAt: Date.now(), lastSeed: verifySeed });
    recordHeld(gen.shape);
    return { ran: true, note: `held across ${runs} runs (cumulative ${c.runsSoFar + runs})` };
  } catch (e) {
    return { ran: false, note: `campaign slice error: ${(e as Error).message.slice(0, 160)}` };
  } finally {
    fork?.stop();
  }
}

/** Pick the next campaign target: canoncode class first (custom > fork-delta),
 * then least-recently-sliced, skipping suspended campaigns. */
export function selectCampaignTarget(): { chainId: string; address: string; campaign: Campaign } | null {
  const store = loadStore();
  const rows = Object.values(store)
    .filter((c) => c.consecutiveBuildErrors < MAX_BUILD_FAILURES)
    .sort((a, b) => {
      const ca = getCanon(a.chainId, a.address)?.codeClass ?? "boilerplate";
      const cb = getCanon(b.chainId, b.address)?.codeClass ?? "boilerplate";
      return campaignPriority({ codeClass: ca } as never, { codeClass: cb } as never) || a.lastSliceAt - b.lastSliceAt;
    });
  return rows.length ? { chainId: rows[0]!.chainId, address: rows[0]!.address, campaign: rows[0]! } : null;
}

// ---------------- SATURATION GATE ----------------
// Invariant fuzzing is SATURATING, not diminishing: an unsound invariant on a
// target shows up in the first tens of thousands of runs (the fleet's largest
// campaign had 15M runs and never violated). A saturated campaign holds slices
// hostage by lexicographic sort, so newer/less-sampled campaigns starve. After
// CLEAN_RUNS_PER_PERCENT runs with zero violations, each further cycle-slice
// costs ~1% of its cumulative budget and gets backoff-scheduled instead — the
// campaign stays discoverable (long-shot recheck), never a slot hostage.
const CLEAN_RUNS_PER_PERCENT = 50_000;
const SLICE_MIN_GAP_MS = 6 * 3600_000; // saturated campaigns recheck ~4x/day

/** True when this campaign has burned enough CLEAN runs that further slices
 * are statistically dead weight until its recheck window elapses. */
export function campaignSaturated(c: { runsSoFar: number; violations: number; lastSliceAt: number }): boolean {
  if (c.violations > 0) return false;
  const saturationRuns = Math.max(1, Math.ceil(c.runsSoFar / CLEAN_RUNS_PER_PERCENT)) * CLEAN_RUNS_PER_PERCENT;
  return c.runsSoFar >= saturationRuns && Date.now() - c.lastSliceAt < SLICE_MIN_GAP_MS;
}

/** Campaigns for a canoncode class (priority order) — the daemon may take a
 * bounded batch per cycle. */
export function selectCampaignBatch(n: number): { chainId: string; address: string; campaign: Campaign }[] {
  const store = loadStore();
  return Object.values(store)
    .filter((c) => c.consecutiveBuildErrors < MAX_BUILD_FAILURES)
    .sort((a, b) => {
      const ca = getCanon(a.chainId, a.address)?.codeClass ?? "boilerplate";
      const cb = getCanon(b.chainId, b.address)?.codeClass ?? "boilerplate";
      return campaignPriority({ codeClass: ca } as never, { codeClass: cb } as never) || a.lastSliceAt - b.lastSliceAt;
    })
    .slice(0, Math.max(0, n))
    .map((c) => ({ chainId: c.chainId, address: c.address, campaign: c }));
}

/** MARKET SHARDING for campaign slices. Without this, every daemon in the
 * fleet picked the SAME global top-N each cycle and eight concurrent `forge`
 * runs wrote the SAME GenFork_<addr>_vN.t.sol: transient "compile error"
 * races on every slice (observed live across all 8 daemons at cycle 1-2) and
 * 8x wasted duplicate fuzz work. Assignment reuses daemon.ts's ownsTarget
 * scheme — hash(lowercased address) % fleetSize === chainOffset — so the
 * daemon that PROBES a target is also the one that FUZZES it. Untouched when
 * LAB_FLEET_SIZE is unset (fleet of 1 owns everything, same as before). */
export function selectCampaignBatchSharded(
  n: number,
  chainOffset: number,
  fleetSize: number
): { chainId: string; address: string; campaign: Campaign }[] {
  const size = Math.max(1, fleetSize || 1);
  const off = ((chainOffset % size) + size) % size;
  const store = loadStore();
  return Object.values(store)
    .filter((c) => c.consecutiveBuildErrors < MAX_BUILD_FAILURES)
    // SATURATION GATE: a campaign past its clean-run budget only rechecks on
    // the ~4x/day cadence instead of starving younger campaigns every cycle.
    .filter((c) => !campaignSaturated(c))
    .filter((c) => {
      let h = 0;
      const addr = c.address.toLowerCase();
      for (let i = 0; i < addr.length; i++) h = (h * 31 + addr.charCodeAt(i)) >>> 0;
      return h % size === off;
    })
    .sort((a, b) => {
      const ca = getCanon(a.chainId, a.address)?.codeClass ?? "boilerplate";
      const cb = getCanon(b.chainId, b.address)?.codeClass ?? "boilerplate";
      return campaignPriority({ codeClass: ca } as never, { codeClass: cb } as never) || a.lastSliceAt - b.lastSliceAt;
    })
    .slice(0, Math.max(0, n))
    .map((c) => ({ chainId: c.chainId, address: c.address, campaign: c }));
}

/** Persisted campaign rows (read-only) for the funnel. */
export function allCampaigns(): Campaign[] {
  return Object.values(loadStore());
}
