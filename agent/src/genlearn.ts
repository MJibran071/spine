// Persistent learning for the GENERIC invariant engine (genharness).
//
// The template engine has a knowledge base (knowledge.ts) and probe outcomes
// have long-term memory (memory.ts). The generic engine — the one that finds
// bugs on shapes the lab has NEVER seen — learned nothing between runs: every
// cycle rebuilt the identical harness, re-tripped identical setUp dead ends,
// and a violation proven on one target never warmed the priors for the next
// target of the same shape.
//
// This module closes the loop. Three stores under reports/genlearn.json:
//   violations : shape -> invariant -> proven violating primitive PATHS
//                (the last [GEN_PATH] sequence that broke the property).
//                The fuzzer re-derives them anyway, but seeding the primitive
//                ORDER lets later harnesses reach deep violations sooner and
//                within fewer fuzz runs.
//   deadends   : shape -> "conditions that make the harness unusable"
//                (address-mode setup that cannot bootstrap: no asset
//                introspection, no pair address, listing state on-chain).
//                Recorded ONCE per shape so later cycles skip the dead end
//                instantly instead of re-deriving it.
//   priors     : per-shape counts of held / violated / error outcomes and the
//                last-learned note. The LLM triage prompt receives these so
//                its hypothesis COMPETES with recorded engine history.
//
// INTELLIGENCE UPGRADE (2026-09): the store no longer only answers "what
// happened" — it now shapes WHAT IS TRIED NEXT:
//   shapeBackoffMs : an erroring shape backs off for a cooling period instead
//                of being re-compiled every cycle (427 identical compile
//                failures was the biggest waste in the old loop). Attempts are
//                still allowed on live fork targets, but throttled.
//   outcomes    : per-target index of the last generic-engine result so a
//                repeated visit skips the re-compile/re-run when nothing
//                material changed (source must differ to retry).
//   failureClasses : per-shape compile-failure classes so triage can say WHY
//                a shape keeps erroring, not just that it did.
//   lessons     : cross-shape lessons mined at consolidation time — targets
//                whose generic probe PRODUCED A DRAIN carry the technique
//                class into every future triage hint for sibling shapes.
//
// All synchronous JSON like knowledge.ts (safe under parallel workers), all
// best-effort: any failure degrades to "no learning", never blocks a run.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

let STORE_PATH = join(REPORT_DIR, "genlearn.json");

export interface GenViolationRecord {
  invariant: string; // GENINV tag, e.g. "native", "supply"
  path: string; // joined [GEN_PATH] steps that produced the violation
  profitWei: string | null;
  when: number; // epoch ms
}

export interface GenDeadendRecord {
  condition: string; // human-readable reason the harness could not run
  when: number;
}

export interface GenPriors {
  held: number;
  violated: number;
  errors: number;
  lastNote: string; // most recent outcome note (truncated)
}

/** How the engine last left one specific target (address mode). */
export interface GenTargetOutcome {
  shape: string; // "none" when no harness could be built
  result: "discovered" | "held" | "error" | "skipped";
  sourceLen: number; // length of the verified source the run was based on
  note: string; // truncated summary of the outcome
  when: number;
}

interface GenLearnStore {
  violations: Record<string, Record<string, GenViolationRecord[]>>;
  deadends: Record<string, GenDeadendRecord[]>;
  priors: Record<string, GenPriors>;
  /** Compile failure classes across the whole engine (self-repair telemetry):
   * class -> occurrence count. A class repeating many times is a GENERATOR
   * bug, not a target property — the dashboard surfaces it as such. */
  compileClasses?: Record<string, { count: number; lastWhen: number; lastDetail: string }>;
  /** Per-shape compile-failure classes: the WHY behind priors.errors. */
  failureClasses?: Record<string, Record<string, { count: number; lastWhen: number; lastDetail: string }>>;
  /** Per-shape attempt backoff: shape -> epoch ms after which another
   * attempt is allowed. 0 / absent = no backoff. */
  shapeBackoffMs?: Record<string, number>;
  /** Per-target last outcome (address mode) — repeat-visit suppression. */
  outcomes?: Record<string, GenTargetOutcome>;
  /** Cross-shape lessons mined during consolidation: shape -> technique
   * classes that PROVABLY drained a sibling target of the same shape. */
  lessons?: Record<string, string[]>;
  /** Self-tests may use a scratch store; production code always default. */
  __testKey?: string;
}

const EMPTY: GenLearnStore = { violations: {}, deadends: {}, priors: {} };

let cache: GenLearnStore | null = null;

function load(): GenLearnStore {
  if (cache) return cache;
  try {
    if (existsSync(STORE_PATH)) {
      const parsed = JSON.parse(readFileSync(STORE_PATH, "utf8")) as GenLearnStore;
      cache = {
        violations: parsed.violations ?? {},
        deadends: parsed.deadends ?? {},
        priors: parsed.priors ?? {},
        compileClasses: parsed.compileClasses,
        failureClasses: parsed.failureClasses,
        shapeBackoffMs: parsed.shapeBackoffMs,
        outcomes: parsed.outcomes,
        lessons: parsed.lessons,
      };
      return cache;
    }
  } catch {
    // corrupt store = fresh start (same policy as knowledge.ts)
  }
  cache = { violations: {}, deadends: {}, priors: {} };
  return cache;
}

function save(): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(STORE_PATH, JSON.stringify(cache ?? EMPTY, null, 2));
  } catch {
    // best-effort: losing a learn beat is never worth crashing a hunt
  }
}

/** Test isolation: point the store at a scratch file for the duration of cb. */
export async function withGenLearnTestStore<T>(cb: () => Promise<T>): Promise<T> {
  const prev = cache;
  cache = { violations: {}, deadends: {}, priors: {} };
  const prevPath = STORE_PATH;
  STORE_PATH = join(REPORT_DIR, "genlearn.test.json");
  try {
    return await cb();
  } finally {
    cache = prev;
    STORE_PATH = prevPath;
  }
}

// ------------------------------------------------------------------ writers

/** Record a proven invariant violation (the discovery itself). */
export function recordViolation(shape: string, rec: Omit<GenViolationRecord, "when">): void {
  if (!shape || !rec.invariant) return;
  const st = load();
  const byInv = (st.violations[shape] = st.violations[shape] ?? {});
  const list = (byInv[rec.invariant] = byInv[rec.invariant] ?? []);
  // Keep the 5 most recent distinct paths per (shape, invariant).
  if (!list.some((v) => v.path === rec.path)) {
    list.push({ ...rec, when: Date.now() });
    while (list.length > 5) list.shift();
  }
  const p = st.priors[shape] ?? { held: 0, violated: 0, errors: 0, lastNote: "" };
  p.violated += 1;
  p.lastNote = `violated ${rec.invariant}${rec.path ? ` via ${rec.path.slice(0, 80)}` : ""}`;
  st.priors[shape] = p; // assign back: the default object must not be lost
  // A discovery resets the shape's error backoff: whatever blocked earlier
  // attempts, the engine now has a working recipe for this shape.
  if (st.shapeBackoffMs) delete st.shapeBackoffMs[shape];
  save();
}

/** Record a held run (no violation) — negative evidence, counts toward priors. */
export function recordHeld(shape: string): void {
  if (!shape) return;
  const st = load();
  const p = st.priors[shape] ?? { held: 0, violated: 0, errors: 0, lastNote: "" };
  p.held += 1;
  p.lastNote = "invariants held";
  st.priors[shape] = p;
  // A held run means the harness COMPILED and RAN: any compile-error backoff
  // is stale — the engine can run this shape right now.
  if (st.shapeBackoffMs) delete st.shapeBackoffMs[shape];
  save();
}

/** Record a compile/setup error outcome (counts toward priors). */
export function recordGenError(shape: string, note: string): void {
  if (!shape) return;
  const st = load();
  const p = st.priors[shape] ?? { held: 0, violated: 0, errors: 0, lastNote: "" };
  p.errors += 1;
  p.lastNote = note.slice(0, 100);
  st.priors[shape] = p;
  save();
}

/** Record one occurrence of a compile failure class (self-repair telemetry).
 * Distinct from per-shape priors: a class repeating across MANY targets is a
 * generator bug — the exact signal the old loop buried as 242 identical notes. */
export function recordCompileClass(failureClass: string, detail: string): void {
  if (!failureClass) return;
  const st = load();
  const map = (st.compileClasses ??= {});
  const e = map[failureClass] ?? { count: 0, lastWhen: 0, lastDetail: "" };
  e.count += 1;
  e.lastWhen = Date.now();
  e.lastDetail = detail.slice(0, 160);
  map[failureClass] = e;
  save();
}

/** Record a compile/setup failure class for one SHAPE (the per-shape WHY).
 * Feeds the triage hint and the cross-shape lesson miner. */
export function recordShapeFailureClass(shape: string, failureClass: string, detail: string): void {
  if (!shape || !failureClass) return;
  const st = load();
  const byClass = (st.failureClasses ??= {});
  const map = (byClass[shape] = byClass[shape] ?? {});
  const e = map[failureClass] ?? { count: 0, lastWhen: 0, lastDetail: "" };
  e.count += 1;
  e.lastWhen = Date.now();
  e.lastDetail = detail.slice(0, 160);
  map[failureClass] = e;
  save();
}

/** Put a shape on an exponential attempt backoff after another erroring run.
 * The window doubles per consecutive error (capped), and any better outcome
 * (held/violation) clears it — so the engine gives a shape room to change
 * (new source, fixed generator) without ever forgetting it entirely. */
export function recordShapeBackoff(shape: string): void {
  if (!shape || shape === "none") return;
  const st = load();
  const map = (st.shapeBackoffMs ??= {});
  const prev = map[shape] ?? 0;
  const now = Date.now();
  // Remaining backoff determines the next window size: 10m -> 20m -> 40m …
  // capped at 6h. A long-expired backoff restarts the ladder at 10m.
  const remaining = Math.max(0, prev - now);
  const next = Math.min(6 * 3_600_000, Math.max(10 * 60_000, remaining * 2));
  map[shape] = now + next;
  save();
}

/** True when the shape recently errored enough times to be cooling down.
 * Callers may still attempt the shape (the gate is advisory), but repeated
 * visitors should skip re-deriving a known-bad compile. */
export function shapeCoolingDown(shape: string): boolean {
  if (!shape || shape === "none") return false;
  const until = load().shapeBackoffMs?.[shape] ?? 0;
  return Date.now() < until;
}

/** Minutes left on a shape's cooldown (0 when none) — for logs and hints. */
export function shapeBackoffMinutesLeft(shape: string): number {
  if (!shape || shape === "none") return 0;
  const until = load().shapeBackoffMs?.[shape] ?? 0;
  return Math.max(0, Math.ceil((until - Date.now()) / 60_000));
}

/** Remember how the generic engine last left ONE target (address mode).
 * A repeated visit with the SAME verified source can skip the re-run; a
 * changed source (re-verified, upgraded ABI) legitimately retries. */
export function recordTargetOutcome(
  address: string,
  outcome: { shape: string; result: GenTargetOutcome["result"]; sourceLen: number; note: string }
): void {
  if (!address) return;
  const st = load();
  const map = (st.outcomes ??= {});
  map[address.toLowerCase()] = { ...outcome, note: outcome.note.slice(0, 120), when: Date.now() };
  // Bound the index: 4k targets ≈ months of fleet history; oldest entries
  // (lowest `when`) are evicted first.
  const keys = Object.keys(map);
  if (keys.length > 4000) {
    keys.sort((a, b) => (map[a]!.when ?? 0) - (map[b]!.when ?? 0));
    for (const k of keys.slice(0, keys.length - 4000)) delete map[k];
  }
  save();
}

/** Last recorded generic-engine outcome for a target (null when unknown). */
export function targetOutcome(address: string): GenTargetOutcome | null {
  const o = load().outcomes?.[address.toLowerCase()];
  return o ? { ...o } : null;
}

/** Record a cross-shape lesson: the technique class `technique` DRAINED a
 * live target of `shape` — future triage of `shape` targets should propose
 * it FIRST. Deduped, newest-first, capped per shape. */
export function recordLesson(shape: string, technique: string): void {
  if (!shape || !technique || shape === "none") return;
  const st = load();
  const map = (st.lessons ??= {});
  const list = map[shape] ?? [];
  const clean = technique.slice(0, 60);
  if (!list.includes(clean)) {
    list.unshift(clean);
    while (list.length > 5) list.pop();
    map[shape] = list;
    save();
  }
}

/** Proven technique classes for a shape (newest first), for triage hints. */
export function knownLessons(shape: string): string[] {
  return [...(load().lessons?.[shape] ?? [])];
}

/** Top repeating compile classes, worst first (dashboard/digest hook). */
export function topCompileClasses(n = 5): { failureClass: string; count: number; lastDetail: string }[] {
  const map = load().compileClasses ?? {};
  return Object.entries(map)
    .map(([failureClass, e]) => ({ failureClass, count: e.count, lastDetail: e.lastDetail }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

/** Record a dead-end condition the engine derived the hard way, so the next
 * target of this shape skips it without re-deriving. Deduped per condition. */
export function recordDeadend(shape: string, condition: string): void {
  if (!shape || !condition) return;
  const st = load();
  const list = (st.deadends[shape] = st.deadends[shape] ?? []);
  const c = condition.slice(0, 160);
  if (!list.some((d) => d.condition === c)) {
    list.push({ condition: c, when: Date.now() });
    while (list.length > 10) list.shift();
  }
  save();
}

// ------------------------------------------------------------------ readers

/** Known violating paths for a shape (newest last), across all invariants. */
export function knownViolations(shape: string): GenViolationRecord[] {
  const st = load();
  return Object.values(st.violations[shape] ?? {}).flat();
}

/** Dead-end conditions recorded for a shape (empty when none). */
export function knownDeadends(shape: string): string[] {
  return (load().deadends[shape] ?? []).map((d) => d.condition);
}

/** Outcome priors for a shape (zeroed when unknown). */
export function shapePriors(shape: string): GenPriors {
  return load().priors[shape] ?? { held: 0, violated: 0, errors: 0, lastNote: "" };
}

/** Per-shape failure classes, worst first (the WHY behind errors). */
export function shapeFailureClasses(shape: string): { failureClass: string; count: number; lastDetail: string }[] {
  const map = load().failureClasses?.[shape] ?? {};
  return Object.entries(map)
    .map(([failureClass, e]) => ({ failureClass, count: e.count, lastDetail: e.lastDetail }))
    .sort((a, b) => b.count - a.count);
}

/** One-line engine-history hint for the LLM triage prompt ("" when none).
 * NEGATIVE EVIDENCE IS SHAPED: with 30+ errors and zero held runs, the engine
 * has never actually run on this shape — the prompt says so explicitly so the
 * model stops treating error counts as vulnerability evidence. */
export function genLearnHint(shape: string): string {
  try {
    const p = shapePriors(shape);
    const parts: string[] = [];
    if (p.violated > 0) {
      const viols = knownViolations(shape);
      const invariants = [...new Set(viols.map((v) => v.invariant))].join(", ");
      parts.push(`recorded violations: ${p.violated} (invariants: ${invariants || "?"})`);
    }
    if (p.held > 0) parts.push(`${p.held} held run(s)`);
    if (p.errors > 0) {
      parts.push(`${p.errors} error run(s)`);
      // Shaped negative evidence: errors ≠ coverage.
      if (p.held === 0 && p.violated === 0) {
        parts.push("engine has never COMPLETED a run on this shape — errors are engine limitations, not target evidence");
      }
    }
    // Lessons beat everything: another target of this shape was DRAINED by
    // this technique class — propose it first.
    const lessons = knownLessons(shape);
    if (lessons.length > 0) {
      parts.push(`proven on a sibling target of this shape: ${lessons.join(", ")} — propose this FIRST`);
    }
    const dead = knownDeadends(shape);
    if (dead.length > 0) parts.push(`known dead ends: ${dead.slice(0, 3).join("; ")}`);
    const cool = shapeBackoffMinutesLeft(shape);
    if (cool > 0) parts.push(`engine cooling down on this shape for ${cool}m after repeated errors`);
    // Priors AND cooling state both count: a fresh store with an active
    // cooldown still has actionable history for the prompt.
    if (parts.length === 0) return "";
    return `Generic-invariant engine history for shape "${shape}": ${parts.join("; ")}.`;
  } catch {
    return "";
  }
}

/** Compact machine-readable context for code that wants to GATE on engine
 * history (not just print it). Used by investigate.ts to skip re-deriving
 * known-bad runs and by the consolidation miner. */
export function engineGate(shape: string): {
  coolingDown: boolean;
  cooldownMinutesLeft: number;
  deadends: string[];
  violatedBefore: boolean;
  lessons: string[];
} {
  return {
    coolingDown: shapeCoolingDown(shape),
    cooldownMinutesLeft: shapeBackoffMinutesLeft(shape),
    deadends: knownDeadends(shape),
    violatedBefore: shapePriors(shape).violated > 0,
    lessons: knownLessons(shape),
  };
}

/** Full read-side view of what the engine has LEARNED, for the dashboard's
 * memory tab. Priors drive the bars; violations and dead ends are the
 * concrete lessons (a proven primitive path, and a condition not worth
 * re-deriving). Read-only; a corrupt store yields an empty view. */
export function genLearnOverview(): {
  shapes: number;
  violations: number;
  deadends: number;
  priors: { shape: string; held: number; violated: number; errors: number; total: number; lastNote: string }[];
  proven: { shape: string; invariant: string; path: string; profitWei: string | null; when: number }[];
  dead: { shape: string; condition: string; when: number }[];
  cooling: { shape: string; minutesLeft: number }[];
  lessons: { shape: string; techniques: string[] }[];
  failureClasses: { shape: string; classes: { failureClass: string; count: number; lastDetail: string }[] }[];
} {
  const st = load();
  const priors = Object.entries(st.priors)
    .map(([shape, p]) => ({
      shape,
      held: p.held,
      violated: p.violated,
      errors: p.errors,
      total: p.held + p.violated + p.errors,
      lastNote: p.lastNote ?? "",
    }))
    .sort((a, b) => b.violated - a.violated || b.total - a.total);
  const proven = Object.entries(st.violations)
    .flatMap(([shape, byInv]) =>
      Object.entries(byInv).flatMap(([invariant, list]) =>
        list.map((v) => ({ shape, invariant, path: v.path, profitWei: v.profitWei ?? null, when: v.when }))
      )
    )
    .sort((a, b) => b.when - a.when);
  const dead = Object.entries(st.deadends)
    .flatMap(([shape, list]) => list.map((d) => ({ shape, condition: d.condition, when: d.when })))
    .sort((a, b) => b.when - a.when);
  const now = Date.now();
  const cooling = Object.entries(st.shapeBackoffMs ?? {})
    .filter(([, until]) => now < until)
    .map(([shape, until]) => ({ shape, minutesLeft: Math.ceil((until - now) / 60_000) }))
    .sort((a, b) => b.minutesLeft - a.minutesLeft);
  const lessons = Object.entries(st.lessons ?? {}).map(([shape, techniques]) => ({ shape, techniques }));
  const failureClasses = Object.entries(st.failureClasses ?? {}).map(([shape, classes]) => ({
    shape,
    classes: Object.entries(classes)
      .map(([failureClass, e]) => ({ failureClass, count: e.count, lastDetail: e.lastDetail }))
      .sort((a, b) => b.count - a.count),
  }));
  // "Learned shapes" is the union: a shape whose only lesson so far is a dead
  // end HAS been learned about, and counting it here keeps this number
  // consistent with the dead-ends list below it.
  const knownShapes = new Set([
    ...Object.keys(st.priors),
    ...Object.keys(st.violations),
    ...Object.keys(st.deadends),
    ...Object.keys(st.outcomes ?? {}),
    ...Object.keys(st.lessons ?? {}),
    ...Object.keys(st.failureClasses ?? {}),
  ]);
  return {
    shapes: knownShapes.size,
    violations: proven.length,
    deadends: dead.length,
    priors,
    proven,
    dead,
    cooling,
    lessons,
    failureClasses,
  };
}

// ------------------------------------------------ persistent probe dedupe

/** Persistent backing for memory.ts's probe-outcome dedupe: keys survive
 * daemon restarts, so a rebooted fleet does not re-learn (and re-propose)
 * every failed probe. Stored under a dedicated key to keep the main store
 * shape clean. Bounded — oldest-insertion-order eviction. */
const PROBE_DEDUPE_KEY = "__probeDedupe";
const PROBE_DEDUPE_MAX = 8000;

/** One file-backed ordered set (insertion order = array order). */
function probeDedupeRaw(): string[] {
  const raw = (load() as GenLearnStore & { [PROBE_DEDUPE_KEY]?: string[] })[PROBE_DEDUPE_KEY];
  return raw ?? [];
}

/** All known probe-dedupe keys (insertion order). */
export function probeDedupeKeys(): string[] {
  return probeDedupeRaw();
}

/** Add a probe-dedupe key; deduped, bounded to PROBE_DEDUPE_MAX. */
export function recordProbeDedupeKey(key: string): void {
  if (!key) return;
  const list = probeDedupeRaw();
  if (list.includes(key)) return;
  list.push(key);
  while (list.length > PROBE_DEDUPE_MAX) list.shift();
  (load() as GenLearnStore & { [PROBE_DEDUPE_KEY]?: string[] })[PROBE_DEDUPE_KEY] = list;
  save();
}

/** Compact learning snapshot for the dashboard / digest. */
export function genLearnStats(): { shapes: number; violations: number; deadends: number } {
  const st = load();
  const violations = Object.values(st.violations).reduce((n, m) => n + Object.values(m).reduce((k, l) => k + l.length, 0), 0);
  const deadends = Object.values(st.deadends).reduce((n, l) => n + l.length, 0);
  return { shapes: Object.keys(st.priors).length, violations, deadends };
}

// ------------------------------------------------- cross-shape lesson mining

/** Extract target addresses from a memory text, ignoring known system
 * addresses that appear in boilerplate. (Same rule as consolidate.ts.) */
function targetAddresses(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/0x[0-9a-fA-F]{40}/g)) out.add(m[0].toLowerCase());
  return [...out];
}

/** Cross-shape lesson miner: turns the raw probe-memory corpus into per-shape
 * technique priors. A "PROBE SUCCESS … PRODUCED A DRAIN … technique X" memory
 * is PROOF that X works on that shape; the lessons flow into genLearnHint so
 * future triage proposes the proven class first. Returns mined count. */
export function mineLessonsFromMemories(lines: string[]): number {
  let mined = 0;
  for (const line of lines) {
    if (!/PROBE SUCCESS/.test(line) || !/PRODUCED A DRAIN/.test(line)) continue;
    const tech = /technique ([a-z0-9:_-]+)/i.exec(line)?.[1];
    if (!tech) continue;
    const shape = /\(shape: ([^)]+)\)/.exec(line)?.[1]?.trim();
    if (shape) {
      const before = knownLessons(shape).join("|");
      recordLesson(shape, tech);
      if (knownLessons(shape).join("|") !== before) mined++;
      continue;
    }
    // No shape in prose — resolve via the outcome index (address -> shape).
    for (const addr of targetAddresses(line)) {
      const o = targetOutcome(addr);
      if (o && o.shape && o.shape !== "none") {
        const before = knownLessons(o.shape).join("|");
        recordLesson(o.shape, tech);
        if (knownLessons(o.shape).join("|") !== before) mined++;
      }
    }
  }
  return mined;
}
