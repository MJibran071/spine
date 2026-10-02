// Execution tracing — the mechanism tool the outcome tools were missing.
//
// Until now the fleet measured OUTCOMES (a probe drained or it did not) and
// was blind to MECHANISM. This module adds the missing sense:
//
//   traceCalldata  — run ONE call under debug_traceCall with the callTracer:
//                    a decoded call graph (who called whom, with what value,
//                    where it reverted, gas per frame) for any calldata.
//   traceStateDiff — the same call under the prestateTracer: exact per-account
//                    storage deltas + balance deltas. The difference between
//                    "profit came out" and "THESE 3 slots changed, here is how".
//   deepestRevertFrame — parse an existing forge -vvv trace into the deepest
//                    reverted frame, so failed-probe retries adjust based on
//                    WHICH subcall reverted instead of blind re-rolls.
//
// SAFETY DOCTRINE (unchanged): debug_* RPC only ever goes to the LOCAL
// anvil fork — assertLocalRpc guards every entry point, exactly like the
// toolbox tools. Nothing here broadcasts; tracing is observation.
//
// FAIL-SOFT: tracers are anvil-specific and every consumer (probes, triage
// prompts, toolbox reports) must degrade honestly when tracing is
// unavailable — callers get null/empty, never a throw.

import { assertLocalRpc } from "./safety.ts";
import type { AnvilFork } from "./fork.ts";

// ---------------------------------------------------------------------------
// callTracer shapes
// ---------------------------------------------------------------------------

/** One frame of the decoded call graph (anvil callTracer fields). */
export interface TraceFrame {
  kind: "call" | "delegatecall" | "callcode" | "staticcall" | "create" | "create2" | "selfdestruct" | "unknown";
  from: string;
  to: string;
  valueWei: string; // "0" when none
  gasUsed: string; // decimal
  inputSize: number; // bytes
  outputSize: number; // bytes
  error: string | null; // tracer-reported error (revert reason, OOG, ...)
  reverted: boolean; // this frame (or a descendant) reverted
  depth: number;
  children: TraceFrame[];
}

/** Aggregate stats over a call graph. */
export interface TraceStats {
  frames: number;
  maxDepth: number;
  revertedFrames: number;
  delegatecalls: number;
  staticcalls: number;
  creations: number;
  totalGasUsed: string; // decimal (root frame's gasUsed)
  distinctTargets: number;
}

export interface CallTrace {
  ok: boolean;
  unavailableReason?: string; // why tracing failed (honest degradation)
  root: TraceFrame | null;
  stats: TraceStats | null;
}

function kindOf(t: any): TraceFrame["kind"] {
  const k = String(t?.type ?? "").toLowerCase();
  if (k === "call" || k === "delegatecall" || k === "callcode" || k === "staticcall" ||
      k === "create" || k === "create2" || k === "selfdestruct") return k as TraceFrame["kind"];
  return "unknown";
}

function frameFrom(t: any, depth: number): TraceFrame {
  return {
    kind: kindOf(t),
    from: typeof t?.from === "string" ? t.from : "",
    to: typeof t?.to === "string" ? t.to : "",
    valueWei: typeof t?.value === "string" ? (BigInt(t.value).toString()) : "0",
    gasUsed: typeof t?.gasUsed === "string" ? BigInt(t.gasUsed).toString() : "0",
    inputSize: typeof t?.input === "string" ? Math.floor((t.input.length - 2) / 2) : 0,
    outputSize: typeof t?.output === "string" ? Math.floor((t.output.length - 2) / 2) : 0,
    error: typeof t?.error === "string" && t.error ? t.error : null,
    reverted: false, // filled by markReverted
    depth,
    children: Array.isArray(t?.calls) ? t.calls.map((c: any) => frameFrom(c, depth + 1)) : [],
  };
}

/** A frame counts as reverted when IT errored, or any descendant did —
 * matches how a human reads a forge trace (the outer frame "reverted"
 * because an inner frame threw). Single walk computes reverted flags and
 * the aggregate stats together. */
function computeStats(root: TraceFrame): TraceStats {
  const acc = { frames: 0, maxDepth: 0, revertedFrames: 0, delegatecalls: 0, staticcalls: 0, creations: 0, targets: new Set<string>() };
  const walk = (f: TraceFrame): boolean => {
    acc.frames++;
    acc.maxDepth = Math.max(acc.maxDepth, f.depth);
    if (f.error) acc.revertedFrames++;
    if (f.kind === "delegatecall") acc.delegatecalls++;
    if (f.kind === "staticcall") acc.staticcalls++;
    if (f.kind === "create" || f.kind === "create2") acc.creations++;
    if (f.to) acc.targets.add(f.to.toLowerCase());
    let descendantReverted = false;
    for (const c of f.children) {
      if (walk(c)) descendantReverted = true;
    }
    f.reverted = f.error !== null || descendantReverted;
    return f.reverted;
  };
  walk(root);
  return {
    frames: acc.frames,
    maxDepth: acc.maxDepth,
    revertedFrames: acc.revertedFrames,
    delegatecalls: acc.delegatecalls,
    staticcalls: acc.staticcalls,
    creations: acc.creations,
    totalGasUsed: root.gasUsed,
    distinctTargets: acc.targets.size,
  };
}

// ---------------------------------------------------------------------------
// prestateTracer shapes
// ---------------------------------------------------------------------------

export interface StorageDiff {
  slot: string;
  before: string;
  after: string;
}

export interface AccountDiff {
  address: string;
  existedBefore: boolean; // false => created by this call
  balanceDeltaWei: string | null; // null = no balance change reported
  storage: StorageDiff[];
}

export interface StateDiffResult {
  ok: boolean;
  unavailableReason?: string;
  accounts: AccountDiff[];
}

// ---------------------------------------------------------------------------
// tracing entry points (LOCAL fork only)
// ---------------------------------------------------------------------------

const TRACE_TIMEOUT_MS = 15_000;

/** Fire one debug_traceCall with the given tracer on the LOCAL fork.
 * Returns the raw tracer result, or an honest failure object. */
async function rawTrace(
  fork: AnvilFork,
  tx: { from?: string; to: string; data?: string; valueWei?: string },
  tracer: object
): Promise<{ ok: true; result: any } | { ok: false; reason: string }> {
  assertLocalRpc(fork.localRpc, "debug_traceCall");
  const call: Record<string, string> = { to: tx.to, data: tx.data && tx.data !== "0x" ? tx.data : "0x" };
  if (tx.from) call.from = tx.from;
  if (tx.valueWei && tx.valueWei !== "0") call.value = "0x" + BigInt(tx.valueWei).toString(16);
  try {
    const res = await fork.rpc("debug_traceCall", [call, "latest", tracer]);
    if (res === null || res === undefined) return { ok: false, reason: "tracer returned null" };
    return { ok: true, result: res };
  } catch (e) {
    const msg = String((e as Error).message ?? e).replace(/^RPC \S+: /, "");
    // The common cases, named honestly: pre-byzantium-style refusals, tracer
    // not compiled in, or the call itself reverting under some tracer modes.
    return { ok: false, reason: msg.slice(0, 200) };
  }
}

/** Decoded call graph for ONE call, via the callTracer. */
export async function traceCalldata(
  fork: AnvilFork,
  tx: { from?: string; to: string; data?: string; valueWei?: string }
): Promise<CallTrace> {
  const r = await rawTrace(fork, tx, { tracer: "callTracer", tracerConfig: { withLog: false } });
  if (!r.ok) return { ok: false, unavailableReason: r.reason, root: null, stats: null };
  const root = frameFrom(r.result, 0);
  return { ok: true, root, stats: computeStats(root) };
}

/** Per-account storage + balance deltas for ONE call, via the prestateTracer.
 * Best for "what did this probe actually change" — no interpretation, just
 * the exact diff. `prestateTracer` with diffMode requires no `from`. */
export async function traceStateDiff(
  fork: AnvilFork,
  tx: { from?: string; to: string; data?: string; valueWei?: string }
): Promise<StateDiffResult> {
  const r = await rawTrace(fork, tx, { tracer: "prestateTracer", tracerConfig: { diffMode: true } });
  if (!r.ok) return { ok: false, unavailableReason: r.reason, accounts: [] };
  const res = r.result as Record<string, any> | null;
  if (!res || typeof res !== "object") return { ok: false, unavailableReason: "diffMode result missing pre/post", accounts: [] };
  const pre = (res.pre ?? {}) as Record<string, any>;
  const post = (res.post ?? {}) as Record<string, any>;
  const out: AccountDiff[] = [];
  const addrs = new Set([...Object.keys(pre), ...Object.keys(post)]);
  for (const rawAddr of addrs) {
    const before = pre[rawAddr];
    const after = post[rawAddr];
    const existedBefore = before !== undefined;
    if (!existedBefore && after === undefined) continue;
    const balBefore = BigInt(before?.balance ?? "0x0");
    const balAfter = BigInt(after?.balance ?? "0x0");
    const balDelta = balAfter - balBefore;
    // Storage diff: union of keys in both snapshots.
    const sb = new Map<string, string>();
    for (const [k, v] of Object.entries((before?.storage ?? {}) as Record<string, string>)) sb.set(k.toLowerCase(), String(v));
    const sa = new Map<string, string>();
    for (const [k, v] of Object.entries((after?.storage ?? {}) as Record<string, string>)) sa.set(k.toLowerCase(), String(v));
    const storage: StorageDiff[] = [];
    for (const [slot, afterV] of sa) {
      const beforeV = sb.get(slot) ?? "0x0";
      const norm = (h: string) => "0x" + BigInt(h || "0x0").toString();
      if (norm(beforeV) !== norm(afterV)) storage.push({ slot, before: norm(beforeV), after: norm(afterV) });
    }
    for (const [slot, beforeV] of sb) {
      if (!sa.has(slot)) storage.push({ slot, before: BigInt(beforeV || "0x0").toString(), after: "0" });
    }
    storage.sort((a, b) => (a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0));
    out.push({
      address: rawAddr,
      existedBefore,
      balanceDeltaWei: balDelta === 0n ? null : balDelta.toString(),
      storage,
    });
  }
  out.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  return { ok: true, accounts: out };
}

// ---------------------------------------------------------------------------
// forge -vvv trace parsing (no RPC needed — works on captured output)
// ---------------------------------------------------------------------------

export interface RevertFrame {
  depth: number;
  line: string; // the trimmed trace line
  fn?: string; // contract::function when forge names it
  revertText?: string; // reason string / custom error when surfaced
}

/** Parse a failed forge run's output into the deepest frames that carry
 * revert information. Foundry trace geometry, verified against real -vvv
 * output: a CALL line at glyph count g is frame depth g (root call = 0, it
 * has no tree glyph), and that frame's `← [Revert]` RETURN line sits one
 * glyph deeper (g+1). A return line carries no function name, so it borrows
 * the name of the deepest preceding call at its own frame depth. The deepest
 * revert is the true origin (an outer frame "reverted" because an inner one
 * threw), so shallower hits are superseded. */
export function deepestRevertFrames(output: string, max = 3): RevertFrame[] {
  const lines = output.split("\n");
  const hits: RevertFrame[] = [];
  let bestDepth = -1;
  const lastCallFn: string[] = []; // index = frame depth → innermost named call seen there
  for (const line of lines) {
    const indent = line.match(/^[\s│├└─]*/)?.[0] ?? "";
    const glyphs = (indent.match(/[│├└]/g) ?? []).length;
    const isCallLine = !line.includes("←") && /\[\d+\]/.test(line);
    if (isCallLine) {
      const callFn = /([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)/.exec(line)?.[0]
        ?? /([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)/.exec(line)?.[0];
      if (callFn) lastCallFn[glyphs] = callFn;
    }
    if (!/\[Revert\]|EvmError|Panic\(/i.test(line)) continue;
    if (isCallLine) continue;
    if (glyphs === 0) continue; // suite summaries, not trace frames
    if (/traces:|Failing tests|Suite result|panicked at/i.test(line)) continue;
    // The return line at glyph count g belongs to the frame at depth g-1.
    const depth = Math.max(glyphs - 1, 0);
    const fn = lastCallFn[depth];
    const reason = /(?:require|revert)\s*\(\s*"([^"]{3,240})"/.exec(line)?.[1]
      ?? /\[Revert\]\s*(.+)/.exec(line)?.[1]?.trim();
    if (depth > bestDepth) {
      bestDepth = depth;
      hits.length = 0; // deeper origin supersedes shallower ones
    }
    if (hits.length < max && (depth === bestDepth || hits.length === 0)) {
      hits.push({ depth, line: line.trim().slice(0, 240), fn, revertText: reason?.slice(0, 200) });
    }
  }
  return hits;
}

/** One-line human summary for notes fields / triage prompts. */
export function summarizeRevertFrames(frames: RevertFrame[]): string {
  if (frames.length === 0) return "";
  const f = frames[0]!;
  const bits: string[] = [];
  if (f.fn) bits.push(`at ${f.fn}`);
  if (f.revertText) bits.push(`reason: ${f.revertText}`);
  return bits.length ? `${bits.join(", ")} (depth ${f.depth})` : `deepest revert at depth ${f.depth}`;
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

const SHORT = (a: string): string => (a.length > 12 ? `${a.slice(0, 10)}…` : a);

export function renderCallTrace(t: CallTrace, maxFrames = 40): string {
  const L: string[] = [];
  if (!t.ok) {
    L.push(`  (trace unavailable: ${t.unavailableReason ?? "unknown"})`);
    return L.join("\n");
  }
  const s = t.stats!;
  L.push(`  frames=${s.frames} depth=${s.maxDepth} targets=${s.distinctTargets} gas=${s.totalGasUsed}`);
  L.push(`  delegatecalls=${s.delegatecalls} staticcalls=${s.staticcalls} creates=${s.creations} reverted-frames=${s.revertedFrames}`);
  L.push("");
  const walk = (f: TraceFrame): void => {
    if (maxFrames <= 0) return;
    maxFrames--;
    const indent = "  ".repeat(f.depth + 1);
    const flag = f.reverted ? " ← REVERT" : "";
    const val = f.valueWei !== "0" ? ` value=${f.valueWei}` : "";
    L.push(`${indent}${f.kind} ${SHORT(f.from)} -> ${SHORT(f.to)}${val} gas=${f.gasUsed}${f.error ? ` err=${f.error.slice(0, 80)}` : ""}${flag}`);
    for (const c of f.children) walk(c);
  };
  if (t.root) walk(t.root);
  if (maxFrames <= 0) L.push("  … (truncated)");
  return L.join("\n");
}

export function renderStateDiff(d: StateDiffResult, maxAccounts = 12, maxSlots = 12): string {
  const L: string[] = [];
  if (!d.ok) {
    L.push(`  (state diff unavailable: ${d.unavailableReason ?? "unknown"})`);
    return L.join("\n");
  }
  if (d.accounts.length === 0) L.push("  (no state changed)");
  for (const a of d.accounts.slice(0, maxAccounts)) {
    const created = a.existedBefore ? "" : " [CREATED]";
    const bal = a.balanceDeltaWei !== null ? ` balanceΔ=${a.balanceDeltaWei}` : "";
    L.push(`  ${a.address}${created}${bal}`);
    for (const s of a.storage.slice(0, maxSlots)) {
      L.push(`    slot ${s.slot.slice(0, 14)}…: ${s.before.slice(0, 24)} -> ${s.after.slice(0, 24)}`);
    }
    if (a.storage.length > maxSlots) L.push(`    … ${a.storage.length - maxSlots} more slot(s)`);
  }
  if (d.accounts.length > maxAccounts) L.push(`  … ${d.accounts.length - maxAccounts} more account(s)`);
  return L.join("\n");
}
