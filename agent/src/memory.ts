// Long-term memory: LOCAL baseline (always available) + mem0 sidecar upgrade.
//
// Layer 1 — localmem.ts: JSONL store + BM25 recall, zero deps, zero network.
//   Always used; every memory is written here regardless of the sidecar.
// Layer 2 — mem0 sidecar (agent/memory/sidecar.py): semantic recall via local
//   Chroma + Groq LLM extraction. Auto-started when present; takes over
//   /search when healthy. If it fails (venv missing, python broken) the hunt
//   never notices — local memory keeps working.
//
// Safety: loopback-only HTTP for layer 2, storage under reports/memory/ and
// agent/memory/storage/. Every call degrades to a no-op on failure — memory
// must never block or crash the hunt.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { LAB_ROOT, OFFLINE } from "./config.ts";
import { localRemember, localRecall, localMemoryCount } from "./localmem.ts";
import { probeDedupeKeys, recordProbeDedupeKey } from "./genlearn.ts";

const SIDECAR_PORT = parseInt(process.env.MEM0_SIDECAR_PORT ?? "8765", 10) || 8765;
const SIDECAR_URL = `http://127.0.0.1:${SIDECAR_PORT}`;
const HERE = join(LAB_ROOT, "agent");

let spawned = false;
let lastHealthCheck = 0;
let healthy = false;
let failures = 0;
/** Probe-outcome dedupe. The original design was a session-scoped Set, which
 * meant every daemon restart re-learned (and re-proposed) the same failed
 * probes. It is now backed by a PERSISTENT index in the genlearn store, so
 * "we already recorded this outcome" survives restarts. The in-process set
 * remains as a fast path to keep the store read off the hot loop. */
const seenProbeMemories = new Set<string>();
let dedupeCacheLoaded = false;

/** Load the persistent dedupe index once per process (lazy — the genlearn
 * store is sync JSON; reading it at import time would add startup cost to
 * every consumer, including ones that never probe). */
function probeAlreadyKnown(key: string): boolean {
  if (seenProbeMemories.has(key)) return true;
  if (!dedupeCacheLoaded) {
    dedupeCacheLoaded = true;
    try {
      for (const k of probeDedupeKeys()) seenProbeMemories.add(k);
    } catch { /* degraded: session-scoped only */ }
  }
  return seenProbeMemories.has(key);
}

function markProbeKnown(key: string): void {
  seenProbeMemories.add(key);
  try {
    recordProbeDedupeKey(key);
  } catch { /* best-effort: session-scoped dedupe still applies */ }
}

async function health(): Promise<boolean> {
  try {
    const res = await fetch(`${SIDECAR_URL}/health`, { signal: AbortSignal.timeout(2_500) });
    const j = (await res.json()) as { ok?: boolean };
    healthy = j.ok === true;
    return healthy;
  } catch {
    healthy = false;
    return false;
  }
}

/** Start the sidecar detached (survives this process) unless already up. */
function startSidecar(): void {
  if (spawned) return;
  spawned = true; // attempt only once per agent process
  const venvPy = join(HERE, "memory", "venv", "bin", "python");
  const py = existsSync(venvPy) ? venvPy : "python3";
  const script = join(HERE, "memory", "sidecar.py");
  if (!existsSync(script)) return;
  try {
    const child = spawn(py, [script], {
      detached: true,
      stdio: "ignore",
      env: { ...process.env, MEM0_SIDECAR_PORT: String(SIDECAR_PORT) },
    });
    child.unref();
  } catch { /* no layer-2 memory this session */ }
}

/** Ensure the sidecar is reachable; try starting it at most once per process.
 * Health cached 60s; after 3 consecutive failures back off to 10 minutes so a
 * broken sidecar can never stall triage (local memory keeps working). */
export async function memoryAvailable(): Promise<boolean> {
  const backoffMs = failures >= 3 ? 10 * 60_000 : 60_000;
  if (Date.now() - lastHealthCheck < backoffMs) return healthy;
  lastHealthCheck = Date.now();
  if (await health()) {
    failures = 0;
    return true;
  }
  startSidecar();
  // First boot may download the embedding model — allow ~20s, then give up
  // quietly (next process will find it warm).
  for (let i = 0; i < 8; i++) {
    await new Promise((r) => setTimeout(r, 2_500));
    if (await health()) {
      failures = 0;
      return true;
    }
  }
  failures++;
  return healthy;
}

/** Recall memories relevant to `query` (target name, technique, category).
 * mem0 semantic results when the sidecar is healthy, else BM25 local. */
export async function memoryRecall(query: string, limit = 5): Promise<string[]> {
  const q = query.trim();
  if (!q) return [];
  if (OFFLINE) return localRecall(q, limit); // no sidecar traffic in offline mode
  if (await memoryAvailable()) {
    try {
      const res = await fetch(`${SIDECAR_URL}/search`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: q, limit }),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        const j = (await res.json()) as { results?: string[] };
        if (j.results && j.results.length > 0) return j.results;
      }
    } catch { /* fall through to local */ }
  }
  return localRecall(q, limit);
}

/** Store a memory. Fire-and-forget: written locally first (instant, durable),
 * mirrored to the sidecar when healthy. Never awaited on a critical path. */
export function memoryRemember(text: string, metadata?: Record<string, unknown>): void {
  localRemember(text, metadata); // layer 1 always
  if (OFFLINE) return; // no sidecar writes in offline mode (tests, air-gapped runs)
  void (async () => {
    try {
      if (!text.trim() || !(await memoryAvailable())) return;
      await fetch(`${SIDECAR_URL}/add`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, metadata: metadata ?? {} }),
        signal: AbortSignal.timeout(30_000),
      });
    } catch { /* layer 2 is best-effort */ }
  })();
}

export function memoryStats(): { local: number; sidecar: "up" | "down" | "starting" } {
  // Trigger a background health check so the reported status is fresh even in
  // processes (UI server) that never call memoryRecall/memoryRemember.
  void memoryAvailable().catch(() => {});
  return { local: localMemoryCount(), sidecar: healthy ? "up" : spawned || failures > 0 ? "starting" : "checking" } as { local: number; sidecar: "up" | "down" | "starting" };
}

/** LEARNING LOOP: every probe outcome becomes a durable memory. Successes
 * record what worked; failures record what was TRIED AND FAILED (with the
 * revert reason) so later triage of the same shape/target recalls "don't
 * repeat this exact approach" instead of rediscovering the same dead end.
 * Recalled into triage prompts via memoryRecall(shape+category+address). */
export function learnFromProbe(
  target: string,
  shape: string,
  technique: string,
  outcome: "drained" | "simulated-no-drain" | "no-drain" | "reverted" | "investigated",
  detail?: string
): void {
  // Persistent dedupe: one memory per (target, technique, outcome) FOREVER
  // (unless the outcome changes — a later "drained" after "reverted" is new
  // information and gets its own memory). Repeat probe cycles hit the same
  // target every PROBE_EVERY cycles; recording the identical outcome each
  // time just spams the store.
  const dedupeKey = `${target}:${technique}:${outcome}`;
  if (probeAlreadyKnown(dedupeKey)) return;
  markProbeKnown(dedupeKey);
  const shapeShort = shape.slice(0, 60);
  if (outcome === "drained") {
    memoryRemember(
      `PROBE SUCCESS ${new Date().toISOString().slice(0, 10)}: ${target} (shape: ${shapeShort}) — technique ${technique} PRODUCED A DRAIN in simulation. ${detail?.slice(0, 200) ?? ""} Reuse this technique class on similar ${shapeShort} shapes first.`,
      { address: target, shape: shapeShort, technique, result: "success" }
    );
  } else if (outcome === "reverted") {
    memoryRemember(
      `PROBE FAILED ${new Date().toISOString().slice(0, 10)}: ${target} (shape: ${shapeShort}) — technique ${technique} reverted in simulation${detail ? `: ${detail.slice(0, 160)}` : ""}. Do NOT re-propose the identical probe for this target/shape without a materially different approach; try a different entry point or check preconditions (allowances, roles, pausing).`,
      { address: target, shape: shapeShort, technique, result: "failure" }
    );
  } else if (outcome === "no-drain" || outcome === "simulated-no-drain") {
    memoryRemember(
      `PROBE NEUTRAL ${new Date().toISOString().slice(0, 10)}: ${target} (shape: ${shapeShort}) — technique ${technique} simulated cleanly with no value extracted. Probe class exhausted for this target; future triage should look for different primitives.`,
      { address: target, shape: shapeShort, technique, result: "neutral" }
    );
  }
  // "investigated" is already captured by triage's own verdict memory.
}
