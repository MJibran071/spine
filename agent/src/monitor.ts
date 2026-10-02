// Fleet monitor — one command that watches EVERYTHING at once.
//
// The fleet already has per-daemon dashboards (each --ui port shows only its
// own process's view merged with the shared bus) and a static snapshot, but
// nothing answers "is the whole hunt healthy right now?" in one place. This
// monitor is that place:
//
//   npm run monitor            one full report, exit 0 healthy / 1 degraded
//   npm run monitor -- --watch refresh every N s (default 30) until Ctrl-C
//   npm run monitor -- --json  machine-readable snapshot (cron/webhook)
//
// Checks, all read-only:
//   - every daemon registry entry: process alive (kill -0), heartbeat fresh,
//     cycle advancing between polls (watch mode), UI port answering
//   - local forks (anvil children) alive and answering eth_chainId on 127.0.0.1
//   - memory sidecar up/down (the agent's recall layer)
//   - reports/daemon.crash.log tail: new uncaught exceptions since last poll
//   - findings count + newest finding (the fleet's whole reason to exist)
//   - disk: state.json size, memories.jsonl growth, reports dir total
//
// Safety: GET-only polling of loopback ports; process liveness via kill(pid, 0)
// (signal 0 = existence check, never sends a signal); writes NOTHING except its
// own last-poll scratch file under reports/monitor/.
import { existsSync, readFileSync, statSync, mkdirSync, writeFileSync, readdirSync } from "node:fs";
import { join, basename } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import os from "node:os";
import { REPORT_DIR } from "./config.ts";
import { redactRpcUrl } from "./safety.ts";
import type { DaemonInfo } from "./bus.ts";

const CRASH_LOG = join(REPORT_DIR, "daemon.crash.log");
const STATE_PATH = join(REPORT_DIR, "state.json");
const MEM_PATH = join(REPORT_DIR, "memory", "memories.jsonl");
const MONITOR_DIR = join(REPORT_DIR, "monitor");
const LAST_POLL = join(MONITOR_DIR, "last-poll.json");
const GENLEARN_PATH = join(REPORT_DIR, "genlearn.json");
const QUEUE_PATH = join(REPORT_DIR, "triage-queue.json");
const RESPONDER_BASELINE = join(REPORT_DIR, "responder-baseline.json");
const TECHNIQUES_PATH = join(REPORT_DIR, "techniques.json");
const QUARANTINE_DIR = join(REPORT_DIR, "quarantine");
const SELFREPAIR_LOG = join(REPORT_DIR, "selfrepair.log");
const DIGEST_PATH = join(REPORT_DIR, "MEMORY-DIGEST.md");
/** A compile-failure class seen this many times is a generator bug, not bad
 * luck — the monitor escalates it to a note. */
const COMPILE_CLASS_STALE_MS = 2 * 3_600_000; // classes unseen this long are history, not failures
const COMPILE_CLASS_ESCALATE = 20;
/** Memory digest older than this = consolidation isn't running nightly. */
const DIGEST_STALE_MS = 36 * 3_600_000;
/** Responder baseline older than this = the balance watchdog is not
 * completing sweeps (it rewrites the file every sweep; sweeps run every
 * daemon cycle). Generous window: one failed sweep is noise, a stale one
 * is a dead watchdog. */
const RESPONDER_STALE_MS = 6 * 3_600_000;

/** Heartbeat older than this = daemon wedged (matches the bus's 5-min rule). */
const STALE_MS = 5 * 60_000;
/** A cycle must be slower than 3x the configured interval before we complain. */
const CYCLE_GRACE_MULTIPLIER = 3;

export interface DaemonCheck {
  id: string;
  pid: number;
  alive: boolean;
  heartbeatAgeMs: number | null;
  cycle: number;
  cycleAdvanced: boolean | null; // null = first poll, unknown yet
  intervalSec: number;
  uiPort: number | null;
  uiOk: boolean | null; // null = no UI port to check
  verdict: "ok" | "stale" | "dead" | "stalled";
}

export interface ForkCheck {
  pid: number;
  port: number;
  forkUrl: string;
  responds: boolean;
}

/** Age (ms) of the first responder's shared baseline file. Null = the
 * responder has NEVER completed a sweep on this fleet — the watchdog that
 * catches live exploits is not running. */
function responderAgeMs(): number | null {
  try {
    if (!existsSync(RESPONDER_BASELINE)) return null;
    const j = JSON.parse(readFileSync(RESPONDER_BASELINE, "utf8")) as { updatedAt?: number };
    if (!j?.updatedAt) return null;
    return Date.now() - j.updatedAt;
  } catch {
    return null;
  }
}

/** Self-learned technique library size (captures + proven win count). The
 * monitor reports it so a library that STOPS growing while daemons keep
 * finding drains is visible — that is the learning loop going stale. */
function techniquesSummary(): { total: number; wins: number; distilled: number } {
  try {
    if (!existsSync(TECHNIQUES_PATH)) return { total: 0, wins: 0, distilled: 0 };
    const j = JSON.parse(readFileSync(TECHNIQUES_PATH, "utf8")) as {
      techniques?: Record<string, { wins?: number; reuse?: string }>;
    };
    const all = Object.values(j.techniques ?? {});
    return {
      total: all.length,
      wins: all.reduce((n, t) => n + (t.wins ?? 0), 0),
      distilled: all.filter((t) => t.reuse).length,
    };
  } catch {
    return { total: 0, wins: 0, distilled: 0 };
  }
}

export interface MonitorReport {
  at: number;
  healthy: boolean;
  daemons: DaemonCheck[];
  forks: ForkCheck[];
  sidecar: "up" | "down";
  findings: { count: number; newest: string | null };
  crashLog: { bytes: number; newLines: string[] };
  disk: { stateJsonBytes: number; memoriesBytes: number; memoriesDelta: number; reportsDirEntries: number };
  pipeline: {
    queue: { total: number; dueNow: number; waiting: number };
    genlearn: { topClass: string | null; topClassCount: number; quarantined: number };
    selfrepair: { lastAction: string | null };
    consolidation: { digestAgeMs: number | null };
    /** First-responder watchdog: baseline age (null = never swept). */
    responder: { baselineAgeMs: number | null };
    /** Self-learned technique library: captures / proven wins / distilled. */
    techniques: { total: number; wins: number; distilled: number };
    /** DefiLlama small-TVL (<$1M) lane: seeds recorded vs actually probed
     * vs carrying a fuzz campaign. A stall here means the highest base-rate
     * lane is being starved by discovery/priority — the exact failure the
     * lane was built to prevent. */
    smallTvl: { seeds: number; probed: number; campaigned: number; chains: string };
  };
  /** System RAM pressure — the laptop-hang guard. A fleet of 5 daemons plus
   * N anvil forks can eat many GB; when free memory collapses macOS swaps
   * and the whole machine wedges (which is exactly what looked like "the
   * fleet died" in the past). Reported every poll; notes fire at thresholds. */
  ram: { freePct: number; totalGb: number; nodeRssMb: number; anvilCount: number; anvilRssMb: number };
  notes: string[];
}

/** Read-only pipeline health: the triage queue's drainability, genlearn's
 * worst repeating compile class, self-repair's quarantine + ledger tail, and
 * the memory digest's freshness. Each reader is independent — one corrupt
 * store degrades only its own field. */
function pipelineSummary() {
  // Triage queue: dueNow > 0 means the backoff fix is letting it drain.
  let queue = { total: 0, dueNow: 0, waiting: 0 };
  try {
    if (existsSync(QUEUE_PATH)) {
      const q = JSON.parse(readFileSync(QUEUE_PATH, "utf8")) as Record<string, { nextAt?: number }>;
      const now = Date.now();
      for (const v of Object.values(q)) {
        queue.total++;
        if ((v.nextAt ?? 0) <= now) queue.dueNow++;
        else queue.waiting++;
      }
    }
  } catch { /* queue file unreadable — leave zeros */ }

  // genlearn compile classes: a class repeating across many targets = bug.
  // RECENCY GATE: the counters are LIFETIME totals and the fleet's daemons
  // re-persist the whole store from memory, so a hand-pruned class resurrects
  // forever. A class whose last sighting is older than COMPILE_CLASS_STALE_MS
  // is history (its generator bug was fixed), not an active failure — flag
  // only classes seen inside the window.
  let topClass: string | null = null;
  let topClassCount = 0;
  try {
    if (existsSync(GENLEARN_PATH)) {
      const cc = (JSON.parse(readFileSync(GENLEARN_PATH, "utf8")) as { compileClasses?: Record<string, { count: number; lastWhen?: number }> }).compileClasses ?? {};
      const freshCut = Date.now() - COMPILE_CLASS_STALE_MS;
      for (const [k, v] of Object.entries(cc)) {
        if ((v.lastWhen ?? 0) < freshCut) continue;
        if (v.count > topClassCount) {
          topClass = k;
          topClassCount = v.count;
        }
      }
    }
  } catch { /* genlearn store unreadable */ }

  // Self-repair: quarantined offender count + last ledger action.
  let quarantined = 0;
  try {
    if (existsSync(QUARANTINE_DIR)) quarantined = readdirSync(QUARANTINE_DIR).length;
  } catch { /* ignore */ }
  let lastAction: string | null = null;
  try {
    if (existsSync(SELFREPAIR_LOG)) {
      const lines = readFileSync(SELFREPAIR_LOG, "utf8").trimEnd().split("\n");
      lastAction = lines[lines.length - 1] || null;
    }
  } catch { /* ignore */ }

  // Consolidation: digest mtime age (null = never written).
  let digestAgeMs: number | null = null;
  try {
    if (existsSync(DIGEST_PATH)) digestAgeMs = Date.now() - statSync(DIGEST_PATH).mtimeMs;
  } catch { /* ignore */ }

  return {
    queue,
    genlearn: { topClass, topClassCount, quarantined },
    selfrepair: { lastAction },
    consolidation: { digestAgeMs },
    responder: { baselineAgeMs: responderAgeMs() },
    smallTvl: smallTvlSummary(),
    techniques: techniquesSummary(),
  };
}

/** Process liveness without signaling: kill(pid, 0) throws ESRCH when gone,
 * EPERM when owned by another user (still alive). Zero side effects. */
function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: any) {
    return e?.code === "EPERM";
  }
}

/** Loopback-only GET; anything else is refused by design. */
async function loopbackJson(port: number, path: string, timeoutMs = 4000): Promise<unknown | null> {
  try {
    const url = new URL(`http://127.0.0.1:${port}${path}`);
    if (!/^127\.0\.0\.1$|^localhost$/.test(url.hostname)) return null;
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/** Is an anvil on this port? eth_chainId is the cheapest honest probe. */
async function forkResponds(port: number): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(3000),
    });
    const json: any = await res.json();
    return typeof json?.result === "string" && /^0x[0-9a-f]+$/i.test(json.result);
  } catch {
    return false;
  }
}

interface PrevPoll {
  at: number;
  cycles: Record<string, number>;
  crashBytes: number;
  memoriesBytes: number;
  queueDue?: number;
}

function loadPrevPoll(): PrevPoll {
  try {
    return JSON.parse(readFileSync(LAST_POLL, "utf8")) as PrevPoll;
  } catch {
    return { at: 0, cycles: {}, crashBytes: 0, memoriesBytes: 0 };
  }
}

function savePrevPoll(p: PrevPoll): void {
  try {
    mkdirSync(MONITOR_DIR, { recursive: true });
    writeFileSync(LAST_POLL, JSON.stringify(p));
  } catch {
    /* monitor state is best-effort */
  }
}

/** New crash-log lines since the previous poll (full file on first poll). */
function newCrashLines(prevBytes: number): { lines: string[]; bytes: number } {
  try {
    const buf = readFileSync(CRASH_LOG);
    if (buf.length <= prevBytes) return { lines: [], bytes: buf.length };
    const fresh = buf.slice(prevBytes).toString("utf8");
    const lines = fresh.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    return { lines, bytes: buf.length };
  } catch {
    return { lines: [], bytes: 0 };
  }
}

/** Find local anvil forks: pgrep the command line, keep port + fork-url. */
function findForks(): Promise<ForkCheck[]> {
  return new Promise((resolve) => {
    execFile("pgrep", ["-f", "anvil --fork-url"], { timeout: 5_000 }, (err, stdout) => {
      if (err || !stdout.trim()) return resolve([]);
      const pids = stdout.trim().split("\n").map((s) => parseInt(s, 10)).filter((n) => Number.isInteger(n) && n > 0);
      // One ps per batch; parse --port and --fork-url from each command line.
      execFile("ps", ["-o", "pid=,command=", "-p", pids.join(",")], { timeout: 5_000 }, (err2, stdout2) => {
        const out: ForkCheck[] = [];
        if (!err2 && stdout2) {
          for (const line of stdout2.split("\n")) {
            const m = line.trim().match(/^(\d+)\s+(.*)$/);
            if (!m) continue;
            const pid = parseInt(m[1], 10);
            const cmd = m[2];
            const portM = cmd.match(/--port\s+(\d+)/);
            const urlM = cmd.match(/--fork-url\s+(\S+)/);
            out.push({ pid, port: portM ? parseInt(portM[1], 10) : 0, forkUrl: urlM ? urlM[1] : "?", responds: false });
          }
        }
        resolve(out);
      });
    });
  });
}

async function sidecarUp(): Promise<"up" | "down"> {
  // Same probe memory.ts uses: GET /health on the sidecar's loopback port.
  const port = parseInt(process.env.MEM0_SIDECAR_PORT ?? "8765", 10) || 8765;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(2_500) });
    return res.ok ? "up" : "down";
  } catch {
    return "down";
  }
}

function findingsSummary(): { count: number; newest: string | null } {
  try {
    const state = JSON.parse(readFileSync(STATE_PATH, "utf8"));
    const f = state?.findings ?? [];
    const newest = Array.isArray(f) && f.length > 0 ? String(f[f.length - 1]?.msg ?? f[f.length - 1] ?? null) : null;
    return { count: Array.isArray(f) ? f.length : 0, newest };
  } catch {
    return { count: 0, newest: null };
  }
}

function diskSummary(prevMemBytes: number): MonitorReport["disk"] & { prevMemBytes: number } {
  const size = (p: string) => {
    try {
      return statSync(p).size;
    } catch {
      return 0;
    }
  };
  let reportsEntries = 0;
  try {
    reportsEntries = existsSync(REPORT_DIR) ? readdirSync(REPORT_DIR).length : 0;
  } catch {
    /* best-effort */
  }
  return {
    stateJsonBytes: size(STATE_PATH),
    memoriesBytes: size(MEM_PATH),
    memoriesDelta: size(MEM_PATH) - prevMemBytes,
    reportsDirEntries: reportsEntries,
    prevMemBytes,
  };
}

export async function runMonitor(): Promise<MonitorReport> {
  const prev = loadPrevPoll();
  const now = Date.now();
  const notes: string[] = [];

  // ---- daemons from the shared bus (state.json holds every instance) -------
  let registry: Record<string, DaemonInfo> = {};
  try {
    const state = JSON.parse(readFileSync(STATE_PATH, "utf8"));
    registry = state?.daemons ?? {};
  } catch {
    notes.push("state.json unreadable — cannot see the fleet registry");
  }
  const daemons: DaemonCheck[] = [];
  for (const [id, d] of Object.entries(registry)) {
    const alive = pidAlive(d.pid);
    const hbAge = now - d.lastBeat;
    const stale = hbAge > STALE_MS;
    const prevCycle = prev.cycles[id];
    const cycleAdvanced = prevCycle === undefined ? null : d.cycle > prevCycle;
    let uiOk: boolean | null = null;
    if (d.uiPort) {
      const snap = await loopbackJson(d.uiPort, "/api/state");
      uiOk = snap !== null;
    }
    let verdict: DaemonCheck["verdict"] = "ok";
    if (!alive) verdict = "dead";
    else if (stale) verdict = "stale"; // process exists but heart has stopped — wedged cycle
    else if (cycleAdvanced === false && hbAge > d.intervalSec * 1000 * CYCLE_GRACE_MULTIPLIER) verdict = "stalled";
    if (verdict !== "ok") notes.push(`${id}: ${verdict} (pid ${d.pid} ${alive ? "alive" : "GONE"}, heartbeat ${Math.round(hbAge / 1000)}s old, cycle ${d.cycle})`);
    else if (uiOk === false) notes.push(`${id}: dashboard on :${d.uiPort} not answering`);
    daemons.push({ id, pid: d.pid, alive, heartbeatAgeMs: hbAge, cycle: d.cycle, cycleAdvanced, intervalSec: d.intervalSec, uiPort: d.uiPort, uiOk, verdict });
  }
  daemons.sort((a, b) => a.id.localeCompare(b.id));
  if (daemons.length === 0) notes.push("no live daemon entries in the registry — is the hunt running?");

  // ---- forks ----------------------------------------------------------------
  const forkList = await findForks();
  const forks: ForkCheck[] = [];
  for (const f of forkList) {
    const responds = f.port > 0 ? await forkResponds(f.port) : false;
    forks.push({ ...f, responds });
  }
  const deadForks = forks.filter((f) => !f.responds);
  if (deadForks.length > 0) notes.push(`${deadForks.length} anvil fork(s) not answering eth_chainId (ports ${deadForks.map((f) => f.port || "?").join(", ")}) — they recycle on their own, but a persistently dead fork starves probes`);

  // ---- sidecar, findings, crash log, disk ------------------------------------
  const sidecar = await sidecarUp();
  if (sidecar === "down") notes.push("memory sidecar down — recall layer offline (hunting continues without memory)");
  const findings = findingsSummary();
  const crash = newCrashLines(prev.crashBytes);
  // First poll establishes the baseline — the existing log is history, not news.
  const crashIsNews = prev.at > 0 && crash.lines.length > 0;
  if (crashIsNews) notes.push(`NEW in daemon.crash.log: ${crash.lines.slice(0, 3).join(" | ")}`);
  const disk = diskSummary(prev.memoriesBytes);
  const smallTvl = smallTvlSummary();

  // ---- RAM pressure ----------------------------------------------------------
  const ram = ramSummary();
  // Two thresholds: warn at 15% free (daemons feel it), critical at 8% —
  // below that macOS starts swapping hard and every process (including the
  // ones writing memory) slows to a crawl: the observed "laptop hang".
  if (ram.freePct < 8) notes.push(`CRITICAL RAM: ${ram.freePct}% free of ${ram.totalGb}GB (node ${ram.nodeRssMb}MB, ${ram.anvilCount} anvil ${ram.anvilRssMb}MB) — machine will swap/hang; kill anvil forks now`);
  else if (ram.freePct < 15) notes.push(`low RAM: ${ram.freePct}% free of ${ram.totalGb}GB (node ${ram.nodeRssMb}MB, ${ram.anvilCount} anvil ${ram.anvilRssMb}MB) — fleet may stall under pressure`);

  // ---- learning-pipeline health ---------------------------------------------
  const pipeline = pipelineSummary();
  // Queue stall = due-now count NOT shrinking over a ≥5-min baseline while
  // daemons advance (a snapshot of "many due" is the normal post-backoff
  // state; one entry per few minutes is a healthy drain).
  if (
    now - prev.at >= 300_000 &&
    pipeline.queue.dueNow > 50 &&
    prev.queueDue !== undefined &&
    pipeline.queue.dueNow >= prev.queueDue &&
    daemons.some((d) => d.verdict === "ok" && (d.cycleAdvanced ?? false))
  ) {
    notes.push(`triage queue not draining: ${pipeline.queue.dueNow} due now (was ${prev.queueDue}) with daemons advancing — triage loop may be down`);
  }
  if (pipeline.genlearn.topClass && pipeline.genlearn.topClassCount >= COMPILE_CLASS_ESCALATE) {
    notes.push(`genlearn compile class "${pipeline.genlearn.topClass}" repeating (${pipeline.genlearn.topClassCount}x recently) — active generator bug; self-repair should be quarantining`);
  }
  if (pipeline.consolidation.digestAgeMs !== null && pipeline.consolidation.digestAgeMs > DIGEST_STALE_MS) {
    notes.push(`memory digest stale (${Math.round(pipeline.consolidation.digestAgeMs / 3_600_000)}h old) — nightly consolidation not running`);
  }
  // First-responder watchdog health: the sweep writes its baseline on every
  // run. Never written = not running; older than the stale window = failing
  // silently (every failed sweep logs, but only the monitor notices the
  // ABSENCE of successful sweeps).
  if (pipeline.responder.baselineAgeMs === null) {
    notes.push("responder baseline never written — first-responder watchdog has not completed a sweep (live-exploit detection offline)");
  } else if (pipeline.responder.baselineAgeMs > RESPONDER_STALE_MS) {
    notes.push(`responder baseline stale (${Math.round(pipeline.responder.baselineAgeMs / 3_600_000)}h old) — balance sweeps not completing (canary rejections or endpoint outage)`);
  }
  if (pipeline.techniques.total === 0 && findings.count > 0) {
    notes.push("findings exist but the self-learned technique library is empty — capture loop broke after a daemon restart?");
  }
  // Small-TVL lane: every seed should eventually be probed and, for
  // probeable shapes, campaigned. Advisory (lane health ≠ fleet health).
  if (pipeline.smallTvl.seeds === 0) {
    notes.push("small-TVL lane empty — run npm run llama to seed fresh sub-$1M DefiLlama protocols");
  } else if (pipeline.smallTvl.probed === 0) {
    notes.push(`small-TVL lane stalled: ${pipeline.smallTvl.seeds} seed(s) recorded, none ever probed — check scanner rotation coverage for their chains (${pipeline.smallTvl.chains})`);
  } else if (pipeline.smallTvl.campaigned === 0 && pipeline.smallTvl.probed < pipeline.smallTvl.seeds) {
    notes.push(`small-TVL lane partial: ${pipeline.smallTvl.probed}/${pipeline.smallTvl.seeds} seed(s) probed, 0 under fuzz campaigns — investigations may be starving (LLM quota?)`);
  }

  const healthy =
    daemons.length > 0 &&
    daemons.every((d) => d.verdict === "ok" && d.uiOk !== false) &&
    deadForks.length === 0 &&
    sidecar === "up" &&
    !crashIsNews &&
    ram.freePct >= 8; // critical RAM = degraded fleet, honestly

  const report: MonitorReport = {
    at: now,
    healthy,
    daemons,
    forks,
    sidecar,
    findings,
    crashLog: { bytes: crash.bytes, newLines: crash.lines },
    disk: { stateJsonBytes: disk.stateJsonBytes, memoriesBytes: disk.memoriesBytes, memoriesDelta: disk.memoriesDelta, reportsDirEntries: disk.reportsDirEntries },
    pipeline,
    ram,
    notes,
  };

  savePrevPoll({
    at: now,
    cycles: Object.fromEntries(daemons.map((d) => [d.id, d.cycle])),
    crashBytes: crash.bytes,
    memoriesBytes: disk.memoriesBytes,
    queueDue: pipeline.queue.dueNow,
  });
  return report;
}


/** DefiLlama small-TVL (<$1M) lane health: seeds recorded (llama-seeds.json)
 * vs ever-probed (watchlist rows keyed chain:address) vs under fuzz campaign
 * (campaigns.json keyed chainId:address). All reads best-effort — the lane
 * health must never break the monitor. */
function smallTvlSummary(): { seeds: number; probed: number; campaigned: number; chains: string } {
  const out = { seeds: 0, probed: 0, campaigned: 0, chains: "" };
  try {
    const seedsPath = join(REPORT_DIR, "llama-seeds.json");
    if (!existsSync(seedsPath)) return out;
    const seeds = JSON.parse(readFileSync(seedsPath, "utf8")) as { seeds?: Record<string, unknown> };
    const entries = Object.entries(seeds.seeds ?? {});
    out.seeds = entries.length;
    out.chains = [...new Set(entries.map(([k]) => k.split(":")[0]))].sort().join(",");
    const wlPath = join(REPORT_DIR, "state.json");
    const wl = wlPath && existsSync(wlPath) ? (JSON.parse(readFileSync(wlPath, "utf8")) as { watchlist?: Record<string, { lastProbe?: number }> }).watchlist ?? {} : {};
    const campPath = join(REPORT_DIR, "campaigns.json");
    const camps = campPath && existsSync(campPath) ? JSON.parse(readFileSync(campPath, "utf8")) as Record<string, unknown> : {};
    for (const [key] of entries) {
      const chain = key.split(":")[0];
      const addr = key.slice(chain.length + 1).toLowerCase();
      // Scanner labels carry suffixes ("chain:0x… [seed]") — match by address
      // substring rather than exact key.
      const wlKey = Object.keys(wl).find((k) => k.toLowerCase().includes(addr));
      const row = wlKey ? wl[wlKey] : undefined;
      if (row?.lastProbe) out.probed++;
      if (camps[`${chainIdGuess(chain)}:${addr}`] !== undefined) out.campaigned++;
    }
  } catch { /* lane health is advisory */ }
  return out;
}

/** Minimal chain-name → id map for campaign key lookups (mirror of scan.ts's
 * registry; unknown names return "" so the lookup simply misses). */
function chainIdGuess(name: string): string {
  const map: Record<string, string> = {
    ethereum: "1", bsc: "56", avalanche: "43114", sonic: "146", gnosis: "100",
    base: "8453", arbitrum: "42161", optimism: "10", polygon: "137",
    linea: "59144", scroll: "534352", berachain: "80094", blast: "81457",
    hyperevm: "999", robinhood: "4663",
  };
  return map[name.toLowerCase()] ?? "";
}

/** System RAM pressure: total/free from os, per-process RSS from ps. All
 * reads are best-effort — a failing ps degrades to zeros, never blocks. */
function ramSummary(): MonitorReport["ram"] {
  const total = os.totalmem();
  // os.freemem() on macOS counts ONLY fully-unused pages — compressed and
  // purgeable cache are excluded, so a healthy machine reads "2% free" while
  // `memory_pressure -Q` reports 42%. The real free percentage is what the
  // kernel can hand out without swapping; use the OS's own number when the
  // tool exists, fall back to os.freemem() elsewhere (Linux is accurate).
  let free = os.freemem();
  try {
    const out = execFileSync("memory_pressure", ["-Q"], { timeout: 5_000 }).toString();
    const pct = /free percentage:\s*(\d+)%/.exec(out);
    if (pct) free = (total * parseInt(pct[1]!, 10)) / 100;
  } catch { /* macOS tool absent — os.freemem() stands */ }
  let nodeRss = 0;
  let anvilRss = 0;
  let anvilCount = 0;
  try {
    const out = execFileSync("ps", ["-axo", "rss=,command="], { timeout: 5_000 }).toString();
    for (const line of out.split("\n")) {
      const m = line.trim().match(/^(\d+)\s+(.*)$/);
      if (!m) continue;
      const rssMb = parseInt(m[1]!, 10) / 1024;
      const cmd = m[2]!;
      if (/node[\s\S]*index\.ts|node[\s\S]*monitor\.ts/.test(cmd)) nodeRss += rssMb;
      else if (/(^|\/)anvil(\s|$)/.test(cmd)) { anvilRss += rssMb; anvilCount++; }
    }
  } catch { /* ps failed — zeros only */ }
  return {
    freePct: total > 0 ? Math.round((free / total) * 100) : 0,
    totalGb: Math.round(total / 1_073_741_824),
    nodeRssMb: Math.round(nodeRss),
    anvilCount,
    anvilRssMb: Math.round(anvilRss),
  };
}

const DMS_PATH = join(REPORT_DIR, "monitor", "last-ping.txt");

/** Dead-man switch: ping a healthcheck URL each poll while HEALTHY. Silence
 * = pager fires. Sits beside notify.ts (which alerts on FINDINGS) — this
 * alerts on the HUNT BEING DEAD: Mac rebooted, launchd failed, all daemons
 * wedged. Works with any dead-man-switch service that accepts GET pings
 * (healthchecks.io, hc-ping.com, UptimeRobot heartbeat…).
 *
 * Semantics that matter:
 *  - pings only on healthy polls — a DEGRADED fleet stops pinging and pages
 *    within the check's grace period (that is the point),
 *  - degraded polls still record WHY locally (last-ping.txt) so the post-
 *    mortem does not depend on the console that no longer exists,
 *  - failures to ping are best-effort: never fatal, retried next poll. */
const DMS_URL = process.env.LAB_DEADMAN_URL?.trim() || "";
async function deadManPing(healthy: boolean, note: string): Promise<void> {
  try {
    mkdirSync(MONITOR_DIR, { recursive: true });
    writeFileSync(DMS_PATH, `${new Date().toISOString()} healthy=${healthy} ${note.slice(0, 200)}\n`);
    if (!DMS_URL || !healthy) return;
    await fetch(DMS_URL, { signal: AbortSignal.timeout(5_000) });
  } catch {
    // pager unreachable — the next healthy poll retries; never fatal
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const isMain = process.argv[1] && basename(process.argv[1]) === "monitor.ts";
if (isMain) {
  const args = process.argv.slice(2);
  const watch = args.includes("--watch");
  const asJson = args.includes("--json");
  const watchIdx = args.indexOf("--watch");
  const intervalSec = watch && args[watchIdx + 1] && !isNaN(Number(args[watchIdx + 1])) ? Number(args[watchIdx + 1]) : 30;

  function render(r: MonitorReport): string {
    const lines: string[] = [];
    const mark = (ok: boolean) => (ok ? "✓" : "✗");
    lines.push(`FLEET MONITOR — ${new Date(r.at).toISOString().replace("T", " ").slice(0, 19)} UTC — ${r.healthy ? "HEALTHY" : "DEGRADED"}`);
    lines.push("");
    lines.push("Daemons:");
    for (const d of r.daemons) {
      const cyc = d.cycleAdvanced === null ? "" : d.cycleAdvanced ? " ▲advancing" : " ●not-advancing";
      const ui = d.uiOk === null ? "" : d.uiOk ? ` ui:${d.uiPort}✓` : ` ui:${d.uiPort}✗`;
      lines.push(`  ${mark(d.verdict === "ok")} ${d.id.padEnd(10)} pid ${d.pid} cycle ${d.cycle}${cyc} hb ${Math.round((d.heartbeatAgeMs ?? 0) / 1000)}s${ui}`);
    }
    lines.push("");
    lines.push(`Forks: ${r.forks.length} anvil process(es) — ${r.forks.filter((f) => f.responds).length} answering eth_chainId`);
    for (const f of r.forks) lines.push(`  ${mark(f.responds)} :${f.port || "?"} ${redactRpcUrl(f.forkUrl)}`);
    lines.push(`Memory sidecar: ${r.sidecar}`);
    lines.push(`Findings: ${r.findings.count}${r.findings.newest ? ` — newest: ${r.findings.newest.slice(0, 100)}` : ""}`);
    lines.push(`Crash log: ${r.crashLog.bytes} bytes${r.crashLog.newLines.length ? ` — ${r.crashLog.newLines.length} NEW line(s)` : " (no new)"}`);
    lines.push(`Disk: state.json ${(r.disk.stateJsonBytes / 1024).toFixed(0)}KB · memories ${(r.disk.memoriesBytes / 1024).toFixed(0)}KB (${r.disk.memoriesDelta >= 0 ? "+" : ""}${r.disk.memoriesDelta}B since last poll) · reports/ ${r.disk.reportsDirEntries} entries`);
    lines.push("");
    lines.push("Learning pipeline:");
    const q = r.pipeline.queue;
    lines.push(`  Triage queue: ${q.total} entries — ${q.dueNow} due now, ${q.waiting} in backoff`);
    lines.push(`RAM: ${r.ram.freePct}% free of ${r.ram.totalGb}GB — node ${r.ram.nodeRssMb}MB · anvil ${r.ram.anvilCount} proc(s) ${r.ram.anvilRssMb}MB`);
    const g = r.pipeline.genlearn;
    lines.push(`  Genlearn: worst compile class ${g.topClass ? `"${g.topClass}" ×${g.topClassCount}` : "none recorded"} · quarantined files: ${g.quarantined}`);
    lines.push(`  Self-repair: ${r.pipeline.selfrepair.lastAction ? r.pipeline.selfrepair.lastAction.slice(0, 110) : "no actions yet"}`);
    const cAge = r.pipeline.consolidation.digestAgeMs;
    lines.push(`  Consolidation: ${cAge === null ? "digest never written" : `digest ${cAge < 3_600_000 ? "fresh" : `${Math.round(cAge / 3_600_000)}h old`}`}`);
    const resp = r.pipeline.responder;
    lines.push(`  Responder: ${resp.baselineAgeMs === null ? "baseline never written (watchdog offline)" : `baseline ${resp.baselineAgeMs < 3_600_000 ? "fresh" : `${Math.round(resp.baselineAgeMs / 3_600_000)}h old`}`}`);
    const t = r.pipeline.techniques;
    lines.push(`  Technique library: ${t.total} learned (from ${t.wins} proven drain(s), ${t.distilled} distilled)`);
    const s = r.pipeline.smallTvl;
    lines.push(`  Small-TVL lane (<$1M): ${s.seeds} seed(s) on [${s.chains || "none"}] — ${s.probed} probed, ${s.campaigned} campaigned`);
    if (r.notes.length) {
      lines.push("");
      lines.push("Notes:");
      for (const n of r.notes) lines.push(`  ! ${n}`);
    }
    return lines.join("\n");
  }

  async function once(): Promise<number> {
    const r = await runMonitor();
    if (asJson) console.log(JSON.stringify(r, null, 2));
    else console.log(render(r));
    const note = r.notes.length ? r.notes.join("; ") : "ok";
    void deadManPing(r.healthy, note); // fire-and-forget; retried next poll
    return r.healthy ? 0 : 1;
  }

  if (!watch) {
    const code = await once();
    process.exit(code);
  } else {
    console.log(`watching every ${intervalSec}s — Ctrl-C to stop`);
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const code = await once();
      if (code !== 0) console.log("(degraded — see notes above)");
      await new Promise((res) => setTimeout(res, intervalSec * 1000));
    }
  }
}
