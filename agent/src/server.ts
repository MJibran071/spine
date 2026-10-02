// Read-only dashboard server for the lab agent.
// Binds 127.0.0.1 ONLY (same allowlist philosophy as the rest of the agent).
// Serves: GET / (dashboard), GET /api/state (JSON).
// The page itself (embedding all of its CSS/animation JS) lives in ui-page.ts.
import http from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { assertLocalRpc } from "./safety.ts";
import { snapshot } from "./bus.ts";
import type { DaemonInfo } from "./bus.ts";
import { memoryStats } from "./memory.ts";
import { localMemorySummary, localSearch } from "./localmem.ts";
import { genLearnOverview } from "./genlearn.ts";
import { countWins } from "./knowledge.ts";
import { allTechniques, techniquesStats } from "./techniques.ts";
import { REPORT_DIR } from "./config.ts";
import { PAGE } from "./ui-page.ts";
import { triageHealth } from "./triage.ts";
import { triageQueueStats } from "./triageQueue.ts";
import { logEvent } from "./bus.ts";
import { runMonitor, type MonitorReport } from "./monitor.ts";
import { allAttackIdeas, ideasStats as ideasStatsOf } from "./attackideas.ts";
import { campaignStats } from "./campaigns.ts";
import { canonStats } from "./canoncode.ts";
import { readFunnel } from "./funnel.ts";
import { getUiControls, setTriageBacklog } from "./controls.ts";
import { backlogStats } from "./backlogtriage.ts";

const STALE_MS = 5 * 60_000; // matches the Daemons tab's stated 5-minute rule

/** Fleet-wide snapshot: each dashboard used to serve ONLY its own process's
 * in-memory registry, so every UI showed "1 daemon" — itself. The shared
 * state.json holds every instance's registry entry (merged on each persist),
 * so read it fresh and merge: fresher heartbeat wins per daemon id, stale
 * entries (>5 min) are dropped exactly like snapshot()'s prune does. */
function fleetSnapshot(): ReturnType<typeof snapshot> {
  const s = snapshot();
  try {
    const p = join(REPORT_DIR, "state.json");
    if (existsSync(p)) {
      const disk = JSON.parse(readFileSync(p, "utf8")) as { daemons?: Record<string, DaemonInfo> };
      const merged: Record<string, DaemonInfo> = { ...(s.daemons ?? {}) };
      const now = Date.now();
      for (const [id, d] of Object.entries(disk.daemons ?? {})) {
        if (now - d.lastBeat > STALE_MS) continue; // ghost entry — age out
        if (!merged[id] || d.lastBeat > merged[id].lastBeat) merged[id] = d;
      }
      for (const [id, d] of Object.entries(merged)) {
        if (now - d.lastBeat > STALE_MS) delete merged[id]; // stale in-memory too
      }
      s.daemons = merged;
    }
  } catch {
    // disk read failed — serve the in-process view, degraded but honest
  }
  return s;
}

/** Everything the Memory tab needs, in one read: the local store (size, kinds,
 * growth, newest entries), the generic engine's learned priors/violations/dead
 * ends, and the knowledge-base win count. All read-only and best-effort — a
 * broken store degrades to zeros instead of failing the dashboard. */
function memoryDetail(): unknown {
  let mem: ReturnType<typeof memoryStats> = { local: 0, sidecar: "down" } as ReturnType<typeof memoryStats>;
  let local: ReturnType<typeof localMemorySummary> | null = null;
  let learning: ReturnType<typeof genLearnOverview> | null = null;
  let kbWins = 0;
  let learned: ReturnType<typeof techniquesStats> | null = null;
  let learnedTop: ReturnType<typeof allTechniques> = [];
  try {
    mem = memoryStats();
  } catch { /* cosmetic */ }
  try {
    local = localMemorySummary(80);
  } catch { /* cosmetic */ }
  try {
    learning = genLearnOverview();
  } catch { /* cosmetic */ }
  try {
    kbWins = countWins();
  } catch { /* cosmetic */ }
  // Self-learned technique library: stats + the top entries (proven drains
  // and their generalizations) for the Memory tab.
  try {
    learned = techniquesStats();
    learnedTop = allTechniques().slice(0, 12).map((t) => ({
      id: t.id,
      origin: t.origin,
      technique: t.technique,
      shape: t.shape,
      observation: t.observation,
      path: t.path,
      profitWei: t.profitWei,
      provenOn: t.provenOn,
      generalization: t.generalization,
      reuse: t.reuse,
      wins: t.wins,
      transferredTo: t.transferredTo,
      last: t.last,
    }));
  } catch { /* cosmetic */ }
  // "Recent" is capped for the wire: the dashboard streams the newest tail and
  // a 5000-entry store must not become a 5 MB poll every 2 seconds.
  return {
    stats: mem,
    local,
    learning,
    kbWins,
    learned: learned ? { ...learned, top: learnedTop } : { total: 0, distilled: 0, proven: 0, shapes: 0, top: [] },
  };
}

/** Cache for the fleet monitor report. runMonitor() does real network I/O
 * (loopback HTTP probes, anvil eth_chainId) so it must never run per 2-second
 * dashboard poll: cache the result and refresh in the background at most
 * once per MONITOR_TTL_MS. The first caller after expiry gets the stale data
 * plus triggers an async refresh — the endpoint never blocks the request.
 * Exports so tests can inject/inspect; a negative TTL disables caching. */
export const MONITOR_TTL_MS = 30_000;
let _monitorCache: { at: number; report: MonitorReport | null } = { at: 0, report: null };
let _monitorRefreshing = false;
export function resetMonitorCache(): void {
  _monitorCache = { at: 0, report: null };
}
export function monitorSnapshot(): MonitorReport | null {
  const now = Date.now();
  if (_monitorCache.report === null || now - _monitorCache.at > MONITOR_TTL_MS) {
    if (!_monitorRefreshing) {
      _monitorRefreshing = true;
      runMonitor()
        .then((r) => {
          _monitorCache = { at: Date.now(), report: r };
        })
        .catch(() => {
          // runMonitor is best-effort read-only; keep serving the last good report
        })
        .finally(() => {
          _monitorRefreshing = false;
        });
    }
  }
  return _monitorCache.report;
}

/** Last watchdog heartbeat line (null when no watchdog is running). */
function watchdogStatus(): { line: string; at: number } | null {
  try {
    const p = join(REPORT_DIR, "watchdog.log");
    if (!existsSync(p)) return null;
    const lines = readFileSync(p, "utf8").trim().split("\n");
    const last = lines[lines.length - 1] ?? "";
    if (!last) return null;
    return { line: last.slice(0, 160), at: Date.now() };
  } catch {
    return null;
  }
}

/** Render the dashboard as a standalone static HTML file (for previews).
 * The state is injected with a replacer FUNCTION: a state string containing
 * `$&`/`$'`/`$1` (bounty descriptors like "$15,000,000" are plausible) would
 * otherwise be interpreted as a replacement pattern and corrupt the JSON. */
export function renderStaticHtml(state: unknown): string {
  // The exported page must show the same Memory tab as a live one, and the
  // memory view is read from disk at render time, so enrich here rather than
  // duplicating the assembly at every export call site.
  const enriched: Record<string, unknown> = { ...(state as Record<string, unknown>) };
  if (enriched.memoryDetail === undefined) {
    try {
      enriched.memoryDetail = memoryDetail();
    } catch { /* memory stays absent in the export — the tab degrades */ }
  }
  // Same rule for the funnel strip: an export that omits it renders a dash
  // forever while the live dashboard shows the real numbers.
  if (enriched.funnel === undefined) {
    try {
      enriched.funnel = readFunnel();
    } catch { /* funnel stays absent in the export — the card degrades */ }
  }
  return PAGE
    .replace("/*__STATE__*/null", () => JSON.stringify(enriched))
    // Tell the page it is a frozen export, so it renders its state instead of
    // polling an /api/state that does not exist next to the file.
    .replace("/*__STATIC__*/false", "true");
}

const UI_PORT_RANGE = 10;

/** Serve the dashboard on `port` — or the next free port above it when
 * several daemons run at once (each instance then owns its own URL instead
 * of silently losing the dashboard to whoever bound first). Still resolves
 * (never rejects): the dashboard is optional, the hunt is not. */
export function startUiServer(port = 7333, staticState?: unknown): Promise<string> {
  const base = Number.isFinite(port) && port > 0 ? port : 7333;
  const tryPorts = Array.from({ length: UI_PORT_RANGE }, (_, i) => base + i);

  const attempt = (i: number): Promise<string> => {
    if (i >= tryPorts.length) {
      return Promise.resolve(`http://127.0.0.1:${base} (busy — serving static reports/dashboard.html only)`);
    }
    return listenOnce(tryPorts[i]!, staticState).then(
      (bound) => bound ?? attempt(i + 1)
    );
  };
  return attempt(0);
}

/** Try to bind one port. Resolves the URL on success, null when busy. */
function listenOnce(port: number, staticState?: unknown): Promise<string | null> {
  const url = `http://127.0.0.1:${port}`;
  assertLocalRpc(url, "ui server bind"); // same allowlist: loopback only

  const page = staticState ? renderStaticHtml(staticState) : PAGE;

  const server = http.createServer(async (req, res) => {
    // A malformed request line (scanner/probe garbage) must never throw here:
    // a synchronous throw in a handler is an uncaughtException and would kill
    // the whole daemon. Async only because the toggle endpoint reads a body;
    // every other path is untouched and stays fully synchronous inside.
    let u: URL;
    try {
      u = new URL(req.url ?? "/", url);
    } catch {
      res.writeHead(400).end("bad request");
      return;
    }
    try {
      // The dashboard's single write path: the operator ON/OFF switch for
      // the LLM triage backlog. POST-only, loopback-only (the server cannot
      // bind anything else), body-less, idempotent — a toggle is a toggle.
      // Explicitly allowlisted BEFORE the blanket 405 so the "read-only"
      // doctrine stays intact for every other method/path combination.
      if (req.method === "POST" && u.pathname === "/api/backlog-toggle") {
        const body = await new Promise<string>((resolve) => {
          let data = "";
          req.on("data", (c: Buffer) => { data += c.toString(); if (data.length > 4096) req.destroy(); });
          req.on("end", () => resolve(data));
          req.on("error", () => resolve(data));
        });
        let on: boolean;
        try {
          const parsed = JSON.parse(body || "{}") as { on?: unknown };
          if (typeof parsed.on !== "boolean") throw new Error("expected {\"on\":true|false}");
          on = parsed.on;
        } catch {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: 'body must be JSON: {"on":true} or {"on":false}' }));
          return;
        }
        const controls = setTriageBacklog(on);
        try {
          // Land in the activity feed the same second — the operator should
          // see the flip reflected in the log they are already watching.
          logEvent("scan", `operator switch: LLM triage backlog turned ${on ? "ON" : "OFF"}${on ? " — unknown-shape rows will be enqueued + drained each cycle (capacity-gated)" : ""}`);
        } catch { /* cosmetic */ }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ ok: true, triageBacklog: controls.triageBacklog, changedAt: controls.changedAt ?? null, backlog: backlogStats() }));
        return;
      }
      if (req.method !== "GET") {
        res.writeHead(405).end("read-only");
        return;
      }
      if (u.pathname === "/api/state") {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        // memoryStats rides along so the dashboard can show the learning-loop
        // size without a separate endpoint (it is per-process local info).
        let memory: { local: number; sidecar: string } = { local: 0, sidecar: "down" };
        try {
          memory = memoryStats();
        } catch { /* stats are cosmetic */ }
        // Triage health rides along: whether the analysis path is actually
        // working (key/budget/rate-limit state) is the single most important
        // thing to see on this dashboard, and was previously invisible.
        let triage: ReturnType<typeof triageHealth> | null = null;
        let triageQueue: ReturnType<typeof triageQueueStats> | null = null;
        try {
          triage = triageHealth();
          triageQueue = triageQueueStats();
        } catch { /* cosmetic */ }
        let detail: unknown = null;
        try {
          detail = memoryDetail();
        } catch { /* cosmetic */ }
        // Attack ideas ride along: the LLM's ranked "how I'd attack this" plans
        // (ideas-only — nothing executed). Cheap local read, best-effort.
        // NOTE: the stats function is imported as ideasStatsOf — assigning
        // `ideasStats = ideasStats()` against a same-named local shadows the
        // import (TDZ), throws, and the catch silently left the dashboard's
        // idea budget counter at "—" forever.
        let attackIdeas: ReturnType<typeof allAttackIdeas> = [];
        let ideasStats: ReturnType<typeof ideasStatsOf> | null = null;
        try {
          attackIdeas = allAttackIdeas();
          ideasStats = ideasStatsOf();
        } catch { /* cosmetic */ }
        // Fuzz-campaign + code-class stats: the dashboard strip that shows the
        // accumulating bug-finding pressure (and whether it is aimed at the
        // custom/fork-delta code where bugs actually live).
        let campStats: ReturnType<typeof campaignStats> | null = null;
        let cStats: ReturnType<typeof canonStats> | null = null;
        try {
          campStats = campaignStats();
          cStats = canonStats();
        } catch { /* cosmetic */ }
        // Funnel strip: watched → probed → sourced → classified → custom →
        // fuzzed → violated → verified. Observability only — must never break
        // the stats response.
        let funnelStats: ReturnType<typeof readFunnel> | null = null;
        try {
          funnelStats = readFunnel();
        } catch { /* cosmetic */ }
        // Operator switch + backlog view: the dashboard header button and the
        // backlog pill both read this. Cheap (30s-cached watchlist scan).
        let backlog: ReturnType<typeof backlogStats> | null = null;
        try {
          backlog = backlogStats();
        } catch { /* cosmetic */ }
        res.end(JSON.stringify({ ...fleetSnapshot(), memory, memoryDetail: detail, watchdog: watchdogStatus(), triage, triageQueue, attackIdeas, ideasStats, campaignStats: campStats, canonStats: cStats, funnel: funnelStats, backlog }));
        return;
      }
      // Read-only recall against the agent's own long-term memory. GET only,
      // like every other endpoint here — the dashboard can ask what the agent
      // remembers without any write path existing.
      if (u.pathname === "/api/memory") {
        const q = (u.searchParams.get("q") ?? "").trim();
        const limit = Math.min(50, Math.max(1, Number(u.searchParams.get("limit") ?? 20) || 20));
        let results: unknown[] = [];
        let error: string | null = null;
        try {
          results = q ? localSearch(q, limit) : [];
        } catch (e) {
          error = (e as Error).message.slice(0, 120);
        }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ query: q, limit, count: results.length, results, error }));
        return;
      }
      // Fleet monitor: the same checks as `npm run monitor` (daemon verdicts,
      // fork health, sidecar, crash log, learning pipeline) as JSON. Served
      // from a 30s cache — the probes are real I/O, not per-poll work.
      if (u.pathname === "/api/monitor") {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ available: monitorSnapshot() !== null, report: monitorSnapshot() }));
        return;
      }
      if (u.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(page);
        return;
      }
      res.writeHead(404).end();
    } catch {
      try {
        res.writeHead(500).end();
      } catch {
        // socket already gone
      }
    }
  });

  return new Promise((resolve) => {
    server.once("error", (err: NodeJS.ErrnoException) => {
      // Another hunt instance already owns this port — try the next one.
      if (err.code === "EADDRINUSE") resolve(null);
      else resolve(null);
    });
    server.listen(port, "127.0.0.1", () => resolve(url));
  });
}
