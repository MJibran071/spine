// Backlog triage — the machinery behind the dashboard's ON/OFF switch.
//
// WHY: the fleet's triage capacity is fully provisioned (18 keys, 2400
// calls/day) but the daemon only triages what its scan rotation happens to
// visit — while 44% of the watchlist sits at shape:"unknown" and the daily
// budget goes home unspent. When the operator flips the switch
// (controls.ts), this module feeds those unknown rows into the EXISTING
// triage pipeline and drains them on the daemon's cycle:
//
//   1. pick unknown-shape rows on chains the fleet can actually fork;
//   2. enqueue a bounded slice per cycle through triageQueue.ts — so
//      MAX_ATTEMPTS, backoff, and the 24h age bound all apply unchanged;
//   3. drain due items via drainTriageQueue (the same executor a fresh
//      target gets) — verdicts land in memory, watchlist rows gain shapes,
//      and a real hypothesis feeds the existing probe pipeline.
//
// Safety: nothing new is executed and nothing broadcasts. The drain is
// capacity-gated (live key + unspent daily budget) exactly like the
// retry-queue drain — the switch allocates IDLE capacity, it never overrides
// cooldowns, budgets, or rate limits. Every fork is local anvil, read-only.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { triageBacklogEnabled } from "./controls.ts";
import { CHAINS } from "./scan.ts";
import { isProductionTarget } from "./findings.ts";
import { enqueueTriage, dueTriage, triageQueueStats } from "./triageQueue.ts";
import { drainTriageQueue } from "./triagedrain.ts";
import { triageHealth } from "./triage.ts";
import { logEvent } from "./bus.ts";

const STATE_PATH = join(REPORT_DIR, "state.json");
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

interface WatchRow {
  address?: string;
  shape?: string;
  enlisted?: boolean;
  fresh?: boolean;
  bounty?: string;
}

/** One forkable, still-unclassified watchlist row. */
export interface BacklogRow {
  key: string;
  chainId: string;
  chainName: string;
  address: string; // lowercase
  shape?: string;
  fresh?: boolean;
  enlisted?: boolean;
  bounty?: string;
}

// state.json is ~1.3 MB and the daemon rewrites it every cycle — reading it
// per dashboard poll (2s) would be real I/O churn. 30s cache, same TTL the
// fleet monitor endpoint uses.
const WATCH_TTL_MS = 30_000;
let _watchCache: { at: number; rows: BacklogRow[] } = { at: 0, rows: [] };

function watchRows(): BacklogRow[] {
  if (Date.now() - _watchCache.at < WATCH_TTL_MS) return _watchCache.rows;
  const out: BacklogRow[] = [];
  try {
    const disk = JSON.parse(readFileSync(STATE_PATH, "utf8")) as { watchlist?: Record<string, WatchRow> };
    for (const [key, row] of Object.entries(disk.watchlist ?? {})) {
      if (!row || typeof row !== "object") continue;
      // Split "chainName:0x…" keys; legacy bare-address rows are mainnet.
      // Non-EVM namespaces (solana, deepdive, robinhood, …) never qualify.
      let chainName: string;
      let address: string;
      const ci = key.indexOf(":");
      if (ci > 0 && !key.startsWith("0x")) {
        chainName = key.slice(0, ci);
        address = key.slice(ci + 1);
      } else if (ADDR_RE.test(key)) {
        chainName = "ethereum";
        address = key;
      } else continue;
      const chain = CHAINS.find((c) => c.name === chainName);
      if (!chain || !ADDR_RE.test(address)) continue;
      out.push({
        key,
        chainId: chain.id,
        chainName,
        address: address.toLowerCase(),
        shape: row.shape,
        fresh: row.fresh,
        enlisted: row.enlisted,
        bounty: row.bounty,
      });
    }
  } catch {
    // state.json missing or corrupt: empty backlog this read, never fatal.
  }
  _watchCache = { at: Date.now(), rows: out };
  return out;
}

export interface BacklogStats {
  enabled: boolean;
  /** Unknown-shape rows on forkable chains (the actual backlog). */
  candidates: number;
  queueSize: number;
  dueNow: number;
  keys: number;
  budget: { used: number; max: number };
  lastEnqueued: number;
  lastAttempted: number;
  lastResolved: number;
  lastNote: string | null;
  lastRunAt: number | null;
}

const _last = { enqueued: 0, attempted: 0, resolved: 0, note: null as string | null, at: null as number | null };

/** Dashboard-facing view: switch state + backlog size + what the last tick did. */
export function backlogStats(): BacklogStats {
  const rows = watchRows();
  const candidates = rows.filter((r) => !r.shape || r.shape === "unknown").length;
  let queueSize = 0, dueNow = 0, keys = 0, used = 0, max = 0;
  try {
    const q = triageQueueStats();
    queueSize = q.size;
    dueNow = q.due;
  } catch { /* cosmetic */ }
  try {
    const h = triageHealth();
    keys = h.keys;
    used = h.budget.used;
    max = h.budget.max;
  } catch { /* cosmetic */ }
  return {
    enabled: triageBacklogEnabled(),
    candidates,
    queueSize,
    dueNow,
    keys,
    budget: { used, max },
    lastEnqueued: _last.enqueued,
    lastAttempted: _last.attempted,
    lastResolved: _last.resolved,
    lastNote: _last.note,
    lastRunAt: _last.at,
  };
}

export interface BacklogTickResult {
  enabled: boolean;
  skippedCapacity?: boolean;
  enqueued: number;
  attempted: number;
  resolved: number;
  note: string | null;
}

/** One daemon-cycle slice of backlog work: enqueue up to `limit` new unknown
 * rows, then drain up to `limit` due queue items. Cheap when OFF (one flag
 * read) so it is safe to call unconditionally every cycle. */
export async function runBacklogTick(opts: {
  daemonId: string;
  forkPortBase: number;
  limit?: number;
}): Promise<BacklogTickResult> {
  const res: BacklogTickResult = { enabled: triageBacklogEnabled(), enqueued: 0, attempted: 0, resolved: 0, note: null };
  if (!res.enabled) return res;

  try {
    // Capacity gate — identical philosophy to the retry-queue drain: a tick
    // with zero live capacity would only churn cooldowns.
    const h = triageHealth();
    if (h.keys === 0 || h.budget.left <= 0) {
      res.skippedCapacity = true;
      res.note = h.keys === 0 ? "no triage keys in this process" : "daily budget spent";
      return res;
    }

    const limit = Math.max(1, Math.min(opts.limit ?? 3, 8));
    const rows = watchRows();
    const unknown = rows.filter((r) => !r.shape || r.shape === "unknown");
    if (unknown.length === 0) {
      res.note = "backlog empty";
      return res;
    }

    // Highest prior first: fresh deployments, then enlisted (probeable
    // class) rows, then bounty-carrying rows; stable within a tier.
    const ranked = unknown.slice().sort((a, b) =>
      (b.fresh ? 1 : 0) - (a.fresh ? 1 : 0) ||
      (b.enlisted ? 1 : 0) - (a.enlisted ? 1 : 0) ||
      (b.bounty ? 1 : 0) - (a.bounty ? 1 : 0)
    );

    // Idempotent: never re-enqueue rows that are merely waiting their backoff
    // (a re-enqueue would bump attempts toward the give-up bound for no reason).
    const queued = new Set(dueTriage(500).map((i) => `${i.chainId}:${i.address}`));
    let enqueued = 0;
    for (const r of ranked) {
      if (enqueued >= limit) break;
      if (queued.has(`${r.chainId}:${r.address}`)) continue;
      // Same production-target bar the drain applies — dead/demo rows would
      // just be retired on sight, so don't spend queue slots on them.
      if (!isProductionTarget(r.chainId, r.address)) continue;
      const er = enqueueTriage(r.chainId, r.address, "backlog-operator");
      if (er.queued && er.attempts === 1) enqueued++;
      // gaveUp / re-enqueue results are silently absorbed: the bound did its job.
    }
    res.enqueued = enqueued;

    // Drain through the real executor (investigateUnknownShape) — verdicts
    // retire queue entries, classify rows, and can produce findings.
    const dr = await drainTriageQueue({
      daemonId: opts.daemonId,
      forkPortBase: opts.forkPortBase,
      limit,
    });
    res.attempted = dr.attempted;
    res.resolved = dr.resolved;

    res.note = `backlog ${unknown.length} row(s) unknown`;
    _last.enqueued = enqueued;
    _last.attempted = dr.attempted;
    _last.resolved = dr.resolved;
    _last.note = res.note;
    _last.at = Date.now();

    if (enqueued > 0 || dr.attempted > 0) {
      logEvent("scan", `backlog triage: ${enqueued} enqueued, ${dr.attempted} drained, ${dr.resolved} verdict(s) — ${unknown.length} row(s) still unknown`);
    }
  } catch (e) {
    res.note = `backlog tick error: ${(e as Error).message.slice(0, 120)}`;
  }
  return res;
}
