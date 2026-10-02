// Persistent retry queue for DEFERRED triage analyses.
//
// WHY THIS EXISTS
// Triage capacity is finite (a fleet-wide daily call cap plus per-key rate
// limits) while the watchlist is not: ~800 targets want ~800 analyses per
// sweep, and the fleet can afford a fraction of that. The old code handled the
// shortfall by writing one indistinguishable string — "triage unavailable (no
// LAB_LLM_KEY or API error)" — onto the target's watchlist row and moving on.
// The row then looked analysed, the reason was lost, and nothing came back for
// it: 510 of 808 targets were in exactly that state.
//
// The queue keeps the WORK instead of the excuse: a target whose analysis was
// deferred (budget, cooldown, 429, 5xx, timeout, unparseable) is recorded with
// exponential backoff and re-attempted when capacity returns. Terminal answers
// (a hypothesis, or nothing to read) are removed — retrying those would be
// busywork.
//
// Storage: reports/triage-queue.json. Bounded (MAX_ITEMS) and self-pruning
// (MAX_ATTEMPTS, MAX_AGE_MS) so a stuck target can never grow into a backlog
// that outlives the reason it was queued.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const QUEUE_PATH = join(REPORT_DIR, "triage-queue.json");

/** Give up after this many attempts — a target stuck behind an exhausted key
 * pool for hours should surface as a stat, not spin forever. */
export const TRIAGE_MAX_ATTEMPTS = 6;
/** Nothing older than this stays queued, whatever its attempt count. */
const MAX_AGE_MS = 24 * 60 * 60_000;
const MAX_ITEMS = 2_000;
const BASE_DELAY_MS = 60_000; // first retry: ~1 minute
const MAX_DELAY_MS = 30 * 60_000; // cap: half an hour

export interface TriageQueueItem {
  key: string; // chainId:lowercased-address
  chainId: string;
  address: string;
  attempts: number;
  firstQueuedAt: number;
  nextAt: number;
  reason: string; // why it was deferred last (TriageReason or "give-up")
}

type QueueFile = Record<string, TriageQueueItem>;

function keyOf(chainId: string, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}

function load(): QueueFile {
  try {
    if (!existsSync(QUEUE_PATH)) return {};
    const j = JSON.parse(readFileSync(QUEUE_PATH, "utf8")) as QueueFile;
    if (!j || typeof j !== "object") return {};
    const out: QueueFile = {};
    const now = Date.now();
    const items = Object.values(j).filter(
      (i): i is TriageQueueItem =>
        !!i && typeof i.address === "string" && typeof i.nextAt === "number" && now - i.firstQueuedAt < MAX_AGE_MS
    );
    // Oldest deadlines first; overflow drops the least urgent tail.
    items.sort((a, b) => a.nextAt - b.nextAt);
    for (const i of items.slice(0, MAX_ITEMS)) out[i.key] = i;
    return out;
  } catch {
    return {};
  }
}

function save(q: QueueFile): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(QUEUE_PATH, JSON.stringify(q, null, 2));
  } catch {
    // the queue is an optimisation for scarce capacity, never a hard dependency
  }
}

/** Backoff before the next attempt, growing with the attempt count and
 * jittered so N daemons don't retry the whole queue in lockstep. */
function backoffMs(attempts: number): number {
  const base = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * Math.pow(2, Math.max(0, attempts - 1)));
  const jitter = 0.8 + Math.random() * 0.4; // ±20%
  return Math.round(base * jitter);
}

export interface EnqueueResult {
  queued: boolean; // true = now waiting; false = tracked but past the limit
  attempts: number;
  nextAt: number;
  nextRetryMs: number;
  gaveUp: boolean;
}

/** Record a deferred analysis. Idempotent per target: a second deferral bumps
 * the attempt count and pushes the next attempt further out. */
export function enqueueTriage(chainId: string, address: string, reason: string): EnqueueResult {
  const q = load();
  const k = keyOf(chainId, address);
  const prev = q[k];
  const attempts = (prev?.attempts ?? 0) + 1;
  const now = Date.now();
  if (attempts > TRIAGE_MAX_ATTEMPTS) {
    delete q[k]; // stop retrying; the caller logs the give-up
    save(q);
    return { queued: false, attempts, nextAt: now, nextRetryMs: 0, gaveUp: true };
  }
  const item: TriageQueueItem = {
    key: k,
    chainId,
    address: address.toLowerCase(),
    attempts,
    firstQueuedAt: prev?.firstQueuedAt ?? now,
    nextAt: now + backoffMs(attempts),
    reason,
  };
  q[k] = item;
  save(q);
  return { queued: true, attempts, nextAt: item.nextAt, nextRetryMs: item.nextAt - now, gaveUp: false };
}

/** Items whose backoff has elapsed, most overdue first. Does not mutate — the
 * caller resolves or re-enqueues after the attempt. */
export function dueTriage(limit = 50, now = Date.now()): TriageQueueItem[] {
  return Object.values(load())
    .filter((i) => i.nextAt <= now)
    .sort((a, b) => a.nextAt - b.nextAt)
    .slice(0, limit);
}

/** Retired: the analysis happened (or turned out to be impossible). */
export function resolveTriage(chainId: string, address: string): boolean {
  const q = load();
  const k = keyOf(chainId, address);
  if (!q[k]) return false;
  delete q[k];
  save(q);
  return true;
}

/** Retired by address alone, when the caller does not know the chain id. */
export function resolveTriageByAddress(address: string): number {
  const q = load();
  const needle = address.toLowerCase();
  let removed = 0;
  for (const [k, i] of Object.entries(q)) {
    if (i.address.toLowerCase() === needle) {
      delete q[k];
      removed++;
    }
  }
  if (removed > 0) save(q);
  return removed;
}

export interface TriageQueueStats {
  size: number;
  due: number;
  oldestQueuedAt: number | null;
  maxAttemptsSeen: number;
  byReason: Record<string, number>;
}

export function triageQueueStats(now = Date.now()): TriageQueueStats {
  const items = Object.values(load());
  const byReason: Record<string, number> = {};
  for (const i of items) byReason[i.reason] = (byReason[i.reason] ?? 0) + 1;
  return {
    size: items.length,
    due: items.filter((i) => i.nextAt <= now).length,
    oldestQueuedAt: items.length ? Math.min(...items.map((i) => i.firstQueuedAt)) : null,
    maxAttemptsSeen: items.length ? Math.max(...items.map((i) => i.attempts)) : 0,
    byReason,
  };
}

/** Test/maintenance hook: drop the queue file's in-memory view by rewriting it
 * empty. Returns how many items were discarded. */
export function clearTriageQueue(): number {
  const n = Object.keys(load()).length;
  save({});
  return n;
}
