// Triage retry-queue DRAIN — the piece that made the queue a leak.
//
// WHY: enqueueTriage()/dueTriage() existed and the daemon computed `retryDue`
// every cycle as a PRIORITY signal for fresh targets, but nothing ever
// re-attempted the queued work itself. With deferrals arriving faster than
// fresh-target visits, the queue only ever grew: 167 items due, 158 of them
// still at attempt 1 after ~a day, every one a target with no hypothesis.
//
// The drain closes the loop: each cycle it takes a bounded slice of DUE items
// and re-runs the REAL triage executor (investigateUnknownShape — the same
// code path a fresh target gets) on a local fork of that target's chain:
//   - verdict lands  -> the queue entry is retired (resolveTriage already
//     fires inside the investigation),
//   - still deferred -> enqueueTriage bumps the attempt with backoff, exactly
//     like any fresh deferral; the existing MAX_ATTEMPTS=6 / 24h age bounds
//     finally mean something because attempts now increment,
//   - probe error    -> re-queued as probe-error (still bounded by attempts).
//
// Gating on real capacity, not just deadlines: when every key is in cooldown
// or the budget is spent, a drain attempt would just churn the same keys and
// double-count cooldowns — so the drain skips cycles with zero available
// capacity and lets the backoff clocks run. Nothing here is new authority:
// read-only RPC + the local-only fork rules the whole fleet runs under.
import { CHAINS } from "./scan.ts";
import { AnvilFork, spawnForkWithFailover } from "./fork.ts";
import { dueTriage, type TriageQueueItem } from "./triageQueue.ts";
import { investigateUnknownShape } from "./investigate.ts";
import { isProductionTarget } from "./findings.ts";
import { keyCooldownStats } from "./triage.ts";

export interface DrainResult {
  attempted: number;
  resolved: number;
  redeferred: number;
  errored: number;
  skippedNoCapacity: boolean;
  skippedNoKeys: boolean;
  notes: string[];
}

/** True when at least one triage key has meaningful headroom (not cooling
 * down). Reads the pool's public cooldown stats — no double-counting. */
function keysAvailable(): boolean {
  try {
    const s = keyCooldownStats();
    return s.keys > 0 && s.cooling < s.keys;
  } catch {
    return false; // no pool in this process — don't fake it
  }
}

/** Drain up to `limit` due triage items on real local forks. Serial on
 * purpose: each drain item spawns a fork, and the drain must never crowd out
 * the probe queue that feeds the same workers. */
export async function drainTriageQueue(opts: {
  daemonId: string;
  forkPortBase: number;
  limit?: number;
}): Promise<DrainResult> {
  const out: DrainResult = {
    attempted: 0, resolved: 0, redeferred: 0, errored: 0,
    skippedNoCapacity: false, skippedNoKeys: false, notes: [],
  };
  try {
    // Both gates: without keys in this process the executor would defer
    // instantly (no-key deferrals requeue nothing — resolveTriage on no-input —
    // so draining then would silently DELETE work other daemons can do).
    if (!keysAvailable()) { out.skippedNoKeys = true; return out; }

    const due = dueTriage(opts.limit ?? 6);
    if (due.length === 0) return out;
    let port = opts.forkPortBase;

    for (const item of due) {
      const chain = CHAINS.find((c) => c.id === item.chainId);
      if (!chain || !isProductionTarget(item.chainId, item.address)) {
        // Unreachable chain or dead row: retire rather than age out 24h later.
        out.errored++;
        out.notes.push(`${item.key}: chain not forkable — retiring`);
        const { resolveTriage } = await import("./triageQueue.ts");
        resolveTriage(item.chainId, item.address);
        continue;
      }
      const key = `${chain.name}:${item.address}`;
      out.attempted++;
      let fork: AnvilFork | null = null;
      try {
        fork = await spawnForkWithFailover(chain.rpcs[0]!, port, chain.rpcs.slice(1));
        port++;
        const inv = await investigateUnknownShape(fork, item.chainId, chain.name, item.address, chain, {
          daemonId: opts.daemonId,
          watchKey: key,
        });
        // investigateUnknownShape retires the entry internally when a verdict
        // lands; a deferral re-enqueues with the next backoff. Classify for
        // the log line from the resulting summary.
        if (inv.finding) { out.resolved++; out.notes.push(`${key}: ${inv.summary.slice(0, 90)}`); }
        else if (/deferred|cooldown|rate|429|budget/i.test(inv.summary)) out.redeferred++;
        else { out.resolved++; }
      } catch (e) {
        out.errored++;
        const { enqueueTriage } = await import("./triageQueue.ts");
        try { enqueueTriage(item.chainId, item.address, "probe-error"); } catch { /* bounded by attempts */ }
        out.notes.push(`${key}: probe error — ${(e as Error).message.slice(0, 80)}`);
      } finally {
        try { fork?.stop(); } catch { /* already gone */ }
      }
    }
  } catch (e) {
    out.notes.push(`drain aborted: ${(e as Error).message.slice(0, 120)}`);
  }
  return out;
}

/** Exposed for tests: does this process have live key capacity? */
export function _keysAvailableForTest(): boolean {
  return keysAvailable();
}

export type { TriageQueueItem };
