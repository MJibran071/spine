// Bounded-concurrency worker pool for the agent's parallel phases.
// Each unit of work runs on a "worker slot"; N slots = N concurrent forge
// processes / forks / analysis targets. Results keep their input order.
export interface PoolResult<T> {
  index: number;
  ok: boolean;
  value?: T;
  error?: string;
}

export function workerCount(flagValue: string | undefined, fallback: number): number {
  const n = parseInt(flagValue ?? "", 10);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(n, 16); // hard ceiling: public RPCs and local CPU are finite
}

/** Run `tasks` with at most `workers` running concurrently. */
export async function runPool<T>(
  workers: number,
  tasks: Array<() => Promise<T>>
): Promise<PoolResult<T>[]> {
  const results: PoolResult<T>[] = new Array(tasks.length);
  let next = 0;

  async function slot(): Promise<void> {
    for (;;) {
      const i = next++;
      if (i >= tasks.length) return;
      try {
        results[i] = { index: i, ok: true, value: await tasks[i]!() };
      } catch (e) {
        results[i] = { index: i, ok: false, error: (e as Error).message };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, Math.min(workers, tasks.length)) }, slot));
  return results;
}
