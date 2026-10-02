// Operator controls — the dashboard's write path, kept deliberately tiny.
//
// WHY: the whole UI server is GET-only ("read-only") and that doctrine is
// right for data. But the operator had no way to turn an IDLE subsystem on:
// the LLM triage pool (18 keys, budget 0/2400 used) sat fully provisioned
// while 1,218 watchlist rows stayed shape:"unknown" because the daemon only
// triages what its scan rotation happens to visit. This module is the single
// flag behind the dashboard's ON/OFF button — nothing else in the fleet is
// operator-writable.
//
// Storage: one JSON file in REPORT_DIR (default reports/ui-controls.json),
// read fresh on every access (no cache) so any process — daemon, UI server,
// one-shot CLI — sees the same state immediately and restarts keep the choice.
//
// Safety rails that make the ON state honest:
//   - the backlog drain NEVER skips the queue: it enqueues through
//     triageQueue.ts, so MAX_ATTEMPTS=6 / 24h-age bounds and backoff apply;
//   - the drain is capacity-gated (live key + daily budget) exactly like the
//     retry-queue drain — the switch allocates idle capacity, it never
//     overrides cooldowns, budgets, or rate limits;
//   - everything stays read-only fork probing (investigateUnknownShape),
//     same authority as any other daemon cycle work.
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { REPORT_DIR } from "./config.ts";

const CONTROLS_PATH = join(REPORT_DIR, "ui-controls.json");

export interface UiControls {
  /** Master switch: run the LLM triage over the shape:"unknown" backlog. */
  triageBacklog: boolean;
  /** ISO timestamp of the last flip, for the dashboard's "since" hint. */
  changedAt?: string;
}

const DEFAULTS: UiControls = { triageBacklog: false };

function read(): UiControls {
  try {
    if (!existsSync(CONTROLS_PATH)) return { ...DEFAULTS };
    const raw = JSON.parse(readFileSync(CONTROLS_PATH, "utf8")) as Partial<UiControls>;
    return { ...DEFAULTS, ...raw };
  } catch {
    // Corrupt file must never take the daemon down — fall back to defaults
    // (OFF) and let the next write heal the file.
    return { ...DEFAULTS };
  }
}

function write(c: UiControls): void {
  try {
    mkdirSync(dirname(CONTROLS_PATH), { recursive: true });
    // Atomic write: rename within the same dir, so a crash mid-write can
    // never leave a truncated controls file behind.
    const tmp = CONTROLS_PATH + ".tmp";
    writeFileSync(tmp, JSON.stringify(c, null, 2) + "\n");
    renameSync(tmp, CONTROLS_PATH);
  } catch {
    // Unwritable disk is cosmetic here: the flag stays in-memory for this
    // call and the next write retries. Never fatal.
  }
}

export function getUiControls(): UiControls {
  return read();
}

export function triageBacklogEnabled(): boolean {
  return read().triageBacklog === true;
}

/** Flip the backlog switch. Returns the new state (true = ON). */
export function setTriageBacklog(on: boolean): UiControls {
  const c: UiControls = { ...read(), triageBacklog: !!on, changedAt: new Date().toISOString() };
  write(c);
  return c;
}
