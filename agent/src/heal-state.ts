// One-off (rerunnable) heal of reports/state.json through the hydrate
// hygiene: loads the persisted session via hydrateFromDisk — which runs
// scrubFindingsHygiene at the chokepoint — then persists the cleaned result
// back. Local disk only; no RPC, no forks, nothing broadcast.
//
// Heals:
//   - DRAIN flags on rows whose lastResult is a probe REFUSAL
//     ("probe blocked by vault gating…") or a clean probe;
//   - UNCLASSIFIED BALANCE DROP findings older than 7 days, dropped from the
//     findings feed (event history retained);
//   - duplicate finding cards (same kind+message).
import { hydrateFromDisk, snapshot, persistSnapshot } from "./bus.ts";

if (!hydrateFromDisk()) {
  console.error("heal: no readable reports/state.json — nothing to do");
  process.exit(1);
}
const before = snapshot();
persistSnapshot();
const after = snapshot();
const flagsBefore = Object.values(before.watchlist).filter((w) => w.finding).length;
const flagsAfter = Object.values(after.watchlist).filter((w) => w.finding).length;
console.log(`heal: findings feed ${before.findings.length} -> ${after.findings.length}`);
console.log(`heal: DRAIN flags ${flagsBefore} -> ${flagsAfter} (cleared: ${flagsBefore - flagsAfter})`);
console.log("heal: reports/state.json rewritten");
