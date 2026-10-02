// Regression test for WATCHLIST IDENTITY.
//
// Historical bug: investigateUnknownShape() upserted its human-readable log
// label (`ethereum:0x7d2768dE…`) as the watchlist key. A truncated key cannot
// be resolved on a fork, so it can never be probed — the live session carried
// 728 of them (48% of a 1518-entry watchlist; 721 duplicating a real row),
// which split every investigated target's evidence across two entries: the
// triage/detector summary on the phantom row, the probe result on the real one.
//
// Three layers keep it from coming back, and all three are checked here:
//   1. key derivation  (watchKeyOf — observation lands on the caller's row)
//   2. write chokepoint (upsertWatch refuses a display label, audibly)
//   3. stale-file migration (hydrate drops old phantom rows; persist cannot
//      merge a phantom row back in from disk)
//
// Runs against a scratch report dir (LAB_REPORT_DIR) — the live hunt's
// reports/state.json is never touched.
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-watchkeys-"));
process.env.LAB_REPORT_DIR = SCRATCH; // must be set before the bus reads config
const STATE_PATH = join(SCRATCH, "state.json");

// Dynamic import: a static one would be hoisted above the env assignment.
const { isPhantomWatchKey, upsertWatch, snapshot, hydrateFromDisk, prunePhantomWatchKeys, logEvent, watchKeyOf } =
  await import("./bus.ts");

let failures = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    console.log(`ok: ${name}`);
    return;
  }
  failures++;
  console.error(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
}

const ADDR = "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"; // Aave v2 Pool

// ---- 1. key derivation ----------------------------------------------------
const label = `ethereum:${ADDR} [hot]`;
check("watchKeyOf falls back to chain:lowercased-address", watchKeyOf("ethereum", ADDR) === `ethereum:${ADDR.toLowerCase()}`, watchKeyOf("ethereum", ADDR));
check("watchKeyOf honours the caller's canonical key verbatim", watchKeyOf("ethereum", ADDR, label) === label);
check("scanner row and investigation row key match (the bug)", watchKeyOf("ethereum", ADDR.toLowerCase(), label) === label);
check("watchKeyOf ignores a blank override", watchKeyOf("ethereum", ADDR, "   ") === `ethereum:${ADDR.toLowerCase()}`);

// ---- 2. phantom classification -------------------------------------------
for (const p of [`ethereum:${ADDR.slice(0, 10)}…`, `${ADDR.slice(0, 6)}…${ADDR.slice(-4)}`, "0x123...abc", "ethereum:0x…"]) {
  check(`phantom: ${JSON.stringify(p)}`, isPhantomWatchKey(p));
}
for (const r of [`ethereum:${ADDR}`, ADDR, label, "solana:raydium-amm-v4", "base:0xcdac0d6c6c59727a65f871236188350531885c43 [seed]"]) {
  check(`resolvable: ${r.length > 26 ? `${r.slice(0, 26)}…` : r}`, !isPhantomWatchKey(r));
}
check("phantom: empty key", isPhantomWatchKey(""));
check("phantom: undefined key", isPhantomWatchKey(undefined));
check("phantom: non-string key", isPhantomWatchKey(42));

// ---- 3. write chokepoint -------------------------------------------------
const phantomKey = `ethereum:${ADDR.slice(0, 10)}…`;
upsertWatch({ address: phantomKey, shape: "unknown", lastResult: "triage summary" });
check("upsertWatch refuses a display-truncated key", snapshot().watchlist[phantomKey] === undefined);
check(
  "...and the refusal is auditable",
  snapshot().events.some((e) => e.kind === "safety" && e.msg.includes("refused display-truncated"))
);
upsertWatch({ address: label, shape: "unknown", lastResult: "investigation summary" });
check("upsertWatch accepts the canonical key", snapshot().watchlist[label]?.lastResult === "investigation summary");
upsertWatch({ address: label, lastResult: "probe result" });
const sameTarget = Object.keys(snapshot().watchlist).filter((k) => k.toLowerCase().startsWith(`ethereum:${ADDR.slice(0, 10).toLowerCase()}`));
check("probe result merges onto the same row (one target = one row)", sameTarget.length === 1 && snapshot().watchlist[sameTarget[0]!]?.lastResult === "probe result", sameTarget.join(", "));

// ---- 4. stale-file migration --------------------------------------------
const REAL = "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc";
const realKey = `ethereum:${REAL} [hot]`;
mkdirSync(SCRATCH, { recursive: true });
const stale = {
  mode: "idle", startedAt: 0, cycle: 0, daemonCount: 1, challenges: {}, findings: [], events: [],
  kbWins: 0, genEngine: { results: {}, harnessable: 0, discoveries: 0 }, daemons: {},
  watchlist: {
    [`ethereum:${REAL.slice(0, 10)}…`]: { address: `ethereum:${REAL.slice(0, 10)}…`, shape: "unknown", lastResult: "old triage" },
    [`${REAL.slice(0, 6)}…`]: { address: `${REAL.slice(0, 6)}…`, lastResult: "old probe" },
    [realKey]: { address: realKey, shape: "unknown", lastResult: "kept" },
  },
};
writeFileSync(STATE_PATH, JSON.stringify(stale, null, 2));
check("hydrateFromDisk succeeds on a stale session", hydrateFromDisk() === true);
const keys = Object.keys(snapshot().watchlist);
check("stale phantom rows are dropped on hydrate", keys.every((k) => !isPhantomWatchKey(k)), keys.join(", "));
check("real rows survive the migration", snapshot().watchlist[realKey]?.lastResult === "kept");
check("the migration is reported", snapshot().events.some((e) => e.kind === "safety" && e.msg.includes("unprobeable display-truncated")));

// ---- 5. persist cannot re-import phantom rows ----------------------------
const sneak = `ethereum:${"0x6033f7f88332b8db6ad452b7c6d5bb643990ae3f".slice(0, 10)}…`;
const raw = JSON.parse(readFileSync(STATE_PATH, "utf8"));
raw.watchlist[sneak] = { address: sneak, lastResult: "sneaked back" };
writeFileSync(STATE_PATH, JSON.stringify(raw, null, 2));
logEvent("scan", "persist round-trip"); // triggers persistSnapshot (read+merge+write)
const after = JSON.parse(readFileSync(STATE_PATH, "utf8"));
const afterKeys = Object.keys(after.watchlist);
check("a phantom row on disk is not merged back in on persist", afterKeys.every((k) => !isPhantomWatchKey(k)), afterKeys.join(", "));
check("real rows still persist", afterKeys.includes(realKey));
check("prunePhantomWatchKeys is a no-op on a clean store", prunePhantomWatchKeys() === 0);

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? "\nwatchlist identity: all checks passed" : `\nwatchlist identity: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
