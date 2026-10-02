// Regression test for the findings-hygiene migration in the bus hydrate path.
//
// The pre-classification fleet recorded raw balance drops as "findings" —
// mostly ordinary user withdrawals — and flagged innocent watchlist rows with
// DRAIN pills. Those rows poison the UI's findings feed even after the
// responder itself was fixed, because every daemon re-persists them from
// memory. The scrub therefore lives in hydrateFromState, the chokepoint every
// consumer hydrates through, and must be surgical:
//   - old-prefix findings/events are removed ONCE;
//   - the NEW "UNCLASSIFIED BALANCE DROP on" prefix (which CONTAINS the old
//     prefix as a substring) must NEVER match — a genuine future signal;
//   - a DRAIN flag contradicting the row's own "probe ran clean" lastResult
//     is cleared; a flag consistent with a real escalation is kept.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0;
let failures = 0;
function eq(name: string, got: unknown, want: unknown) {
  const ok = got === want;
  if (ok) pass++;
  else failures++;
  console.log(`${ok ? "ok" : "FAIL"} — ${name}${ok ? "" : ` (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
}
function check(name: string, cond: boolean) {
  if (cond) pass++;
  else failures++;
  console.log(`${cond ? "ok" : "FAIL"} — ${name}`);
}

const SCRATCH = mkdtempSync(join(tmpdir(), "bus-hygiene-"));
mkdirSync(join(SCRATCH, "reports"), { recursive: true });
process.env.LAB_REPORT_DIR = join(SCRATCH, "reports");

const TARGET = "0x" + "cc".repeat(20); // stale DRAIN flag on a clean row
const GATED = "0x" + "ee".repeat(20); // DRAIN flag on a PROBE-REFUSAL row
const KEEP = "0x" + "dd".repeat(20); // genuine escalation-style flag
// Hand-resolved verdict: the Gearbox PoolV3 "UNCLASSIFIED BALANCE DROP" was
// traced to a benign ERC4626 redeem (owner == receiver == tx.from) — retired
// EXACTLY, while a near-identical new signal must survive untouched.
const RESOLVED_MSG =
  "UNCLASSIFIED BALANCE DROP on auto-enlisted live vault (0x9396dcbf78fc526bb003665337c5e73b699571ef) WETH: -25073165982900038238 (220023619929654875202 -> 194950453946754836964) — opening incident";
const NEAR_MISS_MSG =
  "UNCLASSIFIED BALANCE DROP on auto-enlisted live vault (0x1111111111111111111111111111111111111111) WETH: -99000000000000000000 (220023619929654875202 -> 194950453946754836964) — opening incident";
// A near-identical message on a HAND-RESOLVED target retires wholesale — the
// address cannot collide with another protocol's finding.
const RESOLVED_TARGET_NEAR_MISS_MSG =
  "UNCLASSIFIED BALANCE DROP on auto-enlisted live vault (0x9396dcbf78fc526bb003665337c5e73b699571ef) WETH: -99000000000000000000 (220023619929654875202 -> 194950453946754836964) — opening incident";
const NOW_MS = Date.now();
writeFileSync(
  join(SCRATCH, "reports", "state.json"),
  JSON.stringify({
    watchlist: {
      [TARGET]: { address: TARGET, finding: true, lastResult: "probe ran clean: no violation observed (NO_VIOLATION)" },
      [GATED]: { address: GATED, finding: true, lastResult: "probe blocked by vault gating (allowlist/roles): every path reverted — needs manual analysis" },
      [KEEP]: { address: KEEP, finding: true, lastResult: "INCIDENT: WETH drop 5000000000000000000 — report INCIDENT-x.md" },
    },
    findings: [
      { t: 1, kind: "finding", msg: "BALANCE DROP on auto-enlisted live vault (0x9396…) WETH: -20000000000000000000 (… -> …)" },
      { t: NOW_MS, kind: "finding", msg: "UNCLASSIFIED BALANCE DROP on RealVault (0xabc…) WETH: -5000000000000000000" },
      { t: NOW_MS - 8 * 86_400_000, kind: "finding", msg: "UNCLASSIFIED BALANCE DROP on OldVault (0xbbc…) USDC: -1000000 — opening incident" },
      { t: 5, kind: "finding", msg: RESOLVED_MSG },
      { t: NOW_MS - 3_600_000, kind: "finding", msg: NEAR_MISS_MSG },
      { t: NOW_MS - 3_600_000, kind: "finding", msg: RESOLVED_TARGET_NEAR_MISS_MSG },
    ],
    events: [
      { t: 3, kind: "finding", msg: "BALANCE DROP on auto-enlisted live vault (0x9396…) WETH: -20000000000000000000" },
      { t: 7, kind: "finding", msg: RESOLVED_MSG },
      { t: 4, kind: "scan", msg: "responder: balance endpoint eth-mainnet.public.blastapi.io passed balance+eth_call canaries" },
    ],
  })
);

const { hydrateFromDisk, snapshot } = await import("./bus.ts");

eq("hydrate succeeded", hydrateFromDisk(), true);
const s = snapshot();

// UNCLASSIFIED feed: the RECENT one survives (substring must not match the
// old-prefix scrub), the >7-day-old one ages out of the feed.
const recentUnclassified = s.findings.find((f) => f.msg.startsWith("UNCLASSIFIED BALANCE DROP on RealVault"));
check("recent UNCLASSIFIED finding survives (substring must not match)", Boolean(recentUnclassified));
check("UNCLASSIFIED finding older than 7 days expired from the feed",
  !s.findings.find((f) => f.msg.startsWith("UNCLASSIFIED BALANCE DROP on OldVault")));
eq("feed holds near-miss + recent UNCLASSIFIED only", s.findings.length, 2);
check("hand-resolved finding retired EXACTLY (near-miss on another target untouched)",
  !s.findings.find((f) => f.msg === RESOLVED_MSG) && Boolean(s.findings.find((f) => f.msg === NEAR_MISS_MSG)));
check("near-miss on a hand-resolved TARGET retires wholesale (address cannot collide)",
  !s.findings.find((f) => f.msg === RESOLVED_TARGET_NEAR_MISS_MSG));
const findingEvents = s.events.filter((e) => e.kind === "finding");
eq("old-prefix + resolved finding-kind events scrubbed from the stream", findingEvents.length, 0);
check("non-finding events untouched", s.events.some((e) => e.kind === "scan" && e.msg.includes("canaries")));
eq("stale DRAIN flag cleared on the clean row", s.watchlist[TARGET].finding, false);
check("DRAIN flag cleared on a PROBE-REFUSAL row (gating is not a drain)", s.watchlist[GATED].finding === false);
check("genuine escalation flag kept", s.watchlist[KEEP].finding === true);
check("scrub recorded honestly in the safety log", s.events.some((e) => e.kind === "safety" && e.msg.includes("scrubbed")));
check("resolved-retirement recorded in the safety log", s.events.some((e) => e.kind === "safety" && e.msg.includes("hand-resolved")));
check("ttl-expiry recorded in the safety log", s.events.some((e) => e.kind === "safety" && e.msg.includes("UNCLASSIFIED finding(s) older than 7 days")));

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? `\nbus hygiene: all ${pass} checks passed` : `\nbus hygiene: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
