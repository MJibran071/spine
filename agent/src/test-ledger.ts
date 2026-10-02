// Regression tests for the hypothesis + claim ledger and KB few-shot retrieval.
//
// What must hold:
//   1. ensureHypotheses dedups; nextHypothesis returns the OLDEST untested
//      row and null once every hypothesis is tested;
//   2. markHypothesis records status/evidence and returns false for unknown
//      techniques (the fallback path depends on that signal);
//   3. untestedTargets / ledgerStats reflect the live rows;
//   4. claimTarget is exclusive across daemons, self-heals after the TTL,
//      and releaseClaim only releases your own claim;
//   5. sampleWins retrieves by token overlap with signals/shape and returns
//      NOTHING when there is no overlap (never fabricate priors).
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
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

const SCRATCH = mkdtempSync(join(tmpdir(), "ledger-test-"));
mkdirSync(join(SCRATCH, "reports"), { recursive: true });
process.env.LAB_REPORT_DIR = join(SCRATCH, "reports");

const {
  ensureHypotheses, nextHypothesis, markHypothesis, untestedTargets, ledgerStats, claimTarget, releaseClaim,
} = await import("./ledger.ts");
const { sampleWins, recordWin } = await import("./knowledge.ts");

const CH = "1";
const A = "0x" + "aa".repeat(20);
const B = "0x" + "bb".repeat(20);

// ---- 1. seeding + ordering -------------------------------------------------
eq("seed two hypotheses on A", ensureHypotheses(CH, A, [
  { technique: "sig-gated-claim", origin: "detector" },
  { technique: "oracle-spot-price", origin: "detector" },
]), 2);
eq("re-seed is a no-op (dedup)", ensureHypotheses(CH, A, [{ technique: "sig-gated-claim", origin: "detector" }]), 0);
eq("seed one on B", ensureHypotheses(CH, B, [{ technique: "unauthorized-mint", origin: "triage" }]), 1);

const first = nextHypothesis(CH, A);
check("oldest untested returned first", Boolean(first && first.technique === "sig-gated-claim"));

// ---- 2. marking -------------------------------------------------------------
markHypothesis(CH, A, "sig-gated-claim", "refuted", "probe held; no unguarded claim path");
eq("marked row leaves the untested set", nextHypothesis(CH, A)?.technique, "oracle-spot-price");
eq("markHypothesis on unknown row returns false", markHypothesis(CH, A, "no-such-technique", "held"), false);
markHypothesis(CH, A, "oracle-spot-price", "held", "probe reverted: liquidity too thin");
eq("all-A-tested -> nextHypothesis null", nextHypothesis(CH, A), null);

const st = ledgerStats();
eq("stats: total", st.hypotheses.total, 3);
eq("stats: untested", st.hypotheses.untested, 1);
eq("stats: refuted", st.hypotheses.refuted, 1);
eq("stats: held", st.hypotheses.held, 1);
eq("stats: actionable", st.hypotheses.actionable, 0);

const unt = untestedTargets();
check("untestedTargets names exactly B", unt.has(`${CH}:${B}`) && !unt.has(`${CH}:${A}`));

// ---- 3. claims --------------------------------------------------------------
eq("daemon-1 claims A", claimTarget(CH, A, "daemon-1"), true);
eq("daemon-2 cannot claim A while live", claimTarget(CH, A, "daemon-2"), false);
eq("same daemon may re-claim (idempotent)", claimTarget(CH, A, "daemon-1"), true);
releaseClaim(CH, A, "daemon-2"); // wrong owner: must NOT release
eq("foreign release is a no-op", claimTarget(CH, A, "daemon-3"), false);
releaseClaim(CH, A, "daemon-1");
eq("owner release frees the claim", claimTarget(CH, A, "daemon-2"), true);
releaseClaim(CH, A, "daemon-2");

// ---- 4. sampleWins retrieval -------------------------------------------------
recordWin("test-sig-a", "spot-oracle-manipulation", { pool: "0x1" });
recordWin("test-sig-b", "sig-gated-claim-replay", { claim: "0x2" });
recordWin("test-sig-c", "lz-governance-replay", { gov: "0x3" });

const hits = sampleWins("unknown-pair", ["oracle-spot-price", "credit-balance-confusion"], 3);
check("retrieves the oracle-adjacent win first", hits.length > 0 && hits[0].technique === "spot-oracle-manipulation");
const none = sampleWins("totally-unrelated-shape", ["completely-different-thing"], 3);
eq("no overlap -> empty (never fabricate priors)", none.length, 0);

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? `\nledger: all ${pass} checks passed` : `\nledger: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
