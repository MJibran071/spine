// Smoke test for the GENERIC-engine learning loop (genlearn.ts + genharness
// integration). Verifies the loop that makes the engine smarter run over run:
//   1. record → recall round-trip (violations, deadends, priors)
//   2. LEARNED PRIMITIVE ORDER: a proven violating path promotes its
//      primitives to the front of the NEXT harness's fuzz surface
//   3. deadend dedupe (no store spam across cycles)
//   4. triage hint emission (engine history reaches the LLM prompt)
// Runs against a scratch store (reports/genlearn.test.json) — production
// learning data is untouched.
import {
  withGenLearnTestStore, recordViolation, recordDeadend, recordHeld, knownViolations, knownDeadends, shapePriors, genLearnHint,
  recordShapeBackoff, shapeCoolingDown, shapeBackoffMinutesLeft, recordTargetOutcome, targetOutcome,
  recordShapeFailureClass, shapeFailureClasses, recordLesson, knownLessons, mineLessonsFromMemories,
  engineGate, recordProbeDedupeKey, probeDedupeKeys, genLearnOverview,
} from "./genlearn.ts";
import { buildHarness, archiveGenHarness } from "./genharness.ts";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url)); // agent/src
const LAB_ROOT = join(HERE, "..", "..");
const CHALLENGE = "SideEntranceLenderPool";
const SRC_PATH = join(LAB_ROOT, "src", "challenges", "SideEntranceLenderPool.sol");

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

await withGenLearnTestStore(async () => {
  // ---- 1. round-trip ----
  // Paths use the [GEN_PATH] format the engine actually records (bare names).
  recordViolation("lender-native", {
    invariant: "native",
    path: "donateNative -> flashLoan -> setCallbackDeposits -> withdraw",
    profitWei: "5000000000000000000",
  });
  recordViolation("lender-native", {
    invariant: "native",
    path: "flashLoan -> setCallbackDeposits -> withdraw",
    profitWei: "3000000000000000000",
  });
  const viols = knownViolations("lender-native");
  if (viols.length !== 2) fail(`expected 2 recorded violations, got ${viols.length}`);
  const pri = shapePriors("lender-native");
  if (pri.violated !== 2) fail(`expected violated=2, got ${pri.violated}`);
  console.log("ok: record/recall round-trip (violations + priors)");

  // ---- 2. learned primitive order (the "smarter next run" proof) ----
  const source = readFileSync(SRC_PATH, "utf8");
  const h1 = buildHarness(
    { challengeName: "LearningProbe", sources: [source], sourcePaths: [SRC_PATH], mode: "source" },
    0
  );
  if (!h1) fail("SideEntranceLenderPool should produce a lender-native harness");
  const h1Text = readFileSync(h1.filePath, "utf8");
  // The NEWEST recorded violating path (the 3-step one) must be embedded as
  // a deterministic replay primitive in the NEXT harness of the same shape.
  if (!h1Text.includes("function fuzz_replayLearned(")) fail("learned replay primitive missing from the next harness");
  if (!h1Text.includes("Learned priors:")) fail("harness header missing the learned-priors annotation");
  const replayBody = h1Text.slice(h1Text.indexOf("function fuzz_replayLearned("));
  // Newest path = "flashLoan -> setCallbackDeposits -> withdraw": exactly 3
  // steps, in recorded order, and nothing else.
  const steps = [...replayBody.matchAll(/fuzz_(\w+)\([^)]*\); \/\/ step (\d+)\/(\d+)/g)].map((m) => `${m[1]}:${m[2]}/${m[3]}`);
  if (steps.length !== 3) fail(`expected exactly 3 replay steps (newest path only), got [${steps.join(", ")}]`);
  if (steps[0] !== "flashLoan:1/3" || steps[1] !== "setCallbackDeposits:2/3" || steps[2] !== "withdraw:3/3") {
    fail(`replay steps wrong or out of order: [${steps.join(", ")}]`);
  }
  console.log("ok: learned attack replay — newest proven path embedded as fuzz_replayLearned (flashLoan -> setCallbackDeposits -> withdraw, in order)");

  // Cleanup: archive the generated harness so test/agent/ never keeps a
  // permanently-failing invariant test (whole-fleet forge lockout risk).
  archiveGenHarness(h1.filePath, h1.contractName);

  // ---- 3. deadend dedupe ----
  recordDeadend("lender-native", "setUp failed: shape heuristics did not fit");
  recordDeadend("lender-native", "setUp failed: shape heuristics did not fit");
  recordDeadend("lender-native", "setUp failed: shape heuristics did not fit");
  const dead = knownDeadends("lender-native");
  if (dead.length !== 1) fail(`deadend dedupe failed: expected 1 entry, got ${dead.length}`);
  console.log("ok: deadend dedupe (3 identical records -> 1 stored)");

  // ---- 4. triage hint ----
  const hint = genLearnHint("lender-native");
  if (!hint.includes("recorded violations")) fail(`triage hint missing violation history: "${hint}"`);
  if (!hint.includes("known dead ends")) fail("triage hint missing dead-end history");
  recordHeld("token");
  if (!genLearnHint("token").includes("held run(s)")) fail("held runs missing from hint");
  console.log("ok: triage hint carries engine history to the LLM prompt");

  // ---- 5. shape cooldown: errors back off, success clears ----
  if (shapeCoolingDown("erc4626")) fail("fresh shape must not be cooling down");
  recordShapeBackoff("erc4626");
  if (!shapeCoolingDown("erc4626")) fail("backoff after error not registered");
  if (shapeBackoffMinutesLeft("erc4626") < 9) fail(`first backoff should be ~10m, got ${shapeBackoffMinutesLeft("erc4626")}m`);
  recordShapeBackoff("erc4626"); // consecutive error doubles the window
  if (shapeBackoffMinutesLeft("erc4626") < 19) fail(`second backoff should double to ~20m, got ${shapeBackoffMinutesLeft("erc4626")}m`);
  const hintCooling = genLearnHint("erc4626");
  if (!hintCooling.includes("cooling down")) fail("cooling state missing from triage hint");
  recordHeld("erc4626"); // a completed run proves the shape works again
  if (shapeCoolingDown("erc4626")) fail("held run must clear the cooldown");
  console.log("ok: shape cooldown (exponential backoff, cleared by a held run, surfaced in hint)");

  // ---- 6. per-target outcome index: repeat-visit skip ----
  recordTargetOutcome("0xAbC0000000000000000000000000000000000001", {
    shape: "erc4626", result: "error", sourceLen: 1234, note: "compile error",
  });
  const prevOutcome = targetOutcome("0xabc0000000000000000000000000000000000001"); // case-insensitive key
  if (!prevOutcome || prevOutcome.result !== "error" || prevOutcome.sourceLen !== 1234) {
    fail(`target outcome round-trip failed: ${JSON.stringify(prevOutcome)}`);
  }
  const o = genLearnOverview();
  if (!o.cooling || !o.failureClasses || !o.lessons) fail("genLearnOverview missing the new intelligence fields");
  console.log("ok: per-target outcome index (address-keyed, case-insensitive, overview exposes it)");

  // ---- 7. per-shape failure classes: the WHY behind errors ----
  recordShapeFailureClass("erc4626", "compile", "Identifier not found: asset");
  recordShapeFailureClass("erc4626", "compile", "Identifier not found: asset");
  recordShapeFailureClass("erc4626", "setUp", "no asset introspection");
  const fc = shapeFailureClasses("erc4626");
  if (fc.length !== 2) fail(`expected 2 failure classes, got ${fc.length}`);
  if (fc[0]!.failureClass !== "compile" || fc[0]!.count !== 2) fail(`worst class first failed: ${JSON.stringify(fc[0])}`);
  console.log("ok: per-shape failure classes (counted, worst first)");

  // ---- 8. cross-shape lessons: proven techniques proposed first ----
  if (knownLessons("lender-native").length !== 0) fail("fresh shape must have no lessons");
  recordLesson("lender-native", "generic-invariant:native");
  recordLesson("lender-native", "side-entrance-reentrancy");
  recordLesson("lender-native", "side-entrance-reentrancy"); // dedupe
  const lessons = knownLessons("lender-native");
  if (lessons.length !== 2) fail(`expected 2 lessons after dedupe, got ${lessons.length}`);
  if (lessons[0] !== "side-entrance-reentrancy") fail(`newest lesson first: ${JSON.stringify(lessons)}`);
  const hintLessons = genLearnHint("lender-native");
  if (!hintLessons.includes("proven on a sibling target") || !hintLessons.includes("FIRST")) {
    fail(`lesson missing from hint: "${hintLessons}"`);
  }
  console.log("ok: cross-shape lessons (deduped, newest first, proposed FIRST in the hint)");

  // ---- 9. lesson miner: PROBE SUCCESS memories become shape priors ----
  const mined = mineLessonsFromMemories([
    'PROBE SUCCESS 2026-09-17: 0xbbb0000000000000000000000000000000000002 (shape: lender-asset) — technique flash-loan-donation PRODUCED A DRAIN in simulation.',
    'PROBE FAILED 2026-09-17: 0xbbb0000000000000000000000000000000000003 (shape: lender-asset) — technique reentrancy reverted.',
  ]);
  if (mined !== 1) fail(`miner must ignore failures and dedupe wins: mined=${mined}`);
  if (!knownLessons("lender-asset").includes("flash-loan-donation")) fail("mined lesson missing from shape priors");
  // No shape in prose -> resolve via the per-target outcome index.
  recordTargetOutcome("0xbbb0000000000000000000000000000000000004", {
    shape: "token", result: "held", sourceLen: 10, note: "held",
  });
  mineLessonsFromMemories([
    'PROBE SUCCESS 2026-09-17: 0xbbb0000000000000000000000000000000000004 — technique unauthorized-mint PRODUCED A DRAIN in simulation.',
  ]);
  if (!knownLessons("token").includes("unauthorized-mint")) fail("address-resolved lesson missing");
  console.log("ok: lesson miner (wins only, shape from prose or the outcome index)");

  // ---- 10. engine gate + persistent probe dedupe ----
  recordShapeBackoff("oracle-spot");
  const gate = engineGate("oracle-spot");
  if (!gate.coolingDown || gate.violatedBefore || gate.deadends.length !== 0) fail(`engineGate wrong: ${JSON.stringify(gate)}`);
  recordProbeDedupeKey("t1:tech:x:reverted");
  recordProbeDedupeKey("t1:tech:x:reverted"); // dedupe
  const pk = probeDedupeKeys();
  if (pk.length !== 1 || pk[0] !== "t1:tech:x:reverted") fail(`persistent dedupe broken: ${JSON.stringify(pk)}`);
  console.log("ok: engine gate object + persistent probe-dedupe store");

  console.log("\nGENLEARN SMOKE TEST: ALL PASS — the engine now learns across runs AND spends its attempts where history says learning is possible.");
});
