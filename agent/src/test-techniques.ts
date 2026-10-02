// Smoke test for the SELF-LEARNED TECHNIQUE LIBRARY (techniques.ts).
// Verifies the loop that lets the agent learn hacking techniques from its own
// proven work and reuse them:
//   1. capture → recall round-trip (dedupe, win-count, transfer evidence)
//   2. retrieval order — proven techniques rank first, retrieval works
//   3. techniquesHint emission (what future triage prompts will see)
//   4. derived curiosity questions grow from the library
//   5. distillation marks a technique generalized WITHOUT a key (honest skip,
//      proven fact preserved) and the mock path generalizes when a key exists
// Runs against a scratch in-memory store — production data untouched.
import {
  withTechniquesTestStore, captureProvenDrain, allTechniques, topTechniques,
  techniquesHint, techniquesStats, derivedQuestions, distillPending,
} from "./techniques.ts";

function fail(msg: never): void {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

await withTechniquesTestStore(async () => {
  // ---- 1. capture → recall round-trip ----
  const id = captureProvenDrain({
    origin: "generic-invariant",
    technique: "generic-invariant:native",
    shape: "lender-native",
    observation: 'universal invariant "native" violated',
    path: "fuzz_flashLoan -> fuzz_setCallbackDeposits -> fuzz_withdraw",
    profitWei: "5000000000000000000",
    provenOn: "0xaaaa000000000000000000000000000000000001",
  });
  if (!id) fail("captureProvenDrain returned null for a valid capture");
  // Re-prove the identical technique: dedupe bumps wins instead of adding noise.
  captureProvenDrain({
    origin: "generic-invariant",
    technique: "generic-invariant:native",
    shape: "lender-native",
    path: "fuzz_flashLoan -> fuzz_setCallbackDeposits -> fuzz_withdraw",
    profitWei: "3000000000000000000",
    provenOn: "0xaaaa000000000000000000000000000000000002",
  });
  const all = allTechniques();
  if (all.length !== 1) fail(`expected 1 deduped technique, got ${all.length}`);
  if (all[0]!.wins !== 2) fail(`expected wins=2 after re-proof, got ${all[0]!.wins}`);
  if (!all[0]!.transferredTo.includes("0xaaaa000000000000000000000000000000000002")) {
    fail("second proof target not recorded as transfer evidence");
  }
  if (!all[0]!.path.startsWith("flashLoan -> setCallbackDeposits -> withdraw")) {
    fail(`fuzz_ prefix should be stripped, path preserved — got "${all[0]!.path}"`);
  }
  console.log("ok: capture/dedupe/transfer round-trip (wins=2, transfer evidence recorded)");

  // ---- 2. retrieval: proven techniques rank, shape filter works ----
  captureProvenDrain({
    origin: "template",
    technique: "side-entrance-reentrancy",
    shape: "lender-native",
    observation: "flash-loan reentrancy via deposit-in-callback",
    provenOn: "SideEntranceLenderPool",
  });
  const shapeTops = topTechniques("lender-native", 5);
  if (shapeTops.length !== 2) fail(`expected 2 techniques for shape lender-native, got ${shapeTops.length}`);
  // Live recon shapes are prose ("side-entrance-style lender (…)") — token
  // overlap must still retrieve the lender-native techniques.
  const proseTops = topTechniques("side-entrance-style lender (flashLoan(uint256)+deposit+withdraw)", 5);
  if (proseTops.length === 0) fail("prose shape must still retrieve overlapping techniques");
  if (!proseTops.some((t) => t.technique === "side-entrance-reentrancy")) {
    fail("prose shape retrieval missed the reentrancy technique");
  }
  const noShape = topTechniques("erc4626", 5);
  if (noShape.length !== 0) fail(`expected 0 techniques for unrelated shape, got ${noShape.length}`);
  if (techniquesStats().proven !== 3 || techniquesStats().total !== 2) {
    fail(`stats wrong: ${JSON.stringify(techniquesStats())}`);
  }
  console.log("ok: retrieval + shape filtering + stats");

  // ---- 3. hint emission (what triage prompts will see) ----
  const hint = techniquesHint("lender-native", 3);
  if (!hint.includes("TECHNIQUES THE FLEET ITSELF PROVED")) fail("hint missing header");
  if (!hint.includes("proven 2x")) fail("hint missing win count");
  if (!hint.includes("flashLoan -> setCallbackDeposits -> withdraw")) fail("hint missing the proven path");
  if (techniquesHint("erc4626", 3) !== "") fail("hint must be empty when nothing matches (never fabricate priors)");
  console.log("ok: techniquesHint emission (and honest empty on no match)");

  // ---- 4. derived curiosity questions grow from the library ----
  const dqs = derivedQuestions();
  if (dqs.length !== 2) fail(`expected 2 derived questions (one per technique class), got ${dqs.length}`);
  const dq = dqs.find((q) => q.technique === "generic-invariant:native");
  if (!dq) fail("derived question for generic-invariant:native missing");
  if (!dq!.id.startsWith("derived:")) fail(`derived id wrong: ${dq!.id}`);
  if (!dq!.wondering.includes("Could what drained")) fail("derived question phrasing wrong");
  console.log("ok: question catalog grew itself from the library (2 derived questions)");

  // ---- 5. distillation: honest skip without a key, proven fact preserved ----
  const distillSkip = await distillPending(2);
  // Without LAB_LLM_KEY the LLM step cannot run; the capture must survive
  // untouched either way.
  if (allTechniques().length !== 2) fail("distillation pass must never lose captured techniques");
  if (distillSkip > 0) {
    const t = allTechniques().find((x) => x.reuse);
    if (!t) fail("distillation claimed success but no technique carries a reuse note");
    if (!t!.reuse) fail("distilled technique missing reuse note");
    console.log("ok: distillation generalized a proven drain (LLM available)");
  } else {
    console.log("ok: distillation honestly skipped (no LLM key) — proven facts preserved");
  }
});

console.log("PASS: techniques");
