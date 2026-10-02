// Shared challenge-solving job: the single implementation used by BOTH the
// one-shot lab run and the daemon's lab watch, so parallel workers execute
// the same logic everywhere. One job = one challenge = template attempts
// (knowledge-base first) then the fuzz-synthesis fallback.
import { rankStrategies, buildParamVariants, STRATEGIES } from "./strategies.ts";
import { generateTest, TemplateUnsatisfiableError } from "./generator.ts";
import { runTestContract, runTestContractFor } from "./runner.ts";
import { featureSignature, priorWin, recordWin } from "./knowledge.ts";
import { synthesizeHarness, evaluateSynthOutput, archiveHarness } from "./synth.ts";
import { buildHarness, evaluateGenHarness, archiveGenHarness } from "./genharness.ts";
import { recordViolation, recordHeld, recordGenError, recordDeadend } from "./genlearn.ts";
import { captureProvenDrain } from "./techniques.ts";
import { learnFromProbe } from "./memory.ts";
import type { Challenge, ChallengeFeatures } from "./discovery.ts";
import type { Strategy } from "./strategies.ts";
import { upsertChallenge, logEvent, recordGenResult } from "./bus.ts";
import { readFileSync } from "node:fs";

interface PlanStep {
  strategy: Strategy;
  params: Record<string, string>;
  note: string;
}

/** Challenge source text for the generic engine (reads the discovered files). */
function readSources(challenge: Challenge): string[] {
  try {
    return challenge.sources.map((p) => readFileSync(p, "utf8"));
  } catch {
    return [];
  }
}

export function planForChallenge(
  features: ChallengeFeatures,
  maxAttempts: number,
  challengeName?: string
): PlanStep[] {
  const sig = featureSignature(features, challengeName);
  const ranked = rankStrategies(features);
  const plan: PlanStep[] = [];

  const prior = priorWin(sig);
  if (prior) {
    const s = STRATEGIES.find((x) => x.id === prior.technique);
    if (s && ranked.some((r) => r.id === s.id)) {
      plan.push({ strategy: s, params: prior.params, note: "known win from knowledge base" });
    }
  }
  for (const s of ranked) {
    for (const params of buildParamVariants(s)) {
      if (!plan.some((p) => p.strategy.id === s.id && JSON.stringify(p.params) === JSON.stringify(params))) {
        plan.push({ strategy: s, params, note: "search" });
      }
    }
  }
  return plan.slice(0, maxAttempts);
}

export interface SolveOutcome {
  challenge: string;
  solved: boolean;
  technique?: string;
  attempts: number;
  note?: string;
  /** Set when the GENERIC invariant engine (genharness) made the discovery. */
  genInvariant?: string;
}

/** Solve one challenge: template strategies first, then fuzz synthesis. */
export async function solveChallenge(
  challenge: Challenge,
  maxAttempts: number,
  log: (s: string) => void
): Promise<SolveOutcome> {
  upsertChallenge({ name: challenge.name, status: "pending", note: "attacking" });
  const plan = planForChallenge(challenge.features, maxAttempts, challenge.name);
  if (plan.length === 0) {
    upsertChallenge({ name: challenge.name, status: "no-strategy" });
    log(`${challenge.name}: no matching technique yet`);
    return { challenge: challenge.name, solved: false, attempts: 0, note: "no-strategy" };
  }

  // Strategies whose template cannot be rendered for this target (e.g. one that
  // casts a deployed pool ADDRESS while the challenge is only a contract NAME).
  // Skipped, never written: forge compiles the whole test tree at once, so an
  // uncompilable harness would blank out every other harness in the run.
  const skipped: string[] = [];

  for (let i = 0; i < plan.length; i++) {
    const step = plan[i]!;
    let gen: ReturnType<typeof generateTest>;
    try {
      gen = generateTest(challenge, step.strategy, step.params, i);
    } catch (err) {
      if (!(err instanceof TemplateUnsatisfiableError)) throw err;
      skipped.push(step.strategy.id);
      upsertChallenge({ name: challenge.name, status: "pending", note: `${step.strategy.id}: not applicable` });
      log(`${challenge.name}: ${step.strategy.id} not applicable — ${err.message}`);
      logEvent("lab", `${challenge.name}: ${step.strategy.id} skipped (${err.message})`);
      continue;
    }
    // Template harnesses are bound to their assigned challenge: a pass that
    // never references the challenge is a self-contained false win and is
    // rejected (misattribution guard).
    const res = await runTestContractFor(gen.contractName, challenge.name);
    if (res.ok && res.passed.includes("test_agentSolve")) {
      recordWin(featureSignature(challenge.features, challenge.name), step.strategy.id, step.params);
      // SELF-LEARNED TECHNIQUE: every template win joins the transferable
      // library — a technique proven in the lab is a hypothesis for live
      // targets of the same shape forever after.
      try {
        captureProvenDrain({
          origin: "template",
          technique: step.strategy.id,
          shape: challenge.name,
          observation: step.strategy.technique,
          provenOn: challenge.name,
        });
      } catch { /* technique capture is best-effort */ }
      upsertChallenge({
        name: challenge.name,
        status: "solved",
        technique: step.strategy.technique,
        attempts: i + 1,
        note: step.note,
      });
      const kb = step.note === "known win from knowledge base" ? " (kb hit)" : "";
      logEvent("lab", `${challenge.name} DRAINED via ${step.strategy.id}${kb}`);
      log(`${challenge.name}: DRAINED via ${step.strategy.id}${kb}`);
      return { challenge: challenge.name, solved: true, technique: step.strategy.id, attempts: i + 1, note: step.note };
    }
    // Archive failed attempts IMMEDIATELY: forge compiles the whole test/agent
    // dir on every run, so a harness that fails to compile poisons every
    // later attempt for every challenge (whole-fleet compile lockout).
    archiveGenHarness(gen.filePath, gen.contractName);
    log(`${challenge.name}: attempt ${i + 1} (${step.strategy.id}) did not drain — harness archived`);
  }

  // SYNTH PHASE: fuzz-driven discovery when all template attempts fail.
  const synth = synthesizeHarness(challenge.name, 0);
  if (synth) {
    const sres = await runTestContract(synth.contractName);
    const ev = evaluateSynthOutput(sres.output);
    if (ev.discovered) {
      upsertChallenge({
        name: challenge.name,
        status: "solved",
        technique: `fuzz-synthesis: ${ev.path || synth.recipe.expectedFinding}`,
        attempts: plan.length + 1,
        note: "discovered by fuzzer",
      });
      logEvent(
        "lab",
        `${challenge.name}: fuzz synthesis DISCOVERED a drain -- ${synth.recipe.expectedFinding}${ev.path ? ` via ${ev.path}` : ""}`
      );
      log(`${challenge.name}: DISCOVERED by fuzz synthesis (${ev.path || synth.recipe.expectedFinding})`);
      // The fuzzer found the breaking sequence from primitives alone — capture
      // the reconstructed path as a self-learned technique.
      try {
        captureProvenDrain({
          origin: "synthesis",
          technique: `fuzz-synthesis:${synth.recipe.challengeMatch.toLowerCase()}`,
          shape: challenge.name,
          observation: synth.recipe.expectedFinding,
          path: ev.path,
          provenOn: challenge.name,
        });
      } catch { /* technique capture is best-effort */ }
      // Archive the discovered harness: the finding lives in state/KB now, and
      // leaving a permanently-failing test in test/agent/ would poison every
      // future forge run (same failure mode as stale broken harnesses).
      archiveHarness(synth.filePath, synth.contractName);
      return { challenge: challenge.name, solved: true, technique: `fuzz-synthesis`, attempts: plan.length + 1, note: "discovered by fuzzer" };
    }
    if (ev.compileError) {
      log(`${challenge.name}: synth harness failed to compile (agent bug -- not a result)`);
      if (ev.compileErrorDetail) log(`${challenge.name}:   compiler said: ${ev.compileErrorDetail.split("\n")[0]}`);
    } else {
      log(`${challenge.name}: synth invariant held -- needs manual analysis`);
    }
    archiveHarness(synth.filePath, synth.contractName);
  }

  // GENERIC PHASE (universal invariant catalog): no template and no recipe
  // matched — synthesize a fuzzer harness from the challenge's own ABI and
  // universal properties. This is how the agent finds bugs on shapes it has
  // never seen, without any hand-written exploit.
  try {
    const gen = buildHarness({ challengeName: challenge.name, sources: readSources(challenge), sourcePaths: challenge.sources, mode: "source" }, 0);
    if (gen) {
      log(`${challenge.name}: generic engine — ${gen.shape} harness, ${gen.skippedFns.length} skipped entrypoint(s)`);
      const gres = await runTestContract(gen.contractName);
      const ev = evaluateGenHarness(gres.output);
      recordGenResult(challenge.name, {
        shape: gen.shape,
        result: ev.discovered ? "discovered" : ev.compileError || ev.setupFailed ? "error" : "held",
        invariant: ev.discovered ? ev.invariant : undefined,
      });
      // LEARNING LOOP: the generic engine remembers its outcomes per shape —
      // proven violating paths seed future primitive order; errors/dead ends
      // are recorded once so later cycles skip re-deriving them.
      try {
        if (ev.discovered) {
          recordViolation(gen.shape, { invariant: ev.invariant, path: ev.path, profitWei: ev.profitWei });
          captureProvenDrain({
            origin: "generic-invariant",
            technique: `generic-invariant:${ev.invariant}`,
            shape: gen.shape,
            observation: `universal invariant "${ev.invariant}" violated`,
            path: ev.path,
            profitWei: ev.profitWei,
            provenOn: challenge.name,
          });
          learnFromProbe(challenge.name, gen.shape, `generic-invariant:${ev.invariant}`, "drained", ev.path ? `violating path: ${ev.path}` : undefined);
        } else if (ev.compileError) {
          recordGenError(gen.shape, `generic harness failed to compile: ${ev.compileErrorDetail?.split("\n")[0] ?? "unknown"}`);
        } else if (ev.setupFailed) {
          recordGenError(gen.shape, "setUp failed (shape heuristics did not fit)");
          recordDeadend(gen.shape, "setUp failed: shape heuristics did not fit the target's constructor/state surface");
        } else {
          recordHeld(gen.shape);
        }
      } catch {
        // learning must never turn a solved run into an error
      }
      if (ev.discovered) {
        upsertChallenge({
          name: challenge.name,
          status: "solved",
          technique: `generic-invariant: ${ev.invariant}`,
          attempts: plan.length + 1,
          note: "discovered by generic invariant engine",
        });
        logEvent(
          "lab",
          `${challenge.name}: GENERIC DISCOVERY — invariant ${ev.invariant} violated${ev.path ? ` via ${ev.path}` : ""}`
        );
        log(`${challenge.name}: DISCOVERED by generic invariant engine (${ev.invariant}; ${ev.path})`);
        archiveGenHarness(gen.filePath, gen.contractName);
        return {
          challenge: challenge.name,
          solved: true,
          technique: `generic-invariant: ${ev.invariant}`,
          attempts: plan.length + 1,
          note: "discovered by generic invariant engine",
          genInvariant: ev.invariant,
        };
      }
      if (ev.compileError) {
        log(`${challenge.name}: generic harness failed to compile (agent bug -- not a result)`);
        if (ev.compileErrorDetail) log(`${challenge.name}:   compiler said: ${ev.compileErrorDetail.split("\n")[0]}`);
      } else if (ev.setupFailed) {
        log(`${challenge.name}: generic harness setUp failed (shape heuristics did not fit)`);
        if (ev.setupFailedDetail) log(`${challenge.name}:   setUp said: ${ev.setupFailedDetail}`);
      } else {
        log(`${challenge.name}: generic invariants held (${plan.length} template attempts + universal catalog clean)`);
      }
      archiveGenHarness(gen.filePath, gen.contractName);
    } else {
      recordGenResult(challenge.name, { shape: "none", result: "skipped", note: "no harnessable shape" });
    }
  } catch {
    // The generic engine must never turn a template loss into an error.
  }

  const attempted = plan.length - skipped.length;
  upsertChallenge({
    name: challenge.name,
    status: "failed",
    attempts: attempted,
    note: skipped.length > 0 ? `${skipped.length} strategy(ies) not applicable` : undefined,
  });
  log(
    `${challenge.name}: not solved (${attempted} attempts${skipped.length > 0 ? `, ${skipped.length} not applicable: ${skipped.join(", ")}` : ""})`
  );
  return { challenge: challenge.name, solved: false, attempts: attempted };
}
