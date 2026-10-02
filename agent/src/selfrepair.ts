// Self-repair for forge compile failures in the agent-generated test tree.
//
// The problem this closes: forge compiles the WHOLE test tree in one pass, so
// one malformed agent-generated file (test/agent/, reports/gen/ templates)
// makes every probe and every harness on every target fail with the identical
// "Compiler run failed" — 412 of 444 generic-engine attempts died this way,
// the same few parse errors repeating cycle after cycle with nobody deleting
// the offender. (The daemon fleet re-generates the same broken file each
// cycle: repairing the generator input is future work; stopping the poisoning
// is what unblocks the pipeline today.)
//
// Strategy, same rails as the rest of the agent (best-effort, never crash):
//   1. Parse solc output for `--> path:line:col` error locations.
//   2. Quarantine ONLY agent-generated offenders (paths under the agent test
//      dir or the reports/gen archive) by moving them aside. A file whose
//      syntax the generator produced is regenerated fresh next cycle; a
//      repo-owned file is never touched.
//   3. Record the failure class in genlearn so priors and triage hints say
//      "compile failure quarantined N times" instead of silently repeating.
//   4. Callers retry the forge invocation once; if it passes, the pipeline
//      is unstuck and the quarantine succeeded.
import { existsSync, mkdirSync, renameSync, appendFileSync, readFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { AGENT_TEST_DIR, REPORT_DIR, LAB_ROOT } from "./config.ts";
import { recordCompileClass } from "./genlearn.ts";

/** Quarantine dir: outside every compile tree (reports/, like other stores). */
const QUARANTINE_DIR = join(REPORT_DIR, "quarantine");
const LEDGER_PATH = join(REPORT_DIR, "selfrepair.log");

/** Failure classes already recorded this process (dedup log spam). */
const seenClasses = new Set<string>();

/** True when `path` is a file the agent generated itself (safe to move).
 * Repo-owned sources (src/, test/, lib/, script/) are NEVER quarantined. */
export function isAgentGenerated(path: string): boolean {
  const abs = resolve(path.startsWith("/") ? path : join(LAB_ROOT, path));
  const agentDir = resolve(AGENT_TEST_DIR);
  const genDir = resolve(join(REPORT_DIR, "gen"));
  return abs.startsWith(agentDir + sep) || abs.startsWith(genDir + sep);
}

/** Extract the FIRST error location from forge/solc output: `--> path:line:col`.
 * Returns null when the output carries no location (e.g. process-level fail). */
export function firstErrorLocation(output: string): { path: string; line: number; col: number } | null {
  const m = output.match(/--> ([^\s:]+):(\d+):(\d+)/);
  if (!m) return null;
  return { path: m[1]!, line: parseInt(m[2]!, 10), col: parseInt(m[3]!, 10) };
}

/** Short failure class from compile output, for genlearn priors + log dedup.
 * e.g. "solc2314(Expected ')' but got '>')" — stable across occurrences. */
export function compileFailureClass(output: string): string {
  const m = output.match(/Error \((\d+)\): ([^\n]+)/);
  if (m) return `solc${m[1]}(${m[2]!.slice(0, 60)})`;
  if (/Compiler run failed/.test(output)) return "solc-unknown-parse";
  return "forge-run-failed";
}

function recordRepair(kind: string, detail: string, failureClass = ""): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    appendFileSync(LEDGER_PATH, `[${new Date().toISOString()}] ${kind}: ${detail}\n`);
    if (failureClass && (kind === "quarantine" || kind === "still-broken" || kind === "unrepairable")) {
      recordCompileClass(failureClass, `${kind}: ${detail}`);
    }
  } catch {
    // logging must never break the repair
  }
}

/** Quarantine one agent-generated file: move it to reports/quarantine/ with a
 * timestamped name (evidence preserved, out of the compile tree). Returns
 * true when the file was actually moved. */
export function quarantineFile(path: string, reason: string): boolean {
  try {
    if (!isAgentGenerated(path)) return false; // repo-owned: hands off
    if (!existsSync(path)) return false;
    mkdirSync(QUARANTINE_DIR, { recursive: true });
    const base = path.split("/").pop() ?? "unknown.sol";
    const dest = join(QUARANTINE_DIR, `${Date.now()}-${base}`);
    renameSync(path, dest);
    recordRepair("quarantine", `${reason} :: ${path} -> ${dest}`, reason);
    return true;
  } catch {
    return false;
  }
}

export interface RepairOutcome {
  repaired: boolean; // something was quarantined
  failureClass: string;
  detail: string;
}

/** One-shot compile repair from raw forge output. Returns repaired=false when
 * the output names no agent-generated offender (nothing safe to do). */
export function repairFromCompileOutput(output: string): RepairOutcome {
  const failureClass = compileFailureClass(output);
  const loc = firstErrorLocation(output);
  if (!loc) {
    return { repaired: false, failureClass, detail: "no error location in compiler output" };
  }
  if (!isAgentGenerated(loc.path)) {
    const detail = `error in repo-owned file ${loc.path} — not quarantinable, needs a human/generator fix`;
    if (!seenClasses.has(failureClass)) {
      seenClasses.add(failureClass);
      recordRepair("unrepairable", detail, failureClass);
    }
    return { repaired: false, failureClass, detail };
  }
  const moved = quarantineFile(loc.path, failureClass);
  if (!moved) {
    return { repaired: false, failureClass, detail: `quarantine failed for ${loc.path}` };
  }
  return { repaired: true, failureClass, detail: `quarantined ${loc.path} (${failureClass})` };
}

/** Attempt a forge run with ONE self-repair retry: on a compile failure that
 * names an agent-generated offender, quarantine it and re-run. This is the
 * wrapper every agent-generated compile path should use. */
export async function forgeWithSelfRepair(
  run: () => Promise<{ code: number; output: string }>,
  label: string
): Promise<{ code: number; output: string; repaired: boolean }> {
  const first = await run();
  if (first.code === 0 || !/Compiler run failed|Error \(\d+\)/.test(first.output)) {
    return { ...first, repaired: false };
  }
  const outcome = repairFromCompileOutput(first.output);
  if (!outcome.repaired) {
    recordRepair("still-broken", `${label} :: ${outcome.failureClass} :: ${outcome.detail}`, outcome.failureClass);
    return { ...first, repaired: false };
  }
  const second = await run();
  if (second.code !== 0) {
    // Second failure: try once more to quarantine (multi-file poisoning).
    const again = repairFromCompileOutput(second.output);
    if (again.repaired) {
      const third = await run();
      return { ...third, repaired: true };
    }
  }
  return { ...second, repaired: true };
}

/** Read the repair ledger tail (dashboard/digest hook). */
export function repairLedger(lines = 20): string[] {
  try {
    if (!existsSync(LEDGER_PATH)) return [];
    return readFileSync(LEDGER_PATH, "utf8").trimEnd().split("\n").slice(-lines);
  } catch {
    return [];
  }
}
