// Runs forge commands and parses results.
import { spawn } from "node:child_process";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AGENT_TEST_DIR, LAB_ROOT, forgeEnv } from "./config.ts";
import { assertLocalRpc } from "./safety.ts";
import { forgeWithSelfRepair } from "./selfrepair.ts";

export interface ForgeResult {
  ok: boolean;
  output: string;
  passed: string[];
  failed: string[];
  profitWei?: bigint;
}

export function run(cmd: string, args: string[], opts: { timeoutMs?: number } = {}): Promise<{ code: number; output: string }> {
  return new Promise((resolvePromise, reject) => {
    // detached:true puts the child in its own process group so the timeout
    // kill can take down the WHOLE tree: killing only `forge` leaves its
    // solc children reparented to launchd, leaking ~150MB each — the source
    // of the "application memory full" orphans (10+/day under RAM pressure).
    const child = spawn(cmd, args, {
      cwd: LAB_ROOT,
      env: forgeEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let output = "";
    child.stdout.on("data", (d: Buffer) => (output += d.toString()));
    child.stderr.on("data", (d: Buffer) => (output += d.toString()));
    const timer = setTimeout(
      () => {
        try {
          // Negative PID = signal the whole process group (works because the
          // child is detached above). Falls back to the direct child if the
          // group is already gone.
          process.kill(-child.pid!, "SIGKILL");
        } catch {
          try { child.kill("SIGKILL"); } catch { /* already dead */ }
        }
        reject(new Error(`${cmd} timed out`));
      },
      opts.timeoutMs ?? 120_000
    );
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? -1, output });
    });
  });
}

export async function forge(args: string[], timeoutMs?: number): Promise<{ code: number; output: string }> {
  return run("forge", args, { timeoutMs });
}

// ---------------------------------------------------------------------------
// CROSS-PROCESS FORGE LOCK — 8 daemons share ONE foundry project.
// forge compiles the whole test/agent tree; two concurrent forge runs observe
// each other's mid-write GenFork files and fail with transient compile errors
// (observed live across every fleet daemon on slice 1). The lock serializes
// compile-heavy forge invocations; staleness detection means a killed daemon
// can never wedge the fleet, and the deadline ensures the lock can only ever
// add latency, never deadlock.
// ---------------------------------------------------------------------------
const FORGE_LOCK = join(LAB_ROOT, "forge.lock");
const FORGE_LOCK_DEADLINE_MS = 120_000;

function lockHolderAlive(): boolean {
  try {
    const pid = parseInt(readFileSync(FORGE_LOCK, "utf8").trim(), 10);
    if (!Number.isFinite(pid) || pid === process.pid) return false;
    try {
      process.kill(pid, 0); // signal 0 = liveness probe
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code !== "ESRCH"; // ESRCH = holder gone
    }
  } catch {
    return false; // unreadable/missing lock = no live holder
  }
}

async function withForgeLock<T>(fn: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + FORGE_LOCK_DEADLINE_MS;
  for (;;) {
    // Atomic acquire: "wx" fails when the file already exists (no TOCTOU).
    try {
      writeFileSync(FORGE_LOCK, String(process.pid), { flag: "wx" });
      break;
    } catch {
      if (!lockHolderAlive()) {
        try { unlinkSync(FORGE_LOCK); } catch { /* another waiter cleaned it */ }
        continue;
      }
    }
    if (Date.now() > deadline) break; // degraded-but-alive: run unlocked
    await new Promise((r) => setTimeout(r, 300 + Math.floor(Math.random() * 400)));
  }
  try {
    return await fn();
  } finally {
    try {
      if (parseInt(readFileSync(FORGE_LOCK, "utf8").trim(), 10) === process.pid) unlinkSync(FORGE_LOCK);
    } catch { /* already released */ }
  }
}

/** forge under the cross-process lock, with ONE clean retry on a compile
 * failure (a sibling's artifact may have been mid-write when solc read it). */
async function forgeLocked(args: string[], timeoutMs: number): Promise<{ code: number; output: string }> {
  return withForgeLock(async () => {
    let res = await forge(args, timeoutMs);
    if (res.code !== 0 && /Compiler run failed/i.test(res.output)) {
      await new Promise((r) => setTimeout(r, 1_500));
      res = await forge(args, timeoutMs);
    }
    return res;
  });
}

/** Run a single test contract against a LOCAL fork (address-mode invariant
 * harnesses bind to live addresses that exist only on the anvil fork).
 * The fork RPC must be 127.0.0.1 — same allowlist as every agent RPC.
 *
 * opts.fuzzRuns / opts.fuzzSeed turn the run into a BOUNDED CAMPAIGN SLICE:
 * the default invariant config is 64 runs, once per target, ever — which is
 * why the fleet found nothing. A campaign persists per-target state and
 * calls this with increasing fuzzRuns (1024 → 4096 → …) and a DETERMINISTIC
 * seed so each slice explores DIFFERENT sequences while remaining reproducible.
 */
export async function runTestContractOnFork(
  contractName: string,
  forkRpc: string,
  opts: { fuzzRuns?: number; fuzzSeed?: string; timeoutMs?: number } = {}
): Promise<ForgeResult> {
  assertLocalRpc(forkRpc, "forked test run");
  const args = ["test", "--match-contract", contractName, "--fork-url", forkRpc];
  if (opts.fuzzRuns && opts.fuzzRuns > 0) args.push("--fuzz-runs", String(opts.fuzzRuns));
  if (opts.fuzzSeed) args.push("--fuzz-seed", opts.fuzzSeed);
  const timeout = opts.timeoutMs ?? (opts.fuzzRuns && opts.fuzzRuns > 512 ? 600_000 : 300_000);
  // Self-repair wrapper: forge compiles the whole test tree, so a malformed
  // agent-generated file anywhere in test/agent/ poisons EVERY harness. On a
  // compile failure naming an agent-generated file, quarantine it and retry
  // once instead of failing every target every cycle (412/444 historical).
  // forgeLocked serializes the compile against sibling daemons and retries
  // transient mid-write races before selfrepair misreads them as real bugs.
  const { code, output } = await forgeWithSelfRepair(() => forgeLocked(args, timeout), `test-on-fork:${contractName}`);
  const passed = [...output.matchAll(/\[PASS\]\s+(\S+)\(/g)].map((m) => m[1]);
  const failed = [...output.matchAll(/\[FAIL[^\]]*\]\s+(\S+)\(/g)].map((m) => m[1]).filter((n) => n !== "setUp");
  const profitMatch = output.match(/\[PROFIT_WEI\]\s+(\d+)/);
  return {
    ok: code === 0,
    output,
    passed,
    failed,
    profitWei: profitMatch ? BigInt(profitMatch[1]) : undefined,
  };
}

/** Run a single test contract and parse PASS/FAIL lines + [PROFIT_WEI] logs. */
export async function runTestContract(contractName: string): Promise<ForgeResult> {
  const { code, output } = await forgeWithSelfRepair(
    () => forgeLocked(["test", "--match-contract", contractName], 300_000),
    `test:${contractName}`
  );
  const passed = [...output.matchAll(/\[PASS\]\s+(\S+)\(/g)].map((m) => m[1]);
  const failed = [...output.matchAll(/\[FAIL[^\]]*\]\s+(\S+)\(/g)].map((m) => m[1]).filter((n) => n !== "setUp");
  const setUpFailed = /FAIL.*setUp\(\)/.test(output);
  const profitMatch = output.match(/\[PROFIT_WEI\]\s+(\d+)/);
  return {
    ok: code === 0,
    output,
    passed,
    failed,
    profitWei: profitMatch ? BigInt(profitMatch[1]) : undefined,
    ...(setUpFailed ? {} : {}),
  };
}

/**
 * Run a TEMPLATE-GENERATED harness for a specific challenge and verify it
 * actually exercised that challenge. A harness whose test passes WITHOUT
 * referencing its assigned challenge (self-contained: constructs its own
 * vulnerable contract elsewhere and proves someone else's bug) is counted as
 * a failure — this is what prevents a fallback technique from winning credit
 * on a challenge it never touched (misattribution guard).
 */
export async function runTestContractFor(contractName: string, assignedChallenge: string): Promise<ForgeResult> {
  const res = await runTestContract(contractName);
  if (!res.ok) return res;
  // Must match where generator.ts writes (AGENT_TEST_DIR, overridable for tests)
  // -- hardcoding test/agent here silently reported 'harness-missing'.
  const harnessPath = `${AGENT_TEST_DIR}/${contractName}.t.sol`;
  let src = "";
  try {
    src = readFileSync(harnessPath, "utf8");
  } catch {
    return { ...res, ok: false, failed: [...res.failed, "harness-missing"] };
  }
  const nameRe = new RegExp(`^[A-Za-z0-9_]+$`);
  if (!nameRe.test(assignedChallenge)) {
    return { ...res, ok: false, failed: [...res.failed, "harness-did-not-touch-assigned-challenge"] };
  }
  // A "reference" must be semantic — an import, instantiation, type usage or
  // external call — NOT the challenge name that leaks into the contract
  // identifier or the header comment of every generated harness.
  // A "reference" must be semantic — an import, instantiation, type usage or
  // external call — NOT the challenge name that leaks into the contract
  // identifier or the header comment of every generated harness.
  const wordRe = new RegExp(`\\b${assignedChallenge}\\b`);
  const lines = src.split("\n");
  const semantic = lines.some((line) => {
    const t = line.trim();
    if (t.startsWith("//") || t.startsWith("*")) return false; // comments don't count
    if (!wordRe.test(t)) return false;
    return (
      t.includes("import ") ||
      t.includes(`new ${assignedChallenge}`) ||
      t.includes(`${assignedChallenge}.`) ||
      t.includes(`is ${assignedChallenge}`) ||
      t.includes(`${assignedChallenge}(`) ||
      // Address-bound targets (e.g. spot-oracle probes): the challenge "name"
      // is the pool address assigned to a constant in the harness code.
      t.includes(`= ${assignedChallenge}`) ||
      t.includes(`${assignedChallenge};`)
    );
  });
  if (!semantic) {
    return {
      ...res,
      ok: false,
      failed: [...res.failed, "harness-did-not-touch-assigned-challenge"],
    };
  }
  return res;
}
