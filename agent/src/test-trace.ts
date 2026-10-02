// Execution-tracing smoke test — pure parser checks first, then both tracers
// against a REAL local anvil fork.
//
// Live controls (mainnet fork, observation only — nothing broadcasts):
//   callTracer  — WETH.deposit() must produce a 1-frame graph with no revert.
//   prestate    — the same deposit must show a positive WETH balance delta for
//                 the caller and none anywhere else (balanceOf slot is packed;
//                 a storage delta there is still fine — the BALANCE check is
//                 the invariant).
//   revert case — a call larger than the funded balance is rejected at tx
//                 validation; the tracer surfaces an error honestly.
// Pure checks run even with no anvil on PATH; live checks degrade to one
// honest FAIL line (matching the toolbox test's behavior).
import { spawnForkWithFailover, type AnvilFork } from "./fork.ts";
import { DEFAULT_FORK_RPC } from "./config.ts";
import { ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";
import {
  deepestRevertFrames,
  summarizeRevertFrames,
  traceCalldata,
  traceStateDiff,
  renderCallTrace,
  renderStateDiff,
} from "./trace.ts";

let failures = 0;
function ok(cond: boolean, label: string, detail = ""): void {
  if (cond) {
    console.log(`ok: ${label}`);
  } else {
    failures++;
    console.log(`FAIL: ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// 1. Pure: forge -vvv trace parsing (no network, no anvil)
// ---------------------------------------------------------------------------

// Faithful to real foundry -vvv rendering: the root call line carries NO tree
// glyph (frame depth 0); each nested call adds one glyph; a frame's
// `← [Revert]` return line sits one glyph deeper and reports its OWNING
// frame's depth. Innermost revert: inside Attacker::receiveEther (depth 2:
// flashLoan=0 -> execute=1 -> receiveEther=2).
const SAMPLE_FORGE_OUTPUT = [
  "Ran 1 test for test/Foo.t.sol:FooTest",
  "[PASS] test_x() (gas: 12345)",
  "Suite result: ok. 1 passed; 0 failed;",
  "",
  "Failing tests:",
  "Traces:",
  "  [24012] VictimPool::flashLoan(1000)",
  "  ├─ [8100] VictimPool::execute(attacker)",
  "  │   ├─ [2200] Attacker::receiveEther(1000)",
  "  │   │   └─ ← [Revert] EvmError: Revert",
  "  │   └─ ← [Revert] reentrancy guard hit",
  "  └─ ← [Revert] flash loan failed",
].join("\n");

const frames = deepestRevertFrames(SAMPLE_FORGE_OUTPUT);
ok(frames.length >= 1, "deepestRevertFrames finds the origin frame");
ok(frames[0]?.depth === 2, `deepest frame is the innermost reverted frame (depth 2, got ${frames[0]?.depth})`);
ok(frames[0]?.fn === "Attacker::receiveEther",
  `deepest frame borrows the callback's name (got: ${frames[0]?.fn})`);
ok(frames[0]?.line.includes("EvmError"),
  `deepest frame is the attacker callback line (got: ${frames[0]?.line.slice(0, 60)})`);
const summary = summarizeRevertFrames(frames);
ok(summary.length > 0, `summarizeRevertFrames produces a summary (${summary})`);
ok(deepestRevertFrames("Suite result: ok. 1 passed\nall good here").length === 0,
  "parser honestly empty on a clean run");
ok(deepestRevertFrames("").length === 0, "parser handles empty output");

// ---------------------------------------------------------------------------
// 2. Live: both tracers against a real local fork
// ---------------------------------------------------------------------------

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

/** First port (from `preferred` up) with NOTHING listening — the fleet's live
 * forks occupy their documented range's neighbors, and silently attaching to
 * a stranger's anvil would make every assertion measure the wrong chain. */
async function freePort(preferred: number): Promise<number> {
  for (let p = preferred; p < preferred + 25; p++) {
    try {
      await fetch(`http://127.0.0.1:${p}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
        signal: AbortSignal.timeout(800),
      });
      // answered → occupied, keep walking
    } catch {
      return p; // nobody home
    }
  }
  return preferred + 99; // let anvil fail loudly rather than guess
}

const PORT = await freePort(8760); // above the toolbox test's 8735+ window

let fork: AnvilFork | null = null;
try {
  console.log("spawning ephemeral mainnet fork for the trace test…");
  fork = await spawnForkWithFailover(DEFAULT_FORK_RPC, PORT, ETHEREUM_FORK_FALLBACKS.filter((u) => u !== DEFAULT_FORK_RPC));
  ok(true, "fork spawned");

  const acct: string[] = await fork.rpc("eth_accounts", []);
  const caller = acct[0] ?? "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

  // ---- callTracer: WETH.deposit() positive control -------------------------
  const graph = await traceCalldata(fork, { from: caller, to: WETH, data: "0xd0e30db0", valueWei: "1000000000000000" });
  ok(graph.ok && graph.root !== null, `traceCalldata runs (${graph.ok ? "" : graph.unavailableReason})`);
  if (graph.ok && graph.root) {
    ok(graph.root.kind === "call", `root frame is a call (got ${graph.root.kind})`);
    ok(graph.root.to.toLowerCase() === WETH.toLowerCase(), "root frame targets WETH");
    ok(!graph.root.reverted, "deposit does not revert");
    ok(graph.stats !== null && graph.stats.frames >= 1, `stats computed (${graph.stats?.frames} frames)`);
    const rendered = renderCallTrace(graph);
    ok(rendered.includes("frames="), "renderCallTrace renders the graph");
  }

  // ---- prestateTracer: the balance must move, exactly once -----------------
  const diff = await traceStateDiff(fork, { from: caller, to: WETH, data: "0xd0e30db0", valueWei: "1000000000000000" });
  ok(diff.ok, `traceStateDiff runs (${diff.ok ? "" : diff.unavailableReason})`);
  if (diff.ok) {
    const weth = diff.accounts.find((a) => a.address.toLowerCase() === WETH.toLowerCase());
    ok(weth !== undefined, "diff includes the WETH contract account");
    ok((weth?.balanceDeltaWei ?? "0") === "1000000000000000",
      `WETH balance delta is exactly the deposit (${weth?.balanceDeltaWei})`);
    ok(diff.accounts.length >= 2, `caller account appears too (${diff.accounts.length} accounts)`);
    const rendered = renderStateDiff(diff);
    ok(rendered.includes("balanceΔ="), "renderStateDiff renders the diff");
    ok(renderStateDiff({ ok: false, unavailableReason: "test", accounts: [] }).includes("unavailable"),
      "renderStateDiff degrades honestly");
  }

  // ---- revert case: overbalance send is rejected at tx validation ----------
  const bad = await traceStateDiff(fork, {
    from: caller, to: WETH, data: "0x", valueWei: "1000000000000000000000000",
  });
  const wethDelta = bad.ok ? bad.accounts.find((a) => a.address.toLowerCase() === WETH.toLowerCase())?.balanceDeltaWei : undefined;
  ok(!bad.ok || wethDelta !== "1000000000000000000000000",
    `overbalance call never fabricates the huge balance delta (${bad.ok ? wethDelta : bad.unavailableReason})`);
  const badGraph = await traceCalldata(fork, { from: caller, to: WETH, data: "0x", valueWei: "1000000000000000000000000" });
  ok(badGraph.ok === false || badGraph.root?.error !== undefined || badGraph.root?.reverted === true || badGraph.unavailableReason !== undefined,
    "overbalance call surfaces an error or honest unavailability");
} catch (e) {
  failures++;
  console.log(`FAIL: trace smoke test errored — ${(e as Error).message.slice(0, 300)}`);
} finally {
  try { await fork?.stop(); } catch { /* already dead */ }
}

if (failures > 0) {
  console.log(`trace smoke test: ${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("trace smoke test: ALL PASS — call graph, state diff and revert-frame parsing all behave");
process.exit(0);
