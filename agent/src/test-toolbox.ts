// Toolbox smoke test — every tool against a REAL local anvil fork.
// Spawns one ephemeral mainnet fork (127.0.0.1, throwaway), then exercises
// storageSpy / privilegeMap / whaleFinder / timeWarp / impersonateCall and
// asserts the outputs are structurally honest. Everything runs against the
// local fork only; the impersonation calls are positive/negative controls
// (deposit succeeds, garbage selector reverts) — nothing is broadcast.
import { spawnForkWithFailover, type AnvilFork } from "./fork.ts";
import { DEFAULT_FORK_RPC } from "./config.ts";
import { ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";
import {
  storageSpy,
  privilegeMap,
  roleEnum,
  whaleFinder,
  timeWarp,
  impersonateCall,
  traceCall,
  renderToolboxReport,
} from "./toolbox.ts";

let failures = 0;
function ok(cond: boolean, label: string, detail = ""): void {
  if (cond) {
    console.log(`ok: ${label}`);
  } else {
    failures++;
    console.log(`FAIL: ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

/** First port (from `preferred` up) with NOTHING listening. A live fleet
 * daemon grows beyond its documented port ranges — attaching to a stranger's
 * anvil would make every assertion measure the WRONG chain (verified live:
 * a rotation fork on 8720 answered eth_blockNumber and silently served a
 * non-ethereum chain). */
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

const PORT = await freePort(8735);

let fork: AnvilFork | null = null;
try {
  console.log("spawning ephemeral mainnet fork for the toolbox test…");
  fork = await spawnForkWithFailover(DEFAULT_FORK_RPC, PORT, ETHEREUM_FORK_FALLBACKS.filter((u) => u !== DEFAULT_FORK_RPC));
  ok(true, "fork spawned");

  // ---- storageSpy ---------------------------------------------------------
  const slots = await storageSpy(fork, WETH, 8);
  ok(slots.length >= 1, `storageSpy finds nonzero slots (${slots.length})`);
  ok(slots.some((s) => s.asInt !== undefined || s.asAddress !== undefined || s.raw.length > 2),
    "storageSpy returns decoded/raw words");

  // ---- privilegeMap -------------------------------------------------------
  const privs = await privilegeMap(fork, WETH);
  ok(Array.isArray(privs), `privilegeMap runs (WETH has no owner: ${privs.length} entries, empty is correct)`);

  // ---- roleEnum (absent extension → []) ----------------------------------
  const roles = await roleEnum(fork, WETH);
  ok(Array.isArray(roles) && roles.length === 0, "roleEnum honestly empty on non-AccessControl target");

  // ---- whaleFinder (small window to keep the test fast) -------------------
  const whales = await whaleFinder(fork, WETH, 300, 5);
  ok(whales.length >= 1, `whaleFinder ranks recent movers (${whales.length})`);
  ok(whales.every((w) => /^0x[0-9a-fA-F]{40}$/.test(w.address) && BigInt(w.approxBalance) > 0n),
    "whaleFinder addresses are valid, balances positive");

  // ---- timeWarp ------------------------------------------------------------
  const before = Number(await fork.rpc("eth_getBlockByNumber", ["latest", false]).then((b: any) => b?.timestamp ?? 0));
  const after = await timeWarp(fork, 3_600);
  ok(after >= before + 3_000, `timeWarp advances the clock (+${after - before}s)`);

  // ---- impersonateCall: positive control (anyone can deposit) --------------
  const deposit = await impersonateCall(fork, whales[0]?.address ?? WETH, WETH, "0xd0e30db0", { valueWei: "0x38D7EA4C68000" });
  ok(deposit.succeeded === true, `impersonate positive control: deposit succeeds (${deposit.note})`);

  // ---- impersonateCall: negative control (deterministic rejection) --------
  // WETH9's assembly dispatch zero-pads out-of-range calldata, so even
  // arg-less real selectors execute as zero-transfers and SUCCEED (verified
  // live — a genuinely great audit finding about hand-written assembly).
  // The deterministic negative control is economic: a value transfer larger
  // than the funded balance is rejected by anvil at tx-validation time.
  const garbage = await impersonateCall(fork, whales[0]?.address ?? WETH, whales[0]?.address ?? WETH, "0x", { valueWei: "0xC097CE7BC90715B34B9F1000000000" }); // 10^30 wei >> 1 ETH funded
  ok(garbage.succeeded === false, `impersonate negative control: overbalance tx rejected (${garbage.note}${garbage.revertReason ? " — " + garbage.revertReason.slice(0, 60) : ""})`);

  // ---- traceCall: the mechanism tool (call graph + state diff) -------------
  const acct: string[] = await fork.rpc("eth_accounts", []);
  const tr = await traceCall(fork, WETH, "0xd0e30db0", { from: acct[0], valueWei: "1000000000000000" });
  ok(tr.traceAvailable, `traceCall runs (${tr.traceAvailable ? "" : tr.unavailableReason})`);
  ok(tr.callGraph.includes("frames="), "traceCall renders the call graph");
  ok(tr.stateDiff.includes(WETH.toLowerCase()) && tr.stateDiff.includes("balanceΔ=1000000000000000"),
    "traceCall renders the exact balance delta");

  // ---- report renderer ------------------------------------------------------
  const report = renderToolboxReport(`ethereum:${WETH}`, {
    slots, privileges: privs, roles, whales, warp: `+1h → block ts ${after}`, trace: tr,
  });
  ok(report.includes("TOOLBOX REPORT") && report.includes("Whales"), "renderToolboxReport renders the full report");
  ok(report.includes("Execution trace") && report.includes("State diff"), "renderToolboxReport includes the trace sections");
} catch (e) {
  failures++;
  console.log(`FAIL: toolbox smoke test errored — ${(e as Error).message.slice(0, 300)}`);
} finally {
  try { await fork?.stop(); } catch { /* already dead */ }
}

if (failures > 0) {
  console.log(`toolbox smoke test: ${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("toolbox smoke test: ALL PASS — storage, privileges, whales, warp and impersonation all behave on a live fork");
process.exit(0);
