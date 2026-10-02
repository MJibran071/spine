// The hacker toolbox — what a human auditor does first on any target, done
// mechanically on the LOCAL fork:
//
//   storageSpy      — dump + decode storage slots (proxy/admin/balance slots):
//                     the raw state recon's ABI surface can't see.
//   privilegeMap    — who can do damage: EIP-1967 admin/impl, owner()/admin()
//                     getters, each classified EOA (hot key) vs contract.
//   roleEnum        — OZ AccessControlEnumerable members for well-known roles.
//   whaleFinder     — top recent-transfer recipients of a token: the right
//                     impersonation candidates ("what if THIS whale moved").
//   timeWarp        — advance the fork clock to surface time-gated logic
//                     (vesting, timelocks, epoch flips) that "never" fires.
//   impersonateCall — THE privilege experiment: become the admin/whale on the
//                     fork, fire the call, report honestly whether it succeeds.
//   traceCall       — execution tracing: the call graph (callTracer) and the
//                     exact storage/balance deltas (prestateTracer diffMode)
//                     of one call. Outcomes say WHAT happened; traces say HOW.
//
// SAFETY DOCTRINE (unchanged): every mutation (impersonation, warp) happens
// on a throwaway 127.0.0.1 anvil fork; nothing is ever broadcast. The
// allowlist (assertLocalRpc) guards every call path.
import { execFileSync } from "node:child_process";
import { AnvilFork, toChecksumAddress } from "./fork.ts";
import { assertLocalRpc } from "./safety.ts";
import { traceCalldata, traceStateDiff, renderCallTrace, renderStateDiff } from "./trace.ts";

// Verified EIP-1967 slots (same constants as governance.ts).
const SLOT_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
// keccak256("Transfer(address,address,uint256)") — same constant as responder.ts.
const TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const selectorCache = new Map<string, string>();
/** 4-byte selector via `cast sig` (the repo's verified keccak path). */
function selectorOf(signature: string): string {
  const hit = selectorCache.get(signature);
  if (hit) return hit;
  let sel = "0x00000000";
  try {
    sel = execFileSync("cast", ["sig", signature], { encoding: "utf8", timeout: 5_000 }).trim();
  } catch { /* cast unavailable — caller treats the call as absent */ }
  selectorCache.set(signature, sel);
  return sel;
}

const EMPTY_WORD = /^0x0{64}$/;

/** Read one raw storage word from the LOCAL fork. */
export async function readSlot(fork: AnvilFork, address: string, slot: string): Promise<string> {
  assertLocalRpc(fork.localRpc, "storage read");
  const v = await fork.rpc("eth_getStorageAt", [address, slot, "latest"]);
  return typeof v === "string" ? v : "0x";
}

/** Heuristic decode of a 32-byte word: small uint, or left-padded address. */
function decodeWord(hex: string): { asInt?: string; asAddress?: string } {
  const out: { asInt?: string; asAddress?: string } = {};
  if (!/^0x[0-9a-fA-F]+$/.test(hex)) return out;
  try {
    const bi = BigInt(hex);
    if (bi === 0n) return out;
    out.asInt = bi.toString();
    // Left-padded address pattern: high 12 bytes zero, low 20 nonzero.
    if (/^0x0{24}[0-9a-fA-F]{40}$/.test(hex)) {
      out.asAddress = toChecksumAddress("0x" + hex.slice(-40));
    }
  } catch { /* unreachable given the regex, kept for safety */ }
  return out;
}

export interface StorageSlot { slot: string; label?: string; raw: string; asInt?: string; asAddress?: string }

/** Dump nonzero slots 0..N plus EIP-1967 slots, heuristically decoded. */
export async function storageSpy(fork: AnvilFork, address: string, slots = 24): Promise<StorageSlot[]> {
  const out: StorageSlot[] = [];
  for (let i = 0; i < slots; i++) {
    const slot = "0x" + i.toString(16).padStart(64, "0");
    const raw = await readSlot(fork, address, slot);
    if (EMPTY_WORD.test(raw)) continue;
    out.push({ slot: `#${i}`, raw, ...decodeWord(raw) });
  }
  for (const [label, slot] of [
    ["EIP-1967 admin slot", SLOT_ADMIN],
    ["EIP-1967 implementation", SLOT_IMPLEMENTATION],
    ["EIP-1967 beacon", SLOT_BEACON],
  ] as const) {
    const raw = await readSlot(fork, address, slot);
    if (!EMPTY_WORD.test(raw)) {
      out.push({ slot: label, raw, asAddress: toChecksumAddress("0x" + raw.slice(-40)) });
    }
  }
  return out;
}

export interface PrivilegeEntry { source: string; who: string; kind: "eoa" | "contract" | "unknown" }

async function codeKind(fork: AnvilFork, addr: string): Promise<"eoa" | "contract" | "unknown"> {
  try {
    const code = await fork.rpc("eth_getCode", [addr, "latest"]);
    return typeof code === "string" && code.length > 2 ? "contract" : "eoa";
  } catch { return "unknown"; }
}

async function tryCall(fork: AnvilFork, to: string, data: string): Promise<string | null> {
  try {
    const r = await fork.rpc("eth_call", [{ to, data }, "latest"]);
    return typeof r === "string" && r !== "0x" ? r : null;
  } catch { return null; }
}

/** Map the authorities that matter: EIP-1967 admin/impl, then owner(),
 * admin(), pendingAdmin(), guardian() when present. EOA admins are flagged
 * by the caller via `kind` — an EOA admin key is the classic $50M mistake. */
export async function privilegeMap(fork: AnvilFork, address: string): Promise<PrivilegeEntry[]> {
  const out: PrivilegeEntry[] = [];
  const adminSlot = await readSlot(fork, address, SLOT_ADMIN);
  if (!EMPTY_WORD.test(adminSlot)) {
    const who = toChecksumAddress("0x" + adminSlot.slice(-40));
    out.push({ source: "EIP-1967 admin slot", who, kind: await codeKind(fork, who) });
  }
  const implSlot = await readSlot(fork, address, SLOT_IMPLEMENTATION);
  if (!EMPTY_WORD.test(implSlot)) {
    const who = toChecksumAddress("0x" + implSlot.slice(-40));
    out.push({ source: "EIP-1967 implementation", who, kind: await codeKind(fork, who) });
  }
  const beacon = await readSlot(fork, address, SLOT_BEACON);
  if (!EMPTY_WORD.test(beacon)) {
    const who = toChecksumAddress("0x" + beacon.slice(-40));
    out.push({ source: "EIP-1967 beacon", who, kind: await codeKind(fork, who) });
  }
  for (const sig of ["owner()", "admin()", "pendingAdmin()", "guardian()", "governor()"]) {
    const sel = selectorOf(sig);
    if (sel === "0x00000000") continue;
    const r = await tryCall(fork, address, sel);
    if (r && r.length >= 42 && /^0x0{24}[0-9a-fA-F]{40}$/.test(r)) {
      const who = toChecksumAddress("0x" + r.slice(-40));
      if (BigInt(who) !== 0n) out.push({ source: `${sig} getter`, who, kind: await codeKind(fork, who) });
    }
  }
  return out;
}

/** Best-effort OZ AccessControlEnumerable walk for well-known roles.
 * Silently returns [] when the extension is absent (wrong selector reverts). */
export async function roleEnum(fork: AnvilFork, address: string): Promise<PrivilegeEntry[]> {
  const out: PrivilegeEntry[] = [];
  const roles: Array<[string, string]> = [
    ["DEFAULT_ADMIN_ROLE", "0x0000000000000000000000000000000000000000000000000000000000000000"],
    ["MINTER_ROLE", "0x9f2df0fed2c77648de5860a4cc50fcd208e8f8d2abe8c7b58b1ebc1b6f81a2b8"],
    ["PAUSER_ROLE", "0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a"],
    ["UPGRADER_ROLE", "0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3"],
  ];
  const countSel = selectorOf("getRoleMemberCount(bytes32)");
  const memberSel = selectorOf("getRoleMember(bytes32,uint256)");
  if (countSel === "0x00000000" || memberSel === "0x00000000") return out;
  for (const [label, role] of roles) {
    const countR = await tryCall(fork, address, countSel + role.slice(2));
    if (!countR) continue;
    let count = 0;
    try { count = Number(BigInt(countR)); } catch { continue; }
    for (let i = 0; i < Math.min(count, 20); i++) {
      const idx = i.toString(16).padStart(64, "0");
      const memberR = await tryCall(fork, address, memberSel + role.slice(2) + idx);
      if (memberR && memberR.length >= 42) {
        const who = toChecksumAddress("0x" + memberR.slice(-40));
        if (BigInt(who) !== 0n) out.push({ source: label, who, kind: await codeKind(fork, who) });
      }
    }
  }
  return out;
}

export interface Whale { address: string; approxBalance: string }

/** Top recipients by recent Transfer volume — impersonation candidates.
 * Heuristic (sum of received ≠ balance) but the right ranking: whoever MOVES
 * size is the account whose key you want to hold on the fork. */
export async function whaleFinder(fork: AnvilFork, token: string, blocks = 50_000, top = 10): Promise<Whale[]> {
  assertLocalRpc(fork.localRpc, "log query");
  const head = Number(await fork.rpc("eth_blockNumber", []));
  let from = Math.max(0, head - blocks);
  // Adaptive window: many remote RPCs cap eth_getLogs ranges (flashbots: 10
  // blocks; others: 1k-10k). Probe with a small window, then walk backwards
  // in chunks until the RPC rejects or the query budget is spent.
  const MAX_CHUNKS = 20;
  let chunk = Math.min(blocks, 10);
  const totals = new Map<string, bigint>();
  let chunks = 0;
  while (chunks < MAX_CHUNKS && from < head) {
    const to = Math.min(head, from + chunk);
    try {
      const logs = await fork.rpc("eth_getLogs", [{
        address: token,
        topics: [TOPIC_TRANSFER],
        fromBlock: "0x" + from.toString(16),
        toBlock: "0x" + to.toString(16),
      }]);
      chunks++;
      from = to + 1;
      if (chunks === 1 && to - from < chunk / 2) chunk = Math.max(1, Math.floor(chunk)); // first chunk accepted as-is
      chunk = Math.min(chunk * 2, 5_000); // grow cautiously on success
      if (Array.isArray(logs)) {
        for (const log of logs.slice(0, 8_000)) {
          const topic = log?.topics?.[2] ?? "";
          if (!/^0x[0-9a-fA-F]{64}$/.test(topic)) continue;
          const toAddr = "0x" + topic.slice(-40);
          let value = 0n;
          try { value = BigInt(log.data ?? "0x0"); } catch { continue; }
          if (value === 0n) continue;
          totals.set(toAddr, (totals.get(toAddr) ?? 0n) + value);
        }
      }
    } catch {
      if (chunk <= 2) break; // even a 2-block chunk is rejected: give up honestly
      chunk = Math.max(1, Math.floor(chunk / 4)); // shrink and retry the same range
    }
  }
  return [...totals.entries()]
    .sort((a, b) => (b[1] > a[1] ? 1 : b[1] < a[1] ? -1 : 0))
    .slice(0, top)
    .map(([address, v]) => ({ address: toChecksumAddress(address), approxBalance: v.toString() }));
}

/** Advance the fork's clock and mine. Local fork only, by construction. */
export async function timeWarp(fork: AnvilFork, seconds: number): Promise<number> {
  assertLocalRpc(fork.localRpc, "time warp");
  await fork.rpc("evm_increaseTime", [seconds]);
  await fork.rpc("evm_mine", []);
  const block = await fork.rpc("eth_getBlockByNumber", ["latest", false]);
  return Number(block?.timestamp ?? 0);
}

export interface ImpersonateResult {
  impersonated: string;
  calldata: string;
  succeeded: boolean;
  txHash?: string;
  revertReason?: string;
  note: string;
}

/** THE privilege experiment: become `who`, send the calldata, mine, and read
 * the receipt. Answers "is the protection real or access-control theater?"
 * — without this, a privilege claim is just a guess. Local fork only. */
export async function impersonateCall(
  fork: AnvilFork,
  who: string,
  target: string,
  calldata: string,
  opts: { valueWei?: string } = {}
): Promise<ImpersonateResult> {
  assertLocalRpc(fork.localRpc, "impersonation");
  const to = toChecksumAddress(target);
  const from = toChecksumAddress(who);
  const data = calldata.startsWith("0x") ? calldata : "0x" + calldata;
  await fork.rpc("anvil_impersonateAccount", [from]);
  await fork.rpc("anvil_setBalance", [from, "0xDE0B6B3A7640000"]); // 1 ETH gas money
  try {
    const hash = await fork.rpc("eth_sendTransaction", [{
      from, to, data, value: opts.valueWei ?? "0x0",
    }]);
    await fork.rpc("evm_mine", []);
    let status: string | null = null;
    try {
      const receipt = await fork.rpc("eth_getTransactionReceipt", [hash]);
      status = typeof receipt?.status === "string" ? receipt.status : null;
    } catch { /* receipt not found — mined too fast; treat as unknown-success */ }
    if (status === "0x0") {
      return { impersonated: from, calldata: data, succeeded: false, txHash: hash, note: "call REVERTED while impersonated — protection held on the local fork" };
    }
    return { impersonated: from, calldata: data, succeeded: true, txHash: hash, note: "call SUCCEEDED while impersonated — the privilege is real" };
  } catch (e) {
    // Pre-mining rejection (anvil validates at tx time): that IS the revert.
    return { impersonated: from, calldata: data, succeeded: false, revertReason: String((e as Error).message).replace(/^RPC \S+: /, "").slice(0, 220), note: "call REJECTED while impersonated — protection held on the local fork" };
  } finally {
    try { await fork.rpc("anvil_stopImpersonatingAccount", [from]); } catch { /* fork may be dying */ }
  }
}

// ---------------------------------------------------------------------------
// Execution tracing (the mechanism tool)
// ---------------------------------------------------------------------------

export interface TraceToolResult {
  to: string;
  calldata: string;
  callGraph: string; // rendered callTracer output ("" when unavailable)
  stateDiff: string; // rendered prestateTracer diff ("" when unavailable)
  traceAvailable: boolean;
  unavailableReason?: string;
}

/** Run one call under BOTH tracers on the LOCAL fork: the call graph (who
 * called whom, where it reverted, gas per frame) and the exact storage/
 * balance deltas. Read-only observation; each half degrades honestly.
 * `from` defaults to a fresh fork-funded attacker identity so calls that
 * check msg.sender still execute. */
export async function traceCall(
  fork: AnvilFork,
  target: string,
  calldata: string,
  opts: { from?: string; valueWei?: string } = {}
): Promise<TraceToolResult> {
  const to = toChecksumAddress(target);
  const data = calldata.startsWith("0x") ? calldata : "0x" + calldata;
  // Default caller: anvil's funded account #0 — a real, funded, fork-local
  // identity. (An arbitrary "from" would work for eth_call, but some tracer
  // modes re-execute; a funded real account is the honest default.)
  let from = opts.from;
  if (!from) {
    try {
      const accounts: string[] = await fork.rpc("eth_accounts", []);
      from = Array.isArray(accounts) && accounts.length > 0 ? accounts[0] : undefined;
    } catch { /* default caller is best-effort */ }
  }
  const tx = { from, to, data, valueWei: opts.valueWei };
  const [graph, diff] = await Promise.all([
    traceCalldata(fork, tx),
    traceStateDiff(fork, tx),
  ]);
  const traceAvailable = graph.ok || diff.ok;
  return {
    to,
    calldata: data,
    callGraph: graph.ok ? renderCallTrace(graph) : "",
    stateDiff: diff.ok ? renderStateDiff(diff) : "",
    traceAvailable,
    unavailableReason: traceAvailable ? undefined : (graph.unavailableReason ?? diff.unavailableReason ?? "tracer unavailable"),
  };
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

export function renderToolboxReport(target: string, data: {
  slots: StorageSlot[];
  privileges: PrivilegeEntry[];
  roles: PrivilegeEntry[];
  whales: Whale[];
  warp?: string;
  trace?: TraceToolResult;
}): string {
  const L: string[] = [];
  L.push(`# TOOLBOX REPORT — ${target}`);
  L.push("");
  L.push("## Storage (nonzero slots, decoded)");
  if (data.slots.length === 0) L.push("  (all scanned slots empty)");
  for (const s of data.slots) {
    const dec = [s.asAddress, s.asInt ? `int=${s.asInt}` : ""].filter(Boolean).join(" ");
    L.push(`  ${s.slot.padEnd(26)} ${dec ? dec + "  " : ""}${s.raw.slice(0, 22)}…`);
  }
  L.push("");
  L.push("## Privileges");
  if (data.privileges.length === 0) L.push("  (no standard authority surfaces found)");
  for (const p of data.privileges) L.push(`  ${p.source.padEnd(28)} ${p.who}  (${p.kind})`);
  if (data.roles.length > 0) {
    L.push("");
    L.push("## AccessControl roles");
    for (const r of data.roles) L.push(`  ${r.source.padEnd(28)} ${r.who}  (${r.kind})`);
  }
  L.push("");
  L.push("## Whales (by recent transfer volume)");
  if (data.whales.length === 0) L.push("  (no transfers in the scanned window)");
  for (const w of data.whales) L.push(`  ${w.address}  ~${w.approxBalance}`);
  if (data.warp) {
    L.push("");
    L.push(`## Time warp: ${data.warp}`);
  }
  if (data.trace) {
    L.push("");
    L.push(`## Execution trace of ${data.trace.to} ${data.trace.calldata.slice(0, 12)}…`);
    if (!data.trace.traceAvailable) {
      L.push(`  (unavailable: ${data.trace.unavailableReason ?? "unknown"})`);
    } else {
      if (data.trace.callGraph) {
        L.push("### Call graph");
        L.push(data.trace.callGraph);
      }
      if (data.trace.stateDiff) {
        L.push("### State diff (prestateTracer)");
        L.push(data.trace.stateDiff);
      }
    }
  }
  return L.join("\n");
}
