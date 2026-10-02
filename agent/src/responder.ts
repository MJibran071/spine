// First responder: watch live protocol balances for anomalous drops, then
// prove what happened. When a watched protocol's holdings fall sharply in one
// window, the responder:
//   1. forks LOCALLY at current head (read-only, nothing broadcast),
//   2. extracts forensic evidence on-chain (code, selectors, admin pointers),
//   3. writes an emergency report with the incident's on-chain facts,
//   4. fires the finding notification.
// Finding a live exploit in progress is a signal for DEFENDERS and bounty
// programs — first accurate reports earn top payouts. Nothing here ever
// broadcasts or moves funds; all RPC stays on 127.0.0.1 via AnvilFork.
//
// Asset coverage: native ETH is NOT enough. Aave's Pool holds almost no raw
// ETH (deposits sit in aTokens), and most primitives hold WETH/USDC/USDT/DAI
// — so every sweep reads native + the major ERC-20 assets and a drop in ANY
// of them is an incident. Asset addresses are runtime-VERIFIED (code present
// + balanceOf readable) before they enter a baseline; an endpoint that serves
// garbage reads is rejected by the canary, never recorded as history.
import { existsSync, readFileSync, writeFileSync, appendFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, forgeEnv } from "./config.ts";
import { infraRpcOnce, CHAINS, type ChainSpec } from "./scan.ts";
import { redactRpcUrl } from "./safety.ts";
import { AnvilFork, reconPool, spawnForkWithFailover } from "./fork.ts";
import { ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";
import { notifyFinding } from "./notify.ts";
import { logEvent, upsertWatch } from "./bus.ts";

// Watched protocols per chain (verified live addresses only). These are the
// highest-TVL primitives worth defending — and where first reports pay best.
const WATCHED: Record<string, { address: string; name: string }[]> = {
  "1": [
    { address: "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", name: "Aave v2 Pool" },
    { address: "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", name: "Aave v3 Pool" },
    { address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8", name: "Balancer Vault" },
    { address: "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", name: "Compound cETH" },
  ],
  // Arbitrum — Aave V3 + GMX Vault (highest TVL non-Aave protocol on Arbitrum)
  "42161": [
    { address: "0x794a61358D6845594F94dc1DB02A252b5b4814aD", name: "Aave v3 Pool (Arbitrum)" },
    { address: "0x489ee077994B6658eAfA855C308275EAd8097C4A", name: "GMX Vault (Arbitrum)" },
  ],
  // Base — Aave V3
  "8453": [
    { address: "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", name: "Aave v3 Pool (Base)" },
  ],
};

// Balance-canary: the WETH contract provably holds millions of ETH on mainnet.
// An endpoint that reads it as 0 (or errors) is serving garbage state reads —
// verified live: rpc.flashbots.net returns 0x0 for eth_getBalance. Feeding
// that into a baseline would fabricate incidents, so every sweep first finds
// an endpoint that reads the canary sanely and uses ONLY that one.
const CANARY_ADDRESS = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const CANARY_MIN_WEI = 10n ** 22n; // 10,000 ETH — WETH holds millions

/** Major ERC-20 assets tracked alongside native balances. Each was VERIFIED
 * on-chain before inclusion (code present + decimals() + symbol() — registry
 * doctrine); each entry is runtime-verified again every sweep before it
 * enters a baseline, so a renamed/hot-swapped address can never poison it.
 * Decimals drive the per-asset incident floor (see MIN_INCIDENT_BY_DECIMALS).
 * Deliberately ABSENT: stETH — its rebasing balance grows on its own, which
 * would fabricate "drops" (or mask real ones); wstETH is the tracked
 * non-rebasing wrapper for the same exposure. */
const TRACKED_ASSETS: Record<string, string[]> = {
  "1": [
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC (8 dec, verified)
    "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf", // cbBTC (8 dec, verified)
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0", // wstETH (18 dec, verified)
    "0x4c9edd5852cd905f086c759e8383e09bff1e68b3", // USDe (18 dec, verified)
  ],
  "42161": [
    "0x82af49447d8a07e3bd95bd0d56f35241523fbab1", // WETH (Arbitrum, verified)
    "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", // USDC.e (Arbitrum, verified; native USDC unreachable from the verification endpoints available — honest exclusion)
    "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", // USDT0 (Arbitrum, verified)
    "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f", // WBTC (Arbitrum, verified)
  ],
  "8453": [
    "0x4200000000000000000000000000000000000006", // WETH (Base, verified)
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", // USDC (Base, verified)
  ],
};
const BALANCE_OF = "0x70a08231"; // balanceOf(address)

/** Per-asset incident FLOOR in whole units, by the asset's decimals. Dust
 * sweeps previously had to use one native-sized floor for every asset, which
 * either ignored BTC-payload drops (floor too high for 8 decimals) or cried
 * wolf over 6-decimal stable dust (floor too low). Scaled at comparison time:
 *   floorWei = wholeUnits * 10^decimals.
 * 8-dec BTC: 0.5 whole BTC (a stolen-btc payload is life-changing and a
 * plausible bounty floor); 6-dec stables: $25k; 18-dec ETH-class: 10 units.
 * The caller's native `minDropWei` stays the floor for native ETH. */
const MIN_INCIDENT_WHOLE_UNITS: Record<number, string> = {
  8: "0.5",
  6: "25000",
  18: "10",
};
const DEFAULT_INCIDENT_WHOLE_UNITS = "10";
/** Verified decimals for the tracked assets (same verification pass as above).
 * Unknown assets fall back to the 18-decimal default — conservative in the
 * direction of escalating more, never less. */
const ASSET_DECIMALS: Record<string, number> = {
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": 18, // WETH
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 6, // USDC
  "0xdac17f958d2ee523a2206206994597c13d831ec7": 6, // USDT
  "0x6b175474e89094c44da98b954eedeac495271d0f": 18, // DAI
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": 8, // WBTC
  "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": 8, // cbBTC
  "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": 18, // wstETH
  "0x4c9edd5852cd905f086c759e8383e09bff1e68b3": 18, // USDe
  "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": 18, // Arbitrum WETH
  "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": 6, // Arbitrum USDC.e
  "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": 6, // Arbitrum USDT0
  "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f": 8, // Arbitrum WBTC
  "0x4200000000000000000000000000000000000006": 18, // Base WETH
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 6, // Base USDC
};

/** Incident floor (wei) for one asset: wholeUnits * 10^decimals. Exported for
 * the regression test. */
export function incidentFloorWei(asset: string, nativeMinDropWei: bigint): bigint {
  if (asset === "native") return nativeMinDropWei;
  const dec = ASSET_DECIMALS[asset.toLowerCase()] ?? 18;
  const whole = MIN_INCIDENT_WHOLE_UNITS[dec] ?? DEFAULT_INCIDENT_WHOLE_UNITS;
  const [intPart, fracPart = ""] = whole.split(".");
  const digits = BigInt(`${intPart}${fracPart}`);
  const scale = 10n ** BigInt(dec - fracPart.length);
  return digits * scale;
}

/** Find an endpoint that serves BOTH honest balance reads and eth_call.
 * The native canary alone is not enough: rpc.flashbots.net reads balances
 * sanely but refuses eth_call outright ("rpc method is not whitelisted" —
 * verified live), which silently zeroes every ERC-20 asset read. So the
 * second canary makes an eth_call too: the WETH contract's own WETH balance
 * (accumulated wrap fees — far above dust), proving eth_call works AND the
 * node serves non-garbage token state. */
const ETH_CALL_CANARY_MIN_WEI = 10n ** 12n; // dust floor; WETH holds far more
async function pickBalanceEndpoint(chain: ChainSpec): Promise<string | null> {
  for (const url of chain.rpcs) {
    try {
      const hex = (await infraRpcOnce(url, "eth_getBalance", [CANARY_ADDRESS, "latest"], 8_000)) as string;
      if (!(typeof hex === "string" && hex.startsWith("0x") && BigInt(hex) >= CANARY_MIN_WEI)) continue;
      // eth_call capability + sanity: balanceOf(WETH) on the WETH contract.
      const callWei = await erc20BalanceWei(url, CANARY_ADDRESS, CANARY_ADDRESS);
      if (callWei === null || BigInt(callWei) < ETH_CALL_CANARY_MIN_WEI) continue;
      return url;
    } catch {
      // next endpoint
    }
  }
  return null;
}

const STATE_PATH = join(REPORT_DIR, "responder-baseline.json");

// A drop needs TWO-sided evidence before it earns the word "incident":
//   - value leaving the pool with no matching deposits, and
//   - ideally, inflow to the pool from the very contracts receiving the outflow
//     (profit consolidation — the signature of essentially every live exploit).
// Normal vault usage is one-sided by design: users deposit, users withdraw.
const TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// Two event dialects say "ordinary flow": WETH9-style Withdrawal/Deposit
// (address,uint256) AND the ERC-4626 vault pair Withdraw/Deposit
// (address,address,uint256,uint256). The 2026-09-28 spETH false positive was
// a legit 4626 redemption (vault emitted Withdraw + share burn + WETH out)
// escalated as an incident because only the WETH9 topics were known.
const TOPIC_WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65";
const TOPIC_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";
const TOPIC_WITHDRAW_4626 = "0xfbde797d201c968ac33fd458de3f7ec4b08ea47ccce5de98f1e7ad2499cb1da"; // cast keccak verified
const TOPIC_DEPOSIT_4626 = "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7"; // cast keccak verified
const LOGS_BLOCK_WINDOW = 8000; // ~27h on Ethereum mainnet; oversized on L2s by design
const LOGS_MAX_RANGE = 50000; // eth_getLogs hard cap guard — never request more
/** Some endpoints (verified live 2026-09-17 on 0x9396dcbf incidents) refuse
 * eth_getLogs beyond a ~10-block range — classification then ALWAYS fails,
 * every unexplained drop escalates, and the same vault re-fires incidents
 * sweep after sweep. Adaptive shrink walks the chunk down to the endpoint's
 * real limit (the error usually names it) instead of giving up to noise. */
const LOGS_MIN_RANGE = 10;
/** When the endpoint refuses even the minimum chunk (rate limits, auth, or a
 * window it cannot serve), classification CANNOT LOOK — fail over across the
 * chain's endpoints for the remaining requests instead of failing on one
 * endpoint (verified live: blastapi rate-limited mid-scan, killing every
 * classification while 8 sibling endpoints sat idle). */
const LOGS_FAILOVER_REQUESTS = 12;
/** Hard cap on log requests per classification: a 10-block-chunk endpoint
 * can never turn one drop into thousands of calls. When the cap is hit the
 * evidence is honestly partial, not fabricated. */
const LOGS_MAX_REQUESTS = 40;
const DRAIN_CONFIRM_RATIO = 20n; // inflow from withdrawers >= 5% of the drop confirms consolidation
/** Cross-daemon dedup: the fleet shares one baseline file and all five daemons
 * sweep the same watchlist. Whatever the FIRST daemon to see a balance change
 * decides, the others must not re-fire it. */
const CROSS_DAEMON_DEDUP_MS = 30 * 60_000;
/** Per-target+asset re-escalation window for UNCONFIRMED incidents. The
 * cross-daemon window (30 min) only suppresses the SAME baseline race; a
 * vault whose balance keeps oscillating around a benign rebalance level used
 * to re-open an incident report + alert every sweep (0x4f95…d87c printed 13
 * identical INCIDIDENT files in 3 days). A drop that survived 12h without
 * classification is, empirically, flow — a genuinely new exploit drops the
 * balance FURTHER, which is a new key value and re-escalates immediately. */
const PER_ENTRY_INCIDENT_TTL_MS = 12 * 60 * 60_000;

interface Baseline {
  // key: `${chainId}:${address.toLowerCase()}` -> decimal wei
  // (per-asset keys: `${chainId}:${address.toLowerCase()}:${asset.toLowerCase()}`,
  //  native uses asset key "native")
  balances: Record<string, string>;
  updatedAt: number;
  /** Cross-daemon dedup: key + time of the last escalated incident. Kept in
   * sync with the newest recentIncidents entry for older readers. */
  lastIncident?: { key: string; at: number };
  /** Cross-daemon dedup RING: every recent escalation, not just the last —
   * two different incidents inside one window must not erase each other. */
  recentIncidents?: { key: string; at: number }[];
}

function loadBaseline(): Baseline {
  try {
    const b = JSON.parse(readFileSync(STATE_PATH, "utf8")) as Baseline;
    if (b && typeof b.balances === "object") {
      // Migration: pre-asset baselines keyed without an asset part are native
      // balances — rekey so old history stays comparable instead of being read
      // as a from-zero drop on the first asset sweep.
      const migrated: Record<string, string> = {};
      for (const [k, v] of Object.entries(b.balances)) {
        if (k.split(":").length === 2) migrated[`${k}:native`] = v;
        else migrated[k] = v;
      }
      // Migrate the single-slot record into the ring, prune expired entries.
      const ring = [...(b.recentIncidents ?? [])];
      if (b.lastIncident && !ring.some((e) => e.key === b.lastIncident!.key && e.at === b.lastIncident!.at)) ring.push(b.lastIncident);
      const fresh = pruneIncidents(ring);
      return { balances: migrated, updatedAt: b.updatedAt ?? 0, lastIncident: fresh[fresh.length - 1], recentIncidents: fresh };
    }
  } catch {
    // first run
  }
  return { balances: {}, updatedAt: 0 };
}

/** Drop ring entries older than the longest suppression window (they can
 * never suppress anything again) and cap the ring so one pathological day
 * stays bounded. The ring must retain the PER-ENTRY incident TTL's history —
 * a shorter cutoff would silently erase the evidence the 12h re-escalation
 * suppression needs. */
function pruneIncidents(ring: { key: string; at: number }[]): { key: string; at: number }[] {
  const cutoff = Date.now() - Math.max(CROSS_DAEMON_DEDUP_MS, PER_ENTRY_INCIDENT_TTL_MS);
  const fresh = ring.filter((e) => e && typeof e.at === "number" && e.at >= cutoff);
  fresh.sort((a, b) => a.at - b.at);
  return fresh.slice(-32);
}

/** Pure merge used by saveBaseline — exported so the concurrency regression
 * test can exercise fleet-race semantics without network or forks. */
export function mergeBaselines(b: Baseline, disk: Baseline, readKeys?: Set<string>): Baseline {
  const merged: Baseline = {
    balances: { ...(readKeys ? disk.balances : b.balances) },
    updatedAt: Math.max(b.updatedAt, disk.updatedAt),
    lastIncident: undefined,
    recentIncidents: pruneIncidents([...(b.recentIncidents ?? []), ...(disk.recentIncidents ?? [])]),
  };
  if (readKeys) {
    for (const k of readKeys) {
      const v = b.balances[k];
      if (v !== undefined) merged.balances[k] = v;
    }
  }
  const newest = merged.recentIncidents?.[merged.recentIncidents.length - 1];
  if (newest) merged.lastIncident = newest;
  else if (b.lastIncident || disk.lastIncident) merged.lastIncident = (b.lastIncident?.at ?? 0) >= (disk.lastIncident?.at ?? 0) ? b.lastIncident : disk.lastIncident;
  return merged;
}

/** MERGE-ON-WRITE save. Five daemons share this one file and sweep in
 * parallel: a sweep that loaded the old baseline and then wrote its whole
 * snapshot would ERASE whatever a sibling recorded meanwhile — both the
 * dedup record (same drop re-fires, verified live 13 minutes apart on
 * 0x9396…71ef) and the updated balance (the same before/after values every
 * time). So the save re-reads disk and merges (see mergeBaselines); the
 * write is atomic (tmp+rename) so a concurrent reader never sees a torn
 * file. */
function saveBaseline(b: Baseline, readKeys?: Set<string>): void {
  try {
    const disk = loadBaseline();
    const merged = mergeBaselines(b, disk, readKeys);
    const tmp = `${STATE_PATH}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(merged));
    renameSync(tmp, STATE_PATH);
  } catch {
    // merge failed (unreadable disk?) — fall back to a plain write rather
    // than losing this sweep's readings entirely
    try {
      writeFileSync(STATE_PATH, JSON.stringify(b));
    } catch {
      // non-fatal
    }
  }
}

/** Has this exact incident key been escalated inside the dedup window — by
 * THIS daemon or any fleet sibling sharing the baseline file? Exported for
 * the concurrency regression test. */
export function recentlyEscalated(b: Baseline, incidentKey: string, nowMs: number): boolean {
  if (b.lastIncident && b.lastIncident.key === incidentKey && nowMs - b.lastIncident.at < CROSS_DAEMON_DEDUP_MS) return true;
  return (b.recentIncidents ?? []).some((e) => e.key === incidentKey && nowMs - e.at < CROSS_DAEMON_DEDUP_MS);
}

/** Same ring lookup with a caller-chosen window — used for the per-entry
 * UNCONFIRMED-incident TTL (12h), deliberately far longer than the cross-daemon
 * race window. An unconfirmed drop that survives a full window without
 * classification is, empirically, ordinary flow; a genuinely new exploit
 * deepens the drop and therefore re-escalates on its own merits. */
export function escalatedWithin(b: Baseline, incidentKey: string, nowMs: number, ttlMs: number): boolean {
  if (b.lastIncident && b.lastIncident.key === incidentKey && nowMs - b.lastIncident.at < ttlMs) return true;
  return (b.recentIncidents ?? []).some((e) => e.key === incidentKey && nowMs - e.at < ttlMs);
}

/** Watched targets, deduped against the scanner's auto-enlistment so the
 * responder also covers any Ethereum ERC-4626 vault the scanner finds. */
export function responderTargets(): { chainId: string; address: string; name: string }[] {
  const out = new Map<string, { chainId: string; address: string; name: string }>();
  for (const [chainId, entries] of Object.entries(WATCHED)) {
    for (const e of entries) out.set(`${chainId}:${e.address.toLowerCase()}`, { chainId, ...e });
  }
  // Enlisted live vaults ride along (chain 1 for now — fork machinery is EVM).
  try {
    const state = JSON.parse(readFileSync(join(REPORT_DIR, "state.json"), "utf8")) as {
      watchlist?: Record<string, { enlisted?: boolean; shape?: string }>;
    };
    for (const [addr, w] of Object.entries(state.watchlist ?? {})) {
      if (w.enlisted && /^0x[0-9a-fA-F]{40}$/.test(addr) && !addr.includes(":")) {
        const key = `1:${addr.toLowerCase()}`;
        if (!out.has(key)) out.set(key, { chainId: "1", address: addr, name: "auto-enlisted live vault" });
      }
    }
  } catch {
    // no state yet — static list only
  }
  return [...out.values()];
}

/** Current native balance (wei, decimal string) via a CANARY-VALIDATED
 * endpoint. `endpoint` must come from pickBalanceEndpoint — never read
 * balances from unvalidated endpoints. */
async function nativeBalanceWei(endpoint: string, address: string): Promise<string | null> {
  try {
    const hex = (await infraRpcOnce(endpoint, "eth_getBalance", [address.toLowerCase(), "latest"], 8_000)) as string;
    if (typeof hex !== "string" || !hex.startsWith("0x")) return null;
    return BigInt(hex).toString();
  } catch {
    return null;
  }
}

/** ERC-20 balance via eth_call balanceOf — read-only, canary-validated
 * endpoint only. Returns null when the call fails (asset treated as absent
 * for this sweep; never recorded as zero). */
async function erc20BalanceWei(endpoint: string, asset: string, holder: string): Promise<string | null> {
  try {
    const hex = (await infraRpcOnce(endpoint, "eth_call", [
      { to: asset, data: `${BALANCE_OF}${holder.replace(/^0x/, "").padStart(64, "0")}` },
      "latest",
    ], 8_000)) as string;
    if (typeof hex !== "string" || !/^0x[0-9a-f]+$/i.test(hex)) return null;
    return BigInt(hex).toString();
  } catch {
    return null;
  }
}

/** Assets to track for a chain, filtered to ones that actually have code and
 * answer balanceOf — verified per sweep against the VALIDATED endpoint, so a
 * wrong/renamed address can never poison a baseline (verified live: WETH,
 * USDC, USDT, DAI all return code + sane balances on chain 1). */
async function verifiedAssets(endpoint: string, chainId: string): Promise<string[]> {
  const out: string[] = [];
  for (const asset of TRACKED_ASSETS[chainId] ?? []) {
    try {
      const code = (await infraRpcOnce(endpoint, "eth_getCode", [asset, "latest"], 8_000)) as string;
      if (typeof code !== "string" || code.length <= 2) continue; // no contract — skip
      const probe = await erc20BalanceWei(endpoint, asset, CANARY_ADDRESS);
      if (probe !== null) out.push(asset);
    } catch {
      // skip this asset this sweep
    }
  }
  return out;
}

export interface ResponderResult {
  checked: number;
  /** Escalated incidents (classification UNCONFIRMED) — report + notify. */
  drops: number;
  reports: string[];
  /** Reads that failed this sweep (null balance) — skipped honestly, but
   * counted and logged so persistent read failures are visible, not silent. */
  skipped: number;
  /** Drops that went through on-chain activity classification. */
  classified: number;
  /** Classified benign (normal deposits/withdrawals) — logged, never reported. */
  benign: number;
  /** Classified unconfirmed — escalated as incidents. */
  unconfirmed: number;
  /** Same balance change already escalated by another daemon (shared baseline
   * file) — suppressed. */
  deduped: number;
}

/** One responder sweep: read native + tracked ERC-20 balances, compare to the
 * baseline, classify every drop against the chain's actual activity, and
 * escalate only UNCONFIRMED drops. Benign flow (deposits/withdrawals) is
 * logged for visibility but is never an incident. */
export async function runResponderSweep(opts: {
  forkUrl: string | null;
  dropBps: number; // e.g. 500 = 5%
  minDropWei: bigint; // ignore dust (per asset; callers scale per decimals)
  chainName: string; // label for the rotating scan (currently "ethereum")
  /** Fork port for the forensic anvil (default 8620). */
  forkPort?: number;
  /** When false, escalations are counted and recorded for dedup but the
   * forensic fork/report is skipped (tests; offline operation). */
  forkEnabled?: boolean;
}): Promise<ResponderResult> {
  const targets = responderTargets().filter((t) => opts.chainName === "*" || t.chainId === opts.chainName || opts.chainName === "1");
  const baseline = loadBaseline();
  const result: ResponderResult = { checked: 0, drops: 0, reports: [], skipped: 0, classified: 0, benign: 0, unconfirmed: 0, deduped: 0 };
  const nowMs = Date.now();
  const next: Baseline = { balances: { ...baseline.balances }, updatedAt: nowMs, lastIncident: baseline.lastIncident, recentIncidents: baseline.recentIncidents };
  const readKeys = new Set<string>(); // keys THIS sweep actually read — save merges around the rest
  // The validated endpoint is picked ONCE per sweep and reused for every
  // target/asset read — mixing endpoints mid-sweep would compare balances
  // observed by different nodes.
  let endpoint: string | null = null;

  for (const t of targets) {
    const chain = CHAINS.find((c) => c.id === t.chainId);
    if (!chain) continue;
    // Validate the balance source ONCE per sweep; if no endpoint reads the
    // canary sanely, skip the whole sweep WITHOUT touching the baseline
    // (a skipped sweep is honest; a poisoned one fabricates history).
    if (!endpoint) {
      endpoint = await pickBalanceEndpoint(chain);
      if (!endpoint) {
        logEvent("scan", "responder: no endpoint passed the balance+eth_call canaries — sweep skipped, baseline untouched");
        return result;
      }
      logEvent("scan", `responder: balance endpoint ${new URL(endpoint).host} passed balance+eth_call canaries`);
    }

    const assets = ["native", ...(await verifiedAssets(endpoint, t.chainId))];
    for (const asset of assets) {
      const key = `${t.chainId}:${t.address.toLowerCase()}:${asset}`;
      const now =
        asset === "native"
          ? await nativeBalanceWei(endpoint, t.address)
          : await erc20BalanceWei(endpoint, asset, t.address);
      if (now === null) {
        result.skipped++;
        continue;
      }
      result.checked++;
      readKeys.add(key);
      const before = baseline.balances[key];

      if (before !== undefined) {
        const beforeB = BigInt(before);
        const nowB = BigInt(now);
        if (nowB < beforeB) {
          const drop = beforeB - nowB;
          const dropBps = (drop * 10_000n) / (beforeB || 1n);
          // Per-asset floor: the caller's minDropWei governs native ETH; each
          // ERC-20 asset gets its own decimals-scaled floor so a 0.5-BTC payload
          // is never ignored and 6-decimal stable dust never cries wolf.
          const floor = incidentFloorWei(asset, opts.minDropWei);
          if (dropBps >= BigInt(opts.dropBps) && drop >= floor) {
            const ik = `${t.chainId}:${t.address.toLowerCase()}:${asset.toLowerCase()}`;
            if (recentlyEscalated(baseline, ik, nowMs)) {
              // Another daemon already escalated this exact balance change.
              result.deduped++;
              next.balances[key] = now;
              continue;
            }
            if (escalatedWithin(baseline, ik, nowMs, PER_ENTRY_INCIDENT_TTL_MS)) {
              // This vault+asset already produced an UNCONFIRMED incident
              // within the per-entry TTL. Re-opening a report + firing an
              // alert every sweep for one benign rebalance is noise, not
              // vigilance; the baseline below still tracks reality so a
              // genuinely deeper drop (a real exploit) re-escalates fresh.
              result.deduped++;
              logEvent("scan", `responder: ${t.name} ${assetLabel(asset)} drop suppressed - unconfirmed incident already escalated for this entry within ${PER_ENTRY_INCIDENT_TTL_MS / 3_600_000}h`);
              next.balances[key] = now;
              continue;
            }
            // A raw balance drop is a SYMPTOM, not a finding: withdrawals move
            // the same number a drain does (verified live: one vault printed
            // -50 WETH, +17, +8 within a day of ordinary user flow). Classify
            // the activity around the drop BEFORE spending the word "incident".
            const fromTs = baseline.updatedAt > 0 ? baseline.updatedAt - 120_000 : 0;
            const verdict = await classifyDropByActivity(endpoint, t, fromTs);
            result.classified++;
            // Only ordinary-flow verdicts are benign; anything else
            // (unconfirmed, no-activity, failed classification) escalates.
            if (verdict.outcome === "benign-withdrawal" || verdict.outcome === "benign-flow") {
              result.benign++;
              const eth = Number(drop) / 1e18;
              logEvent("scan", `responder: ${t.name} ${assetLabel(asset)} -${eth.toFixed(3)} classified ${verdict.outcome} — NOT an incident (${verdict.evidence})`);
            } else {
              result.drops++;
              result.unconfirmed++;
              if (opts.forkEnabled !== false) {
                // Pass the classification verdict itself as activity evidence —
                // a bare string here once crashed report writing downstream
                // (activity.map is not a function, 2026-09-16).
                const report = await respondToIncident(t, asset, beforeB, nowB, drop, opts.forkUrl, [`${verdict.outcome}: ${verdict.evidence}`], opts.forkPort ?? 8620);
                if (report) result.reports.push(report);
              } else {
                logEvent("scan", `responder: escalation recorded for ${t.name} ${assetLabel(asset)} — forensics skipped (fork disabled)`);
              }
              // Reset to the observed balance so the SAME drop never re-fires on
              // the next sweep (baseline must track reality after an incident),
              // and record the escalation IMMEDIATELY with a merge-save so a
              // sibling sweeping right now dedups against it (the old flow let
              // the end-of-sweep write clobber a sibling's record — verified
              // live as the same finding re-firing 13 minutes apart).
              next.balances[key] = now;
              next.recentIncidents = pruneIncidents([...(next.recentIncidents ?? []), { key: ik, at: Date.now() }]);
              next.lastIncident = { key: ik, at: Date.now() };
              saveBaseline(next, readKeys);
              continue;
            }
          }
        }
      }
      next.balances[key] = now;
    }
  }
  saveBaseline(next);
  return result;
}

const ASSET_NAMES: Record<string, string> = {
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
  "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
  "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
  "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": "cbBTC",
  "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": "wstETH",
  "0x4c9edd5852cd905f086c759e8383e09bff1e68b3": "USDe",
  "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "WETH (Arbitrum)",
  "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "USDC.e (Arbitrum)",
  "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": "USDT0 (Arbitrum)",
  "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f": "WBTC (Arbitrum)",
  "0x4200000000000000000000000000000000000006": "WETH (Base)",
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC (Base)",
  native: "native ETH",
};
function assetLabel(asset: string): string {
  return ASSET_NAMES[asset.toLowerCase()] ?? `${asset.slice(0, 10)}…`;
}

/** Normalize activity evidence into report lines. Accepts the historical
 * shapes callers have passed (single string, list, undefined) so a future
 * signature drift can never crash incident report writing again. */
export function normalizeActivityLines(activity: string | string[] | null | undefined): string[] {
  if (Array.isArray(activity)) return activity.filter((l): l is string => typeof l === "string" && l.length > 0);
  if (typeof activity === "string" && activity.length > 0) return [activity];
  return [];
}

/** Incident path: fork at head, gather forensics, write report, alert. */
export async function respondToIncident(
  t: { chainId: string; address: string; name: string },
  asset: string,
  beforeWei: bigint,
  nowWei: bigint,
  dropWei: bigint,
  forkUrl: string | null,
  activity: string | string[] | null | undefined,
  forkPort = 8620
): Promise<string | null> {
  const activityLines = normalizeActivityLines(activity);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const label = assetLabel(asset);
  // NOTE: the "BALANCE DROP on" prefix is retired history — the fleet's
  // pre-classification sessions recorded raw (often benign) drops under it,
  // and the bus scrubs that prefix on hydrate. Keep this NEW prefix distinct:
  // it is only reached for drops that on-chain classification could not explain.
  logEvent("finding", `UNCLASSIFIED BALANCE DROP on ${t.name} (${t.address}) ${label}: -${dropWei} (${beforeWei} -> ${nowWei}) — opening incident`);
  let fork: AnvilFork | null = null;
  try {
    const url = forkUrl ?? "https://rpc.flashbots.net";
    fork = await spawnForkWithFailover(url, forkPort, ETHEREUM_FORK_FALLBACKS);
    const recon = await reconPool(fork, t.address);
    const evidence = [
      `chain: ${t.chainId}`,
      `contract: ${t.name} (${t.address})`,
      `asset: ${label}${asset !== "native" ? ` (${asset})` : ""}`,
      `asset balance: ${beforeWei} -> ${nowWei} (drop ${dropWei})`,
      `classified shape: ${recon.shape}`,
      ...activityLines.map((l) => `activity: ${l}`),
      `detected entrypoints: ${recon.selectors.join(", ") || "none recognized"}`,
      `fork head: local anvil at block ${await fork.rpc("eth_blockNumber").then((b: any) => BigInt(b as string).toString()).catch(() => "unknown")}`,
      `fork source: ${redactRpcUrl(fork.forkUrl ?? "local attach")} (read-only; nothing broadcast)`,
    ];
    const reportPath = join(REPORT_DIR, `INCIDENT-${ts}-${t.address.slice(0, 10)}.md`);
    const md = [
      "# INCIDENT REPORT — unclassified balance drop",
      "",
      `_generated ${new Date().toISOString()} — first-responder forensic snapshot; read-only, nothing broadcast_`,
      "",
      ...evidence.map((l) => `- ${l}`),
      "",
      "## What this is",
      "",
      `The watcher detected a sharp ${label} balance drop on a watched protocol between two sweeps, and the`,
      `on-chain activity around the drop did NOT match ordinary deposit/withdrawal flow — but it is not yet`,
      `a confirmed exploit. This draft is the on-chain evidence a first report needs. Confirm the exploit tx, the root cause,`,
      "and submit through the project's official bounty/first-responder channel.",
      "",
      "## Next steps for the operator",
      "",
      "1. Pull recent txs touching the contract from the explorer and identify the exploit transaction.",
      `2. If the drop is in ${label !== "native ETH" ? "a tracked ERC-20 asset" : "native ETH"}, check the protocol's accounting contract for the matching side (e.g. aTokens for Aave).`,
      "3. Re-run the technique probes locally (`npm run fork -- --pool <addr> --fork-url <rpc>`).",
      "4. Submit the first report — speed matters for first-responder payouts.",
      "",
    ].join("\n");
    writeFileSync(reportPath, md);
    upsertWatch({ address: t.address, lastResult: `INCIDENT: ${label} drop ${dropWei} — report ${reportPath}`, finding: true });
    await notifyFinding(
      "INCIDENT: unclassified balance drop on watched protocol",
      `${t.name} dropped ${dropWei} ${label}. Emergency report: ${reportPath}`
    );
    logEvent("fork", `incident report written: ${reportPath}`);
    return reportPath;
  } catch (e) {
    appendFileSync(join(REPORT_DIR, "responder-errors.log"), `${new Date().toISOString()} ${t.address}: ${(e as Error).message}\n`);
    return null;
  } finally {
    fork?.stop();
  }
}

export type DropOutcome = "benign-withdrawal" | "benign-flow" | "no-activity" | "unconfirmed";

export interface DropVerdict {
  outcome: DropOutcome;
  evidence: string;
}

/** Classify a balance drop by reading the target's actual on-chain activity in
 * the window since the previous sweep. Only "unconfirmed" escalates.
 *
 * Logic (two-sided evidence, deliberately conservative):
 *   - withdraw events from the pool  -> ordinary user withdrawals: benign
 *   - transfer OUT with NO withdraw events and NO matching inflow: unconfirmed
 *   - outflow AND matching inflow to the same addresses (profit consolidation):
 *     unconfirmed
 *   - no logs at all in the window: unconfirmed (rare; could be native-only
 *     movement or an indexer gap — never pretend to know which)
 */
export async function classifyDropByActivity(
  endpointArg: string,
  t: { chainId: string; address: string; name: string },
  fromTimestampMs: number
): Promise<DropVerdict> {
  try {
    let endpoint = String(endpointArg);
    let failoverRemaining = LOGS_FAILOVER_REQUESTS;
    const headHex = (await infraRpcOnce(endpoint, "eth_blockNumber", [], 8_000)) as string;
    const head = Number(BigInt(headHex));
    let fromBlock = Math.max(0, head - LOGS_BLOCK_WINDOW);
    let logs: any[] = [];
    let chunkBlocks = LOGS_MAX_RANGE;
    let requests = 0;
    let partial = false;
    while (fromBlock <= head) {
      const end = Math.min(fromBlock + chunkBlocks, head);
      requests++;
      try {
        const batch = (await infraRpcOnce(endpoint, "eth_getLogs", [{ address: t.address, fromBlock: `0x${fromBlock.toString(16)}`, toBlock: `0x${end.toString(16)}` }], 12_000)) as any[];
        if (Array.isArray(batch)) logs = logs.concat(batch);
        fromBlock = end + 1;
      } catch (e) {
        const msg = (e as Error).message;
        // RATE LIMIT = the endpoint is unhealthy for ANY request right now
        // (blastapi -32097 killed every classification while 8 sibling
        // endpoints sat idle). Fail over IMMEDIATELY, before the shrink
        // logic — shrinking cannot fix a request the endpoint won't serve at
        // all, and waiting out the shrink ladder wastes the request budget.
        if (/rate limit|too many requests|-32097|429/i.test(msg)) {
          if (failoverRemaining > 0) {
            failoverRemaining--;
            const alt = (CHAINS.find((c) => c.id === String(t.chainId))?.rpcs ?? []).find((u) => u !== endpoint);
            if (alt) {
              endpoint = alt;
              continue; // retry the same position on the healthy endpoint
            }
          }
          throw e;
        }
        // Range rejection: shrink the chunk (and clamp the window so a
        // 10-block-chunk endpoint still covers the most RECENT blocks it can
        // afford — recency is what classification needs) and retry the same
        // position. Any other failure is real and propagates.
        if (/block range|10 block|too many blocks|exceeds max/i.test(msg) && chunkBlocks > LOGS_MIN_RANGE) {
          chunkBlocks = Math.max(LOGS_MIN_RANGE, Math.floor(chunkBlocks / 8));
          fromBlock = Math.max(fromBlock, head - chunkBlocks * LOGS_MAX_REQUESTS);
          continue;
        }
        throw e;
      }
      if (requests >= LOGS_MAX_REQUESTS && fromBlock <= head) {
        partial = true;
        break;
      }
    }
    if (partial && logs.length === 0) {
      // "No logs found" on a window the endpoint truncated is NOT evidence of
      // quiet — it is evidence we COULD NOT LOOK. The old no-activity verdict
      // here escalated benign rebalances into INCIDENT reports whenever the
      // public RPC capped eth_getLogs at 10 blocks. Honest outcome:
      // unconfirmed, with the reason in the evidence string.
      return { outcome: "unconfirmed", evidence: `classification incomplete: log window limited to the most recent ~${chunkBlocks * LOGS_MAX_REQUESTS} blocks by the endpoint (scanned to its cap, nothing found in it)` };
    }
    if (logs.length === 0) {
      return { outcome: "no-activity", evidence: `no logs from ${t.address} in the sweep window` };
    }
    const windowStartTs = fromTimestampMs > 0 ? fromTimestampMs : 0;
    const recent = logs.filter((l) => {
      const ts = Number(l?.blockTimestamp ?? 0);
      return !(ts > 0 && windowStartTs > 0 && ts * 1000 < windowStartTs);
    });
    if (recent.length === 0) {
      return { outcome: "no-activity", evidence: `${logs.length} log(s) from ${t.address} but all older than the sweep window` };
    }
    let withdraws = 0;
    let deposits = 0;
    let outSum = 0n;
    const outTo = new Map<string, bigint>();
    const inflowFrom = new Map<string, bigint>();
    for (const l of recent) {
      const topics: string[] = Array.isArray(l.topics) ? l.topics : [];
      if (topics[0] === TOPIC_WITHDRAWAL || topics[0] === TOPIC_WITHDRAW_4626) {
        withdraws++;
      } else if (topics[0] === TOPIC_DEPOSIT || topics[0] === TOPIC_DEPOSIT_4626) {
        deposits++;
      } else if (topics[0] === TOPIC_TRANSFER && topics.length >= 3) {
        // A 32-byte topic holds a 20-byte address in its LAST 40 hex chars.
        const from = `0x${topics[1].slice(24)}`.toLowerCase();
        const to = `0x${topics[2].slice(24)}`.toLowerCase();
        const val = BigInt(l.data ?? 0);
        if (from === t.address.toLowerCase()) {
          outSum += val;
          outTo.set(to, (outTo.get(to) ?? 0n) + val);
        } else if (to === t.address.toLowerCase()) {
          inflowFrom.set(from, (inflowFrom.get(from) ?? 0n) + val);
        }
      }
    }
    // Order matters: value LEAVING the pool is judged first. A Deposit does
    // not launder a transfer-out — ordinary flow moves value via
    // Withdrawal/Deposit events, not raw transfers from the pool.
    if (withdraws > 0 && deposits > 0) {
      return { outcome: "benign-flow", evidence: `${withdraws} Withdrawal + ${deposits} Deposit event(s) in window — normal vault operation` };
    }
    if (withdraws > 0) {
      return { outcome: "benign-withdrawal", evidence: `${withdraws} Withdrawal event(s) in window — user withdrawals explain the drop` };
    }
    if (outSum > 0n) {
      let consolidation = 0n;
      for (const [who, amt] of outTo) consolidation += inflowFrom.get(who) ?? 0n;
      const outs = [...outTo.entries()].sort((a, b) => (a[1] > b[1] ? -1 : 1)).slice(0, 3).map(([a, v]) => `${a.slice(0, 10)}… ${v}`);
      if (consolidation * DRAIN_CONFIRM_RATIO >= outSum) {
        return { outcome: "unconfirmed", evidence: `NO withdraw events, pure transfer out (${outs.join(", ")}) with matching inflow to the SAME addresses — profit-consolidation pattern` };
      }
      return { outcome: "unconfirmed", evidence: `NO withdraw events, pure transfer out (${outs.join(", ")}) — ${recent.length} log(s) in window, no ordinary-flow explanation` };
    }
    if (deposits > 0) {
      return { outcome: "benign-flow", evidence: `${deposits} Deposit event(s) in window — inbound flow, not a drain` };
    }
    if (outSum === 0n) {
      return { outcome: "no-activity", evidence: `${recent.length} log(s) but none move value out of ${t.address}` };
    }
    let consolidation = 0n;
    for (const [who, amt] of outTo) consolidation += inflowFrom.get(who) ?? 0n;
    const outs = [...outTo.entries()].sort((a, b) => (a[1] > b[1] ? -1 : 1)).slice(0, 3).map(([a, v]) => `${a.slice(0, 10)}… ${Number(v) / 1e18 > 0.0001 ? `${(Number(v) / 1e18).toFixed(3)}` : v.toString()}`);
    if (consolidation * DRAIN_CONFIRM_RATIO >= outSum) {
      return { outcome: "unconfirmed", evidence: `NO withdraw/deposit events, pure transfer out (${outs.join(", ")}) with matching inflow to the SAME addresses — profit-consolidation pattern` };
    }
    return { outcome: "unconfirmed", evidence: `NO withdraw/deposit events, pure transfer out (${outs.join(", ")}) — ${recent.length} log(s) in window, no ordinary-flow explanation` };
  } catch (e) {
    // Classification is evidence-gathering, not truth: if it fails we do NOT
    // silently bless the drop as benign — but we also must not fabricate
    // incidents on infra flakiness. Surface it and stay conservative.
    return { outcome: "unconfirmed", evidence: `classification failed: ${(e as Error).message}` };
  }
}
