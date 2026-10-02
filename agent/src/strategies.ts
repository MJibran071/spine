// Strategy library: maps challenge features to exploit techniques, with
// human-readable reasoning and bounded parameter sweeps for the search loop.
import type { ChallengeFeatures } from "./discovery.ts";

export interface Strategy {
  id: string;
  technique: string;
  reason: string;
  template: string;
  baseParams: Record<string, string[]>;
  matches: (f: ChallengeFeatures) => number; // score, <= 0 = no match
}

export const STRATEGIES: Strategy[] = [
  {
    id: "side-entrance-reentrancy",
    technique: "Flash-loan reentrancy: book the loaned ETH as a deposit in the callback, then withdraw",
    reason: "self-serve flashLoan + ether callback + deposit/withdraw in the same pool",
    template: "side-entrance",
    baseParams: { FLASH_AMOUNT: ["1000e18", "500e18", "2000e18"] },
    matches: (f) =>
      (f.hasFlashLoan && f.hasEtherCallback && f.hasDepositWithdraw ? 5 : 0) +
      // A pool whose flashLoan takes a borrower argument is NOT self-serve.
      (f.callerChoosesBorrower ? -10 : 0) +
      (f.pricesOffAmm ? -2 : 0) +
      (f.makesArbitraryCall ? -3 : 0),
  },
  {
    id: "forced-fee-griefing",
    technique: "Caller-chosen borrower forces victims to pay fees; credit-confusion bug then drains the pool",
    reason: "flashLoan(address,...) lets the caller nominate who pays",
    template: "naive-receiver",
    baseParams: { GRIEF_COUNT: ["10", "5", "20"] },
    matches: (f) => (f.hasFlashLoan && f.callerChoosesBorrower ? 4 : 0) + (f.hasNftMarketplace ? -3 : 0),
  },
  {
    id: "spot-oracle-manipulation",
    technique: "Dump the AMM spot price, borrow the pool cheaply, iterate until drained",
    reason: "collateral priced from AMM spot reserves",
    template: "uniswap_pair",
    baseParams: { DUMP_TOKENS: ["25000e18", "10000e18", "50000e18"] },
    matches: (f) => (f.pricesOffAmm ? 4 : 0) + (f.hasFlashLoan ? 1 : 0),
  },
  {
    id: "arbitrary-external-call",
    technique: "Zero-amount flash loan executes attacker calldata as the pool (approve-then-sweep)",
    reason: "flashLoan forwards attacker-chosen calldata from the pool's context",
    template: "truster",
    baseParams: {},
    matches: (f) => (f.makesArbitraryCall && f.hasFlashLoan ? 5 : 0) + (f.pricesOffAmm ? -2 : 0),
  },
  {
    id: "batch-overcredit",
    technique: "Batch purchase charges one price for N items; flash-loan funds the buy, resale repays",
    reason: "batch NFT purchase with per-item price checks",
    template: "free-rider",
    baseParams: {},
    matches: (f) => (f.hasNftMarketplace ? 4 : 0) + (f.pricesOffAmm ? -2 : 0),
  },
  {
    id: "bridge-claim-replay",
    technique: "One broadcast relayer signature replayed under fresh claim ids (binding omits claim id/recipient)",
    reason: "ecrecover-gated payout claims = bridge signature-binding surface",
    template: "bridge-replay",
    baseParams: {},
    matches: (f) => (f.verifiesSig ? 4 : 0) + (f.hasFlashLoan ? -3 : 0),
  },
  {
    id: "vault-share-inflation",
    technique: "Seed 1 wei of supply, donate to inflate share price, late depositors mint zero shares, harvest",
    reason: "share math over raw asset balance = donation-inflatable vault",
    template: "vault-inflation",
    baseParams: {},
    matches: (f) => (f.hasShareCalc ? 4 : 0) + (f.hasFlashLoan ? -2 : 0),
  },
  {
    id: "unauthorized-mint",
    technique: "Call mint() without authorization to inflate token supply and harvest the minted tokens",
    reason: "mint entrypoint with no access control = unrestricted supply inflation",
    template: "vault-inflation", // closest template shape; synth harness is preferred for this class
    baseParams: {},
    matches: (f) => (f.hasMintSurface ? 5 : 0) + (f.hasFlashLoan ? -1 : 0) + (f.hasShareCalc ? 1 : 0),
  },
  // Name-binding note: sources[] carries the challenge file paths, so each
  // lz-* strategy binds to its exact challenge family (+8) with weak generic
  // fallbacks below — a strategy can never "win" against the wrong contract.
  {
    id: "lz-v2-forged-origin-replay",
    technique: "Forged-origin lzReceive: unconfigured peer/sender bypass plus mark-but-never-check nonce replay double-pays the OApp",
    reason: "LayerZero V2 inbound surface (lzReceive tuple + setPeer) = cross-chain authz and replay classes",
    template: "lz-oapp-v2",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroOAppV2")) && f.hasLzReceiveV2 ? 8 : 0) + (f.hasLzReceiveV2 && !f.makesArbitraryCall && !f.verifiesSig ? 2 : 0),
  },
  {
    id: "lz-v1-empty-path-bypass",
    technique: "V1 empty trusted path: bytes32(0)→address(0) cast authenticates unconfigured chains and pays forged payloads",
    reason: "LayerZero V1 inbound surface (flat lzReceive + setTrustedRemote) = empty-remote bypass class",
    template: "lz-oapp-v1",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroOAppV1")) && f.hasLzReceiveV1 ? 8 : 0) + (f.hasLzReceiveV1 ? 2 : 0),
  },
  {
    id: "lz-endpoint-impersonation",
    technique: "Endpoint impersonation: lzReceive validates the peer but never msg.sender, so anyone delivers a peer-consistent forged Origin and pays itself",
    reason: "lzReceive with peer checks but no endpoint gate = forged delivery class",
    template: "lz-endpoint-impersonation",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroNoEndpointCheck")) ? 8 : 0),
  },
  {
    id: "lz-sig-cross-chain-replay",
    technique: "Cross-chain signature replay: EIP-712 digest missing chainid/contract binding, so one signature collects the payout on every chain",
    reason: "ecrecover-gated payout whose digest does not bind block.chainid = signature-reuse class",
    template: "lz-sig-cross-chain-replay",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroSigReplay")) ? 8 : 0) + (f.verifiesSig && !f.bindsChainId ? 3 : 0),
  },
  {
    id: "lz-governance-replay",
    technique: "Governance proposal-id collision: executed[] recorded but never enforced and keyed by id alone, so a captured id re-executes attacker calldata",
    reason: "lzReceive executing arbitrary target.call with id-only execution tracking",
    template: "lz-governance-replay",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroGovExecutor")) ? 8 : 0) + (f.hasLzReceiveV2 && f.makesArbitraryCall ? 2 : 0),
  },
  {
    id: "lz-oft-fee-on-transfer",
    technique: "Fee-on-transfer OFT inflation: source debits the requested amount while the fee is destroyed, destination mints the full request — value created per hop",
    reason: "omnichain bridge ledger that debits/credits requested amounts on a fee-taking token",
    template: "lz-oft-fee-on-transfer",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroOftFeeOnTransfer")) ? 8 : 0) + (f.hasOftBridge ? 2 : 0),
  },
  {
    id: "lz-oft-decimal-dust",
    technique: "OFT shared-decimal dust inflation: conversion rounds UP, so sub-unit amounts bridge as a full shared unit — value minted per hop from rounding",
    reason: "omnichain ledger whose LD-to-SD conversion rounds up instead of down",
    template: "lz-oft-decimal-dust",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroOftDecimalDust")) ? 8 : 0) + (f.hasDecimalConversion ? 2 : 0),
  },
  {
    id: "lz-nonce-ordering",
    technique: "Nonce-ordering bypass: app-side watermark accepts gaps, bricking delayed in-flight transfers and re-applying the same logical transfer under fresh nonces",
    reason: "lzReceive gating on nonce > lastApplied (lower bound) instead of exact sequence",
    template: "lz-nonce-ordering",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("LayerZeroNonceOrdering")) ? 8 : 0) + (f.hasNonceWatermark ? 2 : 0),
  },
  {
    id: "read-only-reentrancy",
    technique: "Re-enter a view function mid-execution to read stale state while the pool is in an inconsistent state",
    reason: "external call before state update + a dependent protocol reads this contract's balance/price",
    template: "side-entrance", // re-uses side-entrance callback shape
    baseParams: { FLASH_AMOUNT: ["1000e18", "500e18"] },
    matches: (f) =>
      (f.hasFlashLoan && f.hasEtherCallback && !f.hasDepositWithdraw && f.checksRawBalance ? 3 : 0),
  },
  // Name-binding note: sweep/merkle strategies bind to their exact challenge
  // family (+8) like the lz-* entries, with generic feature-based fallbacks —
  // a strategy can never "win" against the wrong contract.
  {
    id: "unprotected-fee-sweep",
    technique: "Unprotected ledger sweep: the fee/treasury sweep ships without its access control and pays an attacker-chosen recipient — one permissionless call drains the router",
    reason: "sweep() over the contract's own balance with no guard = fee-faucet class",
    template: "fee-sweep",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("FeeRouter")) && f.hasSweepSurface ? 8 : 0) + (f.hasSweepSurface ? 2 : 0),
  },
  {
    id: "merkle-claim-hijack",
    technique: "Merkle-claim hijack: leaves bind (index, amount) but not the recipient, and proofs are public — anyone claims any unclaimed grant to themselves",
    reason: "merkle-proof-gated claims whose leaf omits the account = airdrop-hijack class",
    template: "merkle-hijack",
    baseParams: {},
    matches: (f) => (f.sources.some((p) => p.includes("MerkleAirdrop")) && f.hasMerkleClaim ? 8 : 0) + (f.hasMerkleClaim ? 2 : 0),
  },
];

export function rankStrategies(f: ChallengeFeatures): Strategy[] {
  return [...STRATEGIES]
    .map((s) => ({ s, score: s.matches(f) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((x) => x.s);
}

/** Expand a strategy's base params into a bounded sweep of variants. */
export function buildParamVariants(strategy: Strategy, maxVariants = 6): Record<string, string>[] {
  const keys = Object.keys(strategy.baseParams);
  if (keys.length === 0) return [{}];

  const perKey: string[][] = keys.map((k) => {
    const vals = strategy.baseParams[k]!;
    if (vals.length <= 2) return vals;
    // numeric-ish: also try halves of the first two for a wider sweep
    const n = parseNum(vals[0]!);
    if (n === null) return vals.slice(0, 3);
    const half = fmtNum(n / 2n, vals[0]!);
    return [vals[0]!, half, vals[1]!].filter(Boolean) as string[];
  });

  // cartesian product, bounded
  let combos: Record<string, string>[] = [{}];
  for (const k of keys) {
    const idx = keys.indexOf(k);
    const next: Record<string, string>[] = [];
    for (const c of combos) {
      for (const v of perKey[idx]!) next.push({ ...c, [k]: v });
    }
    combos = next.slice(0, maxVariants);
  }
  return combos.slice(0, maxVariants);
}

function parseNum(v: string): bigint | null {
  const m = v.match(/^(\d+)e18$/);
  if (m) return BigInt(m[1]!);
  if (/^\d+$/.test(v)) return BigInt(v);
  return null;
}

function fmtNum(n: bigint, original: string): string {
  return /e18$/.test(original) ? `${n}e18` : n.toString();
}
