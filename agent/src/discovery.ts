// Discovers challenges and extracts heuristic features used for strategy matching.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { LAB_ROOT } from "./config.ts";

export interface ChallengeFeatures {
  hasFlashLoan: boolean;
  hasEtherCallback: boolean; // execute()/receiveEther() style callback
  hasDepositWithdraw: boolean;
  makesArbitraryCall: boolean; // target.call(data)
  pricesOffAmm: boolean; // oracle from pair reserves / spot price
  hasNftMarketplace: boolean;
  callerChoosesBorrower: boolean;
  checksRawBalance: boolean; // solvency from address(this).balance rather than credits
  hasShareCalc: boolean; // vault-style share math (totalSupply/totalAssets)
  verifiesSig: boolean; // ecrecover-gated claims (bridge/vault claim surface)
  hasMintSurface: boolean; // mint(address,uint256) callable without access control
  hasLzReceiveV2: boolean; // LayerZero V2 lzReceive((uint32,bytes32,uint64),...)
  hasLzReceiveV1: boolean; // LayerZero V1 lzReceive(uint16,bytes,uint64,bytes)
  hasLzPeerConfig: boolean; // setPeer / setTrustedRemote config surface
  hasDecimalConversion: boolean; // OFT shared-decimal conversion (_ld2sd / LD_PER_SD)
  hasNonceWatermark: boolean; // app-side sequence watermark (nonce > lastApplied)
  bindsChainId: boolean; // source references block.chainid (sig domain binding present)
  hasOftBridge: boolean; // bridgeOut/bridgeIn omnichain-token surface
  hasSweepSurface: boolean; // sweep() over the contract's own balance — fee-ledger faucet
  hasMerkleClaim: boolean; // merkle-proof-gated claims (airdrop/vesting surface)
  sources: string[];
}

export interface Challenge {
  name: string;
  testFile: string;
  sources: string[];
  features: ChallengeFeatures;
}

const CHALLENGE_DIR = join(LAB_ROOT, "src", "challenges");

export function listChallengeSources(): string[] {
  try {
    return readdirSync(CHALLENGE_DIR)
      .filter((f) => f.endsWith(".sol") && !f.endsWith(".t.sol"))
      .filter((f) => !/Victim|Buyer/.test(f))
      .map((f) => join(CHALLENGE_DIR, f));
  } catch {
    return [];
  }
}

export function extractFeatures(sources: string[]): ChallengeFeatures {
  const all = sources.map((p) => readFileSync(p, "utf8")).join("\n");
  return {
    hasFlashLoan: /\bflashLoan\b/.test(all),
    hasEtherCallback: /\b(execute|receiveEther)\s*[({]/.test(all),
    hasDepositWithdraw: /\bdeposit\s*\(/.test(all) && /\bwithdraw\s*\(/.test(all),
    makesArbitraryCall: /target\.call\s*\(|\(data\)\s*;/.test(all),
    pricesOffAmm: /(tokenPool|getReserves|uniswapPair|computeOraclePrice)/.test(all),
    hasNftMarketplace: /(buyMany|offerMany)/.test(all),
    callerChoosesBorrower: /flashLoan\s*\(\s*address\s+\w+/.test(all),
    checksRawBalance: /address\(this\)\.balance\s*[<>=]|weth\.balanceOf\(address\(this\)\)/.test(all),
    hasShareCalc: /totalSupply\s*[*/]|totalAssets\s*\(/.test(all),
    verifiesSig: /ecrecover\s*\(/.test(all),
    hasMintSurface: /\bfunction\s+mint\s*\(\s*address/.test(all) && !/\bonlyOwner\b|\brequire\s*\(\s*msg\.sender\s*==/.test(all),
    hasLzReceiveV2: /lzReceive\s*\(\s*Origin\s+(memory|calldata)|lzReceive\s*\(\s*\([\s\S]{0,40}uint32[\s\S]{0,40}bytes32[\s\S]{0,40}uint64/.test(all),
    hasLzReceiveV1: /lzReceive\s*\(\s*uint16\s+\w+\s*,\s*bytes\s+(calldata\s+)?\w+\s*,\s*uint64/.test(all),
    hasLzPeerConfig: /\bsetPeer\s*\(|\bsetTrustedRemote\s*\(/.test(all),
    hasDecimalConversion: /_ld2sd|_sd2ld|SHARED_DECIMALS|LD_PER_SD/.test(all),
    hasNonceWatermark: /lastAppliedNonce\s*\+\s*\+|nonce\s*>\s*lastAppliedNonce|lastAppliedNonce\s*=\s*nonce/.test(all),
    bindsChainId: /block\.chainid/.test(all),
    hasOftBridge: /\bbridgeOut\s*\(|\bbridgeIn\s*\(/.test(all),
    hasSweepSurface: /\bsweep\w*\s*\(/.test(all) && /balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/.test(all),
    hasMerkleClaim: /MerkleProof\.verify\s*\(|merkleRoot\s*=/.test(all),
    sources,
  };
}

export function discoverChallenges(): Challenge[] {
  const sources = listChallengeSources();
  const byName = new Map<string, string[]>();
  for (const src of sources) {
    byName.set(src.split("/").pop()!.replace(/\.sol$/, ""), [src]);
  }

  let shippedTests: string[] = [];
  try {
    shippedTests = readdirSync(join(LAB_ROOT, "test")).filter((f) => f.endsWith(".t.sol"));
  } catch {}

  const challenges: Challenge[] = [];
  for (const [name, srcs] of byName) {
    challenges.push({
      name,
      testFile: shippedTests.find((t) => t.toLowerCase().includes(name.toLowerCase().slice(0, 8))) ?? "",
      sources: srcs,
      features: extractFeatures(srcs),
    });
  }
  return challenges;
}

/** Fingerprint of the challenge dir (for the watch daemon's change detection). */
export function labDirFingerprint(): string {
  try {
    return listChallengeSources()
      .map((p) => `${p}:${statSync(p).mtimeMs}`)
      .join("|");
  } catch {
    return "";
  }
}
