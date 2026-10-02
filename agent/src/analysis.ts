// Self-contained static detectors over challenge sources. Zero dependencies,
// no Python needed. If Slither IS installed on PATH, runSlither() adds its
// detector output as extra signal; otherwise the regex detectors stand alone.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";

export interface DetectorFinding {
  detector: string; // e.g. "reentrancy-eth", "arbitrary-send", "oracle-spot"
  severity: "high" | "medium" | "low";
  where: string; // file:line or contract name
  detail: string;
}

interface Rule {
  detector: string;
  severity: DetectorFinding["severity"];
  pattern: RegExp;
  detail: string;
}

// Regex-based detectors. These mirror (in cheap form) what Slither's
// reentrancy-eth / arbitrary-send-eth / oracle detectors flag. They are a
// PRIOR, not a verdict — the fuzzer harness is the actual judge.
const RULES: Rule[] = [
  {
    detector: "reentrancy-eth",
    severity: "high",
    pattern: /\.call\s*\{\s*value[^}]*\}\s*\(\s*["']?\)?|\.transfer\s*\(|\.send\s*\(/,
    detail: "external ETH transfer or value-bearing call — check for state updates after it",
  },
  {
    detector: "arbitrary-send-eth",
    severity: "high",
    pattern: /target\.call\s*\{\s*value[^}]*\}\s*\(\s*\w+\s*\)|\.call\s*\{\s*value[^}]*\}\s*\(\s*data\s*\)/,
    detail: "call with attacker-influenced target/calldata — arbitrary code execution as this contract",
  },
  {
    detector: "oracle-spot-price",
    severity: "high",
    pattern: /getReserves\s*\(\)|balanceOf\s*\(\s*\w*[pP]air\s*\)|uniswapPair|computeOraclePrice\s*\(/,
    detail: "price derived from AMM spot state — manipulable within one transaction",
  },
  {
    detector: "credit-balance-confusion",
    severity: "high",
    pattern: /address\s*\(\s*this\s*\)\s*\.balance\s*[<>]|tokenPool\s*\(\s*\)\s*[<>]|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/,
    detail: "solvency or accounting read from raw contract balance — conflates flash-loaned funds with deposits",
  },
  {
    detector: "unrestricted-per-item-pricing",
    severity: "medium",
    pattern: /for\s*\(\s*uint256\s+\w+\s*=\s*0[\s\S]{0,400}?price\s*\*\s*|buyMany\s*\(/,
    detail: "batch loop with per-item price math — verify total charge scales with item count",
  },
  {
    detector: "caller-chosen-recipient",
    severity: "medium",
    pattern: /flashLoan\s*\(\s*address\s+\w+/,
    detail: "loan recipient chosen by caller — any address can be made to absorb fees/repayment",
  },
  {
    detector: "sig-gated-claim",
    severity: "high",
    pattern: /ecrecover\s*\(/,
    detail: "signature-gated payout/claim — verify the signed digest binds ALL claim parameters (claim id, recipient, amount) or one broadcast signature replays",
  },
  {
    detector: "vault-share-inflation",
    severity: "medium",
    pattern: /convertToShares|totalAssets\s*\(\s*\)|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*\/\s*totalSupply/,
    detail: "share price from raw asset balance — direct donations inflate it; check virtual share offset / dead first shares",
  },
  {
    detector: "lz-cross-chain-sig",
    severity: "high",
    pattern: /lzReceive\s*\(|lzCompose\s*\(|ecrecover[\s\S]{0,400}?amount/,
    detail: "LayerZero receive/compose surface with signature or payout math — verify the origin (srcEid+sender) AND message identity are authenticated, and EIP-712 digests bind chainid + contract",
  },
  {
    detector: "lz-decimal-conversion",
    severity: "medium",
    pattern: /sharedDecimals|_ld2sd|_sd2ld|decimalConversionRate|convertAndTransfer|amountSD|amountLD/,
    detail: "OFT shared-decimal conversion — rounding must be DOWN (dust dropped); ceil() creates per-hop supply inflation",
  },
  {
    detector: "lz-nonce-watermark",
    severity: "medium",
    pattern: /inboundNonce\s*\+\s*\+|nonce\s*>=?\s*lastApplied|lastAppliedNonce|_nonce\s*\+\s*\+\s*;/,
    detail: "app-side nonce/sequence gate — a lower-bound watermark bricks delayed messages; consume exact nonces or map message identity",
  },
  {
    detector: "unprotected-sweep",
    severity: "high",
    pattern: /\bfunction\s+sweep\w*\s*\([^)]*address[\s\S]{0,200}?balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/,
    detail: "sweep function over this contract's own balance taking a destination parameter — verify an access guard exists AND that the destination is forced to the treasury, or anyone drains the fee ledger",
  },
  {
    detector: "merkle-claim-binding",
    severity: "high",
    pattern: /MerkleProof\.verify\s*\(|keccak256\s*\(\s*abi\.encode\s*\(\s*index\s*,\s*amount\s*\)\s*\)/,
    detail: "merkle-gated claim — the leaf must bind the RECIPIENT (keccak(abi.encode(account, index, amount))); a leaf of (index, amount) alone lets anyone redirect every unclaimed grant using public proofs",
  },
];

/** Detector pass over raw source TEXT (e.g. live verified code fetched from
 * a source-verification API). Same rules as runDetectors; `label` stands in
 * for a filename in finding locations. */
export function runDetectorsOnText(text: string, label: string): DetectorFinding[] {
  const findings: DetectorFinding[] = [];
  const lines = text.split("\n");
  for (const rule of RULES) {
    const seen = new Set<number>();
    lines.forEach((line, i) => {
      if (rule.pattern.test(line) && !seen.has(i)) {
        seen.add(i);
        findings.push({
          detector: rule.detector,
          severity: rule.severity,
          where: `${label}:${i + 1}`,
          detail: rule.detail,
        });
      }
    });
  }
  return findings;
}

export function runDetectors(sources: string[]): DetectorFinding[] {
  const findings: DetectorFinding[] = [];
  for (const src of sources) {
    let text = "";
    try {
      text = readFileSync(src, "utf8");
    } catch {
      continue;
    }
    findings.push(...runDetectorsOnText(text, src.split("/").pop()!));
  }
  return findings;
}

/** Detectors → strategy hints. Bridges static signal into the strategy ranker. */
export function detectorToStrategyBoost(detector: string): number {
  switch (detector) {
    case "reentrancy-eth":
      return 2;
    case "arbitrary-send-eth":
      return 3;
    case "oracle-spot-price":
      return 2;
    case "credit-balance-confusion":
      return 3;
    case "unrestricted-per-item-pricing":
      return 1;
    case "caller-chosen-recipient":
      return 1;
    case "sig-gated-claim":
      return 3;
    case "vault-share-inflation":
      return 2;
    default:
      return 0;
  }
}

/** Optional Slither passthrough — used only if installed on PATH. */
export function runSlither(target: string, timeoutMs = 60_000): Promise<string[]> {
  return new Promise((resolve) => {
    const child = execFile(
      "slither",
      [target, "--json", "-"],
      { timeout: timeoutMs },
      (err, stdout) => {
        if (err || !stdout) {
          resolve([]); // not installed or failed — detectors above are the fallback
          return;
        }
        const names: string[] = [];
        try {
          const parsed = JSON.parse(stdout) as {
            results?: { detectors?: Array<{ check?: string }> };
          };
          for (const d of parsed.results?.detectors ?? []) {
            if (d.check) names.push(d.check);
          }
        } catch {
          // parse failure — treat as absent
        }
        resolve(names);
      }
    );
    child.on("error", () => resolve([]));
  });
}

export function slitherAvailableHint(): string {
  return "slither not found on PATH — using built-in regex detectors (install with: pip3 install slither-analyzer)";
}
