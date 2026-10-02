// Shared rules for what counts as a real mainnet finding vs lab/demo noise.
import { isProductionChain } from "./config.ts";
import type { ForkFinding } from "./fork.ts";

const LOCAL_ADDR = /^0x5[fF]b[dD]b2315678afecb367f032d93[fF]642f64180aa3$/;

/** True when a fork probe result is worth alerting / drafting a report for. */
export function isActionableFinding(finding: ForkFinding): boolean {
  if (!finding.simulated || finding.profitWei === "0") return false;
  // Materiality: dust profits (rounding noise on 18-decimal tokens) are not
  // findings. 1e12 wei ≈ 0.000000001 tokens — far below any real impact.
  try {
    if (BigInt(finding.profitWei) < 1_000_000_000_000n) return false;
  } catch {
    return false;
  }
  if (finding.notes.includes("NO_VIOLATION")) return false;
  if (finding.notes.includes("probe reverted")) return false;
  if (finding.notes.includes("probe error:")) return false;
  if (finding.notes.includes("probe skipped")) return false;
  // A vault that refuses every probe identity (allowlist / role gating) is a
  // REFUSAL, not attack surface: it can never be evidence of a drain, so it
  // must not pass the actionable bar even if some other marker matches.
  if (finding.notes.includes("blocked by vault gating")) return false;
  // Require an explicit FINDING signal — balance deltas alone are not enough
  // (local integration fixtures can drain without a real exploit class).
  return (
    finding.notes.includes("probe FINDING:") ||
    finding.notes.includes("[FINDING]") ||
    /ORACLE-SPOT-MANIPULABLE|share inflation|claim replay/i.test(finding.notes)
  );
}

export function isProductionTarget(chainId: string, address: string): boolean {
  if (!isProductionChain(chainId)) return false;
  if (LOCAL_ADDR.test(address)) return false;
  return true;
}
