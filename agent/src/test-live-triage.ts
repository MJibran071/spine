// One-off: end-to-end triage of a real mainnet target through the module path
// (key loaded from agent/.llm-key, OpenRouter free model, budget active).
// Usage: node agent/src/test-live-triage.ts
import { fetchLiveSource } from "./livesrc.ts";
import { triageTarget, triageSummary, triageBudgetLeft } from "./triage.ts";

async function main(): Promise<number> {
  const address = process.argv[2] ?? "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B"; // Compound cETH
  console.log(`target: ${address}`);
  console.log(`budget before: ${triageBudgetLeft()} call(s) left today`);

  const { source, provider } = await fetchLiveSource("1", address);
  if (!source) {
    console.log("no verified source available — cannot run this test");
    return 1;
  }
  console.log(`verified source: ${provider} (${source.length} chars)`);

  const t = await triageTarget({
    chainId: "1",
    address,
    shape: "unknown",
    selectors: ["mint", "redeem", "borrow", "repayBorrow", "liquidateBorrow", "accrueInterest"],
    ethWei: "0",
    wethWei: "0",
    detectorSignals: ["reentrancy-eth", "oracle-spot-price"],
    verifiedSource: source,
    bytecodeHex: null,
  });
  if (!t) {
    console.log("triage returned null (budget spent? cooldown? parse failure?)");
    console.log(`budget after: ${triageBudgetLeft()}`);
    return 1;
  }
  console.log(`\n${triageSummary(t)}`);
  console.log(`probe detail: ${t.probe ? JSON.stringify(t.probe).slice(0, 300) : "(none proposed)"}`);
  console.log(`budget after: ${triageBudgetLeft()} call(s) left today`);
  return 0;
}

process.exit(await main());
