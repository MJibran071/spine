// Regression tests for the bug-finding pressure tools:
//   canoncode — fleet-frequency code classification (boilerplate/fork-delta/custom)
//   campaigns — persistent accumulating fuzz campaigns with cross-seed verification
//   funnel    — pipeline measurement
// All state goes to a scratch LAB_REPORT_DIR; no RPC, no forks, no LLM.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0;
let failures = 0;
function eq(name: string, got: unknown, want: unknown) {
  const ok = got === want;
  if (ok) pass++;
  else failures++;
  console.log(`${ok ? "ok" : "FAIL"} — ${name}${ok ? "" : ` (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
}
function check(name: string, cond: boolean) {
  if (cond) pass++;
  else failures++;
  console.log(`${cond ? "ok" : "FAIL"} — ${name}`);
}

const SCRATCH = mkdtempSync(join(tmpdir(), "pressure-tools-"));
mkdirSync(join(SCRATCH, "reports"), { recursive: true });
process.env.LAB_REPORT_DIR = join(SCRATCH, "reports");

// Empty persisted bus state so the funnel has a clean slate.
writeFileSync(join(SCRATCH, "reports", "state.json"), JSON.stringify({ watchlist: {}, findings: [], events: [] }));

const { classifyTarget, getCanon, canonStats, declaredContractNames } = await import("./canoncode.ts");
const { upsertCampaign, getCampaign, campaignStats, selectCampaignBatch, selectCampaignTarget } = await import("./campaigns.ts");
const { readFunnel, writeFunnelReport } = await import("./funnel.ts");

// ---- 1. canoncode: declaration extraction --------------------------------
{
  const names = declaredContractNames("contract Foo is Base {} interface IBar {} library Math {} abstract contract C {}");
  // Foo, Base (inheritance base counts!), IBar, Math, C — the is-list is part
  // of the type graph, which is exactly what makes fork detection work.
  eq("declared + inherited names extracted (lowercased, distinct)", names.length, 5);
  check("abstract contract caught", names.includes("c"));
  check("inheritance base counted as shared-candidate", names.includes("base"));
}

// ---- 2. canoncode: classification classes ---------------------------------
{
  // STOCK: names that every second target declares -> boilerplate
  const stock = "import '@openzeppelin/contracts/token/ERC20/ERC20.sol'; contract MyVault is ERC20, Ownable {}";
  const r1 = classifyTarget("1", "0x" + "a1".repeat(20), stock);
  // First sighting: MyVault is rare, ERC20/Ownable are ALWAYS_SHARED
  // -> 1 rare of 3 => 0.33 < 0.5 => boilerplate-ish. Assert exact class:
  eq("single rare name on shared base = fork-delta-ish (not custom)", r1.codeClass === "custom", false);
  check("boilerplate base recognized (ERC20/Ownable always shared)", r1.shared >= 2);

  // CUSTOM: a pile of fleet-rare names
  const custom = "contract QuantumLeverageEngine {} contract GorillaYieldMath {} contract ZkSyringeFeed {} contract BaignoirePool {}";
  const r2 = classifyTarget("1", "0x" + "a2".repeat(20), custom);
  eq("all-rare source = custom", r2.codeClass, "custom");
  check("customShare near 1", r2.customShare >= 0.99);

  // FORK DELTA: now re-classify a SECOND target with the same 'MyVault' base
  // (making MyVault fleet-shared) plus custom additions.
  const fork = "contract MyVault is ERC20 { contract CustomFeeRouter {} }";
  const r3 = classifyTarget("1", "0x" + "a3".repeat(20), fork);
  eq("shared base + custom additions = fork-delta", r3.codeClass, "fork-delta");

  // PERSISTENCE: rows are retrievable and the stats add up.
  const got = getCanon("1", "0x" + "A2".repeat(20));
  check("row persisted (case-insensitive lookup)", got !== null && got.codeClass === "custom");
  const st = canonStats();
  eq("stats total = 3 classified targets", st.total, 3);
  eq("stats custom = 1", st.custom, 1);
  // r1 (MyVault is ERC20,Ownable — one rare deployed wrapper on shared base)
  // AND r3 (shared base + CustomFeeRouter) are both fork-delta: the canonical
  // "fork with a custom wrapper" shape the classifier exists to prioritize.
  eq("stats forkDelta = 2", st.forkDelta, 2);
}

// ---- 3. campaigns: registration + selection ordering ----------------------
{
  upsertCampaign({ chainId: "1", address: "0x" + "a2".repeat(20), shape: "erc4626" });
  upsertCampaign({ chainId: "1", address: "0x" + "b1".repeat(20), shape: "lender-native" });
  upsertCampaign({ chainId: "1", address: "0x" + "b2".repeat(20), shape: "token" });

  const st = campaignStats();
  eq("campaigns registered", st.total, 3);
  eq("no slices yet", st.runsSoFar, 0);

  // Selection order: custom (a2) first, then boilerplate by staleness.
  const batch = selectCampaignBatch(3);
  eq("custom campaign selected first", batch[0]!.address, "0x" + "a2".repeat(20));
  const next = selectCampaignTarget();
  check("selectCampaignTarget agrees with batch head", next !== null && next.address === batch[0]!.address);
  check("campaign row retrievable", getCampaign("1", "0x" + "a2".repeat(20)) !== null);
}

// ---- 4. funnel: stage math + bottleneck naming -----------------------------
{
  const f = readFunnel();
  eq("funnel: watched = watchlist size (empty bus)", f.watched, 0);
  eq("funnel: sourced follows canoncode", f.sourced, 3);
  eq("funnel: customish = forkDelta+custom", f.customish, 3);
  eq("funnel: fuzzed follows campaigns", f.fuzzed, 3);
  check("bottleneck names the discovery gap on an empty bus", f.bottleneck.includes("probe coverage") || f.bottleneck.includes("discovery"));
  const p = writeFunnelReport();
  check("FUNNEL.md written", typeof p === "string" && p.endsWith("FUNNEL.md"));
}

// ---- 5. campaigns: build-failure suspension --------------------------------
{
  // getCampaign returns a FRESH parse — persist the suspension via upsert.
  upsertCampaign({ chainId: "1", address: "0x" + "b1".repeat(20), shape: "lender-native", consecutiveBuildErrors: 3 });
  const after = getCampaign("1", "0x" + "b1".repeat(20))!;
  eq("suspension counter persisted", after.consecutiveBuildErrors, 3);
  // A suspended campaign is excluded from selection until reset.
  const batch = selectCampaignBatch(10);
  check("suspended campaign not selected", !batch.some((b) => b.address === "0x" + "b1".repeat(20)));
}

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? `\npressure tools: all ${pass} checks passed` : `\npressure tools: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
