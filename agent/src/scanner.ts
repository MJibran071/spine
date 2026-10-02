// Full-market scanner: multi-chain survey -> rank -> probe -> report.
//
//   1. For every registered chain: verify reachability, collect targets
//      (factory-event discovery + curated seeds).
//   2. Rank targets by an extractable-value hypothesis (native + wrapped-
//      native balances, read-only against the PUBLIC endpoint).
//   3. Fork the chain LOCALLY (anvil, read-only) and recon + probe the top-N
//      through the fork — the agent's RPC allowlist still binds it to
//      127.0.0.1 for every simulation call.
//   4. A reproduced drain becomes a bounty draft. Nothing is ever broadcast.
import { AnvilFork, reconPool, simulateOnFork, spawnForkWithFailover } from "./fork.ts";
import { investigateUnknownShape } from "./investigate.ts";
import { runPool } from "./pool.ts";
import {
  CHAINS,
  discoverAmmTargets,
  discoverHotPairs,
  discoverHotVaults,
  seedTargets,

  chainReachable,
  nativeBalanceWei,
  wrappedBalanceWei,
  totalTvlWei,
  type ChainSpec,
  type ScanTarget,
  type HotPair,
} from "./scan.ts";
// DefiLlama small-TVL (< $1M) per-chain seed registry: the scanner is what
// probes non-Ethereum seeds (it forks each chain's own RPC), so the seed
// registry rides along with the other curated seeds here.
import { llamaSeedTargets } from "./llamatargets.ts";
import { verifyAndReport } from "./verify.ts";
import { isActionableFinding, isProductionTarget } from "./findings.ts";
import { setCycle, upsertWatch, logEvent } from "./bus.ts";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

export interface ScanOptions {
  blocksBack: number; // factory-event lookback window
  topN: number; // how many targets to fork-probe per chain
  maxChains: number; // 0 = all reachable chains
  pauseBetweenChainsMs: number; // be polite to public endpoints
  onlyChains?: string[]; // restrict to these chain names (e.g. --only base,polygon)
  forkPort?: number; // local anvil port (default 8545; daemon rotates to avoid collisions)
  probeWorkers?: number; // concurrent local forks probing the top-N (default 1)
}

export interface ChainReport {
  chain: string;
  reachable: boolean;
  targetsFound: number;
  probed: { address: string; shape: string; result: string; finding: boolean }[];
  error?: string;
}

export async function runScan(opts: ScanOptions): Promise<ChainReport[]> {
  const reports: ChainReport[] = [];
  let candidates = CHAINS.slice(0, opts.maxChains > 0 ? opts.maxChains : CHAINS.length);
  if (opts.onlyChains?.length) {
    const wanted = new Set(opts.onlyChains.map((s) => s.trim().toLowerCase()));
    candidates = candidates.filter((c) => wanted.has(c.name));
  }

  for (const chain of candidates) {
    reports.push(await scanChain(chain, opts));
    if (opts.pauseBetweenChainsMs > 0) {
      await new Promise((r) => setTimeout(r, opts.pauseBetweenChainsMs));
    }
  }
  return reports;
}

async function scanChain(chain: ChainSpec, opts: ScanOptions): Promise<ChainReport> {
  const report: ChainReport = { chain: `${chain.name} (${chain.id})`, reachable: false, targetsFound: 0, probed: [] };

  process.stdout.write(`[scan] ${chain.name}: checking reachability... `);
  if (!(await chainReachable(chain))) {
    console.log("unreachable (skipping)");
    report.error = "RPC unreachable or chainId mismatch";
    return report;
  }
  console.log("ok");

  // ---- discovery (read-only, public endpoint) ----
  let targets: ScanTarget[] = [];
  try {
    const fromFactory = await discoverAmmTargets(chain, opts.blocksBack, 15);
    targets.push(...fromFactory);
  } catch (e) {
    logEvent("scan", `${chain.name}: factory discovery failed: ${(e as Error).message}`);
  }
  targets.push(...seedTargets(chain));
  // DefiLlama small-TVL seeds for THIS chain (reports/llama-seeds.json, filled
  // by the osint/llama lane). Best-effort: a corrupt registry must never kill
  // factory discovery.
  try {
    const llamaSeeds = llamaSeedTargets(chain);
    if (llamaSeeds.length > 0) {
      targets.push(...llamaSeeds);
      console.log(`[scan] ${chain.name}: +${llamaSeeds.length} DefiLlama small-TVL seed(s) (<$1M lane)`);
    }
  } catch { /* seed injection is best-effort */ }

  // Hot-market discovery: pairs with recent swap activity, ranked by native
  // reserves — works on free endpoints where deep factory windows do not.
  let hot: HotPair[] = [];
  try {
    hot = await discoverHotPairs(chain, 40, 120, 40);
    for (const p of hot.slice(0, 15)) {
      targets.push({ chain, address: p.address, source: "hot-pair", factory: `hot ${p.kind}` });
    }
  } catch (e) {
    logEvent("scan", `${chain.name}: hot-pair discovery failed: ${(e as Error).message}`);
  }
  // ERC-4626 vault discovery: scan for recent Deposit/Withdraw events.
  // Catches yield vaults, staking contracts, and lending markets the AMM
  // Swap-event path misses entirely.
  try {
    const vaults = await discoverHotVaults(chain, 40, 20);
    for (const v of vaults) {
      targets.push(v);
    }
    if (vaults.length > 0) logEvent("scan", `${chain.name}: ${vaults.length} ERC-4626 vault candidate(s) discovered`);
  } catch (e) {
    logEvent("scan", `${chain.name}: vault discovery failed: ${(e as Error).message}`);
  }
  report.targetsFound = targets.length;
  if (targets.length === 0) {
    console.log(`[scan] ${chain.name}: no targets discovered`);
    return report;
  }

  // ---- rank by full TVL (native + wrapped-native + major stablecoins, ETH-normalized) ----
  // This ensures high-value stablecoin pools (Aave, Curve, Compound) rank above
  // dust-holding ETH pairs rather than being buried in the list.
  // DefiLlama small-TVL seeds bypass the balance gate: their value sits in LP
  // positions / tokens the native+stable heuristic reads as ~0, which buried
  // the ENTIRE <$1M lane behind hot AMM pairs (observed live: 4/4 probe slots
  // went to [hot] pairs while 6 seeds waited). Their TVL is already attested
  // by DefiLlama — that is the whole point of the lane — so they are always
  // ranked and always ahead of hot-pair discovery. ScanTarget keeps its own
  // per-chain llama-seed records; no cross-module state.
  const llamaSeedAddrs = new Set(llamaSeedTargets(chain).map((t) => t.address));
  const ranked: { target: ScanTarget; balWei: bigint; fresh: boolean }[] = [];
  for (const t of targets.slice(0, 40)) {
    if (t.source === "seed" && llamaSeedAddrs.has(t.address.toLowerCase())) {
      ranked.push({ target: t, balWei: 1n, fresh: true });
      continue;
    }
    const bal = await totalTvlWei(chain, t.address);
    if (bal > 0n) ranked.push({ target: t, balWei: bal, fresh: t.source === "factory" });
  }
  // Freshness-first: factory-created targets from the recent window are new
  // deployments — the highest base-rate bug candidates (new x unaudited x
  // holding value). They sort ahead of established TVL leaders; within each
  // group, higher TVL wins. DefiLlama seeds ride the fresh group (balWei 1n
  // keeps them behind genuinely larger factories but ahead of every hot pair).
  const freshRank = (r: { target: ScanTarget; fresh: boolean }) => (r.target.source === "seed" && llamaSeedAddrs.has(r.target.address.toLowerCase()) ? 2 : r.fresh ? 1 : 0);
  ranked.sort((a, b) => freshRank(b) - freshRank(a) || (b.balWei > a.balWei ? 1 : b.balWei < a.balWei ? -1 : 0));
  const top = ranked.slice(0, opts.topN);
  console.log(
    `[scan] ${chain.name}: ${targets.length} target(s), ${ranked.length} holding value, probing top ${top.length}`
  );
  report.reachable = true;

  // ---- fork + probe top-N (LOCAL forks; agent RPC stays on 127.0.0.1) ----
  // Each probe gets its own short-lived anvil on a distinct port: probes run
  // in parallel and cannot corrupt each other's simulated state. Ports sit
  // above the daemon's ranges (watch 8545/8550+, rotation base 8546).
  const probeForks = Math.min(opts.probeWorkers ?? 1, 4); // anvil is heavy
  // Fork-source: LAB_FORK_URL is an ETHEREUM endpoint override (used by the
  // daemon's watch). It must never be used to fork OTHER chains — a
  // "successful" ethereum fork makes arbitrum/optimism targets look like
  // empty accounts (no code, no verified source) because the contracts only
  // exist on their own chain. Non-ethereum chains fork their own verified
  // public endpoints, with the rest of their rpcs[] as failover.
  const primaryRpc = chain.id === "1" ? process.env.LAB_FORK_URL?.trim() || chain.rpcs[0]! : chain.rpcs[0]!;
  const basePort = (opts.forkPort ?? 8545) + 20;
  await runPool(probeForks, top.map(({ target }, i) => async () => {
    const label = `${chain.name}:${target.address}${target.source === "hot-pair" ? " [hot]" : target.source === "seed" ? " [seed]" : ""}`;
    upsertWatch({ address: label, lastProbe: Date.now() });
    // Failover across the chain's registered RPCs: free endpoints rate-limit
    // fork-grade fetches while passing eth_chainId, so the only proof is a
    // completed anvil boot — which spawnForkWithFailover retries on.
    let fork: AnvilFork;
    try {
      fork = await spawnForkWithFailover(primaryRpc, basePort + i, chain.rpcs);
    } catch (e) {
      const msg = `local fork failed on all endpoints: ${(e as Error).message}`.slice(0, 200);
      upsertWatch({ address: label, lastResult: msg });
      report.probed.push({ address: target.address, shape: "?", result: msg, finding: false });
      return;
    }
    try {
      const recon = await reconPool(fork, target.address);
      // Auto-enlistment: a live target whose shape matches a probeable class
      // (e.g. an ERC-4626 vault) is worth re-probing forever — new vaults are
      // exactly where unaudited share math ships. The daemon's fork watch
      // picks enlisted entries up each cycle. Address must be bare (no
      // chain: prefix) so the watch fork can resolve it on Ethereum.
      const probeable = recon.shape.includes("side-entrance") || recon.shape.includes("erc-4626");
      if (probeable && chain.id === "1") {
        upsertWatch({ address: target.address, shape: recon.shape, enlisted: true });
        console.log(`[scan]   ${label}: auto-enlisted for continuous watch (${recon.shape})`);
      }
      upsertWatch({ address: label, shape: recon.shape });
      const technique: string = recon.shape.includes("side-entrance")
        ? "side-entrance-reentrancy"
        : recon.shape.includes("erc-4626")
        ? "erc4626-share-inflation"
        : "manual-analysis-required";
      let finding = await simulateOnFork(fork, recon, technique);
      // Unknown shape → no template probe ran. INVESTIGATE instead of giving
      // up: verified source -> detectors -> LLM triage -> (validated) probe
      // on this same local fork. Same safety rails; honest summaries.
      // investigationUnknownShape writes its own authoritative summary into
      // the watch state — the caller must not clobber it with the template-
      // probe placeholder note. Only write the probe's notes when nothing was
      // investigated at all (known shapes, or shapes other than unknown).
      let investigated = false;
      if (!finding.simulated && recon.shape.startsWith("unknown")) {
        const inv = await investigateUnknownShape(fork, chain.id, chain.name, target.address, { watchKey: label });
        if (inv.finding) finding = inv.finding;
        upsertWatch({ address: label, lastResult: inv.summary });
        console.log(`[scan]   ${label}: ${inv.summary}`);
        investigated = true;
      }
      const findingHit = isActionableFinding(finding) && isProductionTarget(recon.chainId, target.address);
      if (!investigated) upsertWatch({ address: label, lastResult: finding.notes, finding: findingHit });
      report.probed.push({ address: target.address, shape: `${recon.shape}${target.factory ? ` (${target.factory})` : ""}`, result: finding.notes, finding: findingHit });
      if (findingHit) {
        // Probe hit = SIGNAL. Verify on fresh forks; only 2/2 reproduction
        // produces the alert + evidence + bounty draft (verify.ts).
        const v = await verifyAndReport({
          poolAddr: target.address,
          chainId: recon.chainId,
          finding,
          recon,
          forkUrl: undefined, // scanner uses DEFAULT_FORK_RPC failover set
          label,
        });
        console.log(`[scan]   ${label}: ${v.confirmed ? "*** VERIFIED FINDING" : "signal NOT reproduced"} — ${v.note.slice(0, 200)}`);
      } else {
        console.log(`[scan]   ${label}: ${finding.notes}`);
      }
    } catch (e) {
      const msg = (e as Error).message;
      upsertWatch({ address: label, lastResult: `probe error: ${msg}` });
      report.probed.push({ address: target.address, shape: "?", result: `probe error: ${msg}`, finding: false });
    } finally {
      fork.stop();
    }
  }));
  return report;
}

export function writeScanReport(reports: ChainReport[]): string {
  const lines = [
    "# Full-Market Scan Report",
    "",
    `_generated ${new Date().toISOString()} — read-only discovery + local-fork probes; nothing broadcast_`,
    "",
    "| Chain | Reachable | Targets | Probed | Findings |",
    "|---|---|---|---|---|",
    ...reports.map(
      (r) =>
        `| ${r.chain} | ${r.reachable ? "yes" : "no"} | ${r.targetsFound} | ${r.probed.length} | ${r.probed.filter((p) => p.finding).length} |`
    ),
    "",
  ];
  for (const r of reports) {
    lines.push(`## ${r.chain}`, "");
    if (r.error) lines.push(`- error: ${r.error}`, "");
    for (const p of r.probed) {
      lines.push(`- \`${p.address}\` — ${p.shape}`);
      lines.push(`  - ${p.result}`);
    }
    if (r.probed.length === 0 && !r.error) lines.push("(no targets probed)");
    lines.push("");
  }
  mkdirSync(REPORT_DIR, { recursive: true });
  const path = join(REPORT_DIR, "SCAN.md");
  writeFileSync(path, lines.join("\n"));
  return path;
}
