// Exploit-lab agent entry point.
//
//   npm run lab      — solve all discovered challenges (knowledge-base aware)
//   npm run daemon   — hunt continuously: lab watch + mainnet watchlist probes
//   npm run fork     — one-shot pool recon + simulation (interactive gate)
//   npm run safety   — print and self-test the safety rails
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { discoverChallenges } from "./discovery.ts";
import { runTestContract, forge } from "./runner.ts";
import { runPool, workerCount } from "./pool.ts";
import { solveChallenge } from "./solve.ts";
import { MAX_ATTEMPTS, REPORT_DIR } from "./config.ts";
import { safetySummary, assertLocalRpc, assertSafeArgs, redactRpcUrl } from "./safety.ts";
import { AnvilFork, reconPool, simulateOnFork, spawnForkWithFailover } from "./fork.ts";
import { writeBountyReport } from "./bounty.ts";
import { askApproval } from "./prompts.ts";
import { runDaemon } from "./daemon.ts";
import { runScan, writeScanReport } from "./scanner.ts";
import { NON_EVM_CHAINS } from "./scan.ts";
import { countWins } from "./knowledge.ts";
import { startUiServer, renderStaticHtml } from "./server.ts";
import { runGovernanceScan, writeGovernanceReport } from "./governance.ts";
import { runOsintCycle, searchProvider, tavilyKeyPoolSize } from "./osint.ts";
import { setMode, logEvent, setKbWins, hydrateFromDisk, snapshot } from "./bus.ts";
import { runDetectors, slitherAvailableHint } from "./analysis.ts";
import { synthesizeHarness, evaluateSynthOutput, archiveHarness, SYNTH_RECIPES } from "./synth.ts";
import { buildHarness, evaluateGenHarness, archiveGenHarness } from "./genharness.ts";
import { recordViolation, recordHeld, recordGenError } from "./genlearn.ts";
import { runCuriosityCycle, curiosityStats } from "./curiosity.ts";
import { DEFAULT_FORK_RPC } from "./config.ts";
import { recordGenResult } from "./bus.ts";
import { readFileSync } from "node:fs";
import { runReplayBenchmark } from "./replay.ts";
import { triageUpgradeDiff } from "./upgradediff.ts";
import { fetchLiveSource } from "./livesrc.ts";
import { suggestAttackIdeas, ideasStats } from "./attackideas.ts";
import { storageSpy, privilegeMap, roleEnum, whaleFinder, timeWarp, impersonateCall, traceCall, renderToolboxReport, type Whale, type TraceToolResult } from "./toolbox.ts";
import { toChecksumAddress } from "./fork.ts";
import { CHAINS } from "./scan.ts";
import { runIncidentSweep } from "./incidents.ts";
import { buildReportPackage } from "./report.ts";

interface Row {
  challenge: string;
  status: string;
  technique: string;
  attempts?: number;
  profit?: string;
}

function usage(): number {
  console.log(`Exploit-lab agent (local-only)

  npm run lab [--ui] [--workers N]
                               Solve all discovered challenges autonomously
                               (parallel forge workers; default 4)
  npm run ui                   Serve the last session's dashboard (static)
  npm run snapshot             Write reports/dashboard.html from the last session
  npm run daemon -- [flags]    Hunt continuously (lab watch + mainnet watchlist)
      --interval <SEC>         Seconds between cycles (default 120)
      --max-attempts <N>       Bounded attempts per challenge per cycle (default 8)
      --fork-url <RPC>         Remote RPC that ANVIL forks read-only
      --attach <LOCAL_RPC>     Attach to an already-running local chain instead
      --watch <POOL_ADDR>      Add a pool to the mainnet watchlist (repeatable)
      --scan-every <N>         Rotate a full-market scan across chains every N cycles (default 10; 0 = off)
      --gov-every <N>          Read-only governance/authority scan every N cycles (default 20; 0 = off)
      --workers <N>            Concurrent lab-solve workers (default 4)
      --probe-workers <N>      Concurrent watchlist probes / local forks (default 2)
      --digest-hours <H>       Write reports/DIGEST-*.md every H hours (default 24, 0=off)
      --respond [0|1]          First-responder balance watchdog on watched protocols (default on)
                               (watches native ETH + WETH/USDC/USDT/DAI per protocol)
      --mainnet-only           Skip lab challenges; hunt production chains only
      --no-lab                 This instance skips lab solving (fleet: one owner)
      --scan-top <N>           Targets to fork-probe per chain during rotation (default 8)
  npm run gov                  One-shot read-only governance/admin risk report
  npm run fork -- --fork-url <RPC> --pool <ADDR>
                               Recon a live pool through a LOCAL anvil fork,
                               simulate the matched technique, halt at the
                               approval gate. Nothing is ever broadcast.
  npm run fork -- --attach http://127.0.0.1:8545 --pool <ADDR>
                               Same, but attach to an already-running LOCAL chain.
  npm run sieve -- status      Sieve structured-scrape lane: run inventory, credits, unknown outcomes
  npm run sieve -- run --instruction "…" [--url <page>]… [--field <col>]… [--wait]
                               Start ONE structured scrape (spends credits; the session_id
                               is persisted before polling, so a crash resumes the same run).
                               --shape long|wide  --compliance conservative|regular|yolo
                               --file <document>  --output-schema <file.json>  --force
  npm run sieve -- resume      Poll in-flight runs once (safe to repeat; starts nothing new)
  npm run sieve -- followup <session_id> --instruction "…"
                               Add a turn and wait for the NEW answer (the turn count must advance)
  npm run sieve -- download <session_id> | credits
  npm run sieve-login          One-time browser approval; writes SIEVE_API_KEY into agent/.env
                               Fallback (no device endpoint): create a key in the app's
                               Settings -> API keys, then: pbpaste | npm run sieve-login -- --paste
  npm run analysis             Run static detectors over all challenges (signal, not verdict)
  npm run synth                Fuzz invariant harnesses to DISCOVER drain paths from primitives
  npm run harness              GENERIC invariant engine: auto-generates a fuzzed harness
                               from each challenge's ABI + the universal property
                               catalog (no per-challenge recipe needed)
  npm run scan -- [flags]      Full-market scanner: discover pools on registered chains,
                               rank by extractable-value hypothesis, fork-probe top-N.
                               (read-only discovery + LOCAL forks; nothing broadcasts)
      --blocks-back <N>        Factory-event lookback window (default 200000)
      --top <N>                Targets to fork-probe per chain (default 3)
      --chains <N>             Limit to first N registered chains (0 = all)
      --probe-workers <N>      Concurrent local forks probing the top-N (default 1, max 4)
  npm run safety               Show + self-test the safety rails

Environment (all optional):
  LAB_LLM_KEY                  API key for LLM triage of unknown-shape targets
                               (any OpenAI-compatible endpoint). Without it,
                               unknown shapes still get verified-source detector
                               analysis — just no LLM hypothesis/probe.
  LAB_LLM_URL / LAB_LLM_MODEL  Triage endpoint override (default OpenAI /
                               a cheap reasoning model). The LLM only proposes
                               JSON probe specs; execution stays local-only.
  LAB_ETHERSCAN_KEY            Etherscan V2 key for verified-source fetch.
  LAB_FORK_URL                 Preferred fork source (private endpoint recommended).
  SIEVE_API_KEY                Sieve structured-scrape key. Server-side only: never in a
                               browser bundle, log, or git. Get one with \`npm run
                               sieve-login\` (one browser approval) or Settings -> API keys.
  SIEVE_BASE_URL               Sieve API base override (default https://scrape.usesieve.com).
  LAB_SIEVE_DAILY_MAX          Accepted runs per UTC day (default 12). Polling is free and
                               is not capped. LAB_SIEVE_OSINT=1 lets the OSINT cycle
                               auto-start protocol-intel runs (OFF by default: nothing spends
                               credits until you ask). LAB_OFFLINE=1 disables the whole lane
                               (behavior is unchanged without a key).
  LAB_SIEVE_ENV_FILE           Which dotenv file the login writer targets (default
                               agent/.env) — point it elsewhere to keep keys separate.`);
  return 2;
}

// ---------------------------------------------------------------- lab mode
function writeScoreboard(rows: Row[]): string {
  mkdirSync(REPORT_DIR, { recursive: true });
  const md =
    [
      "# Exploit-Lab Scoreboard",
      "",
      `_generated ${new Date().toISOString()} by the lab agent_`,
      "",
      "| Challenge | Status | Technique | Attempts | Profit (wei) |",
      "|---|---|---|---|---|",
      ...rows.map(
        (r) =>
          `| ${r.challenge} | ${r.status} | ${r.technique} | ${r.attempts ?? "-"} | ${r.profit ?? "-"} |`
      ),
    ].join("\n") + "\n";
  const path = join(REPORT_DIR, "SCOREBOARD.md");
  writeFileSync(path, md);
  return path;
}

async function runLab(workers = 4): Promise<number> {
  setMode("lab");
  console.log(`== Exploit-lab agent: autonomous lab run (${workers} parallel workers, knowledge-base aware) ==\n`);
  const challenges = discoverChallenges();
  console.log(`Discovered ${challenges.length} challenge(s): ${challenges.map((c) => c.name).join(", ")}\n`);

  // One shared build up front: every parallel forge test reuses the compiled
  // artifacts instead of racing to compile the same sources.
  process.stdout.write(">> forge build (shared, once) ... ");
  const build = await forge(["build"]);
  console.log(build.code === 0 ? "ok" : "FAILED (workers will still attempt)");

  const results = await runPool(
    workers,
    challenges.map((c) => () => solveChallenge(c, MAX_ATTEMPTS, (s) => console.log(`>> ${s}`)))
  );

  const rows: Row[] = results.map((r, i) => {
    const v = r.value;
    const status = !r.ok
      ? "ERROR"
      : v?.solved
        ? v.note === "discovered by fuzzer"
          ? "SOLVED (synthesis)"
          : "SOLVED"
        : v?.note === "no-strategy"
          ? "NO STRATEGY"
          : "FAILED";
    return {
      challenge: challenges[i]!.name,
      status,
      technique: v?.technique ?? "-",
      attempts: v?.attempts,
    };
  });
  const solved = rows.filter((r) => r.status.startsWith("SOLVED")).length;

  const path = writeScoreboard(rows);
  setKbWins(countWins());
  console.log(`\n== Scoreboard written to ${path} ==`);
  console.log(`Solved ${solved}/${challenges.length} challenges autonomously.`);
  return solved === challenges.length ? 0 : 1;
}

// --------------------------------------------------------------- fork mode
async function runFork(args: string[]): Promise<number> {
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    if (args[i]!.startsWith("--")) flags.set(args[i]!, args[i + 1] ?? "");
  }
  const forkUrl = flags.get("--fork-url");
  const pool = flags.get("--pool");
  const attachRpc = flags.get("--attach");
  if (!pool || (!forkUrl && !attachRpc)) return usage();

  // SAFETY: the agent never talks to forkUrl itself — only anvil does, and
  // only read-only. Every agent-side RPC goes to 127.0.0.1 (enforced in
  // AnvilFork.rpc), and no broadcast flag ever reaches forge (assertSafeArgs).
  const fork = attachRpc ? AnvilFork.attach(attachRpc) : new AnvilFork(forkUrl!);
  console.log(
    attachRpc
      ? `Attaching to LOCAL chain at ${fork.localRpc}...`
      : "Starting LOCAL anvil fork (read-only) of the remote chain..."
  );
  await fork.start();
  try {
    console.log(`Fork live at ${fork.localRpc} (agent-side allowlist: 127.0.0.1 only)\n`);

    const recon = await reconPool(fork, pool);
    console.log("Pool recon:");
    console.log(JSON.stringify(recon, null, 2));

    // Shape -> technique (extend as new probes are added).
    const technique = recon.shape.includes("side-entrance")
      ? "side-entrance-reentrancy"
      : "manual-analysis-required";

    console.log(`\nSimulating technique: ${technique} (local fork only, no broadcast)`);
    const finding = await simulateOnFork(fork, recon, technique);
    console.log("\nFinding:");
    console.log(JSON.stringify(finding, null, 2));

    if (finding.simulated && finding.profitWei !== "0") {
      const choice = await askApproval(
        `A drain reproduced against pool ${pool} on the local fork.\nWhat should the agent do with this evidence?`,
        [
          "Generate a bug-bounty report draft (recommended, legal)",
          "Print the finding only",
          "Discard",
        ]
      );
      if (choice.startsWith("Generate")) {
        const reportPath = writeBountyReport(recon, finding, attachRpc ? "local (attached)" : redactRpcUrl(forkUrl!));
        console.log(`\nBounty draft written: ${reportPath}`);
        console.log("Submit it through the project's official bounty program.");
      } else if (choice.startsWith("Discard")) {
        console.log("Evidence discarded.");
      }
    } else {
      console.log("\nNo drain reproduced. The pool did not fall to this technique.");
    }
    return 0;
  } finally {
    fork.stop();
  }
}

// ------------------------------------------------------------- safety mode
function runSafety(): number {
  console.log(safetySummary());
  console.log("\nSelf-tests:");

  const tests: Array<[string, () => void]> = [
    ["local RPC URL accepted", () => assertLocalRpc("http://127.0.0.1:8545", "selftest")],
    [
      "non-local RPC URL refused",
      () => {
        try {
          assertLocalRpc("https://mainnet.infura.io", "selftest");
          throw new Error("SELFTEST-FAIL: should have refused");
        } catch (e) {
          if ((e as Error).message.startsWith("SELFTEST-FAIL")) throw e;
        }
      },
    ],
    [
      "--broadcast flag refused",
      () => {
        try {
          assertSafeArgs(["script", "X", "--broadcast"], "selftest");
          throw new Error("SELFTEST-FAIL: should have refused");
        } catch (e) {
          if ((e as Error).message.startsWith("SELFTEST-FAIL")) throw e;
        }
      },
    ],
    [
      "--private-key flag refused",
      () => {
        try {
          assertSafeArgs(["--private-key", "0xdeadbeef"], "selftest");
          throw new Error("SELFTEST-FAIL: should have refused");
        } catch (e) {
          if ((e as Error).message.startsWith("SELFTEST-FAIL")) throw e;
        }
      },
    ],
  ];

  let passed = 0;
  for (const [name, fn] of tests) {
    try {
      fn();
      console.log(`  PASS  ${name}`);
      passed++;
    } catch (e) {
      console.log(`  FAIL  ${name}: ${(e as Error).message}`);
    }
  }
  return passed === tests.length ? 0 : 1;
}

// --------------------------------------------------------------------- main
const [mode, ...rest] = process.argv.slice(2);

async function main(): Promise<number> {
  // Hydrate the persisted session FIRST — before anything publishes (a stray
  // logEvent here would persist empty memory over the on-disk state and the
  // boot-time hydrate would then restore the clobbered file).
  hydrateFromDisk();
  const wantsUi = rest.includes("--ui") || mode === "ui";
  let uiUrl: string | null = null;
  if (wantsUi && mode !== "ui") {
    // --ui-port sets the BASE port; when several daemons run at once the
    // server auto-increments to the next free port, so each instance gets
    // its own dashboard without manual port juggling.
    const portIdx = rest.indexOf("--ui-port");
    const basePort = portIdx >= 0 ? parseInt(rest[portIdx + 1] ?? "", 10) : NaN;
    uiUrl = await startUiServer(Number.isFinite(basePort) && basePort > 0 ? basePort : 7333);
    logEvent("daemon", `dashboard live at ${uiUrl}`);
    console.log(`\nDashboard: ${uiUrl}\n`);
  }

  if (mode === "analysis") {
    setMode("analysis");
    const challenges = discoverChallenges();
    for (const c of challenges) {
      const findings = runDetectors(c.sources);
      console.log(`\n== ${c.name} — ${findings.length} detector finding(s)`);
      for (const f of findings) console.log(`   [${f.severity}] ${f.detector} @ ${f.where}: ${f.detail}`);
      if (findings.length === 0) console.log("   (no detector signals)");
      const recipe = SYNTH_RECIPES.find((r) => c.name.toLowerCase().includes(r.challengeMatch.toLowerCase()));
      console.log(`   synth recipe: ${recipe ? `available (${recipe.expectedFinding})` : "none — extend agent/src/synth.ts RECIPES"}`);
    }
    console.log(`\n${slitherAvailableHint()}`);
    return 0;
  }
  if (mode === "lab") {
    const labFlags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) {
        labFlags.set(rest[i]!, rest[i + 1] && !rest[i + 1]!.startsWith("--") ? rest[i + 1]! : "");
      }
    }
    const code = await runLab(workerCount(labFlags.get("--workers"), 4));
    if (wantsUi) {
      console.log(`\nDashboard still serving at ${"http://127.0.0.1:7333"} — Ctrl-C to stop.`);
      await new Promise(() => {}); // keep the dashboard up after the run
    }
    return code;
  }
  if (mode === "fork") return await runFork(rest.filter((a) => a !== "--ui"));
  if (mode === "safety") return runSafety();
  if (mode === "scan") {
    setMode("scan");
    const flags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) flags.set(rest[i]!, rest[i + 1] ?? "");
    }
    const reports = await runScan({
      blocksBack: parseInt(flags.get("--blocks-back") ?? "200000", 10),
      topN: parseInt(flags.get("--top") ?? "3", 10),
      maxChains: parseInt(flags.get("--chains") ?? "0", 10),
      pauseBetweenChainsMs: 1500,
      onlyChains: (flags.get("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean),
      probeWorkers: workerCount(flags.get("--probe-workers")?.[0], 1),
    });
    const path = writeScanReport(reports);
    console.log(`\nScan report: ${path}`);
    console.log(
      `Summary: ${reports.filter((r) => r.reachable).length} EVM chain(s) scanned, ${reports.reduce((n, r) => n + r.probed.filter((p) => p.finding).length, 0)} reproduced drain(s).`
    );
    console.log(
      `Non-EVM (needs native toolchain, not scannable via anvil): ${NON_EVM_CHAINS.map((c) => c.name).join(", ")}`
    );
    logEvent("scan", `full-market scan complete — report at ${path}`);
    return 0;
  }
  if (mode === "replay") {
    setMode("replay");
    const limit = Math.min(40, Math.max(1, parseInt(rest[0] ?? "12", 10) || 12));
    console.log(`Hack-replay benchmark: replaying the newest ${limit} forkable mainnet incidents on pre-hack forks…`);
    try {
      const { results, mdPath } = await runReplayBenchmark({ limit });
      for (const r of results) console.log(`  ${r.outcome.padEnd(14)} ${r.name} (${r.date}, block ${r.forkBlock ?? "—"})`);
      console.log(`Scoreboard: ${mdPath}`);
      logEvent("scan", `hack-replay benchmark done: ${results.filter((r) => r.outcome === "reproduced").length}/${results.length} reproduced — ${mdPath}`);
    } catch (e) {
      console.error(`benchmark failed: ${(e as Error).message}`);
      return 1;
    }
    return 0;
  }
  if (mode === "ideas") {
    setMode("scan");
    // usage: ideas <chainId> <address> [name]
    const [chainId, address, ...nameRest] = rest;
    if (!chainId || !address) {
      console.log("usage: npm run ideas -- <chainId> <address> [name]");
      console.log("  writes ranked LLM attack IDEAS for a target (never executes them)");
      return 1;
    }
    const name = nameRest.join(" ") || undefined;
    console.log(`Soliciting attack ideas for ${chainId}:${address.slice(0, 10)}…${name ? ` (${name})` : ""}…`);
    const src = await fetchLiveSource(chainId, address);
    if (!src.source) {
      console.log("  no verified source available — ideas need real code to reason about");
      return 1;
    }
    console.log(`  source: ${src.provider}, ${src.source.length} chars`);
    // Privilege intel first: who holds the keys changes what ideas make sense
    // (an EOA admin suggests key-compromise paths; a timelock suggests none).
    let privIntel = "";
    try {
      const port = 8750 + (process.pid % 100);
      const fork = await spawnForkWithFailover(DEFAULT_FORK_RPC, port, []);
      try {
        const privs = await privilegeMap(fork, address);
        const eoaAdmins = privs.filter((p) => p.kind === "eoa");
        privIntel = privs.length === 0
          ? "no standard authority getters found"
          : privs.map((p) => `${p.source}=${p.who}(${p.kind})`).join(", ")
            + (eoaAdmins.length ? " — NOTE: EOA-controlled authority, key compromise is a live path" : "");
      } finally {
        try { await fork.stop(); } catch { /* gone */ }
      }
    } catch { /* fork unavailable — ideas proceed without privilege intel */ }
    if (privIntel) console.log(`  privileges: ${privIntel.slice(0, 160)}`);
    const out = await suggestAttackIdeas({
      chainId,
      address,
      name,
      shape: "unknown",
      selectors: [],
      detectorSignals: [],
      verifiedSource: src.source,
      privilegeIntel: privIntel || null,
    });
    if (out.reason !== "ok") {
      console.log(`  failed: ${out.reason}${out.detail ? ` — ${out.detail}` : ""}`);
      return 1;
    }
    if (out.ideas.length === 0) {
      console.log("  model returned no ideas (contract looks sound)");
      return 0;
    }
    for (const i of out.ideas) {
      console.log(`\n#${i.rank} [${Math.round(i.confidence * 100)}%] ${i.title}`);
      console.log(`   path: ${i.attackPath}`);
      if (i.preconditions) console.log(`   needs: ${i.preconditions}`);
      if (i.whyHard) console.log(`   blocked by: ${i.whyHard}`);
    }
    console.log(`\nstored (${ideasStats().total} total) — visible on the dashboard Ideas tab`);
    return 0;
  }
  if (mode === "funnel") {
    setMode("scan");
    const { readFunnel, writeFunnelReport } = await import("./funnel.ts");
    const f = readFunnel();
    console.log("== FINDING FUNNEL ==");
    console.log(`  watched (discovery)     ${f.watched}`);
    console.log(`  probed                  ${f.probed}`);
    console.log(`  verified source pulled  ${f.sourced}`);
    console.log(`  code-classified         ${f.classified}`);
    console.log(`  custom/fork-delta       ${f.customish}   <- the real bug surface`);
    console.log(`  under fuzz campaigns    ${f.fuzzed}`);
    console.log(`  cumulative fuzz runs    ${f.runsSoFar}`);
    console.log(`  invariant violations    ${f.violated}`);
    console.log(`  cross-seed VERIFIED     ${f.verified}`);
    console.log(`\n  bottleneck: ${f.bottleneck}`);
    const p = writeFunnelReport();
    console.log(`\nwritten: ${p}`);
    return 0;
  }
  if (mode === "campaign") {
    setMode("scan");
    const { selectCampaignTarget, runCampaignSlice, campaignStats, allCampaigns } = await import("./campaigns.ts");
    // npm forwards the `--` separator literally — drop it before positionals.
    const [chainId, address, runsArg] = rest.filter((a) => a !== "--");
    const stats = campaignStats();
    console.log(`campaigns: ${stats.active}/${stats.total} active, ${stats.runsSoFar} cumulative runs, ${stats.violations} violation(s), ${stats.verified} verified`);
    if (chainId && address) {
      const runs = Number(runsArg) > 0 ? Number(runsArg) : undefined;
      console.log(`running one slice against ${address} (chain ${chainId})…`);
      const r = await runCampaignSlice(chainId, address, {
        forkPort: 8740 + (process.pid % 50),
        chainRpcs: [DEFAULT_FORK_RPC],
      });
      console.log(`  ${r.note}${r.discovered ? `  *** ${r.invariant} VERIFIED ***` : ""}`);
      return r.ran ? 0 : 1;
    }
    const next = selectCampaignTarget();
    if (!next) {
      console.log("no campaigns yet — they register when investigations pull verified source (or run: npm run campaign -- <chainId> <address>)");
      return 0;
    }
    console.log(`next up: ${next.address} (chain ${next.chainId}, ${next.campaign.slices} slices, ${next.campaign.runsSoFar} runs so far) — run: npm run campaign -- ${next.chainId} ${next.address}`);
    for (const c of allCampaigns().slice(0, 10)) {
      console.log(`  ${c.address.slice(0, 12)}… chain ${c.chainId} ${c.shape} — ${c.runsSoFar} runs, ${c.violations} violation(s)`);
    }
    return 0;
  }
  if (mode === "toolbox") {
    setMode("scan");
    // usage: toolbox <chainId> <address> [--warp seconds] [--trace 0xSelector[:args]] [--trace-value wei] [--trace-from 0xCaller]
    const flags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) flags.set(rest[i]!, rest[i + 1] && !rest[i + 1]!.startsWith("--") ? rest[i + 1]! : "");
    }
    // Every toolbox flag takes a value slot, so positionals are the tokens
    // that are neither flags nor flag values.
    const positionals: string[] = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) { i++; continue; }
      positionals.push(rest[i]!);
    }
    const [chainId, address] = positionals;
    if (!chainId || !address) {
      console.log("usage: npm run toolbox -- <chainId> <address> [--warp seconds] [--trace 0xSel[:args]] [--trace-value wei] [--trace-from 0xCaller]");
      console.log("  storage spy · privilege map · role walk · whale finder · optional time warp · optional execution trace");
      console.log("  --trace runs the calldata under the call graph tracer AND the state-diff tracer on the local fork (observation only)");
      return 1;
    }
    const warpSec = Number(flags.get("--warp") ?? 0) || 0;
    const traceSel = flags.get("--trace");
    const traceValue = flags.get("--trace-value") ?? undefined;
    const traceFrom = flags.get("--trace-from") || undefined;
    console.log(`Spawning ephemeral ${chainId} fork for ${toChecksumAddress(address)}…`);
    const port = 8740 + (process.pid % 100);
    // Chain-aware failover: the primary is DEFAULT_FORK_RPC (LAB_FORK_URL when
    // set), but one dead endpoint must never kill an interactive session —
    // fall back to this chain's registered fork-grade endpoints (chainId is
    // enforced by spawnForkWithFailover before a fallback fork is accepted).
    const chainSpec = CHAINS.find((c) => c.id === String(chainId));
    const fallbacks = (chainSpec?.rpcs ?? []).filter((u) => u !== DEFAULT_FORK_RPC);
    let fork: AnvilFork | null = null;
    try {
      fork = await spawnForkWithFailover(DEFAULT_FORK_RPC, port, fallbacks);
      const [slots, privs, roles] = await Promise.all([
        storageSpy(fork, address, 24),
        privilegeMap(fork, address),
        roleEnum(fork, address),
      ]);
      let whales: Whale[] = [];
      try { whales = await whaleFinder(fork, address, 50_000, 10); } catch { /* not a token — fine */ }
      let warp: string | undefined;
      if (warpSec > 0) {
        const ts = await timeWarp(fork, warpSec);
        warp = `clock advanced +${warpSec}s → block timestamp ${ts}`;
      }
      let trace: TraceToolResult | undefined;
      if (traceSel) {
        // --trace 0xSelector[:abi-encoded-args] — the colon form keeps raw
        // calldata copy-paste simple; a bare 0x… hex blob also passes through.
        const [sel, args] = traceSel.split(":");
        const calldata = args ? `${sel}${args.startsWith("0x") ? args.slice(2) : args}` : sel!;
        console.log(`Tracing ${calldata.slice(0, 14)}… against ${toChecksumAddress(address)} (call graph + state diff, local fork)…`);
        trace = await traceCall(fork, address, calldata, { from: traceFrom, valueWei: traceValue });
      }
      console.log(renderToolboxReport(`${chainId}:${address}`, { slots, privileges: privs, roles, whales, warp, trace }));
    } catch (e) {
      console.log(`toolbox failed: ${(e as Error).message.split("\n")[0]}`);
      return 1;
    } finally {
      try { await fork?.stop(); } catch { /* already gone */ }
    }
    return 0;
  }
  if (mode === "upgradediff") {
    setMode("scan");
    // usage: upgradediff <proxy> <oldImpl> <newImpl> [chainId]
    const [proxy, oldImpl, newImpl, chainId] = rest;
    if (!proxy || !oldImpl || !newImpl) {
      console.log("usage: npm run upgradediff -- <proxy> <oldImpl> <newImpl> [chainId=1]");
      return 1;
    }
    console.log(`Upgrade-diff triage for ${proxy} (${oldImpl.slice(0, 10)}… -> ${newImpl.slice(0, 10)}…)…`);
    const r = await triageUpgradeDiff(chainId ?? "1", proxy, oldImpl, newImpl);
    if (r.verdict) {
      console.log(`  risk: ${r.verdict.risk} (confidence ${r.verdict.confidence.toFixed(2)})`);
      console.log(`  summary: ${r.verdict.summary}`);
      if (r.verdict.attackHypothesis) console.log(`  attack: ${r.verdict.attackHypothesis}`);
    } else {
      console.log(`  no verdict: ${r.reason}`);
    }
    return r.verdict ? 0 : 1;
  }
  if (mode === "package") {
    setMode("daemon");
    // usage: package <verifiedEvidence.json> [program]
    const [evidencePath, program] = rest;
    if (!evidencePath) {
      console.log("usage: npm run package -- reports/verify/<file>.json [program]");
      return 1;
    }
    try {
      const v = JSON.parse(readFileSync(evidencePath, "utf8"));
      const pkg = buildReportPackage(v, program);
      if (!pkg) { console.log("evidence was not a confirmed verification — refusing to package"); return 1; }
      console.log(`package ready: ${pkg.dir}`);
      console.log(`  submission: ${pkg.submissionPath}`);
      if (pkg.pocPath) console.log(`  poc:        ${pkg.pocPath}`);
    } catch (e) {
      console.error(`packaging failed: ${(e as Error).message}`);
      return 1;
    }
    return 0;
  }
  if (mode === "gov") {
    setMode("gov");
    const flagsOnly = rest.filter((a) => !a.startsWith("--"));
    const reports = await runGovernanceScan(flagsOnly);
    writeFileSync(join(REPORT_DIR, "GOVERNANCE.md"), writeGovernanceReport(reports));
    console.log(`Governance report: ${join(REPORT_DIR, "GOVERNANCE.md")}`);
    for (const r of reports) {
      for (const f of r.authorities) {
        console.log(`  [${r.chain}] ${f.kind} ${f.label}${f.threshold !== undefined ? ` (threshold ${f.threshold}/${f.owners!.length})` : ""}${f.risks.length ? ` — ${f.risks.join("; ")}` : ""}`);
      }
    }
    logEvent("gov", `governance scan complete — ${reports.length} target(s)`);
    return 0;
  }
  if (mode === "osint") {
    setMode("osint");
    const flags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) flags.set(rest[i]!, rest[i + 1] ?? "");
    }
    const top = parseInt(flags.get("--top") ?? "6", 10);
    console.log("OSINT cycle (free, read-only): DefiLlama + rekt.news + " + (searchProvider() === "tavily" ? `Tavily (${tavilyKeyPoolSize()}-key pool)` : "DuckDuckGo Lite"));
    const s = await runOsintCycle({ topSearch: top });
    console.log(`  unaudited-new candidates: ${s.unauditedNew.length}`);
    console.log(`  rekt.news headlines:      ${s.headlines.length}`);
    console.log(`  searches with results:    ${s.searched.length} (provider: ${s.provider})`);
    if (s.seeded) {
      const n = s.seeded.filter((x) => x.action === "seeded").length;
      console.log(`  watchlist seeded:         ${n} new enlisted (of ${s.seeded.length} candidates evaluated)`);
    }
    if (s.smallLane) {
      console.log(`  small-TVL lane (< $${Math.round(s.smallLane.ceiling).toLocaleString()}):  ${s.smallLane.top.length} ranked candidate(s), ${s.smallLane.seeded} enlisted`);
    }
    console.log(`Report: reports/INTEL.md`);
    logEvent("osint", `osint cycle complete — ${s.unauditedNew.length} candidate(s), ${s.headlines.length} headline(s), ${s.searched.length} search group(s) via ${s.provider}`);
    return 0;
  }
  if (mode === "sieve") {
    setMode("scan");
    const {
      startScrape,
      pollScrape,
      followUpScrape,
      resumeSieveRuns,
      sieveStats,
      sieveCredits,
      sieveAvailable,
      loadSieveStore,
      downloadSieveFiles,
      renderSieveReport,
      sieveHealthLine,
    } = await import("./sieve.ts");
    const sub = rest[0] && !rest[0].startsWith("--") ? rest[0] : "status";
    const flags = new Map<string, string[]>();
    for (let i = 0; i < rest.length; i++) {
      if (!rest[i]!.startsWith("--")) continue;
      const key = rest[i]!;
      const val = rest[i + 1] && !rest[i + 1]!.startsWith("--") ? rest[++i]! : "";
      (flags.get(key) ?? flags.set(key, []).get(key)!).push(val);
    }
    const one = (k: string) => flags.get(k)?.[0];
    const compliance = one("--compliance");
    if (compliance && !["conservative", "regular", "yolo"].includes(compliance)) {
      console.log(`--compliance must be conservative|regular|yolo (got \"${compliance}\"). \"regular\" is the default; \"yolo\" relaxes the site-access policy and is your call.`);
      return 2;
    }
    if (sub === "status") {
      const st = sieveStats();
      console.log(`Sieve: ${st.available ? "configured" : "NOT configured (no SIEVE_API_KEY — run npm run sieve-login)"} — ${st.base}`);
      console.log(`  runs today: ${st.runsStartedToday}/${st.dailyMax} (LAB_SIEVE_DAILY_MAX)  |  pending ${st.pending}  done ${st.done} (${st.clean} schema-clean, ${st.dirty} NOT clean)  refused ${st.refused}  errors ${st.errored}`);
      if (st.orphanStarts > 0) {
        console.log(`  ${st.orphanStarts} start outcome(s) UNKNOWN (timed out after sending — deliberately not retried; check the account's runs before starting another)`);
      }
      const sessions = Object.values(loadSieveStore().sessions).sort((a, b) => b.created - a.created).slice(0, 15);
      for (const s of sessions) {
        console.log(`  ${s.session_id}  ${s.status.padEnd(7)} turns=${s.turns} schema=${s.conformance ?? "n/a"}${s.status === "done" && s.clean !== true ? " NOT-CLEAN" : ""}  ${new Date(s.created).toISOString().slice(0, 16)}  ${(s.instruction || "").slice(0, 48)}`);
      }
      if (sieveAvailable()) {
        const c = await sieveCredits();
        if (c) console.log(`  credits: ${c.remaining ?? "?"} remaining of ${c.limit ?? "?"} (plan ${c.plan ?? "?"})`);
      }
      console.log(`  inventory: reports/SIEVE.md`);
      return 0;
    }
    if (!sieveAvailable()) {
      console.log("Sieve is not configured — run `npm run sieve-login` (one browser approval) or add SIEVE_API_KEY to agent/.env.");
      return 1;
    }
    if (sub === "credits") {
      const c = await sieveCredits();
      if (!c) {
        console.log("credits unavailable (key rejected or network error)");
        return 1;
      }
      console.log(`plan ${c.plan ?? "?"}: ${c.used ?? "?"} used, ${c.remaining ?? "?"} remaining of ${c.limit ?? "?"}`);
      return 0;
    }
    if (sub === "resume") {
      const r = await resumeSieveRuns({ maxSessions: 5, force: true });
      console.log(`resume: ${r.polled} polled of ${r.pending} pending — ${r.done} done, ${r.refused} refused, ${r.errors} error(s), 0 duplicates started`);
      console.log(`inventory: ${renderSieveReport()}`);
      return r.errors > 0 ? 1 : 0;
    }
    if (sub === "download") {
      const id = rest[1] && !rest[1].startsWith("--") ? rest[1] : one("--session");
      if (!id) {
        console.log("sieve download <session_id>");
        return 2;
      }
      const files = await downloadSieveFiles(id);
      console.log(files.length > 0 ? `downloaded:\n  ${files.join("\n  ")}` : "no files for that session (or download failed)");
      return files.length > 0 ? 0 : 1;
    }
    if (sub === "followup") {
      const id = rest[1] && !rest[1].startsWith("--") ? rest[1] : one("--session");
      const instruction = one("--instruction");
      if (!id || !instruction) {
        console.log('sieve followup <session_id> --instruction "<follow-up in plain language>"');
        return 2;
      }
      // The turn count is recorded before the message is sent, and the poll
      // below only accepts a terminal status whose turn count advanced —
      // otherwise it would read the PREVIOUS answer.
      const st = await followUpScrape(
        id,
        { instruction, target_urls: flags.get("--url"), fields: flags.get("--field"), compliance_mode: compliance as "regular" | undefined },
        { onStatus: (s, n) => console.log(`  [poll ${n}] ${s.status} turns=${s.turns}`) }
      );
      console.log(`turn complete: ${st.status} — turns now ${st.turns}, schema ${st.conformance}${st.clean ? " (clean)" : " (NOT clean)"}`);
      if (st.summary) console.log(`  summary: ${st.summary}`);
      return st.status === "done" ? 0 : 3;
    }
    if (sub === "run") {
      const instruction = one("--instruction") ?? rest.slice(1).filter((a) => !a.startsWith("--")).join(" ").trim();
      if (!instruction) {
        console.log('sieve run --instruction "<plain language instruction>" [--url <page>]… [--field <name>]… [--shape long|wide] [--compliance regular] [--file <doc>] [--output-schema <file.json>] [--force] [--wait]');
        return 2;
      }
      const jsonFile = (p: string | undefined) => (p ? (JSON.parse(readFileSync(p, "utf8")) as unknown) : undefined);
      const r = await startScrape(
        {
          instruction,
          target_urls: flags.get("--url"),
          fields: flags.get("--field"),
          schema: jsonFile(one("--schema")),
          output_schema: jsonFile(one("--output-schema")),
          table_shape: one("--shape") as "long" | "wide" | undefined,
          compliance_mode: compliance as "conservative" | "regular" | "yolo" | undefined,
          file: one("--file"),
        },
        { ignoreBudget: flags.has("--force") }
      );
      if (!r.ok) {
        console.error(`sieve start failed: ${r.error.message}`);
        if (r.mayHaveStarted) console.error("OUTCOME UNKNOWN: the request was sent and may have created a run — NOT retried, check the account's runs before starting another.");
        return 1;
      }
      console.log(`session ${r.session_id} queued — poll ${r.poll ?? `/api/scrapes/${r.session_id}`}`);
      console.log(`session_id persisted to reports/sieve-state.json (a crash resumes it; nothing duplicate is started)`);
      if (!flags.has("--wait")) {
        console.log("not waiting — the daemon (or `npm run sieve -- resume`) polls it; results land in reports/SIEVE.md");
        return 0;
      }
      const st = await pollScrape(r.session_id, { onStatus: (s, n) => console.log(`  [poll ${n}] ${s.status}${s.turns ? ` turns=${s.turns}` : ""}`) });
      if (st.status === "refused") {
        console.log(`refused (${st.refusal?.code ?? "no code"}) — the run never started${st.refusal?.code === "quota" ? " (credit limit)" : ""}: ${st.refusal?.message ?? ""}`);
        return 3;
      }
      console.log(`done — schema ${st.conformance}${st.clean ? " (clean)" : " (NOT clean — do not present as validated data)"}`);
      if (st.summary) console.log(`  summary: ${st.summary}`);
      const files = await downloadSieveFiles(r.session_id);
      for (const f of st.files ?? []) console.log(`  file ${f.name}${f.size ? ` (${f.size} bytes)` : ""} -> ${files.find((p) => p.endsWith(f.name)) ?? "download failed"}`);
      console.log(`inventory: ${renderSieveReport()}`);
      console.log(sieveHealthLine());
      return 0;
    }
    return usage();
  }
  if (mode === "llama") {
    setMode("scan");
    const { runSmallLane, renderSmallTargets, llamaSeedsByChain } = await import("./llamatargets.ts");
    const flags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) flags.set(rest[i]!, rest[i + 1] ?? "");
    }
    const limit = parseInt(flags.get("--limit") ?? "25", 10) || 25;
    const seed = !rest.includes("--no-seed");
    console.log(`DefiLlama small-TVL lane (TVL < $1M, multi-chain): fresh + unaudited + tiny = highest bug base rate${seed ? "" : "  (seeding off)"}`);
    const lane = await runSmallLane({ seed, limit });
    for (const line of renderSmallTargets(lane.candidates)) console.log(line);
    const seededN = lane.seeds.filter((x) => x.action === "seeded").length;
    const actions = new Map<string, number>();
    for (const x of lane.seeds) actions.set(x.action, (actions.get(x.action) ?? 0) + 1);
    console.log(`\nseeds: ${seededN} recorded — ` + [...actions.entries()].map(([k, v]) => `${k}=${v}`).join(", "));
    const byChain = llamaSeedsByChain();
    if (Object.keys(byChain).length > 0) {
      console.log("registry: " + Object.entries(byChain).map(([c, n]) => `${c}=${n}`).join(", ") + " (non-ethereum seeds are probed by the scanner on their own forks)");
    }
    logEvent("scan", `llama small-TVL pass: ${lane.candidates.length} candidate(s) under ceiling, ${seededN} seed(s) recorded across chains`);
    return 0;
  }
  if (mode === "curiosity") {
    setMode("scan");
    const flags = new Map<string, string>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) flags.set(rest[i]!, rest[i + 1] ?? "");
    }
    const forkUrl = flags.get("--fork-url") ?? undefined;
    const port = parseInt(flags.get("--port") ?? "8554", 10);
    const budget = parseInt(flags.get("--budget") ?? "6", 10);
    const targets = rest.filter((a) => !a.startsWith("--"));
    const watchAddrs = Object.values(snapshot().watchlist).map((w) => w.address);
    const candidates = [...new Set([...targets, ...watchAddrs])].filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a));
    if (candidates.length === 0) {
      console.log("curiosity: no candidates — pass 0x… addresses or seed the watchlist (npm run scan / npm run osint)");
      return 1;
    }
    console.log(`== Curiosity cycle: ${candidates.length} candidate(s), budget ${budget} question(s) ==`);
    let fork: AnvilFork | null = null;
    try {
      fork = forkUrl ? new AnvilFork(forkUrl, port) : await spawnForkWithFailover(DEFAULT_FORK_RPC, port, []);
      await fork.start();
      const bountyAddrs = new Set(Object.values(snapshot().watchlist).filter((w) => w.bounty).map((w) => w.address.toLowerCase()));
      const cq = await runCuriosityCycle(fork, candidates, { budget, bountySet: bountyAddrs });
      for (const n of cq.notes) console.log(`  ? ${n}`);
      const st = curiosityStats();
      console.log(`\nasked ${cq.asked}, signals ${cq.signals} (lifetime: ${st.asked} asked / ${st.signals} signals)`);
      logEvent("scan", `curiosity cycle: ${cq.asked} asked, ${cq.signals} signal(s) over ${candidates.length} candidate(s)`);
      return cq.signals > 0 ? 0 : 0; // signals re-flag targets; exit code stays informational
    } catch (e) {
      console.log(`curiosity cycle failed: ${(e as Error).message}`);
      return 1;
    } finally {
      fork?.stop();
    }
  }
  if (mode === "harness") {
    setMode("harness");
    const challenges = discoverChallenges();
    let discoveries = 0;
    let covered = 0;
    for (const c of challenges) {
      let sources: string[] = [];
      try {
        sources = c.sources.map((p) => readFileSync(p, "utf8"));
      } catch {
        continue;
      }
      const gen = buildHarness({ challengeName: c.name, sources, sourcePaths: c.sources, mode: "source" }, 0);
      if (!gen) {
        console.log(`>> ${c.name}: no harnessable shape (lender/vault/token) — falls through to recipes/probes`);
        recordGenResult(c.name, { shape: "none", result: "skipped", note: "no harnessable shape — recipes/probes path" });
        continue;
      }
      covered++;
      process.stdout.write(`>> ${c.name} <- generic ${gen.shape} harness (${gen.skippedFns.length} skipped entrypoint(s)) ... `);
      const res = await runTestContract(gen.contractName);
      const ev = evaluateGenHarness(res.output);
      recordGenResult(c.name, {
        shape: gen.shape,
        result: ev.discovered ? "discovered" : ev.compileError || ev.setupFailed ? "error" : "held",
        invariant: ev.discovered ? ev.invariant : undefined,
      });
      // LEARNING LOOP: same store as lab/daemon/fork modes — one shape's
      // history sharpens every future harness of that shape.
      try {
        if (ev.discovered) recordViolation(gen.shape, { invariant: ev.invariant, path: ev.path, profitWei: ev.profitWei });
        else if (ev.compileError) recordGenError(gen.shape, "generic harness failed to compile");
        else if (ev.setupFailed) recordGenError(gen.shape, "setUp failed (shape heuristics did not fit)");
        else recordHeld(gen.shape);
      } catch {
        // learning must never turn a discovery run into an error
      }
      if (ev.discovered) {
        discoveries++;
        console.log(`DISCOVERED: invariant "${ev.invariant}" violated${ev.path ? ` via ${ev.path}` : ""}`);
        logEvent("lab", `${c.name}: GENERIC DISCOVERY — invariant ${ev.invariant} violated${ev.path ? ` via ${ev.path}` : ""}`);
      } else if (ev.compileError) {
        console.log("harness failed to compile (agent bug -- not a result)");
        if (ev.compileErrorDetail) console.log(`     compiler said: ${ev.compileErrorDetail.split("\n")[0]}`);
      } else if (ev.setupFailed) {
        console.log("setUp failed (shape heuristics did not fit this challenge)");
      } else {
        console.log("invariants held (no universal property violated)");
      }
      archiveGenHarness(gen.filePath, gen.contractName);
    }
    console.log(`\nGeneric engine: ${covered} challenge(s) harnessable, ${discoveries} universal-property violation(s) found.`);
    logEvent("lab", `generic harness mode: ${covered} harnessable, ${discoveries} discovery(ies)`);
    return 0;
  }
  if (mode === "synth") {
    setMode("synth");
    const challenges = discoverChallenges();
    for (const c of challenges) {
      const synth = synthesizeHarness(c.name, 0);
      if (!synth) {
        console.log(`>> ${c.name}: no synth recipe — skipped`);
        continue;
      }
      process.stdout.write(`>> ${c.name} <- invariant fuzzing (pool never drained) ... `);
      const res = await runTestContract(synth.contractName);
      const ev = evaluateSynthOutput(res.output);
      if (ev.discovered) {
        console.log(`DISCOVERED: ${ev.path || synth.recipe.expectedFinding}`);
        logEvent("lab", `${c.name}: fuzz synthesis DISCOVERED a drain -- ${synth.recipe.expectedFinding}${ev.path ? ` via ${ev.path}` : ""}`);
      } else if (ev.compileError) {
        console.log("synth harness failed to compile (agent bug -- not a result)");
        if (ev.compileErrorDetail) console.log(`     compiler said: ${ev.compileErrorDetail.split("\n")[0]}`);
      } else {
        console.log("invariant held (no drain found)");
      }
      archiveHarness(synth.filePath, synth.contractName);
    }
    return 0;
  }
  if (mode === "snapshot") {
    const hydrated = hydrateFromDisk();
    writeFileSync(join(REPORT_DIR, "dashboard.html"), renderStaticHtml(snapshot()));
    console.log(hydrated ? "Wrote reports/dashboard.html (last session)" : "Wrote reports/dashboard.html (empty state)");
    return 0;
  }
  if (mode === "ui") {
    const hydrated = hydrateFromDisk();
    // NO staticState here: a seeded static render flags the page
    // STATIC_EXPORT, which disables polling — the standalone dashboard froze
    // on its boot snapshot forever (header read "static snapshot", new stat
    // cards never appeared) even though /api/state on the same server serves
    // the LIVE enriched payload (triage, campaigns, canon, funnel). The page
    // paints from /api/state on boot and then polls every 2s.
    const url = await startUiServer(undefined);
    console.log(hydrated ? `Dashboard (last session, live): ${url}` : `Dashboard (no session recorded yet): ${url}`);
    await new Promise(() => {}); // serve until Ctrl-C
  }
  if (mode === "daemon") {
    const flags = new Map<string, string[]>();
    for (let i = 0; i < rest.length; i++) {
      if (rest[i]!.startsWith("--")) {
        const key = rest[i]!;
        const val = rest[i + 1] && !rest[i + 1]!.startsWith("--") ? rest[++i]! : "";
        (flags.get(key) ?? flags.set(key, []).get(key)!).push(val);
      }
    }
    await runDaemon({
      intervalSec: parseInt(flags.get("--interval")?.[0] ?? "120", 10),
      maxAttempts: parseInt(flags.get("--max-attempts")?.[0] ?? "8", 10),
      forkUrl: flags.get("--fork-url")?.[0] ?? null,
      attachRpc: flags.get("--attach")?.[0] ?? null,
      watchlist: flags.get("--watch") ?? [],
      workers: workerCount(flags.get("--workers")?.[0], 4),
      probeWorkers: workerCount(flags.get("--probe-workers")?.[0], 2),
      scanEveryCycles: parseInt(flags.get("--scan-every")?.[0] ?? "10", 10),
      govEveryCycles: parseInt(flags.get("--gov-every")?.[0] ?? "20", 10),
      osintEveryCycles: parseInt(flags.get("--osint-every")?.[0] ?? "12", 10),
      digestHours: parseFloat(flags.get("--digest-hours")?.[0] ?? "24"),
      respond: flags.get("--respond")?.[0] === "0" ? 0 : 1,
      mainnetOnly: flags.has("--mainnet-only"),
      labDisabled: flags.has("--no-lab"),
      scanTopN: parseInt(flags.get("--scan-top")?.[0] ?? "8", 10) || 8,
      scanBlocksBack: parseInt(flags.get("--scan-blocks")?.[0] ?? "80000", 10) || 80000,
      daemonId: flags.get("--daemon-id")?.[0] ?? "default",
      uiPort: uiUrl ? parseInt(uiUrl.slice(uiUrl.lastIndexOf(":") + 1), 10) : null,
      chainOffset: parseInt(flags.get("--chain-offset")?.[0] ?? "0", 10) || 0,
    });
    return 0; // unreachable — daemon runs forever
  }
  return usage();
}

process.exit(await main());
