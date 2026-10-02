// Autonomous daemon: the agent hunts continuously — in parallel.
//
//   - LAB WATCH: solves challenges concurrently (worker pool); re-solves
//     automatically when a challenge file changes.
//   - FORK WATCH: re-probes the mainnet watchlist every cycle, one local
//     read-only fork per worker slot (ports 8550+), so pools are probed in
//     parallel. On a reproduced drain the daemon AUTO-DRAFTS a bug-bounty
//     report (the legal artifact) — nothing is ever broadcast.
//   - ROTATION: one chain of the full-market scanner per scheduled cycle.
//   - GOVERNANCE: read-only authority analysis every scheduled cycle.
import { setTimeout as sleep } from "node:timers/promises";
import { execFileSync } from "node:child_process";
import { discoverChallenges, labDirFingerprint, type Challenge } from "./discovery.ts";
import { runPool } from "./pool.ts";
import { solveChallenge } from "./solve.ts";
import { AnvilFork, reconPool, simulateOnFork, spawnForkWithFailover } from "./fork.ts";
import { runScan } from "./scanner.ts";
import { runGovernanceScan, writeGovernanceReport } from "./governance.ts";
import { runOsintCycle } from "./osint.ts";
import { resumeSieveRuns, sieveAvailable } from "./sieve.ts";
import { seedLzKnowledge } from "./lz.ts";
import { runSolanaWatch, seedSolanaWatchlist } from "./solana.ts";
import { verifyAndReport } from "./verify.ts";
import { runIncidentSweep } from "./incidents.ts";
import { skillCount } from "./skills.ts";
import { ensureHealthyRpc, pickHealthyRpc, ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";
import { redactRpcUrl } from "./safety.ts";
import { setMode, setCycle, upsertWatch, logEvent, setKbWins, snapshot, hydrateFromDisk, pruneDemoState, registerDaemon, daemonHeartbeat } from "./bus.ts";
import { hostname } from "node:os";
import { triageHealth } from "./triage.ts";
import { dueTriage, triageQueueStats } from "./triageQueue.ts";
import { untestedTargets, ledgerStats } from "./ledger.ts";
import { consolidateMemory } from "./consolidate.ts";
import { triageUpgradeDiff } from "./upgradediff.ts";
import { scanForkPriors } from "./forkgraph.ts";
import { upsertWatch as _upsertWatch } from "./bus.ts";

// ---------------- HANG GUARD ----------------
// Every phase below is individually try/caught, but try/catch cannot save a
// phase that never RETURNS: a degraded RPC endpoint turns a bounded 12s call
// into 8 × 12s failover, and a phase composing hundreds of those calls froze
// mainnet-1 for 5.7h (heartbeat stale, cycle stuck, UI serving stale state)
// while every layer of error handling looked perfectly fine. Each long phase
// therefore races a wall-clock deadline: on deadline the cycle moves on and
// the next cycle retries fresh. An in-flight guard keeps an abandoned phase
// from overlapping its own next scheduled run.
const PHASE_DEADLINE_MS = (parseInt(process.env.PHASE_DEADLINE_MIN ?? "30", 10) || 30) * 60_000;
const inFlightPhases = new Map<string, Promise<unknown>>();

/** Run one daemon phase under a wall-clock deadline. Returns undefined when
 * the phase was skipped (previous run still in flight) or hit the deadline. */
async function phaseDeadline<T>(label: string, ms: number, start: () => Promise<T>): Promise<T | undefined> {
  const prev = inFlightPhases.get(label);
  if (prev) {
    logEvent("daemon", `phase ${label}: previous run still in flight (past deadline?) — skipping this cycle`);
    return undefined;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`phase ${label} exceeded ${Math.round(ms / 60_000)}min wall-clock deadline`)), ms);
  });
  const p = start();
  inFlightPhases.set(label, p);
  // Remove the in-flight marker only when the underlying work actually
  // settles — a deadline-abandoned phase stays marked and blocks re-entry.
  p.finally(() => {
    if (inFlightPhases.get(label) === p) inFlightPhases.delete(label);
  }).catch(() => {}); // settled-with-error is handled by the caller's race
  try {
    return await Promise.race([p, timeout]);
  } catch (e) {
    logEvent("daemon", `phase ${label} aborted (continuing): ${(e as Error).message}`);
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

/** Last known recon shape for a watchlist pool ("" if never probed). */
function watchShape(poolAddr: string): string {
  return snapshot().watchlist[poolAddr]?.shape ?? "";
}

/** Spawn a local fork, retrying across verified-mainnet fallback endpoints.
 * eth_chainId probes pass even on rate-limited nodes that then refuse the
 * heavy fork fetch (error -32046 "Cannot fulfill request") — the only real
 * proof is a completed fork boot, so that is what we retry on. */
/** Liveness check for a reused fork: the shared watch fork can die mid-life
 * (upstream RPC throttling kills anvil) while the daemon still holds the
 * object — every probe then fetch-fails until recycle. Verify it answers
 * before reusing; a dead fork is stopped, nulled, and replaced. */
async function forkAlive(f: AnvilFork): Promise<boolean> {
  try {
    await f.rpc("eth_blockNumber");
    return true;
  } catch {
    return false;
  }
}

async function spawnDaemonFork(forkUrl: string, port: number): Promise<AnvilFork> {
  // Cap failover attempts — trying all 8 endpoints × 30s each stalls the hunt.
  const fallbacks = ETHEREUM_FORK_FALLBACKS.filter((u) => u !== forkUrl).slice(0, 2);
  const fork = await spawnForkWithFailover(forkUrl, port, fallbacks);
  if (fork.forkUrl !== forkUrl) {
    console.log(`[daemon]   fork source ${redactRpcUrl(forkUrl)} failed — succeeded on fallback ${redactRpcUrl(fork.forkUrl)}`);
  }
  return fork;
}
import { retryProbe, probeEntryPoints } from "./fork.ts";
import { renderStaticHtml } from "./server.ts";
import { runCampaignSlice, selectCampaignBatchSharded, campaignStats } from "./campaigns.ts";
import { targetOutcome } from "./genlearn.ts";
import { readFunnel } from "./funnel.ts";
import { CHAINS } from "./scan.ts";
import { writeDigest } from "./digest.ts";
import { runResponderSweep } from "./responder.ts";
import { investigateUnknownShape } from "./investigate.ts";
import { drainTriageQueue } from "./triagedrain.ts";
import { runBacklogTick } from "./backlogtriage.ts";
import { learnFromProbe } from "./memory.ts";
import { captureProvenDrain, distillPending } from "./techniques.ts";
import { countWins } from "./knowledge.ts";
import { isActionableFinding, isProductionTarget } from "./findings.ts";
import { runCuriosityCycle, curiosityStats } from "./curiosity.ts";
import { runVaultLoop, enrollBacklog } from "./vaultloop.ts";

/** Chain id of a local fork (decimal string), "1" on any failure — the
 * daemon's watchlist is Ethereum-only today. Cached per fork instance so the
 * synchronous probe path can read it without an RPC round-trip. */
const forkChainIdCache = new WeakMap<object, string>();
function forkChainId(fork: AnvilFork): string {
  return forkChainIdCache.get(fork) ?? "1";
}
async function rememberChainId(fork: AnvilFork): Promise<string> {
  let id = "1";
  try {
    id = BigInt(await fork.rpc("eth_chainId")).toString();
  } catch {}
  forkChainIdCache.set(fork, id);
  return id;
}
import { writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, DEFAULT_FORK_RPC } from "./config.ts";

// A 24/7 process must never die silently: anything uncaught gets persisted
// with a stack trace before the exit, so the crash can be diagnosed (and the
// service supervisor restarts us immediately after).
process.on("uncaughtException", (e) => {
  try {
    appendFileSync(join(REPORT_DIR, "daemon.crash.log"), `\n[${new Date().toISOString()}] uncaughtException:\n${e.stack ?? e.message}\n`);
  } catch {}
  process.exit(1);
});
process.on("unhandledRejection", (e) => {
  try {
    appendFileSync(join(REPORT_DIR, "daemon.crash.log"), `\n[${new Date().toISOString()}] unhandledRejection:\n${(e as Error)?.stack ?? String(e)}\n`);
  } catch {}
});

// Own the log file: when running under a supervisor that cannot redirect
// stdout (launchd + TCC-protected dirs), the process tees its own console
// output to reports/daemon.log so the hunt is always observable.
const TEE_PATH = join(REPORT_DIR, "daemon.log");
const origStdoutWrite = process.stdout.write.bind(process.stdout);
const origStderrWrite = process.stderr.write.bind(process.stderr);
process.stdout.write = ((chunk: any, ...rest: any[]) => {
  try {
    appendFileSync(TEE_PATH, typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
  } catch {}
  return origStdoutWrite(chunk, ...rest);
}) as typeof process.stdout.write;
process.stderr.write = ((chunk: any, ...rest: any[]) => {
  try {
    appendFileSync(TEE_PATH, typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
  } catch {}
  return origStderrWrite(chunk, ...rest);
}) as typeof process.stderr.write;

export interface DaemonOptions {
  intervalSec: number;
  maxAttempts: number;
  forkUrl: string | null;
  attachRpc: string | null;
  watchlist: string[];
  /** Concurrent lab-solve workers (forge processes). */
  workers: number;
  /** Concurrent watchlist probes (local forks). */
  probeWorkers: number;
  /** Run one chain of the full-market scanner every N cycles (0 = never). */
  scanEveryCycles: number;
  /** Run the read-only governance/authority scan every N cycles (0 = never). */
  govEveryCycles: number;
  /** Run the free OSINT intel cycle every N cycles (0 = never). */
  osintEveryCycles: number;
  /** Write a digest report every N hours (0 = never). */
  digestHours: number;
  /** Run the first-responder balance watchdog every cycle (0 = off). */
  respond: number;
  /** Skip lab-challenge solving; hunt production chains only. */
  mainnetOnly: boolean;
  /** Lab work single-owner: this instance skips lab solving so exactly one
   * fleet member owns the shared test/agent dir (compile races otherwise
   * misattribute techniques when daemons archive each other's harnesses). */
  labDisabled: boolean;
  /** Targets to fork-probe per chain during rotation scans. */
  scanTopN: number;
  /** Factory-event lookback for rotation scans (smaller = faster). */
  scanBlocksBack: number;
  /** Instance name in the dashboard's Daemons tab (default "default"). */
  daemonId: string;
  /** Port to serve this instance's dashboard on (null = no UI). */
  uiPort: number | null;
  /** Starting offset into the rotating chain scan so N daemons with different
   * ids cover different chains first instead of scanning in lockstep. */
  chainOffset: number;}/** Chains the rotating scanner covers. Keep in sync with CHAINS in scan.ts
 * (superset is fine — the scanner skips chains it cannot reach). New 2026-09:
 * linea, scroll, berachain, blast, hyperevm. */
const CHAIN_NAMES = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "sonic", "gnosis", "fantom", "celo", "evmos", "linea", "scroll", "berachain", "blast", "hyperevm", "robinhood"];

/** MARKET SHARDING: with N daemons running, each owns the chains whose index
 * in CHAIN_NAMES satisfies `index % N === offset` — the whole market gets
 * covered once instead of 5 daemons scanning in duplicate. Fleet size comes
 * from LAB_FLEET_SIZE (run-multi.sh sets it; a solo daemon defaults to 1 and
 * covers everything). Deterministic, restart-stable, no coordination needed. */
function fleetSize(): number {
  return Math.max(1, parseInt(process.env.LAB_FLEET_SIZE ?? "1", 10) || 1);
}
function ownedChains(offset: number): string[] {
  const n = Math.min(fleetSize(), CHAIN_NAMES.length);
  const off = ((offset % n) + n) % n;
  const owned = CHAIN_NAMES.filter((_, i) => i % n === off);
  return owned.length > 0 ? owned : CHAIN_NAMES;
}
/** Stable shard assignment for watchlist targets (same modulo scheme on the
 * address hash) so exactly one daemon probes each enlisted target. */
function ownsTarget(target: string, offset: number): boolean {
  const n = fleetSize();
  if (n <= 1) return true;
  let h = 0;
  for (let i = 0; i < target.length; i++) h = (h * 31 + target.charCodeAt(i)) >>> 0;
  return h % n === ((offset % n) + n) % n;
}
/** Stable per-daemon anvil port base (8550..8599) derived from the instance
 * id — two daemons with different ids never bind the same port. */
function daemonPortBase(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return 8550 + (h % 50);
}

export async function runDaemon(opts: DaemonOptions): Promise<never> {
  // A 24/7 service restarts (crash, update, host reboot) and must not lose
  // its watchlist memory or finding history: hydrate the persisted session
  // before anything writes. setMode/setCycle below overwrite the stale
  // mode/cycle fields; events, watchlist, and findings carry over.
  hydrateFromDisk();
  // Cross-chain knowledge base: seed the LayerZero threat classes once so
  // every future triage recalls them (idempotent, best-effort).
  seedSolanaWatchlist(); // idempotent — "solana:" namespaced entries, EVM keys untouched
  seedLzKnowledge().then((n) => {
    if (n > 0) console.log(`[daemon] seeded ${n} LayerZero threat-class memories`);
  }).catch(() => {});
  if (opts.mainnetOnly) {
    pruneDemoState();
    setCycle(0);
  }
  const solvedNames = new Set<string>();
  let lastLabFp = "";
  let cycle = 0;
  let scanCursor = Math.abs(opts.chainOffset) % CHAIN_NAMES.length;
  /** One bounty draft per pool per daemon session (no spam). */
  const draftedPools = new Set<string>();
  // Recycled fork for attached mode; watchFork reused across watchlist cycles.
  // Adaptive re-probe cooldown: failKey -> cycle of the last adaptive attempt.
  // Same target + same decoded reason within ADAPTIVE_COOLDOWN_CYCLES = skip
  // the triage spend; the cache is pruned each cycle to stay bounded.
  const ADAPTIVE_COOLDOWN_CYCLES = 10;
  const adaptiveCooldown = new Map<string, number>();  let attachedFork: AnvilFork | null = null;
  let watchFork: AnvilFork | null = null;
  // Per-daemon port base so N concurrent daemons never collide on anvil
  // ports: watch fork on base, per-pool fallback forks on base+50+i.
  // Deterministic per instance id (stable across restarts), spread 8550-8649.
  const WATCH_FORK_PORT = daemonPortBase(opts.daemonId);
  const poolForkPort = (i: number) => WATCH_FORK_PORT + 50 + (i % 49);
  const FORK_RECYCLE_CYCLES = 30;
  let lastForkCycle = 0;
  let lastDigestAt = 0;
  let lastConsolidateCycle = 0;
  const CONSOLIDATE_EVERY_CYCLES = 288; // ~daily at the 45s scan interval

  // Register this instance in the shared registry so the dashboard's Daemons
  // tab shows every running hunt (multi-daemon setups) with live heartbeats.
  const shard = ownedChains(opts.chainOffset);
  registerDaemon({
    id: opts.daemonId,
    pid: process.pid,
    host: hostname(),
    startedAt: Date.now(),
    cycle: 0,
    mode: opts.mainnetOnly ? "mainnet-only" : "lab+mainnet",
    uiPort: opts.uiPort,
    intervalSec: opts.intervalSec,
    mainnetOnly: opts.mainnetOnly,
    watchlistSize: opts.watchlist.length,
    chains: shard.join(","),
  });

  setMode(
    `daemon${opts.mainnetOnly ? " [MAINNET]" : ""} (every ${opts.intervalSec}s, ${opts.workers} solve workers, ${opts.probeWorkers} probe workers` +
      `${opts.watchlist.length ? `, ${opts.watchlist.length} watched pool(s)` : ""}` +
      `${opts.scanEveryCycles > 0 ? `, full-scan rotation every ${opts.scanEveryCycles} cycles (top ${opts.scanTopN})` : ""}` +
      `${opts.govEveryCycles > 0 ? `, governance every ${opts.govEveryCycles} cycles` : ""}` +
      `${opts.osintEveryCycles > 0 ? `, osint intel every ${opts.osintEveryCycles} cycles` : ""})`
  );
  logEvent(
    "daemon",
    `hunt started — ${opts.mainnetOnly ? "MAINNET ONLY" : "lab watch +"} ${opts.watchlist.length} watchlist pool(s)` +
      (opts.scanEveryCycles > 0 ? ` + rotating full-scan (${CHAIN_NAMES.join(", ")})` : "") +
      (opts.govEveryCycles > 0 ? ` + governance scan` : "")
  );
  console.log(
    `[daemon] ${opts.mainnetOnly ? "MAINNET 24/7" : "lab + mainnet"} — every ${opts.intervalSec}s, ${opts.probeWorkers} probe worker(s), scan top-${opts.scanTopN}. Ctrl-C to stop.`
  );
  console.log(`[daemon] instance "${opts.daemonId}" (pid ${process.pid})${opts.uiPort ? ` — dashboard on http://127.0.0.1:${opts.uiPort}` : ""}`);
  const sk = skillCount();
  if (sk > 0) console.log(`[daemon] skills library indexed: ${sk} methodologies available for triage hints`);

  // Lab cycles can legitimately run longer than the registry's 5-minute
  // heartbeat TTL (11 challenges × forge builds), so beating only once per
  // cycle would let the UI prune a LIVE daemon. Beat on a fixed interval
  // instead — independent of cycle progress. unref(): must never hold the
  // process open on its own.
  setInterval(() => daemonHeartbeat(opts.daemonId, cycle), 30_000).unref();

  // Orphan sweep: when a daemon dies mid-compile, or its forge timeout kills
  // the parent but not the solc grandchildren, the solc processes are
  // reparented to launchd (ppid 1) and run forever — observed live: 10
  // orphans (~1.5GB) re-accumulated within an hour. Any compile a LIVE
  // daemon spawns has that daemon as its parent, so reaping ppid-1 compiler
  // processes is safe by construction. Runs EVERY tick — one cheap ps + a
  // few SIGKILLs, much faster than the leak can regrow.
  setInterval(() => {
    try {
      const out = execFileSync("ps", ["-axo", "pid=,ppid=,comm="], { encoding: "utf8", timeout: 10_000 });
      const orphans: number[] = [];
      for (const line of out.split("\n")) {
        const m = line.trim().match(/^(\d+)\s+1\s+(.*)$/);
        if (!m) continue;
        const path = m[2].trim();
        const base = path.slice(path.lastIndexOf("/") + 1);
        if (/^(solc|solc-\S+|forge)$/.test(base)) orphans.push(Number(m[1]));
      }
      if (orphans.length > 0) {
        for (const pid of orphans) {
          try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ }
        }
        logEvent("daemon", `orphan sweep: reaped ${orphans.length} leaked compile process(es) (ppid 1)`);
        console.log(`[daemon] orphan sweep: reaped ${orphans.length} leaked compile process(es)`);
      }
    } catch {
      // ps unavailable or raced — next 30s tick retries.
    }
  }, 30_000).unref();

  // eslint-disable-next-line no-constant-condition
  while (true) {
    cycle++;
    setCycle(cycle);
    daemonHeartbeat(opts.daemonId, cycle);
    try {
      // ---------------- LAB WATCH (parallel) — skipped in mainnet-only mode ----------------
      if (!opts.mainnetOnly && !opts.labDisabled) {
        const fp = labDirFingerprint();
        const labChanged = fp !== lastLabFp;
        const challenges = discoverChallenges();
        const targets: Challenge[] = challenges.filter((c) => labChanged || !solvedNames.has(c.name));

        if (targets.length === 0) {
          console.log(`[daemon][cycle ${cycle}] lab: no new or changed challenges.`);
        } else {
          console.log(
            `[daemon][cycle ${cycle}] lab: solving ${targets.length} challenge(s) on ${Math.min(opts.workers, targets.length)} worker(s)${labChanged ? " (sources changed)" : ""}`
          );
          const results = await runPool(opts.workers, targets.map((c) => () => solveChallenge(c, opts.maxAttempts, (s) => console.log(`[daemon]   ${s}`))));
          for (const r of results) {
            if (r.ok && r.value?.solved) solvedNames.add(r.value.challenge);
          }
          setKbWins(countWins());
        }
        lastLabFp = fp;
      }

      // ---------------- GOVERNANCE SCAN ----------------
      // Staggered by daemon offset so N daemons don't fire every periodic
      // job in the same second (they'd race over shared report files).
      const govPhase = ((opts.chainOffset % opts.govEveryCycles) + opts.govEveryCycles) % opts.govEveryCycles;
      if (opts.govEveryCycles > 0 && cycle % opts.govEveryCycles === govPhase) {
        try {
          console.log(`[daemon][cycle ${cycle}] governance scan (read-only authority analysis)`);
          // onProgress keeps the heartbeat fresh during the (legitimately
          // multi-minute) scan so the monitor never reads it as wedged.
          const gov = await phaseDeadline("governance", PHASE_DEADLINE_MS, () =>
            runGovernanceScan([], { onProgress: () => daemonHeartbeat(opts.daemonId, cycle) })
          );
          if (gov) {
            if (gov.length > 0) {
              writeFileSync(join(REPORT_DIR, "GOVERNANCE.md"), writeGovernanceReport(gov));
            }
            const risky = gov.reduce((n, g) => n + g.authorities.filter((f) => f.risks.length > 0).length, 0);
            logEvent("gov", `governance: ${gov.length} target(s) analyzed, ${risky} with risk flags`);
          }
        } catch (e) {
          logEvent("scan", `governance scan failed (continuing): ${(e as Error).message}`);
        }
      }

      // ---------------- OSINT INTEL (free, read-only) ----------------
      // Solana surveillance: read-only sweeps (public RPC), staggered per
      // daemon so the fleet covers the watch continuously. Every 6 cycles
      // per daemon ≈ every 90s fleet-wide with 5 instances at 45s cycles.
      const solanaEvery = parseInt(process.env.SOLANA_EVERY ?? "6", 10) || 6;
      if (solanaEvery > 0 && cycle % solanaEvery === ((opts.chainOffset % solanaEvery) + solanaEvery) % solanaEvery) {
        try {
          await phaseDeadline("solana-watch", PHASE_DEADLINE_MS, () => runSolanaWatch());
        } catch (e) {
          logEvent("scan", `solana watch failed (continuing): ${(e as Error).message}`);
        }
      }
      // EVM incident surveillance: ownership/upgrade/config events over the
      // whole watchlist (the Solana watcher's EVM twin). Staggered per daemon;
      // offset-0 covers Ethereum enlistments every 8 cycles, other shards
      // sweep their own chain-labeled targets on the same rhythm.
      const incidentEvery = parseInt(process.env.INCIDENT_EVERY ?? "8", 10) || 8;
      if (incidentEvery > 0 && cycle % incidentEvery === ((opts.chainOffset % incidentEvery) + incidentEvery) % incidentEvery) {
        try {
          const before = JSON.stringify(snapshot().watchlist);
          const upgrades = await phaseDeadline("incident-sweep", PHASE_DEADLINE_MS, () =>
            runIncidentSweep(parseInt(process.env.INCIDENT_BLOCKS ?? "3000", 10) || 3000)
          );
          if (upgrades && upgrades > 0) {
            logEvent("scan", `incident sweep: ${upgrades} proxy upgrade(s) detected across watchlist`);
            // Upgrade-diff triage: each newly-seen upgrade gets its diff audited
            // (old vs new implementation, LLM on the diff only). Budget-cheap:
            // one call per upgrade, deduped by the watch row's lastResult —
            // a re-audit would overwrite the same note with a newer timestamp.
            const after = snapshot().watchlist;
            for (const [key, w] of Object.entries(after)) {
              if (!w.lastResult?.includes("PROXY UPGRADE")) continue;
              if ((before && before.includes(w.lastResult)) || JSON.stringify(w).includes("upgrade-diff:")) continue;
              const m = w.lastResult.match(/-> (0x[0-9a-fA-F]{40})/);
              const newImpl = m?.[1];
              if (!newImpl) continue;
              void triageUpgradeDiff("1", key.includes("0x") ? key.slice(key.indexOf("0x")) : key, newImpl, newImpl).catch(() => {});
            }
          }
        } catch (e) {
          logEvent("scan", `incident sweep failed (continuing): ${(e as Error).message}`);
        }
      }
      // Fork-graph priors (slow lane: every ~32 cycles, offset-staggered):
      // stamp watchlist rows whose parent protocol (or a sibling fork) was
      // ever exploited — the probe queue then prioritizes those targets.
      if (cycle % 32 === ((opts.chainOffset % 32) + 32) % 32) {
        try {
          const names = [...new Set(Object.values(snapshot().watchlist).map((w) => w.name).filter((n): n is string => !!n))].slice(0, 40);
          const priors = await scanForkPriors(names);
          for (const [name, p] of priors) {
            for (const [key, w] of Object.entries(snapshot().watchlist)) {
              if (w.name !== name) continue;
              upsertWatch({ address: key, lastResult: w.lastResult ? w.lastResult : `fork of ${p.parent} — hacked lineage: ${p.matched.join(", ")}` });
            }
          }
          if (priors.size > 0) logEvent("scan", `fork-graph: ${priors.size} target(s) with hacked-lineage prior stamped`);
        } catch {
          // prior stamping is enrichment — never gate the cycle
        }
      }
      // Same stagger as governance: offset-0 daemon keeps the original phase.
      const osintPhase = ((opts.chainOffset % opts.osintEveryCycles) + opts.osintEveryCycles) % opts.osintEveryCycles;
      if (opts.osintEveryCycles > 0 && cycle % opts.osintEveryCycles === osintPhase) {
        try {
          console.log(`[daemon][cycle ${cycle}] osint intel cycle (DefiLlama + rekt.news + free search)`);
          const intel = await phaseDeadline("osint", PHASE_DEADLINE_MS, () => runOsintCycle({ cycle })); // cycle drives the non-EVM ecosystem rotation
          if (intel) {
            const withAddr = intel.unauditedNew.filter((p) => p.address && p.chain).length;
            const seededN = intel.seeded?.filter((x) => x.action === "seeded").length ?? 0;
            if (seededN > 0) console.log(`[daemon][cycle ${cycle}] osint: enlisted ${seededN} new watchlist seed(s) from intel candidates`);
            logEvent(
              "osint",
              `osint: ${intel.unauditedNew.length} unaudited-new candidate(s), ${withAddr} with on-chain address, ${intel.headlines.length} rekt headline(s), ${intel.searched.length} search group(s) via ${intel.provider}, ${seededN} watchlist seed(s) enlisted`
            );
          }
        } catch (e) {
          logEvent("osint", `osint cycle failed (continuing): ${(e as Error).message}`);
        }
      }

      // ---------------- DAILY DIGEST ----------------
      if (opts.digestHours > 0 && Date.now() - lastDigestAt >= opts.digestHours * 3_600_000) {
        try {
          const p = writeDigest(opts.digestHours);
          lastDigestAt = Date.now();
          console.log(`[daemon][cycle ${cycle}] digest written: ${p}`);
        } catch (e) {
          logEvent("daemon", `digest failed (continuing): ${(e as Error).message}`);
        }
      }

      // ---------------- FIRST RESPONDER (balance watchdog) ----------------
      daemonHeartbeat(opts.daemonId, cycle); // mid-cycle beat: a busy daemon is alive, not stalled
      if (opts.respond > 0) {
        try {
          const r = await runResponderSweep({
            forkUrl: opts.forkUrl,
            dropBps: 500, // 5% between sweeps = incident
            minDropWei: 10n ** 18n, // ignore sub-1-ETH dust
            chainName: "*",  // all configured chains (ethereum + arbitrum + base)
          });
          if (r.drops > 0) {
            console.log(`[daemon][cycle ${cycle}] responder: ${r.drops} unclassified drop(s) escalated — report(s) written, ${r.benign} benign flow(s) ignored`);
          } else {
            const skipped = r.skipped > 0 ? `, ${r.skipped} read(s) failed (excluded, not zeroed)` : "";
            const benign = r.benign > 0 ? `, ${r.benign} benign drop(s) classified` : "";
            const dedup = r.deduped > 0 ? `, ${r.deduped} already escalated by another daemon` : "";
            console.log(`[daemon][cycle ${cycle}] responder: ${r.checked} watched protocol(s) stable${skipped}${benign}${dedup}`);
          }
        } catch (e) {
          logEvent("daemon", `responder sweep failed (continuing): ${(e as Error).message}`);
        }
      }

      // ---------------- FUZZ CAMPAIGN SLICE (accumulating pressure) ----------------
      // One bounded slice per cycle on the highest-priority target (canoncode
      // class first: custom > fork-delta > boilerplate, then stalest). This is
      // what converts "probe once with 64 runs" into a real campaign that
      // crosses 50k sequences on custom code — where bugs actually live.
      daemonHeartbeat(opts.daemonId, cycle);
      try {
        // Sharded by address hash (same ownsTarget scheme as the fork watch):
        // every daemon slicing the SAME top-N caused 8 concurrent forge runs
        // on one GenFork file — transient compile races and 8x duplicate work.
        const batch = selectCampaignBatchSharded(2, opts.chainOffset, fleetSize());
        for (const { chainId, address } of batch) {
          const slice = await runCampaignSlice(chainId, address, {
            // Per-daemon base (id hash → 8550..8599) + cycle rotation: a shared
            // `8660 + cycle%8` made every daemon bind the SAME port when their
            // campaign cycles aligned — one slice per fleet per tick survived.
            forkPort: daemonPortBase(opts.daemonId) + 60 + (cycle % 8), // 8610..8707, per-daemon
            chainRpcs: (CHAINS.find((c) => c.id === chainId)?.rpcs ?? ["https://rpc.flashbots.net"]),
            daemonId: opts.daemonId,
          });
          if (slice.ran) {
            console.log(`[daemon][cycle ${cycle}] campaign ${address.slice(0, 10)}… (chain ${chainId}): ${slice.note}`);
            logEvent("scan", `campaign slice ${address.slice(0, 10)}…: ${slice.note}`);
            if (slice.discovered) {
              logEvent("finding", `CAMPAIGN VERIFIED VIOLATION on ${address} (chain ${chainId}): invariant "${slice.invariant}" reproduced across seeds`);
            }
          }
        }
        const cs = campaignStats();
        if (cs.total > 0 && cycle % 10 === 0) {
          console.log(`[daemon][cycle ${cycle}] campaigns: ${cs.active}/${cs.total} active, ${cs.runsSoFar} cumulative runs, ${cs.violations} violation(s), ${cs.verified} verified`);
        }
      } catch (e) {
        logEvent("daemon", `campaign slice failed (continuing): ${(e as Error).message}`);
      }

      // ---------------- FUNNEL (measure the pipeline) ----------------
      try {
        const f = readFunnel();
        if (cycle % 10 === 0) logEvent("scan", `funnel: watched ${f.watched} → probed ${f.probed} → sourced ${f.sourced} → custom ${f.customish} → fuzzed ${f.fuzzed} (${f.runsSoFar} runs) → violated ${f.violated} → verified ${f.verified}; bottleneck: ${f.bottleneck}`);
      } catch { /* funnel is observability */ }

      // ---------------- SIEVE (structured scrape lane; resume only) ----------------
      // ONE poll step per in-flight run per cycle — that IS the 5s→30s backoff
      // (the schedule lives on disk, so a restart resumes it). This never starts
      // a run, so a crash cannot duplicate a credit spend; a Sieve outage is
      // contained to this block and cannot stall the hunt.
      if (sieveAvailable()) {
        try {
          const r = await phaseDeadline("sieve", PHASE_DEADLINE_MS, () => resumeSieveRuns({ maxSessions: 2 }));
          if (r && (r.done > 0 || r.refused > 0 || r.errors > 0)) {
            logEvent("scan", `sieve: ${r.polled} polled, ${r.done} run(s) done, ${r.refused} refused, ${r.errors} error(s)`);
          }
        } catch (e) {
          logEvent("scan", `sieve resume failed (continuing): ${(e as Error).message}`);
        }
      }

      // ---------------- FORK WATCH (parallel probes) ----------------
      // RPC health: endpoints die mid-hunt (publicnode did exactly that).
      // Re-verify the fork source every watch cycle and fail over to a
      // verified-mainnet fallback if it went dark.
      // NOTE: gate on CLI watchlist OR any enlisted target in the shared
      // bus watchlist (OSINT/flagship seeds) — a bare `daemon` run must
      // still hunt the seeds it discovers.
      const enlistedCount = Object.values(snapshot().watchlist).filter((w) => w.enlisted).length;
      if (opts.watchlist.length > 0 || enlistedCount > 0) {
        opts.forkUrl = opts.forkUrl ?? DEFAULT_FORK_RPC; // bare-daemon runs still get a fork source
        opts.forkUrl = await ensureHealthyRpc(opts.forkUrl);
        // Attached mode: one shared local chain, recycled periodically.
        if (opts.attachRpc && (!attachedFork || cycle - lastForkCycle > FORK_RECYCLE_CYCLES)) {
          if (attachedFork) attachedFork.stop();
          attachedFork = null;
          try {
            attachedFork = AnvilFork.attach(opts.attachRpc);
            await attachedFork.start();
            await rememberChainId(attachedFork);
            lastForkCycle = cycle;
          } catch (e) {
            attachedFork = null;
            logEvent("fork", `attach failed this cycle: ${(e as Error).message}`);
          }
        }
        // Watchlist mode: reuse one mainnet fork instead of spawning anvil every
        // cycle (each boot costs 20–60s on public RPCs). Recycle periodically
        // so state stays fresh.
        if (!opts.attachRpc && (!watchFork || cycle - lastForkCycle > FORK_RECYCLE_CYCLES)) {
          if (watchFork) watchFork.stop();
          watchFork = null;
          try {
            let forkUrl = opts.forkUrl!;
            const healthy = await pickHealthyRpc([forkUrl], 4_000, "0x1");
            if (!healthy) {
              const fb = await pickHealthyRpc(ETHEREUM_FORK_FALLBACKS, 5_000, "0x1");
              if (fb) {
                console.log(`[daemon]   fork source ${redactRpcUrl(forkUrl)} down — failing over to ${redactRpcUrl(fb)}`);
                forkUrl = fb;
                opts.forkUrl = fb;
              }
            }
            console.log(`[daemon][cycle ${cycle}] booting watch fork from ${redactRpcUrl(forkUrl)}…`);
            watchFork = await spawnDaemonFork(forkUrl, WATCH_FORK_PORT);
            await rememberChainId(watchFork);
            lastForkCycle = cycle;
            console.log(`[daemon][cycle ${cycle}] watch fork live at ${watchFork.localRpc}`);
          } catch (e) {
            watchFork = null;
            logEvent("fork", `watch fork boot failed: ${(e as Error).message}`);
            console.log(`[daemon][cycle ${cycle}] watch fork boot failed: ${(e as Error).message}`);
          }
        }

        // Cycle housekeeping: prune stale adaptive-cooldown entries.
        for (const [k, c] of adaptiveCooldown) if (cycle - c > ADAPTIVE_COOLDOWN_CYCLES) adaptiveCooldown.delete(k);

        // Nightly memory consolidation (in-cycle, cheap): cluster per-target
        // memories, promote anomalies into the hypothesis ledger. Synchronous
        // and capped — typically <100ms on the current store size.
        if (cycle - lastConsolidateCycle >= CONSOLIDATE_EVERY_CYCLES) {
          lastConsolidateCycle = cycle;
          try {
            const c = consolidateMemory();
            for (const line of c.lines) logEvent("memory", line);
          } catch (e) {
            logEvent("memory", `consolidation failed: ${(e as Error).message}`);
          }
          // SELF-LEARNED TECHNIQUES: hand the fleet's newest proven drains to
          // the LLM to be generalized into transferable techniques (bounded
          // per run; the proven facts stay even when the LLM is unavailable).
          try {
            const d = await distillPending(3);
            if (d > 0) logEvent("memory", `technique distillation: ${d} proven drain(s) generalized into reusable technique notes`);
          } catch (e) {
            logEvent("memory", `technique distillation failed: ${(e as Error).message}`);
          }
        }

        // Static watchlist (flags) + auto-enlisted live targets the scanner
        // classified as probeable (e.g. Ethereum ERC-4626 vaults). Deduped.
        // EVM addresses only: the second clause is the real gate (the first
        // would admit base58 Solana keys now living in the shared watchlist).
        const pools = [...new Set([...opts.watchlist, ...Object.values(snapshot().watchlist).filter((w) => w.enlisted).map((w) => w.address)])].filter(
          (a) => /^0x[0-9a-fA-F]{40}$/.test(a) && isProductionTarget("1", a)
        ).filter((a) => !/^0x5[fF]b[dD]b2315678afecb367f032d93[fF]642f64180aa3$/i.test(a));
        // Attached mode serializes probes: one shared chain means concurrent
        // simulations could corrupt each other's ephemeral state. Fork mode
        // gives every slot its own anvil, so probes truly run in parallel.
        const effectiveProbeWorkers = opts.attachRpc ? 1 : opts.probeWorkers;
        // Pools whose shape is unknown have no probe to run — re-checking
        // their (rarely changing) bytecode every cycle wastes a fork spawn;
        // re-probe on a slower cadence. 3 keeps the 350-target unprobed
        // backlog draining in hours instead of days while still amortizing
        // fork spawns over ~3 cycles (~2.5 min).
        const PROBE_EVERY = 3;
        // Shard filter: with N daemons each target is owned by exactly one
        // instance (stable address-hash modulo), so 5 daemons probe 5x the
        // market instead of the same list 5 times.
        // Hypothesis-aware priority: a target with UNTESTED hypotheses jumps
        // the queue — probing it buys new information (systematic elimination).
        // A target whose hypotheses are all refuted/held is a repeat visit and
        // waits its turn. Ledger failure must never break scheduling.
        const untestedHyp = (() => {
          try { return untestedTargets(); } catch { return new Set<string>(); }
        })();
        // SATURATION GATE (fork watch): a target the generic engine left
        // "held" re-probes on a ~6h cadence instead of every cycle — repeated
        // clean re-probes of audited pools were the fleet's biggest throughput
        // sink. Untested-hypothesis targets still jump the queue (new info).
        const CLEAN_RECHECK_MS = 6 * 3_600_000;
        const due = pools.filter((p) => {
          if (!ownsTarget(p.toLowerCase(), opts.chainOffset)) return false;
          const w = watchShape(p);
          if (w && w.includes("unknown")) return cycle % PROBE_EVERY === 0;
          if (w && !w.includes("unknown") && !untestedHyp.has(p.toLowerCase())) {
            const s = targetOutcome(p);
            if (s && s.result === "held" && Date.now() - (s.when ?? 0) < CLEAN_RECHECK_MS) return false;
          }
          return true;
        });
        // Deferred triage work whose backoff has elapsed jumps the queue: it
        // was already waiting on capacity once, and capacity is what just came
        // back. Without this, a target deferred by a 429 storm competes with
        // fresh targets forever and is effectively never analysed.
        const retryDue = new Set(dueTriage(400).map((i) => i.address.toLowerCase()));
        // Priority: (1) deferred-but-due, (2) bounty-flagged targets (live
        // Immunefi programs) and high-value seeds — a bounded worker pool must
        // never be stuck on dust while a $15M-bounty target waits.
        const watchOf = (a: string) => snapshot().watchlist[a];
        due.sort((a, b) => {
          const ra = retryDue.has(a.toLowerCase()) ? 4 : 0;
          const rb = retryDue.has(b.toLowerCase()) ? 4 : 0;
          const ha = untestedHyp.has(a.toLowerCase()) ? 3 : 0;
          const hb = untestedHyp.has(b.toLowerCase()) ? 3 : 0;
          const wa = watchOf(a), wb = watchOf(b);
          const pa = ra + ha + (wa?.bounty ? 2 : 0) + (wa?.seeded ? 1 : 0);
          const pb = rb + hb + (wb?.bounty ? 2 : 0) + (wb?.seeded ? 1 : 0);
          return pb - pa;
        });
        if (untestedHyp.size > 0) {
          console.log(`[daemon][cycle ${cycle}] ledger: ${untestedHyp.size} target(s) with untested hypotheses prioritized`);
        }
        if (retryDue.size > 0) {
          const qs = triageQueueStats();
          console.log(`[daemon][cycle ${cycle}] triage retry queue: ${retryDue.size} due now of ${qs.size} queued (${JSON.stringify(qs.byReason)})`);
        }
        // ---------------- CURIOSITY (budgeted question asking) ----------------
        // Scored "I wonder" experiments on watched targets over the shared
        // watch fork: fee faucets, spot oracles, live bridge surfaces, unbond
        // flows. Read-only at fork head; signals re-flag targets for the
        // standard probe+verify pipeline below. Budgeted so it can never
        // crowd out the probe queue.
        if (watchFork && (await forkAlive(watchFork)) && pools.length > 0) {
          const bountyAddrs = new Set(
            Object.values(snapshot().watchlist)
              .filter((w) => w.bounty)
              .map((w) => w.address.toLowerCase())
          );
          try {
            const cq = await runCuriosityCycle(watchFork, pools, { bountySet: bountyAddrs });
            if (cq.asked > 0) {
              const st = curiosityStats();
              console.log(`[daemon][cycle ${cycle}] curiosity: ${cq.asked} question(s) asked, ${cq.signals} signal(s) (lifetime ${st.asked} asked / ${st.signals} signals)`);
              for (const n of cq.notes) console.log(`[daemon][cycle ${cycle}]   ? ${n}`);
            }
          } catch (e) {
            logEvent("scan", `curiosity cycle failed (continuing): ${(e as Error).message}`);
          }
        }

        // ---------------- DEDICATED ERC-4626 VAULT LOOP ----------------
        // Vault-shaped watchlist rows (48 live) re-probe on a FASTER cadence
        // than the general 3-cycle rotation: unaudited share math is where
        // live bugs ship, so the highest base-rate class gets its own probe
        // loop instead of competing with 1,500 dust rows for slow slots.
        // Chain-aware: each vault forks from its OWN chain's endpoints.
        try {
          const v = await runVaultLoop(cycle, runPool, {
            daemonId: opts.daemonId,
            forkPortBase: WATCH_FORK_PORT + 120, // above watch/pool/scan ranges
            workers: Math.min(effectiveProbeWorkers, 2),
            cap: 6,
            draftedPools,
          });
          if (v.probed > 0) {
            console.log(`[daemon][cycle ${cycle}] vault loop: ${v.probed} ERC-4626 vault(s) probed, ${v.hits} drain signal(s)`);
          }
        } catch (e) {
          logEvent("scan", `vault loop failed (continuing): ${(e as Error).message}`);
        }

        // ---------------- CANON ON-RAMP (classify → campaign) ----------------
        // The funnel showed 17 custom/fork-delta targets classified but never
        // fuzz-enrolled (only vault-shaped rows reached the on-ramp). Each
        // cycle, enroll a bounded slice of the un-enrolled backlog so every
        // classified non-stock target eventually accumulates fuzz slices.
        try {
          const eb = await enrollBacklog(4);
          if (eb.enrolled > 0) {
            console.log(`[daemon][cycle ${cycle}] canon on-ramp: ${eb.enrolled} new campaign(s) enrolled of ${eb.checked} backlog target(s)`);
            for (const n of eb.notes.slice(0, 3)) logEvent("scan", `canon on-ramp: ${n}`);
          }
        } catch (e) {
          logEvent("scan", `canon on-ramp failed (continuing): ${(e as Error).message}`);
        }

        // ---------------- TRIAGE RETRY-QUEUE DRAIN ----------------
        // The queue used to only GROW: enqueue/backoff existed, but nothing
        // re-attempted the deferred work. Each cycle this re-runs the real
        // triage executor on a bounded slice of due items (gated on live key
        // capacity) so verdicts land or attempts increment — never zombie.
        try {
          const dr = await drainTriageQueue({
            daemonId: opts.daemonId,
            forkPortBase: WATCH_FORK_PORT + 160, // above the vault-loop range
            limit: 4,
          });
          if (dr.attempted > 0 || dr.notes.length > 0) {
            console.log(`[daemon][cycle ${cycle}] triage drain: ${dr.attempted} attempted, ${dr.resolved} verdicts, ${dr.redeferred} re-deferred, ${dr.errored} errored${dr.skippedNoKeys ? " (skipped: no key capacity)" : ""}`);
            for (const n of dr.notes.slice(0, 4)) console.log(`[daemon][cycle ${cycle}]   ↺ ${n}`);
          }
        } catch (e) {
          logEvent("scan", `triage drain failed (continuing): ${(e as Error).message}`);
        }

        // ---------------- OPERATOR BACKLOG-TRIAGE TICK ----------------
        // The dashboard's ON/OFF switch (reports/ui-controls.json). When ON,
        // each cycle feeds a bounded slice of shape:"unknown" watchlist rows
        // into the triage queue and drains it through the real executor —
        // spending the idle LLM budget on the 44% of the watchlist the scan
        // rotation never visits. OFF (the default) this is one flag read and
        // returns instantly; ON it is capacity-gated like every other triage
        // path, so it can never outrun keys/budget/cooldowns.
        try {
          const bt = await runBacklogTick({
            daemonId: opts.daemonId,
            forkPortBase: WATCH_FORK_PORT + 200, // above both drain ranges
            limit: 3,
          });
          if (bt.enabled) {
            console.log(`[daemon][cycle ${cycle}] backlog triage (operator switch ON): ${bt.enqueued} enqueued, ${bt.attempted} drained, ${bt.resolved} verdict(s)${bt.skippedCapacity ? " — skipped: " + bt.note : bt.note ? " — " + bt.note : ""}`);
          }
        } catch (e) {
          logEvent("scan", `backlog triage failed (continuing): ${(e as Error).message}`);
        }

        if (due.length === 0) {
          console.log(`[daemon][cycle ${cycle}] fork watch: nothing due in shard (chains: ${shard.join(",")})`);
        } else {
        // Triage health: one line per cycle so a silently-starved analysis path
        // (revoked key, spent budget, 429 storm) is visible instead of showing
        // up only as vague "triage unavailable" strings on watchlist rows.
        try {
          const th = triageHealth();
          if (th.total > 0) {
            const parts = Object.entries(th.counts).filter(([r]) => r !== "ok").map(([r, n]) => `${r}=${n}`);
            const statuses = Object.entries(th.statuses).map(([s, n]) => `HTTP${s}=${n}`);
            console.log(
              `[daemon][cycle ${cycle}] triage health: ${th.ok}/${th.total} ok` +
              (parts.length ? ` | blocked: ${parts.join(" ")}` : "") +
              (statuses.length ? ` | ${statuses.join(" ")}` : "") +
              ` | budget ${th.budget.used}/${th.budget.max} | keys ${th.keys}` +
              (th.cooldownMs > 0 ? ` | backoff ${Math.round(th.cooldownMs / 1000)}s` : "") +
              (th.lastReason && th.lastReason !== "ok" && th.lastDetail ? ` | last: ${th.lastReason} — ${th.lastDetail.slice(0, 90)}` : "")
            );
          }
        } catch { /* health reporting is cosmetic */ }
        console.log(`[daemon][cycle ${cycle}] fork watch: probing ${due.length} pool(s) on ${Math.min(effectiveProbeWorkers, due.length)} worker(s) [shard ${opts.chainOffset}]`);
        await runPool(effectiveProbeWorkers, due.map((poolAddr, i) => async () => {
          const label = `${poolAddr.slice(0, 10)}…`;
          let fork: AnvilFork | null = null;
          try {
            if (opts.attachRpc && attachedFork && (await forkAlive(attachedFork))) {
              fork = attachedFork;
            } else if (watchFork && (await forkAlive(watchFork))) {
              fork = watchFork;
            } else {
              // Dead or missing shared fork: stop the corpse (kill zombie
              // child), null it so the next cycle reboots the shared fork,
              // and give this probe its own dedicated fork as fallback.
              if (watchFork) {
                watchFork.stop();
                watchFork = null;
              }
              fork = await spawnDaemonFork(opts.forkUrl!, poolForkPort(i));
            }
            await rememberChainId(fork); // for forkChainId in the probe path
            const recon = await reconPool(fork, poolAddr);
            upsertWatch({ address: poolAddr, shape: recon.shape, lastProbe: Date.now() });
            const technique = recon.shape.includes("side-entrance") ? "side-entrance-reentrancy" : "manual-analysis-required";
            let finding = await simulateOnFork(fork, recon, technique);
            // Probe resilience: transient infra failures get one spaced retry;
            // high-information revert reasons get one adaptive re-probe via
            // re-triage with the decoded reason injected. Both paths record
            // how the final verdict was reached — no silent rewrites.
            //
            // Cooldown: if this target already failed an adaptive re-probe
            // with the SAME decoded reason, skip the triage spend this cycle
            // (retry after ADAPTIVE_COOLDOWN_CYCLES). Same answer twice is a
            // dead end, not new information.
            const failKey = `${poolAddr.toLowerCase()}:${finding.technique}:${finding.notes.slice(15, 90)}`;
            const lastAdaptive = adaptiveCooldown.get(failKey) ?? -Infinity;
            const cooled = cycle - lastAdaptive < ADAPTIVE_COOLDOWN_CYCLES;
            if (!finding.simulated && !cooled && (finding.notes.includes("probe reverted:") || finding.notes.includes("probe error:"))) {
              adaptiveCooldown.set(failKey, cycle);
              finding = await retryProbe(fork, recon, finding, {
                retriage: async () => {
                  // ABI preflight: which entry points does the target actually
                  // answer? Grounds the re-triage in what the bytecode really
                  // exposes instead of what recon guessed.
                  let ctx = finding.notes;
                  try {
                    const live = await probeEntryPoints(fork, poolAddr, [
                      "deposit()", "withdraw(uint256)", "flashLoan(uint256)",
                      "mint(address,uint256)", "borrow(uint256)", "redeem(uint256,address,address)",
                    ]);
                    if (live.size > 0) {
                      logEvent("scan", `preflight ${poolAddr.slice(0, 10)}… answers: ${[...live].join(", ")}`);
                      ctx = `${finding.notes} | entry points answering: ${[...live].join(", ")}`;
                    }
                  } catch { /* preflight is best-effort */ }
                  const inv = await investigateUnknownShape(fork, forkChainId(fork), "ethereum", poolAddr, {
                    daemonId: opts.daemonId,
                    revertContext: ctx,
                    watchKey: poolAddr,
                  });
                  return inv.finding;
                },
              });
            }
            // Unknown shape: investigate (verified source -> detectors -> LLM
            // triage -> validated probe on this same fork) instead of just
            // logging "no template probe". This is how the 24/7 watch gets
            // smarter than its hand-written templates.
            let investigated = false;
            if (!finding.simulated && recon.shape.startsWith("unknown")) {
              const inv = await investigateUnknownShape(fork, forkChainId(fork), "ethereum", poolAddr, { watchKey: poolAddr, daemonId: opts.daemonId });
              if (inv.finding) finding = inv.finding;
              upsertWatch({ address: poolAddr, lastResult: inv.summary });
              console.log(`[daemon][cycle ${cycle}] ${label}: investigated — ${inv.summary.slice(0, 220)}`);
              investigated = true;
            }
            const chainId = forkChainId(fork);
            const production = isProductionTarget(chainId, poolAddr);
            const actionable = isActionableFinding(finding);
            // Learning loop: persist every distinct outcome as retrievable memory.
            learnFromProbe(
              poolAddr,
              recon.shape,
              technique,
              actionable ? "drained" : finding.simulated ? "simulated-no-drain" : recon.shape.startsWith("unknown") ? "investigated" : "no-drain",
              finding.notes
            );
            // SELF-LEARNED TECHNIQUE: a simulated drain joins the transferable
            // technique library so future targets of this shape inherit the recipe.
            if (actionable) {
              try {
                captureProvenDrain({
                  origin: "triage-probe",
                  technique,
                  shape: recon.shape,
                  observation: finding.notes.slice(0, 300),
                  profitWei: finding.profitWei,
                  provenOn: poolAddr,
                });
              } catch { /* technique capture is best-effort */ }
            }
            if (actionable && production) {
              // Probe hit = SIGNAL, not a finding. Re-verify on FRESH forks;
              // only 2/2 reproduction produces the 🚨 alert + evidence +
              // bounty draft (verify.ts). Non-reproducing hits downgrade to
              // monitoring — honest silence instead of a false alarm.
              const draftKey = `${chainId}:${poolAddr.toLowerCase()}`;
              if (draftedPools.has(draftKey)) {
                console.log(`[daemon][cycle ${cycle}] ${label}: signal already verified this session — skipping re-verify`);
              } else {
                draftedPools.add(draftKey);
                logEvent("scan", `probe SIGNAL on ${poolAddr} (chain ${chainId}) — verifying on fresh forks: ${finding.notes.slice(0, 140)}`);
                const v = await verifyAndReport({
                  poolAddr,
                  chainId,
                  finding,
                  recon,
                  forkUrl: opts.forkUrl ?? opts.attachRpc,
                  label: `${poolAddr.slice(0, 10)}…`,
                });
                console.log(`[daemon][cycle ${cycle}] ${v.confirmed ? "*** VERIFIED FINDING" : "signal NOT reproduced"} on ${poolAddr} (chain ${chainId}): ${v.note.slice(0, 220)}`);
              }
            } else if (!investigated) {
              // Unknown-shape pools already carry the investigation summary —
              // don't clobber it with the "no template probe" placeholder.
              upsertWatch({ address: poolAddr, lastResult: finding.notes, finding: false });
              console.log(`[daemon][cycle ${cycle}] ${label}: no drain (${finding.notes})`);
            }
          } catch (e) {
            upsertWatch({ address: poolAddr, lastResult: `probe error: ${(e as Error).message}` });
            learnFromProbe(poolAddr, watchShape(poolAddr), "manual-analysis-required", "reverted", (e as Error).message);
            console.log(`[daemon][cycle ${cycle}] ${label}: probe error: ${(e as Error).message}`);
          } finally {
            // Only tear down ephemeral slot forks; shared forks persist.
            if (fork && fork !== attachedFork && fork !== watchFork) fork.stop();
          }
        }))
        }
      }

      // ---------------- ROTATING FULL-MARKET SCAN (runs after probes) ----------------
      // Discovery can take minutes on ethereum — never block watchlist probes.
      if (opts.scanEveryCycles > 0 && cycle % opts.scanEveryCycles === 0) {
        // Shard rotation: scan only this instance's chains — across the fleet
        // every chain is covered once, not N times.
        const shardChains = ownedChains(opts.chainOffset);
        const chainName = shardChains[scanCursor % shardChains.length]!;
        scanCursor++;
        daemonHeartbeat(opts.daemonId, cycle); // scans are the longest phase
        console.log(`[daemon][cycle ${cycle}] rotating scan: ${chainName} (blocks ${opts.scanBlocksBack}, top ${opts.scanTopN})`);
        try {
          const reports = await phaseDeadline(`rotation-${chainName}`, PHASE_DEADLINE_MS, () =>
            runScan({
              blocksBack: opts.scanBlocksBack,
              topN: opts.scanTopN,
              maxChains: 0,
              pauseBetweenChainsMs: 0,
              onlyChains: [chainName],
              // Per-daemon port (watch base + 49): pool-fallback forks use
              // base+50.. and the watch fork uses base — never collide.
              forkPort: WATCH_FORK_PORT + 49,
              probeWorkers: opts.probeWorkers,
            })
          );
          const r = reports?.[0];
          logEvent(
            "scan",
            `rotation ${chainName}: ${r?.targetsFound ?? 0} target(s), ${r?.probed.length ?? 0} probed, ${r?.probed.filter((p) => p.finding).length ?? 0} finding(s)${r?.error ? ` (${r.error})` : ""}`
          );
        } catch (e) {
          logEvent("scan", `rotation ${chainName} failed (continuing): ${(e as Error).message}`);
        }
      }
    } catch (e) {
      logEvent("daemon", `cycle error (continuing): ${(e as Error).message}`);
      console.log(`[daemon][cycle ${cycle}] cycle error (continuing): ${(e as Error).message}`);
    }

    // Keep the static dashboard file fresh (preview + sharing).
    try {
      writeFileSync(join(REPORT_DIR, "dashboard.html"), renderStaticHtml(snapshot()));
    } catch {
      // non-fatal
    }

    await sleep(opts.intervalSec * 1000);
  }
}
