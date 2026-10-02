// Dedicated ERC-4626 probe loop — the 48 vault-shaped watchlist rows get
// their own fast cycle instead of the general 3-cycle rotation.
//
// Why: unaudited share math is where live bugs ship (donation/inflation,
// rounding, fee-on-deposit, non-standard redeem paths). The fork watch
// re-probes the whole watchlist every PROBE_EVERY=3 cycles — vaults are the
// highest base-rate class in it, yet they inherit the slowest cadence and
// compete with 1,500 dust rows for worker slots. This loop:
//   - selects vault-shaped rows from the shared watchlist (shape reported by
//     reconPool, keyed `chain:0x…` — chain-aware, not Ethereum-only like the
//     old auto-enlistment);
//   - probes on a FASTER cadence (default every 2nd cycle);
//   - sorts stale + bounty-flagged first so a bounded worker pool always
//     buys the freshest information;
//   - runs the same execution path as every other probe (spawnFork per slot
//     → reconPool → simulateOnFork → investigate on unknown shapes), reusing
//     spawnForkWithFailover across the chain's OWN registered endpoints —
//     LAB_FORK_URL is Ethereum-only and must never fork other chains.
//
// Rails unchanged: local anvil forks only, 127.0.0.1 RPC, nothing broadcast.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { upsertCampaign } from "./campaigns.ts";
import { AnvilFork, reconPool, simulateOnFork, spawnForkWithFailover, type PoolRecon, type ForkFinding } from "./fork.ts";
import { CHAINS } from "./scan.ts";
import { enrollTargetForCampaign, isEnrolled } from "./enroll.ts";
import { investigateUnknownShape } from "./investigate.ts";
import { verifyAndReport } from "./verify.ts";
import { isActionableFinding, isProductionTarget } from "./findings.ts";
import { upsertWatch, logEvent, snapshot } from "./bus.ts";

/**
 * CANON ON-RAMP (funnel-measured gap, 2026-09-28): only the 48 vault-shaped
 * rows used to reach enrollTargetForCampaign, so the funnel stalled at "29
 * custom/fork-delta classified, 17 never fuzzed" — the canoncode classifier
 * saw the code, but nothing scheduled it. This pass walks canoncode's own
 * classified rows (the store is the source of truth, not the watchlist's
 * shape label) and enrolls every custom/fork-delta target that has no
 * campaign yet. Bounded (default 4/cycle), stalest-first, and a no-op once
 * the backlog is drained — enrollTargetForCampaign itself is idempotent.
 *
 * SECOND GAP (measured 2026-09-28, post-Etherscan-key): 1,218 sources sat in
 * reports/source-cache/ but only ~72 targets were ever classified — AMM pairs
 * and other template-probe shapes never reach investigateUnknownShape, so
 * their source was fetched, cached, and never classified. This pass also
 * walks the SOURCE CACHE directly: any cached source with no canoncode row
 * gets classified (corpus-aware, idempotent) and enrolled when non-boilerplate.
 * Since sources are already on disk, this is CPU-only — no API spend.
 */
export async function enrollBacklog(cap = 4): Promise<{ checked: number; enrolled: number; notes: string[] }> {
  const { rowsByClass, classifyTarget, getCanon } = await import("./canoncode.ts");
  void getCanon;
  const { getCampaign } = await import("./campaigns.ts");
  const notes: string[] = [];
  let checked = 0;
  let enrolled = 0;

  // ---- pass 1: classified custom/fork-delta rows still missing a campaign
  const candidates = [...rowsByClass("custom"), ...rowsByClass("fork-delta")]
    .filter((r) => {
      const c = getCampaign(r.chainId, r.address);
      // Pass 1 enrolls only NEVER-registered targets. A SUSPENDED campaign
      // (build errors) is a runCampaignSlice concern: re-enrolling from here
      // just re-fetches the same source, gets "already registered", and eats
      // the cap without reviving anything.
      if (c) return false;
      // A target the generic engine already left with "no harnessable shape"
      // (same source) would just burn the cap re-failing the build — skip it
      // so pass 2 (cache classification) gets the slot instead. The flag lives
      // on the canon row with the source length that failed; a re-verified
      // upgrade (different length) resets it and re-enrolls.
      try {
        const sourceLen = Number(readFileSync(join(REPORT_DIR, "source-cache", `${r.chainId}-${r.address}.sol`), "utf8").length);
        if (r.unharnessableSourceLen === sourceLen) return false;
      } catch { /* no cached source — attempt enroll anyway */ }
      return true;
    })
    .sort((a, b) => a.t - b.t) // oldest classification = staled the longest
    .slice(0, Math.max(0, cap));
  for (const row of candidates) {
    checked++;
    try {
      const hadCampaign = !!getCampaign(row.chainId, row.address);
      const en = await enrollTargetForCampaign(row.chainId, row.address);
      if (en.campaignRegistered && !hadCampaign) enrolled++; // count only NEW registrations
      notes.push(`${row.chainId}:${row.address.slice(0, 10)}… ${en.note}`);
    } catch (e) {
      notes.push(`${row.chainId}:${row.address.slice(0, 10)}… enroll error: ${(e as Error).message.slice(0, 90)}`);
    }
  }
  if (candidates.length > 0) return { checked, enrolled, notes };

  // ---- pass 1.5: IDEA-CARRYING targets — 129 LLM-ranked attack ideas sit in
  // reports/attack-ideas.json for 47 targets, and none of them had a campaign
  // (ideas seeded hypotheses for the TEMPLATE prober, but the fuzz campaigns
  // never saw them). When pass 1 is drained, enroll the highest-ranked
  // idea-carrying targets first — an idea on a target IS the priority signal.
  try {
    const { allAttackIdeas } = await import("./attackideas.ts");
    const seen = new Set<string>();
    const ideaTargets = allAttackIdeas()
      .filter((i) => {
        const k = `${i.chainId}:${i.address.toLowerCase()}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .sort((a, b) => a.rank - b.rank || b.t - a.t); // rank 1 first, newest
    for (const idea of ideaTargets) {
      if (checked >= cap) break;
      const addr = idea.address.toLowerCase();
      if (getCampaign(idea.chainId, addr)) continue; // already enrolled
      // The idea store carries display addresses — checksum before use.
      if (!/^0x[0-9a-fA-F]{40}$/.test(idea.address)) continue;
      checked++;
      try {
        const en = await enrollTargetForCampaign(idea.chainId, idea.address);
        if (en.campaignRegistered) enrolled++;
        notes.push(`${idea.chainId}:${idea.address.slice(0, 10)}… idea-target enroll: ${en.note}`);
      } catch (e) {
        notes.push(`${idea.chainId}:${idea.address.slice(0, 10)}… idea-target enroll error: ${(e as Error).message.slice(0, 80)}`);
      }
    }
  } catch { /* idea store unavailable — best-effort lane */ }
  if (checked >= cap) return { checked, enrolled, notes };

  // ---- pass 2 (only when pass 1 is drained): classify CACHED sources that
  // have no canoncode row yet. Bounded by the same cap. Cache filename shape:
  // <chainId>-<lowercase address>.sol under REPORT_DIR/source-cache/.
  try {
    const { readdirSync, readFileSync } = await import("node:fs");
    const cacheDir = join(REPORT_DIR, "source-cache");
    const files = readdirSync(cacheDir).filter((f) => /^\d+-0x[0-9a-f]{40}\.sol$/.test(f));
    for (const f of files) {
      if (checked >= cap) break;
      const m = f.match(/^(\d+)-(0x[0-9a-f]{40})\.sol$/);
      if (!m) continue;
      const [, chainId, addr] = m;
      if (getCanon(chainId, addr)) continue; // already classified
      checked++;
      try {
        const source = readFileSync(join(cacheDir, f), "utf8");
        if (source.length < 32) continue;
        const canon = classifyTarget(chainId, addr, source); // idempotent, feeds the corpus
        // AMM v2 pairs are classified boilerplate (stock UNI_V2 fork) but ARE
        // harnessable since the amm-v2 generator landed — they skip the
        // boilerplate gate below and register a campaign on shape grounds.
        const { buildHarness } = await import("./genharness.ts");
        const gen = buildHarness(
          { challengeName: `cache-${chainId}-${addr.slice(0, 10)}`, sources: [source], mode: "address", bindAddress: addr, chainId },
          0
        );
        if (!gen) {
          if (canon.codeClass === "boilerplate") {
            notes.push(`${chainId}:${addr.slice(0, 10)}… classified ${canon.codeClass} (from cache) — no campaign (stock surface)`);
          } else {
            notes.push(`${chainId}:${addr.slice(0, 10)}… classified ${canon.codeClass} (from cache) but no harnessable shape`);
          }
          continue;
        }
        upsertCampaign({ chainId, address: addr, shape: gen.shape });
        enrolled++;
        notes.push(`${chainId}:${addr.slice(0, 10)}… campaign registered (${gen.shape}${canon.codeClass === "boilerplate" ? ", stock pair" : ""})`);
      } catch (e) {
        notes.push(`${chainId}:${addr.slice(0, 10)}… cache-classify error: ${(e as Error).message.slice(0, 80)}`);
      }
    }
  } catch { /* no cache dir yet — nothing to do */ }

  return { checked, enrolled, notes };
}

/** Is this watchlist entry a vault-shaped row? Recon labels them
 * "erc-4626-style vault (convertToShares/maxRedeem)" and the scanner's vault
 * discovery tags the factory label "erc4626-vault". */
export function isVaultEntry(entry: { shape?: string; address?: string }): boolean {
  const shape = entry.shape ?? "";
  return shape.includes("4626") || shape.toLowerCase().includes("vault");
}

/** Parse a `chain:0x…` watch key into (chainId, bare address), or null when
 * the row is not a resolvable production target (display labels, solana rows,
 * dev fixtures are all rejected — never probed). */
export function parseVaultTarget(
  key: string,
  entry: { address?: string }
): { chainId: string; address: string; chainName: string } | null {
  // Watch keys carry display suffixes (" [hot]", " [seed]" — the scanner's
  // labels). Strip before matching or EVERY hot-discovered row would be
  // rejected here, which is exactly the class of row the vault loop exists
  // for (the test pins this).
  const bareKey = key.replace(/\s+\[[^\]]*\]\s*$/, "").trim();
  const m = bareKey.match(/^([a-z0-9]+):(0x[0-9a-fA-F]{40})$/);
  const addr = (m?.[2] ?? entry.address ?? "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(addr)) return null;
  const chainName = m?.[1]?.toLowerCase();
  const chain = CHAINS.find((c) => c.name === chainName);
  if (!chain) return null;
  if (!isProductionTarget(chain.id, addr)) return null;
  return { chainId: chain.id, address: addr, chainName: chain.name };
}

/** One selected vault row with its scheduling metadata. */
export interface VaultRow {
  watchKey: string;
  chainId: string;
  chainName: string;
  address: string;
  /** Epoch ms of the last probe (0 = never probed). Sort key: smaller is
   * staler — deterministic, unlike a per-row `Date.now() - lastProbe`.
   * NEVER-PROBED rows must not sort as epoch 0 (1970 = "probed long ago" and
   * never retried), so the sort treats 0 as infinitely stale. */
  lastProbeMs: number;
  bounty: boolean;
}

/** Select the vault rows due this cycle: every vault-shaped, chain-resolvable
 * entry, stalest first (never-probed = infinitely stale), bounty-flagged
 * first. Cadence is BACKLOG-DRIVEN: probeVault stamps lastProbe at start, so
 * the cap+staleness sort alone round-robins the whole set — no per-row phase
 * gating (it only ever shrank batches). `cap` bounds fork pressure. */
export function selectVaultTargets(cycle: number, cap = 6): VaultRow[] {
  void cycle; // kept in the signature for daemon call-site stability
  const rows: VaultRow[] = [];
  for (const [key, w] of Object.entries(snapshot().watchlist)) {
    if (!isVaultEntry(w)) continue;
    const t = parseVaultTarget(key, w);
    if (!t) continue;
    rows.push({
      watchKey: key,
      chainId: t.chainId,
      chainName: t.chainName,
      address: t.address,
      lastProbeMs: w.lastProbe ?? 0,
      bounty: !!w.bounty,
    });
  }
  const staleness = (r: VaultRow): number => (r.lastProbeMs === 0 ? Number.MAX_SAFE_INTEGER : r.lastProbeMs);
  rows.sort(
    (a, b) =>
      Number(b.bounty) - Number(a.bounty) ||
      staleness(a) - staleness(b) || // smaller lastProbe = staler = first
      a.address.localeCompare(b.address) // deterministic tiebreak
  );
  return rows.slice(0, cap);
}

/** Probe one vault on its own short-lived local fork. Runs the standard
 * template probe (erc4626-share-inflation renders whenever the shape does)
 * and, when the shape came back unknown, the full investigation pipeline —
 * identical rails to the scanner. Returns the final finding (or null). */
export async function probeVault(
  row: VaultRow,
  opts: { forkPort: number; daemonId: string; draftedPools: Set<string> }
): Promise<{ finding: ForkFinding | null; note: string }> {
  const chain = CHAINS.find((c) => c.id === row.chainId)!;
  const label = `${row.chainName}:${row.address.slice(0, 10)}…`;
  upsertWatch({ address: row.watchKey, lastProbe: Date.now() });
  let fork: AnvilFork;
  try {
    // Failover across the chain's OWN registered endpoints. A fork that
    // "boots" from the wrong chain makes every target look like an empty
    // account — non-ethereum chains must never inherit LAB_FORK_URL.
    fork = await spawnForkWithFailover(chain.rpcs[0]!, opts.forkPort, chain.rpcs.slice(1));
  } catch (e) {
    const msg = `vault probe: local fork failed on all ${chain.name} endpoints: ${(e as Error).message}`.slice(0, 200);
    upsertWatch({ address: row.watchKey, lastResult: msg });
    return { finding: null, note: msg };
  }
  try {
    const recon: PoolRecon = await reconPool(fork, row.address, chain);
    upsertWatch({ address: row.watchKey, shape: recon.shape });
    const technique = recon.shape.includes("side-entrance")
      ? "side-entrance-reentrancy"
      : recon.shape.includes("erc-4626")
        ? "erc4626-share-inflation"
        : "manual-analysis-required";
    let finding = await simulateOnFork(fork, recon, technique);
    if (!finding.simulated && recon.shape.startsWith("unknown")) {
      const inv = await investigateUnknownShape(fork, row.chainId, row.chainName, row.address, {
        daemonId: opts.daemonId,
        watchKey: row.watchKey,
      });
      if (inv.finding) finding = inv.finding;
      return { finding: inv.finding, note: inv.summary };
    }
    const hit = isActionableFinding(finding) && isProductionTarget(row.chainId, row.address);
    upsertWatch({ address: row.watchKey, lastResult: finding.notes, finding: hit });
    // ON-RAMP: classified + campaign-registered targets are the ones the
    // accumulating fuzzer can actually improve on. Without this, probe-able
    // vaults never reach the classification/campaign path (funnel-measured:
    // 2437 probed, 1 sourced). Once per target — repeat visits skip via the
    // canoncode store lookup.
    if (!isEnrolled(row.chainId, row.address)) {
      try {
        const en = await enrollTargetForCampaign(row.chainId, row.address);
        logEvent("scan", `vault loop enroll ${row.address.slice(0, 10)}…: ${en.note}`);
      } catch { /* on-ramp is best-effort */ }
    }
    if (hit) {
      // Same signal→verify bar as everywhere else: 2/2 fresh-fork reproduction
      // before anything is drafted; non-reproducing hits downgrade honestly.
      const draftKey = `${row.chainId}:${row.address}`;
      if (opts.draftedPools.has(draftKey)) {
        logEvent("scan", `vault loop: ${label} signal already verified this session — skipping re-verify`);
      } else {
        opts.draftedPools.add(draftKey);
        logEvent("scan", `vault loop SIGNAL on ${label} (chain ${row.chainId}) — verifying on fresh forks: ${finding.notes.slice(0, 140)}`);
        const v = await verifyAndReport({
          poolAddr: row.address,
          chainId: row.chainId,
          finding,
          recon,
          forkUrl: undefined, // verify spawns its own fresh forks via the default failover set
          label,
        });
        logEvent("scan", `vault loop: ${v.confirmed ? "*** VERIFIED FINDING" : "signal NOT reproduced"} on ${label} — ${v.note.slice(0, 200)}`);
      }
    }
    return { finding, note: finding.notes };
  } catch (e) {
    const msg = `vault probe error: ${(e as Error).message}`.slice(0, 200);
    upsertWatch({ address: row.watchKey, lastResult: msg });
    return { finding: null, note: msg };
  } finally {
    fork.stop();
  }
}

/** The per-cycle vault pass: select + probe with a bounded worker pool.
 * `runPool` is injected by the caller (daemon) to avoid an import cycle and
 * to keep worker accounting in one place. */
export async function runVaultLoop(
  cycle: number,
  runPool: (n: number, tasks: (() => Promise<void>)[]) => Promise<void>,
  opts: { daemonId: string; forkPortBase: number; workers: number; cap?: number; draftedPools: Set<string> }
): Promise<{ probed: number; hits: number }> {
  const rows = selectVaultTargets(cycle, opts.cap ?? 6);
  if (rows.length === 0) return { probed: 0, hits: 0 };
  logEvent("scan", `vault loop: ${rows.length} ERC-4626 vault(s) due (dedicated sweep, stalest first — faster than the general 3-cycle rotation)`);
  let hits = 0;
  await runPool(
    Math.max(1, Math.min(opts.workers, 4)),
    rows.map((row, i) => async () => {
      const r = await probeVault(row, {
        forkPort: opts.forkPortBase + (i % 20),
        daemonId: opts.daemonId,
        draftedPools: opts.draftedPools,
      });
      if (r.finding?.simulated && r.finding.profitWei !== "0") hits++;
    })
  );
  return { probed: rows.length, hits };
}
