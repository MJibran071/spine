// Persistent knowledge base — the agent gets smarter across runs.
// Key: a stable signature of a challenge's feature vector. Value: the
// technique + parameters that actually drained it, and how often.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import type { ChallengeFeatures } from "./discovery.ts";

const KB_PATH = join(REPORT_DIR, "knowledge.json");

export interface KnowledgeEntry {
  technique: string;
  params: Record<string, string>;
  wins: number;
  lastWin: number; // epoch ms
}

type KB = Record<string, Record<string, KnowledgeEntry>>; // sig -> technique -> entry

function load(): KB {
  try {
    if (existsSync(KB_PATH)) {
      const raw = JSON.parse(readFileSync(KB_PATH, "utf8")) as KB;
      // Flag-set migration: when featureSignature gains flags, older keys (and
      // therefore every recorded win) would silently stop matching. Rewrite
      // legacy keys to the current shape with the new flags defaulted to 0 —
      // correct for every challenge that predates the sweep/merkle classes.
      let migrated = false;
      for (const key of Object.keys(raw)) {
        if (!key.includes("sweep=")) {
          const [flags, name] = key.split("|");
          const newKey = `${flags},sweep=0,merkle=0|${name ?? ""}`;
          raw[newKey] = raw[key]!;
          delete raw[key];
          migrated = true;
        }
      }
      if (migrated) save(raw);
      return raw;
    }
  } catch {
    // corrupt kb = fresh start
  }
  return {};
}

function save(kb: KB): void {
  mkdirSync(REPORT_DIR, { recursive: true });
  writeFileSync(KB_PATH, JSON.stringify(kb, null, 2));
}

/** Stable feature signature used as the knowledge key.
 * Includes a short hash of the challenge name to prevent collision when two
 * challenges share identical boolean flags but have different structures. */
export function featureSignature(f: ChallengeFeatures, challengeName?: string): string {
  const b = (x: boolean) => (x ? "1" : "0");
  const flags = [
    `fl=${b(f.hasFlashLoan)}`,
    `cb=${b(f.hasEtherCallback)}`,
    `dw=${b(f.hasDepositWithdraw)}`,
    `arb=${b(f.makesArbitraryCall)}`,
    `amm=${b(f.pricesOffAmm)}`,
    `nft=${b(f.hasNftMarketplace)}`,
    `ccb=${b(f.callerChoosesBorrower)}`,
    `bal=${b(f.checksRawBalance)}`,
    `share=${b(f.hasShareCalc)}`,
    `sig=${b(f.verifiesSig)}`,
    `mint=${b(f.hasMintSurface ?? false)}`,
    `sweep=${b(f.hasSweepSurface ?? false)}`,
    `merkle=${b(f.hasMerkleClaim ?? false)}`,
  ].join(",");
  // Append a name discriminator so two challenges with identical flags
  // don't share the same KB bucket (false priors from unrelated challenges).
  // 16 chars: long enough that e.g. LayerZeroOAppV1/V2 differ (the 6-char
  // truncation made them collide and cross-suggest each other's priors).
  if (challengeName) {
    const nameHash = challengeName.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16);
    return `${flags}|${nameHash}`;
  }
  return flags;
}

export function priorWin(sig: string): KnowledgeEntry | null {
  const kb = load();
  const entries = Object.values(kb[sig] ?? {});
  if (entries.length === 0) return null;
  // Age-weighted score: wins decay by half every 30 days so stale techniques
  // from old contract versions don't permanently block newer strategies.
  const now = Date.now();
  const HALF_LIFE_MS = 30 * 24 * 3_600_000; // 30 days
  const scored = entries.map((e) => {
    const ageDays = (now - e.lastWin) / HALF_LIFE_MS;
    const score = e.wins * Math.pow(0.5, ageDays); // exponential decay
    return { e, score };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored[0]!.e;
}

// Safe under parallel workers: the body is fully synchronous (no awaits),
// so Node's single thread can never interleave two read-modify-write cycles.
export function recordWin(sig: string, technique: string, params: Record<string, string>): void {
  const kb = load();
  kb[sig] = kb[sig] ?? {};
  const e = kb[sig][technique] ?? { technique, params, wins: 0, lastWin: 0 };
  e.wins += 1;
  e.lastWin = Date.now();
  e.params = params;
  kb[sig][technique] = e;
  save(kb);
}

/** Total recorded wins across all signatures (for the dashboard). */
export function countWins(): number {
  const kb = load();
  return Object.values(kb).reduce((n, byTech) => n + Object.values(byTech).length, 0);
}

/** Retrieve the k most relevant PROVEN wins for a live triage context.
 * Relevance = token overlap between the win's technique and the target's
 * detector signals + interface shape ("oracle-spot-price" retrieves
 * "spot-oracle-manipulation"). Ties break toward recent wins. These feed
 * the triage prompt as few-shot examples — the model sees what a technique
 * that ACTUALLY drained a contract looks like, instead of guessing from a
 * bare source dump. */
export function sampleWins(
  shape: string,
  signals: string[],
  k = 3
): { technique: string; params: Record<string, string>; wins: number }[] {
  const kb = load();
 const contextTokens = new Set(
    [...signals, shape ?? ""]
      .flatMap((s) => (s ?? "").toLowerCase().split(/[^a-z0-9]+/))
      .filter((w) => w.length > 2)
  );
  const all = Object.values(kb).flatMap((byTech) => Object.values(byTech));
  const scored = all.map((e) => {
    const techTokens = e.technique.toLowerCase().split(/[^a-z0-9]+/);
    const overlap = techTokens.filter((t) => contextTokens.has(t)).length;
    return { e, overlap };
  });
  scored.sort((a, b) => b.overlap - a.overlap || b.e.lastWin - a.e.lastWin);
  return scored
    .filter((s) => s.overlap > 0)
    .slice(0, k)
    .map((s) => ({ technique: s.e.technique, params: s.e.params, wins: s.e.wins }));
}
