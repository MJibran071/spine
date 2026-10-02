// Hypothesis + claim ledger — turns the hunt from random re-visitation into
// systematic elimination.
//
// Two shared stores (one file, single-threaded sync reads/writes, same
// pattern as knowledge.ts):
//
//   HYPOTHESES — every detector firing / triage conclusion creates a NAMED
//   hypothesis per target ("sig-gated-claim", "oracle-spot-price", ...).
//   Probes mark them refuted/held/actionable. The scheduler prefers targets
//   that still have UNTESTED hypotheses, so a probe always buys new
//   information instead of re-running a solved question.
//
//   CLAIMS — a daemon claims a target for the duration of a probe. Claims
//   expire on TTL, so a crashed daemon cannot strand a target forever, and a
//   live fleet never double-probes the same address in parallel.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const LEDGER_PATH = join(REPORT_DIR, "hypotheses.json");

export type HypothesisStatus = "untested" | "refuted" | "held" | "actionable";

export type HypothesisOrigin = "detector" | "triage" | "manual" | "curiosity" | "idea";

export interface Hypothesis {
  key: string;
  chainId: string;
  address: string;
  technique: string;
  /** "idea" = seeded from an LLM attack-idea (attackideas.ts) so prose ideas
   * become scheduled, executable, refuted-or-proven ledger rows. */
  origin: HypothesisOrigin;
  status: HypothesisStatus;
  firstSeen: number;
  lastTested?: number;
  tests?: number;
  /** Capped note from the latest test (revert reason, probe outcome). */
  evidence?: string;
}

interface Claim {
  daemonId: string;
  at: number;
}

interface LedgerStore {
  version: 1;
  hypotheses: Record<string, Hypothesis>;
  claims: Record<string, Claim>;
}

/** A probe (recon + source fetch + triage + fork sim) can legitimately run
 * for minutes; the TTL only needs to outlive a LIVE probe. A dead daemon's
 * claim self-heals after this window. */
const CLAIM_TTL_MS = 6 * 60_000;

function load(): LedgerStore {
  try {
    if (existsSync(LEDGER_PATH)) {
      const j = JSON.parse(readFileSync(LEDGER_PATH, "utf8")) as LedgerStore;
      if (j && typeof j === "object" && j.hypotheses && j.claims) return j;
    }
  } catch {
    // corrupt ledger = fresh start (hypotheses are re-derived by design)
  }
  return { version: 1, hypotheses: {}, claims: {} };
}

function save(s: LedgerStore): void {
  mkdirSync(REPORT_DIR, { recursive: true });
  writeFileSync(LEDGER_PATH, JSON.stringify(s));
}

function hypKey(chainId: string, address: string, technique: string): string {
  return `${chainId}:${address.toLowerCase()}:${technique}`;
}
function claimKey(chainId: string, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}

/** Record hypotheses for a target if not already present. Returns how many
 * were NEW (0 = pure repeat — the caller logs nothing new was learned).
 * Origin "idea" rows are UPDATED in place when the same idea re-suggests
 * with a different slug (ideas regenerate; detectors' rows never move). */
export function ensureHypotheses(
  chainId: string,
  address: string,
  items: { technique: string; origin: Hypothesis["origin"] }[]
): number {
  const s = load();
  let added = 0;
  for (const { technique, origin } of items) {
    if (!technique) continue;
    const key = hypKey(chainId, address, technique);
    if (s.hypotheses[key]) continue;
    // Idea regeneration with a refined slug: migrate the old idea row instead
    // of leaving two open rows for one idea (scheduler would re-probe both).
    if (origin === "idea") {
      const stale = Object.values(s.hypotheses).find(
        (h) => h.chainId === chainId && h.address === address.toLowerCase() && h.origin === "idea" && h.status === "untested"
      );
      if (stale) {
        delete s.hypotheses[stale.key];
      }
    }
    s.hypotheses[key] = {
      key,
      chainId,
      address: address.toLowerCase(),
      technique,
      origin,
      status: "untested",
      firstSeen: Date.now(),
    };
    added++;
  }
  if (added > 0) save(s);
  return added;
}

/** The target's oldest UNTESTED hypothesis, or null when every known
 * hypothesis has been tested. This is what makes probes buy information. */
export function nextHypothesis(chainId: string, address: string): Hypothesis | null {
  const s = load();
  const prefix = `${chainId}:${address.toLowerCase()}:`;
  let best: Hypothesis | null = null;
  for (const h of Object.values(s.hypotheses)) {
    if (!h.key.startsWith(prefix) || h.status !== "untested") continue;
    if (!best || h.firstSeen < best.firstSeen) best = h;
  }
  return best;
}

/** Record the outcome of testing a hypothesis. `held` = the probe could not
 * exercise it (reverted for environmental reasons), not that it is wrong.
 * Returns false when no row matched (caller decides on a fallback). */
export function markHypothesis(
  chainId: string,
  address: string,
  technique: string,
  status: Exclude<HypothesisStatus, "untested">,
  evidence?: string
): boolean {
  const s = load();
  const h = s.hypotheses[hypKey(chainId, address, technique)];
  if (!h) return false;
  h.status = status;
  h.lastTested = Date.now();
  h.tests = (h.tests ?? 0) + 1;
  if (evidence) h.evidence = evidence.slice(0, 200);
  save(s);
  return true;
}

/** Lowercased `${chainId}:${addr}` set of targets that still have at least
 * one untested hypothesis. Loaded once per scheduling decision. */
export function untestedTargets(): Set<string> {
  const s = load();
  const out = new Set<string>();
  for (const h of Object.values(s.hypotheses)) {
    if (h.status === "untested") out.add(claimKey(h.chainId, h.address));
  }
  return out;
}

/** Read-only snapshot of all hypotheses — for consolidation/digests that
 * need to see which targets already carry open work without mutating. */
export function allHypotheses(): Hypothesis[] {
  return Object.values(load().hypotheses);
}

export interface LedgerStats {
  hypotheses: { total: number; untested: number; refuted: number; held: number; actionable: number };
  claims: number;
  /** Origin-"idea" rows: the idea→execution loop's conversion funnel. */
  ideas: { total: number; untested: number; refuted: number; held: number; actionable: number };
}

export function ledgerStats(): LedgerStats {
  const s = load();
  const counts = { total: 0, untested: 0, refuted: 0, held: 0, actionable: 0 };
  for (const h of Object.values(s.hypotheses)) {
    counts.total++;
    counts[h.status]++;
  }
  const now = Date.now();
  return {
    hypotheses: counts,
    claims: Object.values(s.claims).filter((c) => now - c.at < CLAIM_TTL_MS).length,
    /** Ideas that entered the pipeline as executable rows (per status). */
    ideas: (() => {
      const ideas = { total: 0, untested: 0, refuted: 0, held: 0, actionable: 0 };
      for (const h of Object.values(s.hypotheses)) {
        if (h.origin !== "idea") continue;
        ideas.total++;
        ideas[h.status]++;
      }
      return ideas;
    })(),
  };
}

/** Claim a target for this daemon's probe. Returns false when another live
 * claim holds it (the probe is skipped — never doubled). */
export function claimTarget(chainId: string, address: string, daemonId: string): boolean {
  const s = load();
  const key = claimKey(chainId, address);
  const now = Date.now();
  const existing = s.claims[key];
  if (existing && now - existing.at < CLAIM_TTL_MS && existing.daemonId !== daemonId) return false;
  s.claims[key] = { daemonId, at: now };
  save(s);
  return true;
}

export function releaseClaim(chainId: string, address: string, daemonId: string): void {
  const s = load();
  const key = claimKey(chainId, address);
  const c = s.claims[key];
  if (c && c.daemonId === daemonId) {
    delete s.claims[key];
    save(s);
  }
}
