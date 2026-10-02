// Memory consolidation — closes the "memory grows but nothing consumes it"
// loop. The local store (memories.jsonl) collects per-target conclusions
// (probe outcomes, triage verdicts, negative results) but nothing turns them
// into pipeline actions. This module reads the raw store, groups everything by
// target, and derives two kinds of value:
//
//   1. Hypothesis promotion — targets whose memories show accumulated
//      *anomalies* (revert-class failures, unusual surfaces, wealth signals)
//      get a `memory-anomaly` hypothesis in the ledger so investigate.ts
//      picks them up on a future cycle instead of the signal dying in prose.
//
//   2. An operator digest — top anomalies per target with counts, newest
//      memory, and the verbatim conclusion lines, written to
//      reports/MEMORY-DIGEST.md for the weekly human review.
//
// Idempotent: promotion is capped per run and only fires for targets not
// already carrying an open hypothesis, so the daemon can call it nightly
// without flooding the ledger. Zero new deps, same conventions as the rest
// of the agent (REPORT_DIR stores, strip-types imports with .ts suffixes).
import { existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { ensureHypotheses, allHypotheses } from "./ledger.ts";
import { localMemoryCount } from "./localmem.ts";
import { genLearnOverview, mineLessonsFromMemories, topCompileClasses } from "./genlearn.ts";
import { techniquesStats } from "./techniques.ts";

const MEMORIES_PATH = join(REPORT_DIR, "memory", "memories.jsonl");
const DIGEST_PATH = join(REPORT_DIR, "MEMORY-DIGEST.md");
/** Promote at most this many targets per run — investigate.ts has a fixed
 * probe budget, so a flood of new hypotheses would just clog the queue. */
const PROMOTE_CAP = 10;

const ADDR_RE = /0x[0-9a-fA-F]{40}/g;

/** Signal words whose presence in a target's memory cluster marks it as
 * anomalous. Chosen from the actual corpus: probe reverts, unresolved
 * shapes, and simulation oddities — not ordinary "clean, nothing found". */
const ANOMALY_PATTERNS: { re: RegExp; weight: number; label: string }[] = [
  { re: /revert(ed)? in simulation|simulated: revert/i, weight: 3, label: "sim-revert" },
  { re: /anvil fork failed|fork failed to start/i, weight: 2, label: "fork-fail" },
  { re: /shape: unknown|no harnessable shape/i, weight: 2, label: "unknown-shape" },
  { re: /manual-analysis-required/i, weight: 2, label: "needs-analysis" },
  { re: /arbitrary call|arbitrary-call/i, weight: 3, label: "arbitrary-call" },
  { re: /unusual|unexpected|anomal/i, weight: 2, label: "flagged-odd" },
  { re: /unverified|no source|source unavailable/i, weight: 2, label: "no-source" },
  { re: /large (?:balance|float|holding)|idle (?:funds|balance)|untouched/i, weight: 3, label: "idle-value" },
  { re: /collect\(|sweep|withdrawal surface|fee router/i, weight: 2, label: "value-surface" },
  { re: /oracle|price feed|stale price/i, weight: 2, label: "oracle-surface" },
  { re: /NOT vulnerable|no value extracted|nothing found|clean/i, weight: -4, label: "negative" },
  { re: /PROBE SUCCESS|PRODUCED A DRAIN/i, weight: 5, label: "prior-win" },
];

export interface TargetAnomaly {
  chainId: string;
  address: string;
  score: number;
  signals: string[];
  memoryCount: number;
  newest: number;
  examples: string[];
}

interface MemoryRecord {
  t: number;
  text: string;
  meta?: Record<string, unknown>;
}

function loadMemories(): MemoryRecord[] {
  try {
    if (!existsSync(MEMORIES_PATH)) return [];
    const out: MemoryRecord[] = [];
    for (const line of readFileSync(MEMORIES_PATH, "utf8").split("\n")) {
      const s = line.trim();
      if (!s) continue;
      try {
        const j = JSON.parse(s) as MemoryRecord;
        if (typeof j.text === "string" && j.text) out.push({ t: Number(j.t) || 0, text: j.text, meta: j.meta });
      } catch {
        // skip malformed line — the store tolerates junk
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Address-only key when the memory doesn't name a chain. Inference order:
 * meta → chain name in the prose → the ledger's existing chain for that
 * address (the fleet records watchlist hypotheses under real chain ids) →
 * "1" (Ethereum — this fleet's watchlist is mainnet-scoped, matching how
 * the daemon itself treats watchlist addresses). Prevents `unknown:` ledger
 * keys that nextHypothesis would never match. */
function makeChainResolver(ledgerChain: Map<string, string>) {
  return (text: string, meta?: Record<string, unknown>): string => {
    if (meta && typeof meta.chainId === "string") return meta.chainId;
    const m = /\b(ethereum|arbitrum|optimism|base|polygon|bsc|avalanche)\b/i.exec(text);
    if (m) return m[1]!.toLowerCase();
    for (const a of targetAddresses(text)) {
      const c = ledgerChain.get(a);
      if (c) return c;
    }
    return "1";
  };
}

/** Extract target addresses from a memory text, ignoring known system
 * addresses that appear in boilerplate. */
function targetAddresses(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(ADDR_RE)) {
    const a = m[0].toLowerCase();
    out.add(a);
  }
  return [...out];
}

/** Exported for deepdive.ts: standalone memory-anomaly score for one record
 * set (same weights as the consolidation run, without clustering). */
export function scoreMemorySignals(records: MemoryRecord[]): { score: number; signals: string[] } {
  let score = 0;
  const signals = new Set<string>();
  for (const r of records) {
    for (const p of ANOMALY_PATTERNS) {
      if (p.re.test(r.text)) {
        score += p.weight;
        signals.add(p.label);
      }
    }
  }
  return { score, signals: [...signals] };
}

/** Memory-record shape shared with deepdive.ts (structural only). */
export interface ScoreableMemory {
  t: number;
  text: string;
}

/** Score one target's memory cluster; returns null when it isn't anomalous. */
function scoreCluster(records: MemoryRecord[]): { score: number; signals: string[]; examples: string[]; newest: number } | null {
  let score = 0;
  const signals = new Set<string>();
  const examples: string[] = [];
  let newest = 0;
  for (const r of records) {
    newest = Math.max(newest, r.t);
    for (const p of ANOMALY_PATTERNS) {
      if (p.re.test(r.text)) {
        score += p.weight;
        signals.add(p.label);
        if (examples.length < 3 && p.weight > 0) examples.push(r.text.slice(0, 220));
      }
    }
  }
  // Volume itself is weak evidence: a target probed 8 times without closure
  // is more interesting than one probed once, but never more than a signal.
  score += Math.min(2, Math.floor(records.length / 4));
  if (score < 3 || signals.size === 0) return null;
  return { score, signals: [...signals], examples, newest };
}

/** Consolidate the memory store. Returns a human-readable summary line set
 * for the caller to log; also writes reports/MEMORY-DIGEST.md. */
export function consolidateMemory(options?: { maxPromote?: number }): { promoted: number; anomalies: number; lines: string[] } {
  const cap = options?.maxPromote ?? PROMOTE_CAP;
  const records = loadMemories();
  const lines: string[] = [];
  if (records.length === 0) {
    return { promoted: 0, anomalies: 0, lines: ["memory store empty — nothing to consolidate"] };
  }

  // Group by target. Chain is inferred per record (ledger-backed resolver).
  const ledgerChain = new Map<string, string>();
  for (const h of allHypotheses()) if (!ledgerChain.has(h.address)) ledgerChain.set(h.address, h.chainId);
  const chainOf = makeChainResolver(ledgerChain);
  const clusters = new Map<string, { chainId: string; address: string; records: MemoryRecord[] }>();
  for (const r of records) {
    const chainId = chainOf(r.text, r.meta);
    for (const addr of targetAddresses(r.text)) {
      const key = `${chainId}:${addr}`;
      let c = clusters.get(key);
      if (!c) {
        c = { chainId, address: addr, records: [] };
        clusters.set(key, c);
      }
      c.records.push(r);
    }
  }

  // Score clusters, keep anomalies.
  const anomalies: TargetAnomaly[] = [];
  for (const c of clusters.values()) {
    const s = scoreCluster(c.records);
    if (s) {
      anomalies.push({
        chainId: c.chainId,
        address: c.address,
        score: s.score,
        signals: s.signals,
        memoryCount: c.records.length,
        newest: s.newest,
        examples: s.examples,
      });
    }
  }
  anomalies.sort((a, b) => b.score - a.score || b.newest - a.newest);

  // Promote the top anomalies that have no open hypothesis yet.
  const existing = allHypotheses();
  const openByAddr = new Map<string, number>();
  for (const h of existing) {
    const k = `${h.chainId}:${h.address.toLowerCase()}`;
    if (h.status === "untested") {
      openByAddr.set(k, (openByAddr.get(k) ?? 0) + 1);
    }
  }
  let promoted = 0;
  for (const a of anomalies) {
    if (promoted >= cap) break;
    const k = `${a.chainId}:${a.address}`;
    if ((openByAddr.get(k) ?? 0) > 0) continue; // already being worked
    const added = ensureHypotheses(a.chainId, a.address, [
      { technique: "memory-anomaly", origin: "curiosity" },
    ]);
    if (added > 0) {
      promoted++;
      lines.push(`promoted ${a.chainId}:${a.address.slice(0, 10)}… score=${a.score} signals=[${a.signals.join(",")}] (${a.memoryCount} memories)`);
    }
  }

  // Operator digest: what a human should glance at weekly.
  const top = anomalies.slice(0, 25);
  const md = [
    `# Memory Digest — ${new Date().toISOString().replace("T", " ").slice(0, 16)}`,
    "",
    `Store: ${localMemoryCount()} memories · clusters: ${clusters.size} · anomalous targets: ${anomalies.length} · promoted this run: ${promoted}`,
    "",
    "| # | Target | Score | Signals | Memories | Newest |",
    "|---|--------|-------|---------|----------|--------|",
    ...top.map((a, i) =>
      `| ${i + 1} | \`${a.chainId}:${a.address.slice(0, 12)}…\` | ${a.score} | ${a.signals.join(", ")} | ${a.memoryCount} | ${a.newest ? new Date(a.newest).toISOString().slice(0, 10) : "?"} |`
    ),
    "",
    "## Example conclusion lines",
    "",
    ...top.slice(0, 8).flatMap((a) => [
      `### ${a.chainId}:${a.address.slice(0, 12)}… (score ${a.score})`,
      ...a.examples.map((e) => `- ${e}`),
      "",
    ]),
  ].join("\n");
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(DIGEST_PATH, md);
  } catch {
    // digest is best-effort; never fail the run on a write error
  }

  // Cross-shape lesson mining: a "PROBE SUCCESS … PRODUCED A DRAIN …
  // technique X" memory is PROOF that X works on the memory's shape — mine
  // those into the genlearn store so future triage hints for that shape
  // propose the proven class FIRST. Idempotent: deduped per (shape, tech).
  let mined = 0;
  try {
    mined = mineLessonsFromMemories(records.map((r) => r.text));
  } catch { /* mining is best-effort */ }
  if (mined > 0) lines.push(`lessons: ${mined} new proven technique class(es) mined into shape priors`);

  // Compile-class telemetry in the digest: a failure class repeating across
  // many targets is a GENERATOR bug, not target noise — surface it where the
  // weekly human review actually looks.
  try {
    const cc = topCompileClasses(5);
    if (cc.length > 0) {
      lines.push(`compile telemetry: ${cc.map((c) => `${c.failureClass}×${c.count}`).join(", ")}`);
    }
  } catch { /* cosmetic */ }

  // Self-learned technique library telemetry: the fleet's own proven drains
  // and how many have been generalized into reusable notes.
  try {
    const t = techniquesStats();
    if (t.total > 0) {
      lines.push(`technique library: ${t.total} self-learned technique(s) from ${t.proven} proven drain(s), ${t.distilled} generalized, across ${t.shapes} shape(s)`);
    }
  } catch { /* cosmetic */ }

  // Engine learning telemetry line: how much the generic engine has actually
  // LEARNED (not just attempted) since the last digest.
  try {
    const g = genLearnOverview();
    const cooling = g.cooling.map((c) => `${c.shape}(${c.minutesLeft}m)`).join(", ");
    lines.push(`engine learning: ${g.violations} proven violation(s), ${g.deadends} dead end(s), ${g.lessons.length} shape(s) carrying proven lessons${cooling ? `, cooling: ${cooling}` : ""}`);
  } catch { /* cosmetic */ }

  lines.push(`consolidation: ${records.length} memories → ${clusters.size} targets → ${anomalies.length} anomalous → ${promoted} promoted (digest: reports/MEMORY-DIGEST.md)`);
  return { promoted, anomalies: anomalies.length, lines };
}

/** CLI entry: `node --experimental-strip-types src/consolidate.ts` */
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = consolidateMemory();
  for (const l of r.lines) console.log(l);
}
