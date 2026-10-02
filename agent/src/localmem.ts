// Local long-term memory baseline: append-only JSONL store with BM25-style
// lexical recall. Zero dependencies, zero network, works instantly — this is
// what memory.ts uses whenever the mem0 sidecar is not (yet) reachable.
//
// Why lexical and not embeddings: the real recall queries are "what do we know
// about 0xabc…", "layerzero bridge triage", "side-entrance reentrancy" —
// addresses, protocol names, and technique names are exactly the high-IDF
// tokens BM25 ranks best, so lexical recall on the actual corpus is effective
// without any model download. When mem0's sidecar comes online it takes over
// (semantic recall, auto-consolidation) and this store remains as history.
//
// Persistence: reports/memory/memories.jsonl — one JSON per line, human-
// readable, grep-able, trivially repairable. Appends are atomic-enough for a
// single-writer-per-record workload and survive every crash mode.
import { existsSync, mkdirSync, appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const STORE_DIR = join(REPORT_DIR, "memory");
const STORE_PATH = join(STORE_DIR, "memories.jsonl");
const MAX_MEMORIES = 5000;

interface MemoryRecord {
  t: number; // epoch ms
  text: string;
  meta?: Record<string, unknown>;
}

function tokenize(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((tok) => tok.length >= 3 && tok.length <= 64);
}

// Simple in-process cache of the parsed store (reload on mtime change).
let cache: { mtime: number; records: MemoryRecord[] } | null = null;

function loadStore(): MemoryRecord[] {
  try {
    if (!existsSync(STORE_PATH)) return [];
    const mtime = 0; // cheap freshness: reload when line count changes
    const raw = readFileSync(STORE_PATH, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    const fingerprint = lines.length; // good-enough change detector
    if (cache && cache.mtime === fingerprint) return cache.records;
    const records: MemoryRecord[] = [];
    for (const line of lines) {
      try {
        records.push(JSON.parse(line) as MemoryRecord);
      } catch {
        // corrupted line (torn write) — skip, the rest of the file is intact
      }
    }
    cache = { mtime: fingerprint, records };
    return records;
  } catch {
    return [];
  }
}

/** Store one memory. Never throws. */
export function localRemember(text: string, metadata?: Record<string, unknown>): void {
  const t = text.trim();
  if (!t) return;
  try {
    mkdirSync(STORE_DIR, { recursive: true });
    const rec: MemoryRecord = { t: Date.now(), text: t.slice(0, 800), meta: metadata ?? {} };
    appendFileSync(STORE_PATH, JSON.stringify(rec) + "\n");
    cache = null; // invalidate
  } catch {
    // memory must never break the hunt
  }
}

/** Memory kind, derived from the prefixes the writers use. Makes the store
 * legible in the dashboard instead of a wall of prose. */
export function classifyMemory(text: string): string {
  if (/^PROBE SUCCESS\b/.test(text)) return "probe-win";
  if (/^PROBE FAILED\b/.test(text)) return "probe-fail";
  if (/^PROBE NEUTRAL\b/.test(text)) return "probe-neutral";
  if (/^Triage\b/.test(text)) return "triage";
  if (/^PROBE\b/.test(text)) return "probe";
  return "other";
}

/** Ranked recall over the local store. One implementation so the lexical
 * `localRecall` used by triage and the dashboard's recall box agree. */
function rank(query: string, limit: number): { t: number; text: string; kind: string; score: number }[] {
  const rawTokens = [...new Set(tokenize(query))];
  if (rawTokens.length === 0) return [];
  const records = loadStore();
  if (records.length === 0) return [];

  // Address PREFIXES: the dashboard displays addresses truncated (`0x8cb36491…`),
  // so the way an operator searches for a target is with a prefix — and a
  // whole-token match would silently find nothing. Expand a hex-looking prefix
  // into the corpus tokens it prefixes (bounded), then rank normally.
  const corpusTokens = new Set<string>();
  for (const r of records) for (const tok of tokenize(r.text)) corpusTokens.add(tok);
  const qTokens = [
    ...new Set(
      rawTokens.flatMap((q) => {
        if (!/^0x[0-9a-f]+$/.test(q) || q.length < 6) return [q];
        const prefixed = [...corpusTokens].filter((t) => t.startsWith(q));
        return prefixed.length > 0 ? prefixed.slice(0, 25) : [q];
      })
    ),
  ];

  // Document frequencies over the store (corpus is small — O(n*|q|) is fine).
  const df = new Map<string, number>();
  for (const r of records) {
    const seen = new Set(tokenize(r.text));
    for (const tok of qTokens) if (seen.has(tok)) df.set(tok, (df.get(tok) ?? 0) + 1);
  }
  const N = records.length;
  const scored = records.map((r) => {
    const toks = tokenize(r.text);
    const tf = new Map<string, number>();
    for (const tok of toks) tf.set(tok, (tf.get(tok) ?? 0) + 1);
    let score = 0;
    for (const q of qTokens) {
      const n = df.get(q) ?? 0;
      if (n === 0) continue;
      const idf = Math.log(1 + (N - n + 0.5) / (n + 0.5));
      score += idf * ((tf.get(q) ?? 0) * 2.5) / ((tf.get(q) ?? 0) + 1.2 * (0.25 + 0.75 * (toks.length / 200)));
    }
    // Recent memories are more relevant — mild recency boost.
    const ageDays = (Date.now() - r.t) / 86_400_000;
    return { t: r.t, text: r.text, kind: classifyMemory(r.text), score: score * (1 + 1 / (1 + ageDays)) };
  });
  return scored.filter((s) => s.score > 0).sort((a, b) => b.score - a.score).slice(0, limit);
}

/** BM25-ish recall: IDF-weighted token overlap, newest wins ties. */
export function localRecall(query: string, limit = 5): string[] {
  return rank(query, limit).map((s) => s.text);
}

/** Recall with provenance, for the dashboard's recall box. */
export function localSearch(query: string, limit = 20): { t: number; text: string; kind: string; score: number }[] {
  return rank(query, limit);
}

export function localMemoryCount(): number {
  return loadStore().length;
}

export interface MemorySummary {
  total: number;
  bytes: number;
  kinds: Record<string, number>;
  /** Newest first, so the dashboard can stream them like a log. */
  recent: { t: number; text: string; kind: string; ref?: string }[];
  /** Counts for the last 12 hours, oldest bucket first (growth sparkline). */
  hourly: number[];
  firstAt: number | null;
  lastAt: number | null;
}

const HOURS = 12;

/** Read-side view of the memory store for the dashboard. Read-only and
 * best-effort: a missing/corrupt store reports zeros, never throws. */
export function localMemorySummary(recentLimit = 80): MemorySummary {
  let records: MemoryRecord[] = [];
  let bytes = 0;
  try {
    records = loadStore();
    if (existsSync(STORE_PATH)) bytes = readFileSync(STORE_PATH).length;
  } catch {
    // unreadable store — report an empty view rather than crash the UI
  }
  const kinds: Record<string, number> = {};
  for (const r of records) {
    const k = classifyMemory(r.text);
    kinds[k] = (kinds[k] ?? 0) + 1;
  }
  const bucketMs = 3_600_000;
  const nowBucket = Math.floor(Date.now() / bucketMs) * bucketMs;
  const hourly = new Array<number>(HOURS).fill(0);
  for (const r of records) {
    const idx = HOURS - 1 - Math.floor((nowBucket - Math.floor(r.t / bucketMs) * bucketMs) / bucketMs);
    if (idx >= 0 && idx < HOURS) hourly[idx]! += 1;
  }
  const recent = records
    .slice(-recentLimit)
    .reverse()
    .map((r) => ({
      t: r.t,
      text: r.text,
      kind: classifyMemory(r.text),
      // Whatever identifier the writer attached — the dashboard links it back
      // to the target it is about.
      ref: typeof r.meta?.address === "string" ? (r.meta.address as string) : undefined,
    }));
  return {
    total: records.length,
    bytes,
    kinds,
    recent,
    hourly,
    firstAt: records[0]?.t ?? null,
    lastAt: records[records.length - 1]?.t ?? null,
  };
}
