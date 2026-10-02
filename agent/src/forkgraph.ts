// Fork-graph prior — "this is a fork of a protocol that got hacked".
//
// When the scanner enlists a live target, the strongest cheap prior a human
// auditor uses is lineage: a fork of a once-exploited protocol inherits the
// exploit surface (same vault math, same admin plane, same oracle habits).
// This module resolves each watchlist entry's parent protocol via DefiLlama's
// public protocol API (which exposes fork relationships as `parent`), then
// stamps the watchlist row with:
//   - the parent protocol name,
//   - whether the parent (or a sibling fork of it) appears in the hacks DB.
//
// What it changes downstream: `forkPrio()` bumps the probe-priority score a
// daemon already computes (bounty +2, seeded +1 → hacked-lineage adds +2), so
// a bounded worker pool never starves the targets shaped like yesterday's
// losses. Free, read-only, 24h cache, never fatal.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, OFFLINE } from "./config.ts";
import { fetchHacks, type HackRecord } from "./hacks.ts";

const CACHE_PATH = join(REPORT_DIR, "osint-cache", "fork-graph.json");
const TTL_MS = 24 * 3_600_000;

/** slug -> { parent slug, name } for every protocol DefiLlama knows. */
interface ForkGraph {
  t: number;
  parents: Record<string, string>; // child slug -> parent slug
  names: Record<string, string>; // slug -> display name
}

function cacheGet(): ForkGraph | null {
  try {
    const j = JSON.parse(readFileSync(CACHE_PATH, "utf8")) as ForkGraph;
    if (Date.now() - j.t < TTL_MS && j.parents) return j;
  } catch { /* miss */ }
  return null;
}

function cachePut(g: ForkGraph): void {
  try {
    mkdirSync(join(REPORT_DIR, "osint-cache"), { recursive: true });
    writeFileSync(CACHE_PATH, JSON.stringify(g));
  } catch { /* non-fatal */ }
}

/** DefiLlama keeps fork lineage in each protocol's `parent` field. The full
 * protocols list is one GET; only the slug/name/parent triple is kept. */
async function loadGraph(): Promise<ForkGraph> {
  const cached = cacheGet();
  if (cached) return cached;
  const empty: ForkGraph = { t: Date.now(), parents: {}, names: {} };
  if (OFFLINE) return empty;
  try {
    const res = await fetch("https://api.llama.fi/protocols", {
      headers: { "user-agent": "Mozilla/5.0 (compatible; ExploitLab-OSINT/1.0; read-only research)" },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) return empty;
    const data = (await res.json()) as { slug?: string; name?: string; parent?: { id?: string; name?: string } | string }[];
    if (!Array.isArray(data) || data.length === 0) return empty;
    const parents: Record<string, string> = {};
    const names: Record<string, string> = {};
    for (const p of data) {
      if (!p.slug) continue;
      names[p.slug] = p.name ?? p.slug;
      const par = p.parent;
      const parentSlug = typeof par === "string" ? par : par?.id ?? null;
      if (parentSlug) parents[p.slug] = String(parentSlug).toLowerCase();
    }
    const g: ForkGraph = { t: Date.now(), parents, names };
    cachePut(g);
    return g;
  } catch {
    return empty;
  }
}

/** Hacked protocol names, lowercased, from the hacks DB (same cache as triage). */
async function hackedNames(): Promise<Set<string>> {
  const hacks = await fetchHacks();
  const out = new Set<string>();
  for (const h of hacks) {
    out.add(h.name.toLowerCase());
    if (h.defillamaId) out.add(String(h.defillamaId).toLowerCase());
  }
  return out;
}

export interface ForkPrior {
  parent: string | null;
  /** True when the parent or a sibling fork appears in the hacks DB. */
  hackedLineage: boolean;
  /** Names of the hacked entries that matched (for the watchlist note). */
  matched: string[];
  /** +N probe-priority bump (0 when nothing matched). */
  prio: number;
}

/** Resolve the prior for one target name (the watchlist row's `name`, which
 * the scanner seeds from DefiLlama protocol names). Never throws. */
export async function forkPrior(name: string | null | undefined): Promise<ForkPrior> {
  const none: ForkPrior = { parent: null, hackedLineage: false, matched: [], prio: 0 };
  if (!name || name.length < 3) return none;
  const graph = await loadGraph();
  if (!graph.parents || Object.keys(graph.parents).length === 0) return none;
  // The watchlist stores display names; DefiLlama keys by slug. Match by
  // normalized display name first, then try the slugified form.
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const slug = norm(name);
  const parent = graph.parents[slug] ?? null;
  if (!parent) return none;
  const hacked = await hackedNames();
  const matched: string[] = [];
  if (hacked.has(parent) || hacked.has(graph.names[parent]?.toLowerCase() ?? "")) {
    matched.push(graph.names[parent] ?? parent);
  }
  // Sibling forks: other protocols sharing the parent.
  for (const [child, par] of Object.entries(graph.parents)) {
    if (par !== parent || child === slug) continue;
    const nm = graph.names[child]?.toLowerCase() ?? "";
    if (hacked.has(child) || (nm && hacked.has(nm))) matched.push(graph.names[child] ?? child);
  }
  if (matched.length === 0) return { parent, hackedLineage: false, matched: [], prio: 0 };
  return { parent, hackedLineage: true, matched: matched.slice(0, 3), prio: 2 };
}

/** Resolve priors for a whole watchlist's names and return only the rows
 * worth stamping (hacked lineage). The daemon calls this on its slow lane. */
export async function scanForkPriors(names: string[]): Promise<Map<string, ForkPrior>> {
  const out = new Map<string, ForkPrior>();
  for (const n of names) {
    const p = await forkPrior(n);
    if (p.hackedLineage) out.set(n, p);
  }
  return out;
}
