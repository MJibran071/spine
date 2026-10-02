// Real-world hack priors from DefiLlama's public hacks database.
//
// The triage LLM used to see a contract in isolation; these priors ground its
// confidence in how the same CATEGORY actually gets exploited (from 500+
// recorded incidents). Read-only GET, 24h disk cache, never fatal.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, OFFLINE } from "./config.ts";

const CACHE_PATH = join(REPORT_DIR, "osint-cache", "hacks-db.json");
const HACKS_TTL_MS = 24 * 3_600_000;

export interface HackRecord {
  date: number; // unix seconds
  name: string;
  classification: string;
  technique: string;
  amount: number | null; // USD
  chain: string[];
  bridgeHack?: boolean;
  targetType?: string;
  defillamaId?: string;
}

function cacheGet(): HackRecord[] | null {
  try {
    const j = JSON.parse(readFileSync(CACHE_PATH, "utf8")) as { t: number; data: HackRecord[] };
    if (Date.now() - j.t < HACKS_TTL_MS && Array.isArray(j.data) && j.data.length > 0) return j.data;
  } catch { /* miss */ }
  return null;
}

function cachePut(data: HackRecord[]): void {
  try {
    mkdirSync(join(REPORT_DIR, "osint-cache"), { recursive: true });
    writeFileSync(CACHE_PATH, JSON.stringify({ t: Date.now(), data }));
  } catch { /* non-fatal */ }
}

/** Full hacks DB (cached 24h). Empty array on failure — callers must degrade. */
export async function fetchHacks(force = false): Promise<HackRecord[]> {
  if (!force) {
    const cached = cacheGet();
    if (cached) return cached;
  }
  // Offline mode: serve the cache if there is one, never reach out. Keeps
  // tests deterministic and air-gapped runs quiet.
  if (OFFLINE) return cacheGet() ?? [];
  try {
    const res = await fetch("https://api.llama.fi/hacks", {
      headers: { "user-agent": "Mozilla/5.0 (compatible; ExploitLab-OSINT/1.0; read-only research)" },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`llama hacks HTTP ${res.status}`);
    const data = (await res.json()) as HackRecord[];
    if (Array.isArray(data) && data.length > 0) cachePut(data); // never cache empty
    return Array.isArray(data) ? data : [];
  } catch {
    return []; // stale-or-nothing: callers degrade to no priors
  }
}

function fmtUsd(n: number): string {
  if (n >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(0)}k`;
  return `$${Math.round(n)}`;
}

/** How a DefiLlama protocol category maps onto hack-DB words ("Dexs" -> dex). */
function categoryWords(category: string): string[] {
  const c = category.toLowerCase();
  const words = new Set<string>([c]);
  if (c.endsWith("s")) words.add(c.slice(0, -1)); // "Dexs" -> "dex"
  if (c === "cdp") { words.add("lending"); words.add("credit"); }
  if (c === "dexs" || c === "amm") { words.add("dex"); words.add("amm"); }
  if (c === "yield") words.add("vault");
  return [...words];
}

/** Category priors string for the triage prompt (<= ~800 chars), or "" when
 * the DB is unavailable. Includes a global recent-techniques line either way. */
export async function categoryPriors(category: string | null): Promise<string> {
  const db = await fetchHacks();
  if (db.length === 0) return "";
  const lines: string[] = ["Real-world priors (DefiLlama hacks DB, for calibration only - do not copy techniques onto unrelated code):"];

  if (category) {
    const words = categoryWords(category);
    const hits = db.filter((h) => {
      const hay = `${h.classification ?? ""} ${h.targetType ?? ""} ${h.technique ?? ""}`.toLowerCase();
      return words.some((w) => hay.includes(w));
    });
    if (hits.length > 0) {
      const total = hits.reduce((s, h) => s + (h.amount ?? 0), 0);
      const byTechnique = new Map<string, number>();
      for (const h of hits) {
        const t = (h.technique || h.classification || "unspecified").trim();
        byTechnique.set(t, (byTechnique.get(t) ?? 0) + 1);
      }
      const top = [...byTechnique.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
      lines.push(`- Category "${category}": ${hits.length} incident(s), ${fmtUsd(total)} lost. Most common techniques: ${top.map(([t, n]) => `${t} (${n})`).join(", ")}.`);
      const recent = hits.filter((h) => h.date > Date.now() / 1000 - 365 * 86_400).sort((a, b) => b.date - a.date).slice(0, 2);
      for (const h of recent) {
        lines.push(`- Recent: ${h.name} (${new Date(h.date * 1000).toISOString().slice(0, 10)}, ${h.amount ? fmtUsd(h.amount) : "n/a"}) - ${h.technique || h.classification}.`);
      }
    } else {
      lines.push(`- No recorded incidents specifically match category "${category}" - rely on the code evidence.`);
    }
  }

  // Global recent-technique drift: what actually works against live protocols lately.
  const cutoff = Date.now() / 1000 - 550 * 86_400; // ~18 months
  const recent = db.filter((h) => h.date > cutoff);
  const g = new Map<string, number>();
  for (const h of recent) {
    const t = (h.technique || h.classification || "").trim().toLowerCase();
    if (t) g.set(t, (g.get(t) ?? 0) + 1);
  }
  const gTop = [...g.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  lines.push(`- Last 18 months, all categories: dominant techniques are ${gTop.map(([t, n]) => `${t} (${n})`).join(", ")}.`);

  return lines.join("\n").slice(0, 1_200);
}
