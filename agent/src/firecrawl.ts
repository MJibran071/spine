// Firecrawl integration — full-site scraping for OSINT deep dives.
//
// What it adds over the plain-DDG/Tavily search in osint.ts: complete page
// content (markdown), not snippets. Used for:
//   - rekt.news post-mortem FULL TEXT (technique details for triage priors)
//   - a candidate protocol's docs/security pages (audits, admin keys, pausing)
//
// Safety/budget model (same discipline as osint.ts):
//   - every call is a read-only HTTPS POST to api.firecrawl.dev
//   - daily credit cap LAB_FIRECRAWL_DAILY_MAX (default 40 — free tier is
//     ~500 one-time credits, so this is weeks of hunting, not minutes)
//   - disk cache 24h per URL (hits AND misses cached — a 404 site will not
//     heal in 5 minutes and re-scraping burns credits)
//   - degraded honestly: no key / out of credits / network error -> null,
//     callers must treat scraping as best-effort context, never a gate.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const CACHE_DIR = join(REPORT_DIR, "firecrawl-cache");
const STATE_PATH = join(REPORT_DIR, "firecrawl-state.json");
const API = "https://api.firecrawl.dev/v1";
const TTL_MS = 24 * 3_600_000;

export function firecrawlKey(): string {
  return (process.env.FIRECRAWL_API_KEY ?? "").trim();
}
export function firecrawlAvailable(): boolean {
  return firecrawlKey().length > 0;
}
function dailyMax(): number {
  return parseInt(process.env.LAB_FIRECRAWL_DAILY_MAX ?? "40", 10) || 40;
}

interface FcBudget {
  day: string;
  credits: number;
}
function loadBudget(): FcBudget {
  const today = new Date().toISOString().slice(0, 10);
  try {
    const b = JSON.parse(readFileSync(STATE_PATH, "utf8")) as FcBudget;
    if (b.day === today) return b;
  } catch { /* fresh day / first run */ }
  return { day: today, credits: 0 };
}
function spendCredit(): boolean {
  const b = loadBudget();
  if (b.credits >= dailyMax()) return false;
  b.credits += 1;
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify(b));
  } catch { /* non-fatal */ }
  return true;
}
export function firecrawlBudgetUsed(): number {
  return loadBudget().credits;
}

function cachePath(url: string): string {
  // URL -> stable filename (no scheme, slashes escaped)
  const safe = url.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9.-]+/g, "_").slice(0, 120);
  return join(CACHE_DIR, `${safe}.json`);
}
function cacheGet(url: string): { markdown: string; metadata?: Record<string, unknown> } | "miss" | null {
  try {
    const p = cachePath(url);
    if (!existsSync(p)) return null; // never fetched
    const j = JSON.parse(readFileSync(p, "utf8")) as { t: number; data: { markdown: string; metadata?: Record<string, unknown> } | "miss" };
    return Date.now() - j.t < TTL_MS ? j.data : null; // expired -> refetch
  } catch {
    return null;
  }
}
function cachePut(url: string, data: { markdown: string; metadata?: Record<string, unknown> } | "miss"): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(cachePath(url), JSON.stringify({ t: Date.now(), data }));
  } catch { /* non-fatal */ }
}

export interface ScrapeResult {
  url: string;
  markdown: string;
  title?: string;
}

/** Scrape one URL to clean markdown. Cached 24h (incl. failures). */
export async function firecrawlScrape(url: string, force = false): Promise<ScrapeResult | null> {
  if (!firecrawlAvailable()) return null;
  if (!force) {
    const c = cacheGet(url);
    if (c === "miss") return null;
    if (c && c !== "miss") return { url, markdown: c.markdown, title: (c.metadata?.title as string) ?? undefined };
  }
  if (!spendCredit()) return null; // budget spent — degrade, don't error
  try {
    const res = await fetch(`${API}/scrape`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${firecrawlKey()}`,
      },
      body: JSON.stringify({ url, formats: ["markdown"], onlyMainContent: true, timeout: 20000 }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      cachePut(url, "miss");
      return null;
    }
    const j = (await res.json()) as { data?: { markdown?: string; metadata?: Record<string, unknown> } };
    const md = j.data?.markdown ?? "";
    if (md.length < 40) {
      cachePut(url, "miss");
      return null;
    }
    const out = { markdown: md, metadata: j.data?.metadata };
    cachePut(url, out);
    return { url, markdown: md, title: (j.data?.metadata?.title as string) ?? undefined };
  } catch {
    cachePut(url, "miss");
    return null;
  }
}

/** Map an entire site (all discoverable URLs). Cheap (1 credit), cached 24h. */
export async function firecrawlMap(url: string, force = false): Promise<string[] | null> {
  if (!firecrawlAvailable()) return null;
  const key = `map:${url}`;
  if (!force) {
    const c = cacheGet(key);
    if (c === "miss") return null;
    if (c && c !== "miss") return (c.metadata?.urls as string[]) ?? null;
  }
  if (!spendCredit()) return null;
  try {
    const res = await fetch(`${API}/map`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${firecrawlKey()}`,
      },
      body: JSON.stringify({ url, limit: 200 }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      cachePut(key, "miss");
      return null;
    }
    const j = (await res.json()) as { links?: Array<{ url: string } | string> };
    const urls = (j.links ?? []).map((l) => (typeof l === "string" ? l : l.url)).filter(Boolean);
    if (urls.length === 0) {
      cachePut(key, "miss");
      return null;
    }
    cachePut(key, { markdown: "", metadata: { urls } });
    return urls;
  } catch {
    cachePut(key, "miss");
    return null;
  }
}

/** Deep-dive a protocol's site: map it, then scrape the handful of pages that
 * historically matter for security triage (security, audits, docs, governance,
 * Risks). Returns up to `maxPages` full-text results. */
export async function firecrawlSiteDeepDive(siteUrl: string, maxPages = 3): Promise<ScrapeResult[]> {
  const urls = await firecrawlMap(siteUrl);
  const candidates: string[] = [];
  if (urls && urls.length > 0) {
    const interesting = /(secur|audit|docs|documentation|gov|govern|risk|post-mortem|incident|bug-?bounty)/i;
    const sameSite = urls.filter((u) => {
      try {
        return new URL(u).host === new URL(siteUrl).host;
      } catch {
        return false;
      }
    });
    candidates.push(...sameSite.filter((u) => interesting.test(u)).slice(0, maxPages));
    if (candidates.length < maxPages) {
      candidates.push(...sameSite.filter((u) => !candidates.includes(u)).slice(0, maxPages - candidates.length));
    }
  } else {
    candidates.push(siteUrl); // map unavailable — at least try the root page
  }
  const out: ScrapeResult[] = [];
  for (const u of candidates.slice(0, maxPages)) {
    const r = await firecrawlScrape(u);
    if (r) out.push(r);
  }
  return out;
}

/** Full text of a rekt.news post-mortem — grounds triage in how real attacks worked. */
export async function rektFullText(slug: string, force = false): Promise<ScrapeResult | null> {
  return firecrawlScrape(`https://rekt.news${slug}`, force);
}
