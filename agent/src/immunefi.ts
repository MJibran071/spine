// Immunefi bounty lookup — read-only, free, best-effort.
//
// Immunefi's GraphQL API is closed to anonymous clients, but public bug-bounty
// pages are reachable: https://immunefi.com/bug-bounty/<slug>/ redirects to
// /information/ and embeds the maximum payout. A slug candidate is derived
// from the protocol name; a 200 on the page = bounty exists.
//
// Every miss is cached (as null) so a not-listed protocol costs one HTTP GET
// per DAY, not per probe cycle. Never throws.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const CACHE_DIR = join(REPORT_DIR, "osint-cache", "immunefi");
const TTL_MS = 24 * 3_600_000;

export interface BountyInfo {
  protocol: string; // the name we looked up
  slug: string;
  maxPayout: string | null; // e.g. "$1,000,000"
  url: string;
}

function cachePath(name: string): string {
  const key = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return join(CACHE_DIR, `${key}.json`);
}

function cacheGet(name: string): BountyInfo | null | "miss" {
  try {
    const p = cachePath(name);
    if (!existsSync(p)) return "miss";
    const j = JSON.parse(readFileSync(p, "utf8")) as { t: number; data: BountyInfo | null; err?: boolean };
    // Network failures are cached for 1h only (they may succeed later); clean
    // answers (hit OR 404-miss) for the full day.
    const ttl = j.err ? 3_600_000 : TTL_MS;
    if (Date.now() - j.t > ttl) return "miss";
    return j.data;
  } catch {
    return "miss";
  }
}

function cachePut(name: string, info: BountyInfo | null, wasError = false): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(cachePath(name), JSON.stringify({ t: Date.now(), data: info, err: wasError }));
  } catch { /* non-fatal */ }
}

function slugFor(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/** Look up whether `protocolName` has a live Immunefi bounty. Returns null
 * when not listed (or lookup failed) — callers must treat null as "unknown,
 * likely no program", never as a verdict. */
export async function bountyFor(protocolName: string): Promise<BountyInfo | null> {
  if (!protocolName?.trim()) return null;
  const cached = cacheGet(protocolName);
  if (cached !== "miss") return cached;
  const slug = slugFor(protocolName);
  if (!slug) return null;
  const url = `https://immunefi.com/bug-bounty/${slug}/`;
  try {
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { "user-agent": "Mozilla/5.0 (compatible; ExploitLab-OSINT/1.0; read-only research)" },
        redirect: "follow",
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      cachePut(protocolName, null, true); // network error — remember briefly, retry within the hour
      return null;
    }
    if (!res.ok) {
      cachePut(protocolName, null); // 404 etc. — remember the miss for a day
      return null;
    }
    const html = await res.text();
    // Max payout appears as a dollar figure near "Maximum Payout" headings.
    const m = html.match(/\$[0-9][0-9,]{2,}(?:\.\d+)?/);
    const info: BountyInfo = {
      protocol: protocolName,
      slug,
      maxPayout: m ? m[0] : null,
      url,
    };
    cachePut(protocolName, info);
    return info;
  } catch {
    return null; // parse hiccup — retry next cycle
  }
}

/** One-line triage-prompt fragment, or "" when no bounty. */
export function bountyLine(info: BountyInfo | null): string {
  if (!info) return "";
  return `live Immunefi program for ${info.protocol} (max payout ${info.maxPayout ?? "undisclosed"}): report only what a local fork actually reproduces; no speculation.`;
}

/** Suffix tokens that hide the real program name: "LayerZero V2" → "LayerZero",
 * "Polygon Bridge" → "Polygon", "Raydium AMM" → "Raydium". */
const SUFFIX_RE = /\s+(?:v\d+|bridge|chain|dex|amm|finance|protocol|token|exchange)$/i;

/** Lookup with suffix fallbacks — DefiLlama names are often decorated
 * ("LayerZero V2") while Immunefi slugs use the bare program name. Each
 * variant's miss is cached a day, so retries stay cheap. */
export async function bountyForProtocol(name: string): Promise<BountyInfo | null> {
  const direct = await bountyFor(name);
  if (direct) return direct;
  let cur = name.trim();
  for (let i = 0; i < 2; i++) {
    const next = cur.replace(SUFFIX_RE, "").trim();
    if (!next || next.toLowerCase() === cur.toLowerCase()) break;
    const hit = await bountyFor(next);
    if (hit) return hit;
    cur = next;
  }
  return null;
}
