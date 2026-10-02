// OSINT layer for the exploit lab: free, keyless, READ-ONLY web intel.
//
// Sources (all free):
//   - DefiLlama API  https://api.llama.fi/protocols   (no key)
//       target discovery: new + unaudited + holding TVL = prime candidates
//   - rekt.news homepage                              (no key)
//       real-world post-mortem headlines for the knowledge-base context
//   - DuckDuckGo Lite https://lite.duckduckgo.com/lite/ (no key, HTML)
//       generic web search fallback
//   - Tavily (OPTIONAL, only if TAVILY_API_KEY is set — free tier exists)
//       preferred search when a key is present; otherwise never contacted
//
// Safety: every request is a read-only HTTP GET/POST, 20s timeout, cached on
// disk, daily-capped like the LLM triage budget. Nothing here executes code,
// touches forks, or writes anything outside reports/.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { logEvent, snapshot, upsertWatch } from "./bus.ts";
import { bountyForProtocol } from "./immunefi.ts";
import { runSmallLane, type SmallTarget } from "./llamatargets.ts";
import { firecrawlAvailable, firecrawlBudgetUsed, rektFullText, firecrawlSiteDeepDive } from "./firecrawl.ts";
import type { ScrapeResult } from "./firecrawl.ts";
import { sieveAvailable, sieveProtocolIntel, sieveHealthLine } from "./sieve.ts";
import { LZ_CLASSES } from "./lz.ts";

const CACHE_DIR = join(REPORT_DIR, "osint-cache");
const STATE_PATH = join(REPORT_DIR, "osint-state.json");
const INTEL_PATH = join(REPORT_DIR, "INTEL.md");

const SEARCH_TTL_MS = 6 * 3_600_000;      // search results: 6h
const LLAMA_TTL_MS = 24 * 3_600_000;      // protocol list: 24h
const REKT_TTL_MS = 24 * 3_600_000;       // rekt headlines: 24h
const UA = "Mozilla/5.0 (compatible; ExploitLab-OSINT/1.0; read-only research)";

/** Daily search budget (DDG + Tavily combined; DDG is free but be polite). */
function searchDailyMax(): number {
  return parseInt(process.env.LAB_OSINT_DAILY_MAX ?? "48", 10) || 48;
}

interface OsintBudget {
  day: string; // YYYY-MM-DD (UTC)
  calls: number;
  cooldownUntil: number; // epoch ms — set after repeated fetch failures
}
function loadBudget(): OsintBudget {
  const today = new Date().toISOString().slice(0, 10);
  try {
    const b = JSON.parse(readFileSync(STATE_PATH, "utf8")) as OsintBudget;
    if (b.day === today) return b;
  } catch { /* fresh day / first run */ }
  return { day: today, calls: 0, cooldownUntil: 0 };
}
function saveBudget(b: OsintBudget): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify(b));
  } catch { /* non-fatal */ }
}
function spendSearchBudget(): boolean {
  const b = loadBudget();
  if (Date.now() < b.cooldownUntil) return false;
  if (b.calls >= searchDailyMax()) return false;
  b.calls += 1;
  saveBudget(b);
  return true;
}
function noteFailure(): void {
  // 3+ failures today = endpoint likely rate-limiting us; back off 30 min.
  const b = loadBudget();
  b.cooldownUntil = Date.now() + 30 * 60_000;
  saveBudget(b);
}

/** Generic disk cache keyed by name. */
function cacheGet(name: string, ttlMs: number): unknown | null {
  try {
    const p = join(CACHE_DIR, `${name}.json`);
    if (!existsSync(p)) return null;
    const j = JSON.parse(readFileSync(p, "utf8")) as { t: number; data: unknown };
    return Date.now() - j.t < ttlMs ? j.data : null;
  } catch {
    return null;
  }
}
function cachePut(name: string, data: unknown): void {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(join(CACHE_DIR, `${name}.json`), JSON.stringify({ t: Date.now(), data }));
  } catch { /* non-fatal */ }
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: { "user-agent": UA, ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(20_000),
  });
}

// ---------------------------------------------------------------------------
// DefiLlama — protocol discovery (no key)
// ---------------------------------------------------------------------------
export interface LlamaProtocol {
  name: string;
  symbol?: string;
  category?: string;
  chain?: string;
  chains?: string[];
  tvl?: number;
  audits?: string;        // "0" none, "1" single, "2" multiple, "3" same-day (verified against live API)
  listedAt?: number;      // unix seconds
  url?: string;
  address?: string;       // main contract on `chain` when known
  slug?: string;
}

export async function llamaProtocols(force = false): Promise<LlamaProtocol[]> {
  if (!force) {
    const cached = cacheGet("llama-protocols", LLAMA_TTL_MS);
    if (cached) return cached as LlamaProtocol[];
  }
  try {
    const res = await fetchWithTimeout("https://api.llama.fi/protocols");
    if (!res.ok) throw new Error(`llama HTTP ${res.status}`);
    const data = (await res.json()) as LlamaProtocol[];
    if (data.length > 0) cachePut("llama-protocols", data); // never cache empty results
    return data;
  } catch (e) {
    noteFailure();
    throw e;
  }
}

export interface UnauditedCandidate {
  name: string;
  chains: string[];
  tvlUsd: number;
  category: string;
  listedDaysAgo: number | null;
  address: string | null;
  chain: string | null;
  url: string;
  /** Max payout when a live Immunefi program was found for this protocol. */
  bountyMaxPayout?: string | null;
}

/** New (listed < 120d), unaudited (`audits === "0"`), TVL ≥ $1M — sorted by TVL. */
export function unauditedNewProtocols(protocols: LlamaProtocol[], limit = 15): UnauditedCandidate[] {
  const nowSec = Date.now() / 1000;
  return protocols
    .filter((p) => (p.tvl ?? 0) >= 1_000_000 && String(p.audits ?? "0") === "0")
    .map((p) => ({
      name: p.name,
      chains: p.chains ?? (p.chain ? [p.chain] : []),
      tvlUsd: p.tvl ?? 0,
      category: p.category ?? "unknown",
      listedDaysAgo: p.listedAt ? Math.floor((nowSec - p.listedAt) / 86_400) : null,
      address: p.address ?? null,
      chain: p.chain ?? null,
      url: p.url ?? "",
    }))
    .filter((p) => p.listedDaysAgo === null || p.listedDaysAgo <= 120)
    .sort((a, b) => b.tvlUsd - a.tvlUsd)
    .slice(0, limit);
}

// ---------------------------------------------------------------------------
// Search: Tavily (optional key) → DuckDuckGo Lite fallback (no key)
// ---------------------------------------------------------------------------
export interface SearchResult {
  title: string;
  url: string;
  source: "tavily" | "ddg-lite";
}

export function searchProvider(): "tavily" | "ddg-lite" {
  const engine = process.env.WEB_SEARCH_ENGINE?.trim().toLowerCase();
  if (engine === "tavily") return "tavily";
  if (engine === "duckduckgo" || engine === "ddg") return "ddg-lite";
  return tavilyKeyPoolSize() > 0 ? "tavily" : "ddg-lite"; // auto-detect
}

// ---------------------------------------------------------------------------
// Tavily key pool: round-robin across TAVILY_API_KEY, TAVILY_API_KEY_2..9.
// A 429/432 (quota), 401/403 (auth) rests the offending key for 10 minutes and
// rotates to the next, so exhausted free-tier keys never burn the shared
// search budget. (Tavily signals plan-limit exhaustion with HTTP 432.)
// ---------------------------------------------------------------------------
export function tavilyKeyPoolSize(): number {
  const out: string[] = [];
  const base = process.env.TAVILY_API_KEY?.trim();
  if (base) out.push(base);
  for (let i = 2; i <= 9; i++) {
    const v = process.env[`TAVILY_API_KEY_${i}`]?.trim();
    if (v) out.push(v);
  }
  return new Set(out).size;
}

let tavilyCursor = 0;
const tavilyCooldownUntil = new Map<string, number>();
const TAVILY_KEY_COOLDOWN_MS = 10 * 60_000;

function nextTavilyKey(): string | null {
  const keys: string[] = [];
  const base = process.env.TAVILY_API_KEY?.trim();
  if (base) keys.push(base);
  for (let i = 2; i <= 9; i++) {
    const v = process.env[`TAVILY_API_KEY_${i}`]?.trim();
    if (v) keys.push(v);
  }
  if (keys.length === 0) return null;
  const now = Date.now();
  for (let n = 0; n < keys.length; n++) {
    const key = keys[(tavilyCursor + n) % keys.length]!;
    if ((tavilyCooldownUntil.get(key) ?? 0) <= now) {
      tavilyCursor = (tavilyCursor + n + 1) % keys.length; // next call starts past this key
      return key;
    }
  }
  return null; // every key is resting — caller falls back to DDG
}

async function tavilySearch(query: string): Promise<SearchResult[]> {
  const total = tavilyKeyPoolSize();
  if (total === 0) throw new Error("tavily: no keys configured");
  let lastErr: unknown = new Error("tavily: no usable keys");
  for (let attempt = 0; attempt < total; attempt++) {
    const key = nextTavilyKey();
    if (!key) break;
    let res: Response;
    try {
      res = await fetchWithTimeout("https://api.tavily.com/search", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: key, query, max_results: 5, include_answer: false }),
      });
    } catch (e) {
      lastErr = e;
      continue; // network hiccup — rotate to the next key
    }
    if (res.status === 429 || res.status === 432 || res.status === 401 || res.status === 403) {
      tavilyCooldownUntil.set(key, Date.now() + TAVILY_KEY_COOLDOWN_MS);
      lastErr = new Error(`tavily HTTP ${res.status} (key ...${key.slice(-4)} rested, rotating)`);
      continue;
    }
    if (!res.ok) throw new Error(`tavily HTTP ${res.status}`);
    const j = (await res.json()) as { results?: Array<{ title?: string; url?: string }> };
    return (j.results ?? [])
      .filter((r) => r.url)
      .map((r) => ({ title: (r.title ?? r.url!).slice(0, 160), url: r.url!, source: "tavily" as const }));
  }
  throw lastErr!;
}

async function ddgLiteSearch(query: string): Promise<SearchResult[]> {
  const url = `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) throw new Error(`ddg HTTP ${res.status}`);
  const html = await res.text();
  // Lite results embed links as //duckduckgo.com/l/?uddg=<urlencoded> — decode.
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  const re = /href="(\/\/duckduckgo\.com\/l\/\?uddg=[^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && out.length < 5) {
    const raw = m[1]!;
    const real = decodeURIComponent(raw.split("uddg=")[1]?.split("&")[0] ?? "");
    if (!real.startsWith("http") || seen.has(real)) continue;
    seen.add(real);
    out.push({ title: real.slice(0, 160), url: real, source: "ddg-lite" });
  }
  return out;
}

export async function searchFree(query: string, force = false): Promise<SearchResult[]> {
  const key = `search-${Buffer.from(query).toString("base64url").slice(0, 80)}`;
  if (!force) {
    const cached = cacheGet(key, SEARCH_TTL_MS);
    if (cached) return cached as SearchResult[];
  }
  if (!spendSearchBudget()) return []; // honest skip — retried next cycle
  try {
    const results = searchProvider() === "tavily" ? await tavilySearch(query) : await ddgLiteSearch(query);
    cachePut(key, results);
    return results;
  } catch {
    // Tavily hiccup → try DDG Lite once; both failing → back off.
    try {
      const fallback = await ddgLiteSearch(query);
      cachePut(key, fallback);
      return fallback;
    } catch {
      noteFailure();
      return [];
    }
  }
}

// ---------------------------------------------------------------------------
// rekt.news — real-world post-mortem headlines (no key)
// ---------------------------------------------------------------------------
export interface RektHeadline {
  title: string;
  slug: string;
}
export async function rektHeadlines(force = false): Promise<RektHeadline[]> {
  if (!force) {
    const cached = cacheGet("rekt-headlines", REKT_TTL_MS);
    if (cached) return cached as RektHeadline[];
  }
  try {
    const res = await fetchWithTimeout("https://rekt.news/");
    if (!res.ok) throw new Error(`rekt HTTP ${res.status}`);
    const html = await res.text();
    // rekt.news markup: articles are plain <a href="/<slug>-rekt"> links (Next.js
    // SSR, no headings inside anchors). Title is derived from the slug.
    const heads: RektHeadline[] = [];
    const seen = new Set<string>();
    const re = /href=\"(\/[a-z0-9-]+-rekt)\/?\"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) && heads.length < 12) {
      const slug = m[1]!; // includes the leading "/" so it joins directly onto https://rekt.news
      if (seen.has(slug)) continue;
      seen.add(slug);
      const words = slug.replace(/^\//, "").replace(/-rekt$/, "").split("-").filter(Boolean);
      const title = words.map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
      if (title.length < 3) continue;
      heads.push({ title, slug });
    }
    if (heads.length > 0) cachePut("rekt-headlines", heads); // never cache empty results
    return heads;
  } catch {
    return []; // site structure changed / rate-limited — degrade honestly
  }
}

// ---------------------------------------------------------------------------
// Flagship targets: blue-chip protocols worth permanent watchlist slots.
// Resolved against DefiLlama at intel time (address + TVL + category), so the
// list stays current without hardcoding addresses. EVM contracts with an
// Ethereum address get enlisted; everything else is recorded as intel context.
// ---------------------------------------------------------------------------
const FLAGSHIP_MATCHES = [
  "aave", "ethena", "chainlink", "curve", "lido", "rocket pool",
  "the sandbox", "illuvium", "gmx", "pendle", "wormhole", "stargate",
  "ether.fi", "pancakeswap", "venus", "compound", "makerdao", "sky lending",
  "jupiter", "uniswap", "1inch", "balancer", "sushiswap", "morpho",
];

export interface FlagshipOutcome {
  name: string;
  chain: string | null;
  address: string | null;
  tvlUsd: number;
  action: "enlisted" | "exists" | "intel-only" | "not-found";
}

/** Resolve flagship protocols from the live DefiLlama list. With enlist=true
 * (default) Ethereum-deployable blue chips are upserted into the watchlist;
 * with enlist=false the function is pure intel for the report (no mutation).
 * Never re-enlists an address already present (manual removals stick). */
export function seedFlagships(protocols: LlamaProtocol[], enlist = true): FlagshipOutcome[] {
  const out: FlagshipOutcome[] = [];
  const watch = snapshot().watchlist;
  const known = new Set(Object.keys(watch).map((k) => k.toLowerCase()));
  for (const match of FLAGSHIP_MATCHES) {
    // Highest-TVL protocol whose name starts with the match (case-insensitive).
    const hit = protocols
      .filter((p) => p.name.toLowerCase().startsWith(match))
      .sort((a, b) => (b.tvl ?? 0) - (a.tvl ?? 0))[0];
    if (!hit) {
      out.push({ name: match, chain: null, address: null, tvlUsd: 0, action: "not-found" });
      continue;
    }
    const addrRaw = hit.address ?? null;
    const prefixed = addrRaw?.match(/^([a-z]+):(0x[0-9a-fA-F]{40})$/i);
    const chainName = prefixed ? prefixed[1]! : hit.chain ?? null;
    const addr = prefixed ? prefixed[2]! : addrRaw && /^0x[0-9a-fA-F]{40}$/.test(addrRaw) ? addrRaw : null;
    const base = { name: hit.name, chain: chainName, address: addr, tvlUsd: hit.tvl ?? 0 };
    if (addr && chainName?.toLowerCase() === "ethereum" && OSINT_CHAIN_TO_ID["ethereum"] === "1") {
      const key = addr.toLowerCase();
      if (known.has(key) || Object.values(watch).some((w) => w.address?.toLowerCase() === key && w.enlisted)) {
        out.push({ ...base, action: "exists" });
      } else if (enlist) {
        upsertWatch({
          address: addr,
          enlisted: true,
          name: hit.name,
          category: hit.category,
          lastResult: `[flagship] ${hit.name} — ${hit.category ?? "?"}, TVL ${fmtUsd(hit.tvl ?? 0)} (permanent watch slot)`,
        });
        known.add(key);
        out.push({ ...base, action: "enlisted" });
      } else {
        out.push({ ...base, action: "intel-only" });
      }
    } else {
      out.push({ ...base, action: "intel-only" }); // non-EVM or no Ethereum contract
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Non-EVM ecosystem watch (Solana, Cardano, XRP, Injective, Monero, Zcash,
// Hyperliquid perp L1, …): no EVM bytecode to fork, so coverage is OSINT —
// rotating ecosystem-specific exploit searches feeding INTEL.md.
// ---------------------------------------------------------------------------
const NON_EVM_ECOSYSTEMS = ["solana", "cardano", "xrp", "injective", "monero", "zcash", "hyperliquid", "ton", "near", "sui", "aptos", "tron"];

function nonEvmQuery(cycle: number): string | null {
  if (NON_EVM_ECOSYSTEMS.length === 0) return null;
  // One ecosystem per intel cycle keeps search budget sane.
  const eco = NON_EVM_ECOSYSTEMS[Math.abs(cycle) % NON_EVM_ECOSYSTEMS.length]!;
  return `${eco} protocol exploit OR hack OR bridge incident 2026`;
}

// ---------------------------------------------------------------------------
// Watchlist auto-seeding: feed INTEL.md's on-chain discovery candidates into
// the bus watchlist with `enlisted: true`, so the daemon's fork watch probes
// them automatically (recon -> investigate -> LLM triage -> validated probe).
// Ethereum-only today (the daemon watch is Ethereum-only). An address already
// present in the watchlist is NEVER re-enlisted — removing a seed by hand sticks.
// ---------------------------------------------------------------------------
const OSINT_CHAIN_TO_ID: Record<string, string> = {
  ethereum: "1",
  arbitrum: "42161",
  optimism: "10",
  base: "8453",
  polygon: "137",
  bsc: "56",
  avalanche: "43114",
  gnosis: "100",
  fantom: "250",
  celo: "42220",
  sonic: "146",
  evmos: "9000",
};

export interface SeedOutcome {
  address: string;
  name: string;
  action: "seeded" | "exists" | "backfilled" | "skipped-chain" | "skipped-invalid" | "skipped-cap";
}

/** Cap on concurrently enlisted OSINT seeds. Each unknown-shape seed costs
 * ~1 investigate (incl. an LLM triage call) per 10 fork-watch cycles, so the
 * cap keeps seeding well inside the triage budget. Override with
 * LAB_OSINT_SEED_MAX. */
function seedCap(): number {
  return parseInt(process.env.LAB_OSINT_SEED_MAX ?? "40", 10) || 40;
}

/** Enlist up to `maxNew` new on-chain candidates (default 10 per cycle). */
export function seedWatchlistFromIntel(s: OsintSummary, maxNew = 10): SeedOutcome[] {
  const out: SeedOutcome[] = [];
  const watch = snapshot().watchlist;
  const known = new Set(Object.keys(watch).map((k) => k.toLowerCase()));
  let liveSeeds = Object.values(watch).filter((w) => w.seeded && w.enlisted && !w.finding).length;
  let seeded = 0;
  for (const c of s.unauditedNew) {
    if (seeded >= maxNew || liveSeeds >= seedCap()) {
      if (c.address && /^0x[0-9a-fA-F]{40}$/.test(c.address) && !known.has(c.address.toLowerCase())) {
        out.push({ address: c.address, name: c.name, action: "skipped-cap" });
      }
      continue;
    }
    if (!c.address || !c.chain) continue;
    const base: Omit<SeedOutcome, "action"> = { address: c.address, name: c.name };
    // DefiLlama serializes multi-chain deployments as "chain:0x…" — strip a
    // known-chain prefix; the prefix is more specific than the row's `chain`.
    let chainName = c.chain;
    let addrRaw = c.address;
    const prefixed = addrRaw.match(/^([a-z]+):(0x[0-9a-fA-F]{40})$/i);
    if (prefixed) {
      chainName = prefixed[1]!;
      addrRaw = prefixed[2]!;
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(addrRaw)) {
      out.push({ ...base, action: "skipped-invalid" }); // non-EVM deployments
      continue;
    }
    if (OSINT_CHAIN_TO_ID[chainName.toLowerCase()] !== "1") {
      out.push({ ...base, action: "skipped-chain" }); // daemon fork-watch is Ethereum-only today
      continue;
    }
    const addr = addrRaw.toLowerCase();
    if (known.has(addr)) {
      // Backfill name/category for seeds created before those fields existed,
      // so triage enrichment + bounty lookups work for early seeds too.
      const existing = watch[addr] ?? Object.values(watch).find((x) => x.address?.toLowerCase() === addr);
      if (existing?.seeded && !existing.name) {
        upsertWatch({ address: addr, name: c.name, category: c.category });
        out.push({ ...base, action: "backfilled" });
      } else {
        out.push({ ...base, action: "exists" });
      }
      continue;
    }
    upsertWatch({
      address: addr,
      enlisted: true,
      seeded: true,
      name: c.name,
      category: c.category,
      bounty: c.bountyMaxPayout ? `max ${c.bountyMaxPayout}` : undefined,
      lastResult: `[osint seed] ${c.name} (category ${c.category}) - unaudited per DefiLlama, TVL ${fmtUsd(c.tvlUsd)}, listed ${c.listedDaysAgo === null ? "?" : `${c.listedDaysAgo}d`} ago`,
    });
    known.add(addr);
    liveSeeds++;
    seeded++;
    out.push({ ...base, action: "seeded" });
  }
  if (seeded > 0) {
    logEvent("osint", `watchlist seeding: ${seeded} new target(s) enlisted from INTEL candidates (fork watch picks them up next cycle)`);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Full intel cycle → reports/INTEL.md
// ---------------------------------------------------------------------------
export interface OsintSummary {
  unauditedNew: UnauditedCandidate[];
  headlines: RektHeadline[];
  searched: Array<{ query: string; results: SearchResult[] }>;
  provider: string;
  /** Firecrawl full-text of 1-2 freshest rekt post-mortems (technique priors). */
  rektFull: Array<{ title: string; excerpt: string }>;
  /** Firecrawl deep-dive of top candidates' own sites (audits/admin pages). */
  siteIntel: Array<{ name: string; pages: Array<{ url: string; excerpt: string }> }>;
  /** Sieve structured-scrape runs STARTED this cycle (facts arrive later via
   * the daemon's resume job into reports/SIEVE.md). */
  sieveIntel?: Array<{ protocol: string; session_id: string }>;
  /** Flagship protocol resolution (Aave, Ethena, Chainlink, Sandbox, …). */
  flagship?: FlagshipOutcome[];
  /** Small-TVL lane (DefiLlama TVL < $1M): the highest base-rate bug surface.
   * Candidates are ranked fresh+unaudited+tiny; seeds are enlisted rows. */
  smallLane?: { ceiling: number; seeded: number; seedActions: Record<string, number>; top: SmallTarget[] };
  /** Non-EVM ecosystem sweep result (rotates one ecosystem per cycle). */
  nonEvm?: { ecosystem: string; results: SearchResult[] };
  /** Watchlist seeding outcome (present when seeding was enabled). */
  seeded?: SeedOutcome[];
}

export async function runOsintCycle(opts?: { topSearch?: number; seedWatchlist?: boolean; cycle?: number }): Promise<OsintSummary> {
  const topSearch = opts?.topSearch ?? 6;
  const doSeed = opts?.seedWatchlist ?? (process.env.LAB_OSINT_SEED ?? "1").trim() !== "0";
  const cycleNum = opts?.cycle ?? Math.floor(Date.now() / 3_600_000);

  const protocols = await llamaProtocols().catch(() => [] as LlamaProtocol[]);
  const unaudited = unauditedNewProtocols(protocols, 15);
  const headlines = await rektHeadlines();

  // Immunefi annotation: one page-GET per candidate name per day (hits and
  // misses cached), run in parallel and hard-capped so annotation can never
  // stall the intel cycle.
  try {
    const candidates = unaudited.filter((c) => c.address && c.name);
    const results = await Promise.all(
      candidates.map(async (c) => ({ c, info: await bountyForProtocol(c.name!) }))
    );
    for (const { c, info } of results) {
      if (info) c.bountyMaxPayout = info.maxPayout;
    }
  } catch { /* annotation is best-effort */ }

  // Context-boosting searches: the freshest unaudited money, plus two generic
  // sweeps. Budget-capped; each result cached 6h.
  const queries: string[] = [];
  for (const p of unaudited.slice(0, topSearch)) {
    queries.push(`"${p.name}" crypto exploit OR hack OR incident 2026`);
  }
  queries.push("flash loan oracle attack 2026 crypto protocol");
  queries.push("defi protocol drained exploit post-mortem 2026");
  // Cross-chain threat-class deep dive: rotates through the LayerZero/
  // Immunefi challenge classes so intel coverage compounds over cycles.
  const lzClass = LZ_CLASSES[Math.abs(cycleNum) % LZ_CLASSES.length]!;
  queries.push(`LayerZero "${lzClass.name}" exploit OR audit finding 2026`);
  // Non-EVM ecosystem sweep: rotates Solana → Cardano → XRP → Injective → …
  // one ecosystem per cycle. This is the ONLY honest coverage possible for
  // non-EVM chains (no EVM bytecode → no local fork probing).
  let nonEvm: OsintSummary["nonEvm"];
  const ecoQuery = nonEvmQuery(cycleNum);
  const ecoName = NON_EVM_ECOSYSTEMS[Math.abs(cycleNum) % NON_EVM_ECOSYSTEMS.length]!;

  const searched: Array<{ query: string; results: SearchResult[] }> = [];
  for (const q of queries) {
    const results = await searchFree(q);
    if (results.length > 0) searched.push({ query: q, results });
  }
  if (ecoQuery) {
    const r = await searchFree(ecoQuery);
    if (r.length > 0) {
      nonEvm = { ecosystem: ecoName, results: r };
      searched.push({ query: ecoQuery, results: r });
    }
  }

  // Firecrawl deep dives (key-gated; every layer degrades to empty arrays):
  //   1) full text of the 2 freshest rekt post-mortems -> technique priors
  //   2) top candidate's own site (audits/admin/docs pages) -> triage context
  const rektFull: Array<{ title: string; excerpt: string }> = [];
  const siteIntel: Array<{ name: string; pages: Array<{ url: string; excerpt: string }> }> = [];
  if (firecrawlAvailable()) {
    for (const h of headlines.slice(0, 2)) {
      const r = await rektFullText(h.slug);
      if (r) rektFull.push({ title: h.title, excerpt: r.markdown.slice(0, 1200) });
    }
    const topWithSite = unaudited.find((p) => p.url && /^https?:\/\//.test(p.url));
    if (topWithSite?.url) {
      const pages = await firecrawlSiteDeepDive(topWithSite.url, 2);
      if (pages.length > 0) {
        siteIntel.push({
          name: topWithSite.name,
          pages: pages.map((p) => ({ url: p.url, excerpt: p.markdown.slice(0, 900) })),
        });
      }
    }
  }

  // Sieve structured lane (key-gated + daily-capped). Starting a run is cheap;
  // the schema-validated payload arrives minutes later, so this only RECORDS a
  // session id — the daemon's resume job polls it and renders reports/SIEVE.md.
  // AUTO-START IS OPT-IN (LAB_SIEVE_OSINT=1): accepted runs spend credits, and
  // a 24/7 fleet must never begin spending money because a key appeared.
  const sieveOsintOn = (process.env.LAB_SIEVE_OSINT ?? "0").trim() === "1";
  const sieveIntel: Array<{ protocol: string; session_id: string }> = [];
  if (sieveOsintOn && sieveAvailable()) {
    const siteTarget = unaudited.find((p) => p.url && /^https?:\/\//.test(p.url));
    if (siteTarget?.url) {
      const sid = await sieveProtocolIntel(siteTarget.name, siteTarget.url).catch(() => null);
      if (sid) sieveIntel.push({ protocol: siteTarget.name, session_id: sid });
    }
  }

  const summary: OsintSummary = {
    unauditedNew: unaudited,
    headlines,
    searched,
    provider: searchProvider(),
    rektFull,
    siteIntel,
    sieveIntel,
    nonEvm,
  };
  // Flagship resolution BEFORE the report write so the flagship table renders.
  // Resolution always runs (it is intel); watchlist enlistment respects the kill switch.
  try {
    summary.flagship = seedFlagships(protocols, doSeed);
    const enlisted = summary.flagship.filter((f) => f.action === "enlisted").length;
    if (enlisted > 0) logEvent("osint", `flagship watch: ${enlisted} blue-chip protocol(s) enlisted from DefiLlama`);
  } catch {
    /* flagship seeding is best-effort */
  }
  // Small-TVL lane: the same DefiLlama list (cache hit — no extra HTTP) run
  // through the OPPOSITE filter. Big TVL buys audits; fresh + unaudited + tiny
  // is where undiscovered bugs concentrate. Llama fetch failure must not kill
  // the intel cycle — the lane degrades to absent.
  try {
    const lane = await runSmallLane({ seed: doSeed, limit: 25 });
    summary.smallLane = {
      ceiling: lane.ceiling,
      seeded: lane.seeds.filter((x) => x.action === "seeded").length,
      seedActions: lane.seeds.reduce<Record<string, number>>((acc, x) => {
        acc[x.action] = (acc[x.action] ?? 0) + 1;
        return acc;
      }, {}),
      top: lane.candidates.slice(0, 10),
    };
  } catch {
    /* small-TVL lane is best-effort */
  }
  writeIntelReport(summary); // report first — seeding must never lose intel
  if (doSeed) {
    try {
      summary.seeded = seedWatchlistFromIntel(summary);
    } catch {
      /* seeding is best-effort; intel cycle still succeeds */
    }
  }
  return summary;
}

function fmtUsd(n: number): string {
  if (n >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  return `$${Math.round(n)}`;
}

export function writeIntelReport(s: OsintSummary): string {
  const lines: string[] = [];
  lines.push(`# OSINT INTEL — ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC`);
  lines.push("");
  lines.push(`Sources: api.llama.fi, rekt.news, ${s.provider} (free, read-only). All findings must be verified on a LOCAL fork before any report.`);

  lines.push("");
  lines.push("## New + unaudited + holding TVL (candidate targets)");
  if (s.unauditedNew.length === 0) {
    lines.push("- none found this cycle (or DefiLlama unreachable)");
  } else {
    lines.push("| Protocol | Category | TVL | Listed | Chains | Immunefi |");
    lines.push("|---|---|---|---|---|---|");
    for (const p of s.unauditedNew) {
      const listed = p.listedDaysAgo === null ? "?" : `${p.listedDaysAgo}d ago`;
      const bounty = p.bountyMaxPayout ? `yes (max ${p.bountyMaxPayout})` : "-";
      lines.push(`| ${p.name} | ${p.category} | ${fmtUsd(p.tvlUsd)} | ${listed} | ${p.chains.slice(0, 3).join(", ")} | ${bounty} |`);
    }
    const withAddr = s.unauditedNew.filter((p) => p.address && p.chain);
    if (withAddr.length > 0) {
      lines.push("");
      lines.push("### On-chain discovery candidates (from DefiLlama metadata)");
      for (const p of withAddr.slice(0, 10)) {
        lines.push(`- ${p.chain}:${p.address} — ${p.name} (${fmtUsd(p.tvlUsd)} TVL)`);
      }
    }
  }

  lines.push("");
  lines.push("## Cross-chain (LayerZero) threat model — standing watch");
  lines.push("| Class | Probeable on fork | Focus |");
  lines.push("|---|---|---|");
  for (const c of LZ_CLASSES) {
    lines.push(`| ${c.name} | ${c.probeable ? "yes" : "intel only"} | ${c.summary} |`);
  }
  lines.push("");
  lines.push("EVM OApps on watched chains get the forged-origin + replay fork probe automatically. " +
    "DVN/library/gas classes need infra context — covered by the rotating intel search, never faked.");

  lines.push("");
  lines.push("## Recent rekt.news headlines (real-world technique feed)");
  if (s.headlines.length === 0) {
    lines.push("- unavailable this cycle");
  } else {
    for (const h of s.headlines) lines.push(`- [${h.title}](https://rekt.news${h.slug})`);
  }

  if (s.rektFull.length > 0) {
    lines.push("");
    lines.push("### Post-mortem full text (Firecrawl)");
    for (const r of s.rektFull) {
      lines.push(`**${r.title}**`);
      lines.push(`> ${r.excerpt.replace(/\n+/g, " ").slice(0, 600)}`);
      lines.push("");
    }
  }

  if (s.siteIntel.length > 0) {
    lines.push("");
    lines.push("### Candidate site deep-dive (Firecrawl)");
    for (const si of s.siteIntel) {
      lines.push(`**${si.name}**`);
      for (const p of si.pages) {
        lines.push(`- <${p.url}> — ${p.excerpt.replace(/\n+/g, " ").slice(0, 300)}`);
      }
    }
  }

  if (s.nonEvm && s.nonEvm.results.length > 0) {
    lines.push("");
    lines.push(`### Non-EVM ecosystem watch: ${s.nonEvm.ecosystem} (rotating — OSINT only, no EVM bytecode to probe)`);
    for (const r of s.nonEvm.results) lines.push(`- ${r.title} — <${r.url}>`);
  }

  if (s.flagship && s.flagship.length > 0) {
    lines.push("");
    lines.push("## Flagship protocol watch (blue chips)");
    lines.push("| Protocol | Chain | TVL | Action |");
    lines.push("|---|---|---|---|");
    for (const f of s.flagship) {
      const action = f.action === "enlisted" ? "✅ enlisted"
        : f.action === "exists" ? "already watched"
        : f.action === "intel-only" ? `intel-only (${f.chain ?? "?"})`
        : "not on DefiLlama";
      lines.push(`| ${f.name} | ${f.chain ?? "-"} | ${f.tvlUsd ? fmtUsd(f.tvlUsd) : "-"} | ${action} |`);
    }
  }

  if (s.smallLane) {
    const lane = s.smallLane;
    lines.push("");
    lines.push(`## Small-TVL lane (DefiLlama TVL < ${fmtUsd(lane.ceiling)}) — highest base-rate bug surface`);
    lines.push("");
    lines.push("Fresh + unaudited + tiny: big TVL buys audits, small deployments ship custom code nobody has reviewed. Ranked for fork probing: Ethereum seeds get continuous fork-watch enlistment (`[llama small]` rows), seeds on other supported chains (bsc, base, arbitrum, …) are probed by the rotating scanner on their own forks; chains without an EVM fork path are intel-only. DefiLlama's audits flag is self-reported.");
    lines.push("");
    if (lane.top.length === 0) {
      lines.push("- no candidates under the ceiling this cycle (or DefiLlama unreachable)");
    } else {
      lines.push("| Protocol | Chain | Address | TVL | Audits | Listed | Score | Category |");
      lines.push("|---|---|---|---|---|---|---|---|");
      for (const t of lane.top) {
        const listed = t.listedDaysAgo === null ? "?" : `${t.listedDaysAgo}d ago`;
        lines.push(`| ${t.name} | ${t.chain} | ${t.address ?? "-"} | ${fmtUsd(t.tvlUsd)} | ${t.audits} | ${listed} | ${t.score.toFixed(3)} | ${t.category} |`);
      }
    }
    const actions = Object.entries(lane.seedActions).map(([k, v]) => `${k}=${v}`).join(", ");
    lines.push("");
    lines.push(`- seeds this cycle: ${lane.seeded} recorded (${actions || "none evaluated"})`);
  }

  lines.push("");
  lines.push("## Open-source search highlights");
  if (s.searched.length === 0) {
    lines.push("- no results (budget spent, cooldown, or endpoints unreachable)");
  } else {
    for (const g of s.searched) {
      lines.push("");
      lines.push(`### ${g.query}`);
      for (const r of g.results) lines.push(`- ${r.title} — <${r.url}>`);
    }
  }

  lines.push("");
  lines.push("## Notes");
  const b = loadBudget();
  lines.push(`- search calls today: ${b.calls}/${searchDailyMax()} (provider: ${s.provider}${s.provider === "tavily" ? `, ${tavilyKeyPoolSize()}-key pool with round-robin` : ""})`);
  lines.push(`- firecrawl: ${firecrawlAvailable() ? `enabled, ${firecrawlBudgetUsed()}/${(parseInt(process.env.LAB_FIRECRAWL_DAILY_MAX ?? "40", 10) || 40)} credits today` : "no FIRECRAWL_API_KEY — headline + snippet level only"}`);
  lines.push(sieveHealthLine());
  if (s.sieveIntel && s.sieveIntel.length > 0) {
    lines.push(`- sieve runs started this cycle: ${s.sieveIntel.map((x) => `${x.protocol} (${x.session_id})`).join(", ")} — schema-checked facts land in reports/SIEVE.md when the run finishes`);
  }
  lines.push("- unaudited + new + high TVL is a PRIORITY signal, not a verdict: every candidate needs recon + verified source + a local-fork probe before any disclosure.");
  lines.push("- DefiLlama's `audits` flag is self-reported/incomplete: 'unaudited' here means 'no audit listed on DefiLlama', not 'provably unaudited'. Canonical bridges of major L2s often appear despite heavy auditing.");
  lines.push("- rekt headlines are triage context: compare LLM hypotheses against how real attacks in the same category actually worked.");
  lines.push("- methodology reference: PortSwigger Web Security Academy (https://portswigger.net/web-security) — the fleet's skills library carries condensed checklists for every topic (SSRF, request smuggling, access control, JWT, ...). When a target's OFF-CHAIN surface is in scope (dashboards, APIs, bots), reach for the matching web checklist instead of inventing methodology.");

  mkdirSync(REPORT_DIR, { recursive: true });
  writeFileSync(INTEL_PATH, lines.join("\n") + "\n");
  return INTEL_PATH;
}
