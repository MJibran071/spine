// Small-protocol targeting — the base-rate argument the whole hunt was missing.
//
// WHY TVL < $1M: the fleet's OSINT seed previously filtered the OPPOSITE way
// (unauditedNewProtocols requires tvl >= $1M). But big TVL implies big audit
// spend, big contest history, and thousands of eyes — the highest base rate of
// UNDISCOVERED bugs sits in freshly listed, unaudited, TINY protocols: the
// team shipped, the money is real (deployed contracts hold assets), the code
// is custom, and almost nobody has reviewed it. Empirically that is where
// 2025-2026's hack wave concentrated (small lending forks, new vaults, novel
// staking contracts).
//
// Ranking (smallRank), all normalized 0..1 and summed:
//   freshness  — listed on DefiLlama recently (newer = less audited surface)
//   unaudited  — DefiLlama audits flag ("0" = none)
//   tvl        — log-scaled PROXIMITY to the $1M ceiling: $500k is the sweet
//                spot ($10k deployments are usually dead tests, $990k is a
//                real protocol a day from its audit)
//   category   — lending/vault/staking/AMM shapes the invariant engine can
//                actually harness (an NFT marketplace gets intel only)
//
// Everything is read-only intel + watchlist rows via upsertWatch (same
// contract as OSINT seeding): no new HTTP surface beyond the already-used
// api.llama.fi/protocols list, no writes outside reports/, and nothing here
// touches a fork or broadcasts.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { llamaProtocols, type LlamaProtocol } from "./osint.ts";
import { upsertWatch, snapshot, logEvent } from "./bus.ts";
import { REPORT_DIR } from "./config.ts";
import type { ChainSpec, ScanTarget } from "./scan.ts";

/** TVL ceiling for this targeting lane. Override with LAB_LLAMA_TVL_MAX. */
export function tvlCeiling(): number {
  const v = parseInt(process.env.LAB_LLAMA_TVL_MAX ?? "1_000_000".replace(/_/g, ""), 10);
  return Number.isFinite(v) && v > 0 ? v : 1_000_000;
}

/** Max new seeds enlisted per cycle — a seed costs ~1 investigate per 10
 * fork-watch cycles (LLM triage budget), so it stays inside the same cap the
 * OSINT lane uses. Override with LAB_LLAMA_SEED_MAX. */
export function seedCap(): number {
  const v = parseInt(process.env.LAB_LLAMA_SEED_MAX ?? "10", 10);
  return Number.isFinite(v) && v > 0 ? v : 10;
}

// DefiLlama's `chain` field (its own naming) → the canonical names the rest of
// the agent uses. Only names that appear in practice on api.llama.fi matter.
// BSC and the other multi-chain deployments matter just as much as Ethereum:
// the scanner probes every chain in CHAINS on its own fork, so a $40k BSC
// lending fork is exactly as probeable as a $600k Ethereum one.
const LLAMA_CHAIN_TO_NAME: Record<string, string> = {
  ethereum: "ethereum",
  arbitrum: "arbitrum",
  optimism: "optimism",
  base: "base",
  polygon: "polygon",
  bsc: "bsc",
  avalanche: "avalanche",
  gnosis: "gnosis",
  fantom: "fantom",
  sonic: "sonic",
  celo: "celo",
  linea: "linea",
  scroll: "scroll",
  blast: "blast",
  berachain: "berachain",
  hyperevm: "hyperevm",
};

/** Canonical chain name → decimal chain id (mirror of CHAINS in scan.ts, kept
 * in sync at the call site via chainIdForName fallbacks). Used to key seeds
 * per chain so the scanner can pick them up per chain. */
const CHAIN_NAME_TO_ID: Record<string, string> = {
  ethereum: "1",
  bsc: "56",
  avalanche: "43114",
  sonic: "146",
  gnosis: "100",
  base: "8453",
  arbitrum: "42161",
  optimism: "10",
  polygon: "137",
  linea: "59144",
  scroll: "534352",
  berachain: "80094",
  blast: "81457",
  hyperevm: "999",
  robinhood: "4663",
};

function chainIdForName(name: string): string {
  return CHAIN_NAME_TO_ID[name.toLowerCase()] ?? "0";
}

/** Categories whose contract shapes the harness/probe stack can reason about.
 * Everything else is recorded as intel context only (recorded, never enlisted). */
const HARNESSABLE_CATEGORIES = [
  "lending", "cdp", "vault", "yield", "yield aggregator", "staking",
  "dexes", "amm", "liquidity manager", "restaking", "bridge",
];

export interface SmallTarget {
  name: string;
  /** Canonical chain name (DefiLlama's `chain` field normalized). */
  chain: string;
  /** EVM contract address when DefiLlama exposes one; null = no on-chain hook. */
  address: string | null;
  tvlUsd: number;
  category: string;
  /** DefiLlama audits flag: "0" = none listed, "1"/"2"/"3" = audited. */
  audits: string;
  listedDaysAgo: number | null;
  url: string;
  score: number;
  factors: Record<string, number>;
}

function fmtUsd(n: number): string {
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(0)}k`;
  return `$${Math.round(n)}`;
}

/** Rank one protocol for the small-TVL lane: higher = probe sooner. Exported
 * for tests; pure (no IO, no clock) apart from taking `nowSec` explicitly. */
export function smallRank(
  p: { tvl?: number; audits?: string; listedAt?: number; category?: string; chains?: string[]; chain?: string },
  nowSec: number,
  ceiling: number
): { score: number; factors: Record<string, number> } {
  const tvl = p.tvl ?? 0;
  // Freshness: listed in the last 30d fades from 1.0; older decays over a year.
  const listedDays = p.listedAt ? Math.max(0, Math.floor((nowSec - p.listedAt) / 86_400)) : null;
  const freshness = listedDays === null ? 0.5 : Math.max(0, 1 - listedDays / 365) + (listedDays <= 30 ? 0.5 : 0);
  // Unaudited per DefiLlama's self-reported flag (documented as incomplete).
  const unaudited = String(p.audits ?? "0") === "0" ? 1 : 0;
  // Log-proximity to the ceiling: log10(1+tvl)/log10(1+ceiling) rises with TVL,
  // and the filter caps it — inside the lane, MORE tvl is better (real money,
  // real attack surface) while the ceiling itself keeps us out of audit-land.
  const tvlFactor = Math.log10(1 + tvl) / Math.log10(1 + ceiling);
  const cat = (p.category ?? "").toLowerCase();
  const harnessable = HARNESSABLE_CATEGORIES.some((c) => cat.includes(c)) ? 1 : 0.2;
  const factors = { freshness: Math.min(1, freshness), unaudited, tvl: tvlFactor, harnessable };
  const score = 0.35 * factors.freshness + 0.2 * unaudited + 0.25 * tvlFactor + 0.2 * harnessable;
  return { score, factors };
}

/** Filter + rank the live DefiLlama protocol list down to the small-TVL lane.
 * Pure over its inputs (no fetching) — callers pass llamaProtocols() output.
 * Exported for tests + dry-run rendering. */
export function smallTargets(protocols: LlamaProtocol[], limit = 25): SmallTarget[] {
  const ceiling = tvlCeiling();
  const nowSec = Date.now() / 1000;
  const out: SmallTarget[] = [];
  const seen = new Set<string>();
  for (const p of protocols) {
    const tvl = p.tvl ?? 0;
    if (tvl <= 0 || tvl >= ceiling) continue; // dead deployments and the big-league both stay out
    const addrRaw = p.address ?? null;
    // DefiLlama serializes multi-chain deployments as "chain:0x…" — that
    // prefix names the address's OWN chain and outranks the row's `chain`.
    const prefixed = addrRaw?.match(/^([a-z]+):(0x[0-9a-fA-F]{40})$/i);
    const chainRaw = prefixed ? prefixed[1]! : p.chain ?? p.chains?.[0] ?? "";
    const chain = llamaChainName(chainRaw);
    const addr = prefixed ? prefixed[2]! : addrRaw && /^0x[0-9a-fA-F]{40}$/.test(addrRaw) ? addrRaw : null;
    const name = (p.name ?? "").trim();
    if (!name) continue;
    const dedupeKey = (addr ?? `${name}:${chainRaw}`).toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    const r = smallRank(p, nowSec, ceiling);
    out.push({
      name,
      chain,
      address: addr,
      tvlUsd: tvl,
      category: p.category ?? "unknown",
      audits: String(p.audits ?? "?"),
      listedDaysAgo: p.listedAt ? Math.max(0, Math.floor((nowSec - p.listedAt) / 86_400)) : null,
      url: p.url ?? "",
      score: r.score,
      factors: r.factors,
    });
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}

function llamaChainName(raw: string): string {
  const k = raw.toLowerCase();
  return LLAMA_CHAIN_TO_NAME[k] ?? k;
}

export interface SmallSeedOutcome {
  name: string;
  address: string | null;
  chain: string;
  action: "seeded" | "exists" | "intel-only" | "skipped-invalid" | "skipped-chain" | "skipped-cap";
}

// ---------------------------------------------------------------------------
// Per-chain seed registry. The daemon's fork watch only resolves BARE
// addresses on an Ethereum fork, so non-Ethereum seeds cannot live there —
// but the SCANNER probes every chain in CHAINS on that chain's own fork
// (scanChain forks chain.rpcs[0]). Seeds on supported chains are therefore
// recorded to reports/llama-seeds.json keyed `chain:address` and injected
// into every future scanChain pass via llamaSeedTargets(chain). Ethereum
// seeds ALSO get the continuous fork-watch enlistment (a bare-address row).
// ---------------------------------------------------------------------------
interface LlamaSeedRecord {
  name: string;
  chain: string;
  tvlUsd: number;
  category: string;
  audits: string;
  t: number;
}
interface LlamaSeedsFile {
  version: 1;
  seeds: Record<string, LlamaSeedRecord>;
}

const SEEDS_PATH = join(REPORT_DIR, "llama-seeds.json");

function loadSeeds(): LlamaSeedsFile {
  try {
    const j = JSON.parse(readFileSync(SEEDS_PATH, "utf8")) as LlamaSeedsFile;
    if (j && typeof j === "object" && j.seeds && typeof j.seeds === "object") return j;
  } catch { /* first run */ }
  return { version: 1, seeds: {} };
}

function saveSeeds(f: LlamaSeedsFile): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(SEEDS_PATH, JSON.stringify(f));
  } catch { /* best-effort */ }
}

/** The chain:address seeds recorded for ONE chain (scanner input). Returns
 * ScanTargets with source "seed" so they rank with the other curated seeds. */
export function llamaSeedTargets(chain: ChainSpec): ScanTarget[] {
  const { seeds } = loadSeeds();
  const out: ScanTarget[] = [];
  for (const [key, rec] of Object.entries(seeds)) {
    if (rec.chain !== chain.name) continue;
    const addr = key.slice(chain.name.length + 1).toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(addr)) continue;
    out.push({ chain, address: addr, source: "seed" });
  }
  return out;
}

/** Enlist the top ranked small-TVL targets. MULTI-CHAIN: every seed on a chain
 * the scanner supports (CHAINS registry mirror) is recorded to the per-chain
 * seed registry the scanner consumes; Ethereum seeds additionally get the
 * continuous fork-watch enlistment (bare-address watch row). Chains with no
 * EVM fork support (solana, sui, …) stay intel-only.
 * Never re-enlists/records an address already present — manual removals stick. */
export function seedSmallTargets(targets: SmallTarget[], maxNew = seedCap()): SmallSeedOutcome[] {
  const out: SmallSeedOutcome[] = [];
  const watch = snapshot().watchlist;
  const known = new Set(Object.keys(watch).map((k) => k.toLowerCase()));
  const store = loadSeeds();
  let seeded = 0;
  for (const t of targets) {
    if (seeded >= maxNew) {
      out.push({ name: t.name, address: t.address, chain: t.chain, action: "skipped-cap" });
      continue;
    }
    if (!t.address) {
      out.push({ name: t.name, address: null, chain: t.chain, action: "skipped-invalid" });
      continue;
    }
    const supported = chainIdForName(t.chain) !== "0";
    if (!supported) {
      out.push({ name: t.name, address: t.address, chain: t.chain, action: "skipped-chain" });
      continue;
    }
    const chainKey = `${t.chain}:${t.address.toLowerCase()}`;
    const watchKey = t.address.toLowerCase();
    const alreadySeed = store.seeds[chainKey] !== undefined;
    const alreadyWatch = known.has(watchKey);
    if (alreadySeed || (t.chain === "ethereum" && alreadyWatch)) {
      out.push({ name: t.name, address: t.address, chain: t.chain, action: "exists" });
      continue;
    }
    const listed = t.listedDaysAgo === null ? "?" : `${t.listedDaysAgo}d`;
    store.seeds[chainKey] = {
      name: t.name,
      chain: t.chain,
      tvlUsd: t.tvlUsd,
      category: t.category,
      audits: t.audits,
      t: Date.now(),
    };
    if (t.chain === "ethereum") {
      upsertWatch({
        address: t.address,
        enlisted: true,
        seeded: true,
        name: t.name,
        category: t.category,
        lastResult: `[llama small] ${t.name} — ${t.category}, TVL ${fmtUsd(t.tvlUsd)} (< ${fmtUsd(tvlCeiling())} lane), unaudited=${t.audits === "0" ? "yes" : `no (${t.audits})`}, listed ${listed} ago`,
      });
      known.add(watchKey);
    }
    seeded += 1;
    out.push({ name: t.name, address: t.address, chain: t.chain, action: "seeded" });
  }
  if (seeded > 0) {
    saveSeeds(store);
    logEvent("osint", `small-TVL targeting: ${seeded} DefiLlama protocol(s) < ${fmtUsd(tvlCeiling())} seeded across chains (highest base-rate lane: fresh + unaudited + tiny)`);
  }
  return out;
}

export interface SmallLaneSummary {
  ceiling: number;
  candidates: SmallTarget[];
  seeds: SmallSeedOutcome[];
}

/** Per-chain seed counts — the dashboard/INTEL report read this. */
export function llamaSeedsByChain(): Record<string, number> {
  const { seeds } = loadSeeds();
  const out: Record<string, number> = {};
  for (const rec of Object.values(seeds)) out[rec.chain] = (out[rec.chain] ?? 0) + 1;
  return out;
}

/** Full lane pass: fetch → rank → (optionally) enlist. Shared by the daemon's
 * osint phase and the standalone `npm run llama` CLI. */
export async function runSmallLane(opts?: { seed?: boolean; limit?: number }): Promise<SmallLaneSummary> {
  const doSeed = opts?.seed ?? (process.env.LAB_LLAMA_SEED ?? "1").trim() !== "0";
  const limit = opts?.limit ?? 25;
  const protocols = await llamaProtocols();
  const candidates = smallTargets(protocols, limit);
  const seeds = doSeed ? seedSmallTargets(candidates) : [];
  return { ceiling: tvlCeiling(), candidates, seeds };
}

/** Render the lane for the console/INTEL: one ranked line per candidate. */
export function renderSmallTargets(t: SmallTarget[]): string[] {
  return t.map((x, i) => {
    const listed = x.listedDaysAgo === null ? "?" : `${x.listedDaysAgo}d`;
    const addr = x.address ? `${x.chain}:${x.address}` : x.chain;
    const f = x.factors;
    return `${String(i + 1).padStart(2)}. ${x.name} — ${addr} · ${fmtUsd(x.tvlUsd)} · audits=${x.audits} · listed=${listed} · score=${x.score.toFixed(3)} (fresh ${f.freshness.toFixed(2)}, unaud ${f.unaudited}, tvl ${f.tvl.toFixed(2)}, harness ${f.harnessable.toFixed(2)})`;
  });
}

// ---------------------------------------------------------------------------
// CLI: `npm run llama [-- --no-seed] [-- --limit 50]`
// ---------------------------------------------------------------------------
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "\u0000");
if (isMain) {
  const args = process.argv.slice(2);
  const seed = !args.includes("--no-seed");
  const limitIdx = args.indexOf("--limit");
  const limit = limitIdx >= 0 ? parseInt(args[limitIdx + 1] ?? "", 10) || 25 : 25;
  runSmallLane({ seed, limit })
    .then((s) => {
      console.log(`== DefiLlama small-TVL lane (< ${fmtUsd(s.ceiling)}) ==`);
      for (const line of renderSmallTargets(s.candidates)) console.log(line);
      const seededN = s.seeds.filter((x) => x.action === "seeded").length;
      const actions = new Map<string, number>();
      for (const x of s.seeds) actions.set(x.action, (actions.get(x.action) ?? 0) + 1);
      console.log(`\nseeds: ${seededN} recorded, ` + [...actions.entries()].map(([k, v]) => `${k}=${v}`).join(", "));
      const byChain = llamaSeedsByChain();
      if (Object.keys(byChain).length > 0) {
        console.log("registry: " + Object.entries(byChain).map(([c, n]) => `${c}=${n}`).join(", ") + " (the scanner probes non-ethereum seeds on their own forks)");
      }
      process.exit(0);
    })
    .catch((e) => {
      console.error(`[llama] fatal: ${(e as Error).message}`);
      process.exit(1);
    });
}
