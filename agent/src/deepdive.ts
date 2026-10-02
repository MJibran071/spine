// Deep-dive mode — the strategic shift from breadth to depth. The fleet
// probes ~1,200 watchlist targets with one canned technique each; that finds
// shapes, not bugs. Real bugs live in a handful of high-stakes targets'
// deep logic paths, and those deserve the full stack in one sitting:
//
//   verified source → detector suite → LLM triage (share of the dedicated
//   budget the per-key backoff now makes drainable) → forked simulation →
//   genlearn harness. Every target also leaves a memory + ledger hypothesis
//   so the nightly consolidation and the dashboards see the campaign.
//
// Ranking (deepdiveRank): TVL × unaudited × probeable-shape × payout — the
// four signals OSINT already collects but nothing consumed together. The
// target list comes from INTEL.md's on-chain discovery candidates, blended
// with the watchlist's probeable shapes (erc-4626, layerzero oapp) so the
// campaign can also run on what the fleet already classified.
//
// Everything is bounded and crash-safe: per-target failure is recorded as a
// dead-end memory, never thrown; the run writes a deepdive-<date>.json
// campaign report. CLI: `npm run deepdive` / `-- --top 10 --dry-run`.
import { spawnForkWithFailover } from "./fork.ts";
import { investigateUnknownShape, type InvestigationResult } from "./investigate.ts";
import { DEFAULT_FORK_RPC, REPORT_DIR } from "./config.ts";
import { ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";
import { ensureHypotheses } from "./ledger.ts";
import { localRemember, localMemoryCount } from "./localmem.ts";
import { existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface DeepDiveOptions {
  top?: number;
  dryRun?: boolean;
  forkUrl?: string;
}

interface IntelTarget {
  address: string;
  name: string;
  tvlUsd: number;
  chain: string;
  immunefiMax?: number;
  listedDaysAgo?: number | null;
}

interface DeepDiveResult {
  address: string;
  name: string;
  chainId: string;
  rank: number;
  summary: string;
  finding: string | null;
  investigated: boolean;
  error?: string;
}

const INTEL_PATH = join(REPORT_DIR, "INTEL.md");
const STATE_PATH = join(REPORT_DIR, "state.json");
const CAMPAIGN_DIR = join(REPORT_DIR, "deepdive");

/** TVL parsed from INTEL.md prose ("$7.06B", "$228.1M") into USD. */
function parseTvl(s: string): number {
  const m = /\$([\d,.]+)\s*(B|M|K)?/i.exec(s);
  if (!m) return 0;
  const n = parseFloat(m[1]!.replace(/,/g, ""));
  if (!Number.isFinite(n)) return 0;
  const unit = (m[2] ?? "").toUpperCase();
  return unit === "B" ? n * 1e9 : unit === "M" ? n * 1e6 : unit === "K" ? n * 1e3 : n;
}

/** Extract the on-chain discovery candidates from INTEL.md:
 * `- Ethereum:0xabc… — Protocol Name ($X TVL)`, joined with the candidate
 * table above it (Protocol | Category | TVL | Listed | Chains | Immunefi)
 * for the payout + listing-age factors the bullets don't carry. */
function intelCandidates(): IntelTarget[] {
  if (!existsSync(INTEL_PATH)) return [];
  // First pass: the table's payout/listed columns keyed by protocol name.
  const tableMeta = new Map<string, { immunefiMax?: number; listedDaysAgo?: number | null }>();
  for (const line of readFileSync(INTEL_PATH, "utf8").split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    if (cells.length < 7 || !cells[1] || cells[1] === "Protocol" || /^-+$/.test(cells[1] ?? "")) continue;
    const name = normName(cells[1]!);
    const payoutM = /max\s+\$([\d,.]+)/i.exec(cells[6] ?? "");
    const listedM = /(\d+)d ago/.exec(cells[5] ?? "");
    tableMeta.set(name, {
      immunefiMax: payoutM ? parseFloat(payoutM[1]!.replace(/,/g, "")) : undefined,
      listedDaysAgo: listedM ? parseInt(listedM[1]!, 10) : null,
    });
  }
  const out: IntelTarget[] = [];
  const re = /^-\s+(?:[\w.-]+:)?([\w.-]+:)?(0x[0-9a-fA-F]{40})\s+—\s+(.+?)\s+\((\$[\d,.]+\s*[BMK]?)\s+TVL\)/i;
  for (const line of readFileSync(INTEL_PATH, "utf8").split("\n")) {
    const m = re.exec(line.trim());
    if (!m) continue;
    const name = m[3]!.trim();
    const meta = tableMeta.get(normName(name)) ?? tableMeta.get(normName(name).split(" ")[0]!);
    out.push({
      address: m[2]!.toLowerCase(),
      name,
      tvlUsd: parseTvl(m[4]!),
      chain: (m[1] ?? "ethereum").replace(/:$/, "").toLowerCase(),
      immunefiMax: meta?.immunefiMax,
      listedDaysAgo: meta?.listedDaysAgo ?? null,
    });
  }
  return out;
}

/** Table names vs bullet names differ slightly ("LayerZero V2" both, but
 * "Optimism Bridge" vs "Optimism Bridge") — compare on lowercase alnum. */
function normName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

interface WatchShape {
  shape?: string;
  lastResult?: string;
}

/** Watchlist shapes that mean "a real probe exists or triage can reason".
 * Everything else (unknown) is shallow-breadth territory by definition. */
const PROBEABLE = [/erc-4626/i, /layerzero/i, /lzReceive/i];

/** Rank one candidate: the campaign ordering, 0..1 normalized factors.
 * - tvl: log-scaled (a $7B bridge vs a $200M vault both matter, but the
 *   bridge more; log keeps the top-10 from being one bridge's clones)
 * - payout: Immunefi max bounty when known (deepdive is bounty-hunting)
 * - probeable: watchlist shape says a probe/triage can act on it
 * - fresh: listed recently = less audited surface, more churn
 */
export function deepdiveRank(t: IntelTarget, watchShape?: string): { score: number; factors: Record<string, number> } {
  const tvl = Math.log10(Math.max(t.tvlUsd, 1)) / 10; // $1B → 0.9
  const payout = Math.log10(Math.max(t.immunefiMax ?? 0, 1)) / 8; // $10M → 1.0
  const shape = (watchShape ?? "").toLowerCase();
  const probeable = PROBEABLE.some((re) => re.test(shape)) ? 1 : shape && !/unknown|^\?$/.test(shape) ? 0.5 : 0.2;
  const listed = t.listedDaysAgo ?? null;
  const fresh = listed === null ? 0.4 : Math.max(0, 1 - listed / 365);
  const score = 0.4 * tvl + 0.25 * payout + 0.25 * probeable + 0.1 * fresh;
  return { score, factors: { tvl, payout, probeable, fresh } };
}

function loadWatchShapes(): Map<string, string> {
  const out = new Map<string, string>();
  try {
    if (!existsSync(STATE_PATH)) return out;
    const wl = (JSON.parse(readFileSync(STATE_PATH, "utf8")) as { watchlist?: Record<string, WatchShape> }).watchlist ?? {};
    for (const [k, v] of Object.entries(wl)) {
      const addr = k.toLowerCase();
      const pure = /^0x[0-9a-f]{40}$/.test(addr) ? addr : addr.split(":").find((p) => /^0x[0-9a-f]{40}$/i.test(p));
      if (pure) out.set(pure.toLowerCase(), v.shape ?? "");
    }
  } catch {
    // state.json is another daemon's live file — read failures are tolerated
  }
  return out;
}

/** Build the ranked campaign list (exported for tests + dry-run). */
export function buildCampaign(top: number): { target: IntelTarget; score: number; factors: Record<string, number> }[] {
  const shapes = loadWatchShapes();
  const seen = new Set<string>();
  const ranked: { target: IntelTarget; score: number; factors: Record<string, number> }[] = [];
  for (const t of intelCandidates()) {
    if (seen.has(t.address)) continue;
    seen.add(t.address);
    const r = deepdiveRank(t, shapes.get(t.address));
    ranked.push({ target: t, score: r.score, factors: r.factors });
  }
  ranked.sort((a, b) => b.score - a.score);
  return ranked.slice(0, top);
}

/** Run one deep-dive target through the full stack on a fresh fork. */
async function deepDiveTarget(
  t: IntelTarget,
  forkUrl: string,
  port: number
): Promise<DeepDiveResult> {
  const chainId = "1"; // INTEL candidates are mainnet-scoped
  const rank = 0; // filled by caller ordering context
  let fork: Awaited<ReturnType<typeof spawnForkWithFailover>> | null = null;
  try {
    fork = await spawnForkWithFailover(forkUrl, port, ETHEREUM_FORK_FALLBACKS);
    const inv: InvestigationResult = await investigateUnknownShape(fork, chainId, "ethereum", t.address, {
      daemonId: `deepdive-${process.pid}`,
      watchKey: `deepdive:${t.name}`,
    });
    const finding = inv.finding;
    const profitable = finding?.simulated && finding.profitWei && finding.profitWei !== "0";
    localRemember(
      `DEEPDIVE ${new Date().toISOString().slice(0, 10)}: ${t.name} ${t.address} — ${inv.summary.slice(0, 300)}${profitable ? " PROFITABLE-IN-SIM" : ""}`,
      { kind: "deepdive", target: t.address }
    );
    // The ledger row so the fleet treats deep-dive conclusions as first-class:
    ensureHypotheses(chainId, t.address, [{ technique: "deepdive-full-stack", origin: "manual" }]);
    return {
      address: t.address,
      name: t.name,
      chainId,
      rank,
      summary: inv.summary,
      finding: profitable ? `PROFIT ${finding!.profitWei} wei via ${finding!.technique}` : null,
      investigated: true,
    };
  } catch (e) {
    const msg = (e as Error).message.slice(0, 200);
    localRemember(`DEEPDIVE ${new Date().toISOString().slice(0, 10)}: ${t.name} ${t.address} — campaign probe failed: ${msg}`, {
      kind: "deepdive",
      target: t.address,
    });
    return { address: t.address, name: t.name, chainId: "1", rank, summary: "", finding: null, investigated: false, error: msg };
  } finally {
    try {
      await fork?.stop();
    } catch {
      // fork cleanup is best-effort; a leaked fork dies with the process
    }
  }
}

/** Run the campaign: rank from INTEL.md, investigate top N sequentially
 * (one fork at a time — the same politeness the fleet's probe pool uses). */
export async function runDeepDive(opts: DeepDiveOptions = {}): Promise<DeepDiveResult[]> {
  const top = opts.top ?? 10;
  const forkUrl = opts.forkUrl ?? DEFAULT_FORK_RPC;
  const campaign = buildCampaign(top);
  console.log(`[deepdive] ranked ${campaign.length} target(s):`);
  for (const [i, c] of campaign.entries()) {
    console.log(
      `  ${i + 1}. ${c.target.name} ${c.target.address.slice(0, 10)}… score=${c.score.toFixed(3)} ` +
        `tvl=$${(c.target.tvlUsd / 1e6).toFixed(0)}M factors=${JSON.stringify(c.factors)}`
    );
  }
  if (opts.dryRun) return [];

  const results: DeepDiveResult[] = [];
  let port = 8710; // dedicated deep-dive port range, clear of the fleet
  for (const c of campaign) {
    console.log(`[deepdive] probing ${c.target.name} (${c.target.address.slice(0, 10)}…)…`);
    const r = await deepDiveTarget(c.target, forkUrl, port++);
    r.rank = results.length + 1;
    results.push(r);
    console.log(`[deepdive]   → ${r.error ? `error: ${r.error}` : r.finding ?? r.summary.slice(0, 160)}`);
  }

  // Campaign report: what a human reviews weekly.
  try {
    mkdirSync(CAMPAIGN_DIR, { recursive: true });
    const out = join(CAMPAIGN_DIR, `deepdive-${new Date().toISOString().slice(0, 10)}.json`);
    writeFileSync(out, JSON.stringify({ at: Date.now(), forkUrl, results }, null, 2));
    console.log(`[deepdive] report: ${out}`);
  } catch (e) {
    console.log(`[deepdive] report write failed: ${(e as Error).message}`);
  }
  console.log(`[deepdive] done — memory store now ${localMemoryCount()} records`);
  return results;
}

/** CLI entry: `node --experimental-strip-types src/deepdive.ts -- --top 10 [--dry-run]` */
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const topIdx = args.indexOf("--top");
  const top = topIdx >= 0 ? parseInt(args[topIdx + 1] ?? "", 10) || 10 : 10;
  const dryRun = args.includes("--dry-run");
  runDeepDive({ top, dryRun }).then(
    (r) => process.exit(r.some((x) => x.finding) ? 0 : 0), // exit 0: a campaign with no findings still succeeded
    (e) => {
      console.error(`[deepdive] fatal: ${e.message}`);
      process.exit(1);
    }
  );
}
