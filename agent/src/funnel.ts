// The funnel monitor — you cannot improve what you do not measure.
//
// The complaint that motivated this tool: "so many pools, zero bugs." The
// funnel answers WHERE the pipeline loses candidates, every cycle:
//
//   watched      — rows in the watchlist (discovery surface)
//   probed       — rows with any recorded probe outcome
//   sourced      — targets with verified source fetched (investigations)
//   classified   — of those, targets with a canoncode class on file
//   customish    — classified fork-delta + custom (the real bug surface)
//   fuzzed       — targets with a persistent campaign (accumulating slices)
//   runsSoFar    — cumulative fuzz sequences thrown across all campaigns
//   violated     — campaigns with ≥1 invariant violation (pending or verified)
//   verified     — violations reproduced across seeds (reportable)
//
// Zero-conversion stages name the next fix. Written to reports/FUNNEL.md on
// demand (npm run funnel) and rendered live on the dashboard strip.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { snapshot } from "./bus.ts";
import { canonStats } from "./canoncode.ts";
import { campaignStats } from "./campaigns.ts";

export interface Funnel {
  watched: number;
  probed: number;
  sourced: number;
  classified: number;
  customish: number;
  fuzzed: number;
  runsSoFar: number;
  violated: number;
  verified: number;
  /** The dominant conversion bottleneck right now, as advice. */
  bottleneck: string;
}

export function readFunnel(): Funnel {
  const s = snapshot();
  const rows = Object.values(s.watchlist ?? {});
  const canon = canonStats();
  const camp = campaignStats();
  const probed = rows.filter((w) => w.lastProbe || w.lastResult).length;
  const funnel: Funnel = {
    watched: rows.length,
    probed,
    sourced: canon.total,
    classified: canon.total,
    customish: canon.forkDelta + canon.custom,
    fuzzed: camp.total,
    runsSoFar: camp.runsSoFar,
    violated: camp.violations,
    verified: camp.verified,
    bottleneck: "",
  };
  funnel.bottleneck = bottleneckOf(funnel);
  return funnel;
}

function bottleneckOf(f: Funnel): string {
  if (f.watched === 0) return "discovery: nothing watched yet — run the scanner";
  if (f.probed / Math.max(1, f.watched) < 0.05) return "probe coverage: <5% of watched targets ever probed";
  if (f.sourced === 0) return "source: no verified source pulled — investigations cannot classify or fuzz";
  if (f.classified === 0) return "classification: no target classified yet — source pulled but canoncode never ran";
  if (f.customish === 0) return "prioritization: everything classified stock — widen discovery to newer deployments";
  if (f.fuzzed === 0) return "campaigns: custom targets exist but none is under accumulating fuzz pressure";
  if (f.runsSoFar < 50_000) return "campaign depth: <50k cumulative fuzz runs — keep slicing, depth finds deep bugs";
  if (f.violated === 0) return "fuzzing healthy, no violations yet — campaigns need more slices on custom targets";
  if (f.verified === 0) return "violations pending cross-seed verification";
  return "verified violations exist — confirm and draft reports";
}

export function writeFunnelReport(): string {
  const f = readFunnel();
  const lines = [
    "# Finding Funnel",
    "",
    `_generated ${new Date().toISOString()} — where candidates convert or die_`,
    "",
    "| Stage | Count | Conversion |",
    "|---|---|---|",
    `| watched (discovery) | ${f.watched} | — |`,
    `| probed | ${f.probed} | ${pct(f.probed, f.watched)} |`,
    `| verified source pulled | ${f.sourced} | ${pct(f.sourced, f.watched)} |`,
    `| code-classified | ${f.classified} | ${pct(f.classified, f.watched)} |`,
    `| custom/fork-delta (bug surface) | ${f.customish} | ${pct(f.customish, f.watched)} |`,
    `| under fuzz campaigns | ${f.fuzzed} | ${pct(f.fuzzed, f.watched)} |`,
    `| cumulative fuzz runs | ${f.runsSoFar} | — |`,
    `| invariant violations | ${f.violated} | — |`,
    `| cross-seed VERIFIED | ${f.verified} | — |`,
    "",
    `**Current bottleneck:** ${f.bottleneck}`,
    "",
    llamaSeedLine(),
  ];
  mkdirSync(REPORT_DIR, { recursive: true });
  const path = join(REPORT_DIR, "FUNNEL.md");
  writeFileSync(path, lines.join("\n"));
  return path;
}

function pct(a: number, b: number): string {
  return b > 0 ? `${Math.round((a / b) * 1000) / 10}%` : "—";
}

/** DefiLlama small-TVL (< $1M) seed registry counts, per chain — the lane
 * feeding the top of this funnel. Read straight from the JSON file (no module
 * coupling: the funnel must stay importable from the bare ui server). */
function llamaSeedLine(): string {
  try {
    const j = JSON.parse(readFileSync(join(REPORT_DIR, "llama-seeds.json"), "utf8")) as { seeds?: Record<string, { chain?: string }> };
    const byChain: Record<string, number> = {};
    for (const rec of Object.values(j.seeds ?? {})) {
      const c = rec.chain ?? "?";
      byChain[c] = (byChain[c] ?? 0) + 1;
    }
    const total = Object.values(byChain).reduce((a, b) => a + b, 0);
    if (total === 0) return "_small-TVL lane: no seeds recorded yet (npm run llama)_";
    return `_small-TVL lane (<$1M): ${total} seed(s) — ${Object.entries(byChain).map(([c, n]) => `${c}=${n}`).join(", ")} (ethereum seeds ride the fork watch; other chains are probed by the rotating scanner)_`;
  } catch {
    return "_small-TVL lane: no seed registry yet (npm run llama)_";
  }
}
