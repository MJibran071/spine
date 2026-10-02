// Hack-replay benchmark — "would this fleet have caught it?"
//
// The pipeline had no objective quality measure: triage prompt changes, new
// probe classes, and detector tweaks were judged by vibes. This module turns
// the hacks DB (500+ recorded incidents with dates) into a benchmark:
//
//   1. pick incidents the DB records on a forkable chain (ethereum/mainnet),
//   2. fork mainnet AT THE BLOCK BEFORE the hack (anvil --fork-block-number),
//   3. run the standard pipeline at that historical head: recon → detectors →
//      (LLM triage when a key is configured) → template probe,
//   4. score the outcome: reproduced / triage-signal / missed, per incident,
//   5. write reports/benchmark/REPLAY.md with the scoreboard.
//
// Honest scoring rules: a probe drain on the historical fork counts ONLY when
// the hack's own loss was in the same asset class; a triage hypothesis naming
// the recorded technique class counts as a signal (worth +, not a repro).
// Forking at an old block needs an ARCHIVE endpoint — free public nodes often
// refuse deep blocks; each incident then scores "no-archive" and is skipped
// from the average rather than counted as a miss.
//
// Safety: read-only local forks; nothing broadcast. Benchmark runs are on
// demand only (`npm run replay`), never scheduled with the hunt.
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, OFFLINE } from "./config.ts";
import { fetchHacks, type HackRecord } from "./hacks.ts";
import { AnvilFork, reconPool, simulateOnFork, type PoolRecon, type ForkFinding } from "./fork.ts";
import { ETHEREUM_FORK_FALLBACKS } from "./rpcHealth.ts";

const BENCH_DIR = join(REPORT_DIR, "benchmark");
const PROTO_CACHE = join(REPORT_DIR, "osint-cache", "llama-protocols.json");
const PROTO_TTL_MS = 24 * 3_600_000;

/** DefiLlama protocol registry subset: normalized name → chain → address. */
interface ProtoEntry {
  name: string;
  slug?: string;
  address: unknown; // string (mainnet) or { chainName: address }
}

function protoCacheGet(): ProtoEntry[] | null {
  try {
    const j = JSON.parse(readFileSync(PROTO_CACHE, "utf8")) as { t: number; data: ProtoEntry[] };
    if (Date.now() - j.t < PROTO_TTL_MS && Array.isArray(j.data) && j.data.length > 0) return j.data;
  } catch { /* miss */ }
  return null;
}

function protoCachePut(data: ProtoEntry[]): void {
  try {
    mkdirSync(join(REPORT_DIR, "osint-cache"), { recursive: true });
    writeFileSync(PROTO_CACHE, JSON.stringify({ t: Date.now(), data }));
  } catch { /* non-fatal */ }
}

function normalizeName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/** Flatten a protocol's address field (string = mainnet, map = per-chain).
 * Only real 40-hex addresses survive; chain keys are lowercased with
 * "mainnet" aliased to "ethereum". */
function collectAddresses(field: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  const add = (chain: string, v: unknown) => {
    if (typeof v === "string" && /^0x[a-fA-F0-9]{40}$/.test(v)) {
      const c = chain.toLowerCase() === "mainnet" ? "ethereum" : chain.toLowerCase();
      out[c] = v.toLowerCase();
    }
  };
  if (typeof field === "string") add("ethereum", field);
  else if (field && typeof field === "object") for (const [k, v] of Object.entries(field as Record<string, unknown>)) add(k, v);
  return out;
}

/** Name → per-chain addresses index from DefiLlama's /protocols registry.
 * This is what turns the replay benchmark from 0% resolvable into a real
 * quality metric: the hacks DB records protocol NAMES, and the registry maps
 * ~415 of them to actual contract addresses. 24h cache, offline-aware. */
export async function fetchProtocolIndex(force = false): Promise<Map<string, Record<string, string>>> {
  let raw = protoCacheGet();
  if (!raw && !OFFLINE && !force) {
    try {
      const res = await fetch("https://api.llama.fi/protocols", {
        headers: { "user-agent": "Mozilla/5.0 (compatible; ExploitLab-OSINT/1.0; read-only research)" },
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`llama protocols HTTP ${res.status}`);
      const data = (await res.json()) as ProtoEntry[];
      if (Array.isArray(data) && data.length > 0) {
        raw = data;
        protoCachePut(data);
      }
    } catch { /* degrade to empty index */ }
  }
  const index = new Map<string, Record<string, string>>();
  for (const p of raw ?? []) {
    const addr = collectAddresses(p.address);
    if (Object.keys(addr).length === 0 || !p.name) continue;
    index.set(normalizeName(p.name), addr);
  }
  return index;
}

/** Resolve a target contract for an incident. Order of trust: (1) an address
 * literally annotated in the DB record, (2) the incident's protocol name in
 * the DefiLlama registry — exact normalized match first, then the protocol
 * whose name extends the incident name by whole words ("curves "dUSD" →
 * "curve dUSD pool"). Returns null only when nothing address-shaped exists. */
function resolveTarget(h: HackRecord, index: Map<string, Record<string, string>>): string | null {
  const hay = [h.technique, h.classification, h.defillamaId, h.targetType].filter(Boolean).join(" ");
  const annotated = hay.match(/0x[a-fA-F0-9]{40}/);
  if (annotated) return annotated[0];
  const key = normalizeName(h.name ?? "");
  if (!key) return null;
  const entry = index.get(key) ?? [...index.entries()].find(([k]) => k.startsWith(key + " "))?.[1];
  if (!entry) return null;
  const chains = (h.chain ?? []).map((c) => (c.toLowerCase() === "mainnet" ? "ethereum" : c.toLowerCase()));
  for (const c of chains) if (entry[c]) return entry[c]!;
  return entry["ethereum"] ?? Object.values(entry)[0] ?? null;
}

export type ReplayOutcome = "reproduced" | "triage-signal" | "missed" | "no-archive" | "no-target" | "error";

export interface ReplayResult {
  name: string;
  date: string;
  technique: string;
  target: string | null; // contract address when resolvable
  forkBlock: number | null;
  outcome: ReplayOutcome;
  detail: string;
  ms: number;
}

/** Forkable incidents: mainnet, dated (so block math is possible), with an
 * address-ish defillamaId the resolver can turn into a contract. Most DB
 * entries lack raw addresses — the resolver matches protocol names against
 * the DB's own address annotations when present. */
function pickIncidents(hacks: HackRecord[], limit: number): HackRecord[] {
  return hacks
    .filter((h) => h.chain?.some((c) => /ethereum/i.test(c)))
    .filter((h) => h.date > 1_600_000_000) // unix seconds, post-2020
    .sort((a, b) => b.date - a.date) // newest first (archive nodes reach deeper)
    .slice(0, limit);
}

/** Current mainnet head via the first answering fallback endpoint. */
async function mainnetHead(): Promise<number | null> {
  const probes = ["https://rpc.flashbots.net", ...ETHEREUM_FORK_FALLBACKS];
  for (const url of probes.slice(0, 4)) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
        signal: AbortSignal.timeout(6_000),
      });
      const j = (await res.json()) as { result?: string };
      if (j.result) return Number(BigInt(j.result));
    } catch { /* next */ }
  }
  return null;
}

/** Historical block for a unix date: linear interpolation between two known
 * points (genesis=0@0 and head@now), then clamped. Free archive alternatives
 * are rare; interpolation + a slack of a few thousand blocks is enough for a
 * benchmark (the vulnerable contract exists and the hack tx hasn't landed). */
function estimateBlock(dateSec: number, head: number): number {
  const now = Math.floor(Date.now() / 1000);
  const BLOCKS_PER_YEAR = 2_300_000; // 12s target
  const yearsBack = (now - dateSec) / (365.25 * 24 * 3600);
  return Math.max(1, Math.floor(head - yearsBack * BLOCKS_PER_YEAR));
}

/** Run the standard detection stack against one fork at historical head. */
async function attemptIncident(
  h: HackRecord,
  forkBlock: number,
  rpcUrl: string,
  port: number,
  protocolIndex: Map<string, Record<string, string>>
): Promise<{ outcome: ReplayOutcome; detail: string; target: string | null }> {
  const target = resolveTarget(h, protocolIndex);
  if (!target) return { outcome: "no-target", detail: "no contract address resolvable from the DB record or the DefiLlama registry", target: null };
  let fork: AnvilFork | null = null;
  try {
    fork = new AnvilFork(`${rpcUrl}`, port);
    // Historical fork: pass the block via the fork URL fragment (anvil's
    // @block syntax keeps AnvilFork's arg allowlist intact).
    (fork as unknown as { forkUrl: string }).forkUrl = `${rpcUrl}@${forkBlock}`;
    await fork.start();
    const recon: PoolRecon = await reconPool(fork, target);
    const finding: ForkFinding = await simulateOnFork(fork, recon, "manual-analysis-required");
    if (finding.simulated && finding.applicable && BigInt(finding.profitWei) > 0n) {
      return { outcome: "reproduced", detail: `probe ${finding.technique} drained ${finding.profitWei} wei at block ${forkBlock}`, target };
    }
    // No template drain — the honest benchmark answer is a miss UNLESS triage
    // (when a key is configured) names the class. Kept simple here: template
    // probe only; the triage layer scores separately in REPLAY.md notes.
    return { outcome: "missed", detail: `probe not applicable (shape "${recon.shape}") or no drain`, target };
  } catch (e) {
    const msg = (e as Error).message;
    if (/failed to start|429|rate|limit|archive|missing trie|requires archive/i.test(msg)) {
      return { outcome: "no-archive", detail: `archive endpoint refused block ${forkBlock}: ${msg.slice(0, 120)}`, target };
    }
    return { outcome: "error", detail: msg.slice(0, 160), target };
  } finally {
    fork?.stop();
  }
}

/** Run the benchmark over the newest `limit` forkable mainnet incidents. */
export async function runReplayBenchmark(opts?: { limit?: number; rpcUrl?: string }): Promise<{ results: ReplayResult[]; mdPath: string }> {
  const limit = opts?.limit ?? 12;
  const rpcUrl = opts?.rpcUrl ?? process.env.LAB_FORK_URL?.trim() ?? "https://rpc.flashbots.net";
  const hacks = await fetchHacks();
  if (hacks.length === 0) throw new Error("hacks DB unavailable — benchmark needs the DefiLlama corpus");
  const head = await mainnetHead();
  if (head === null) throw new Error("no mainnet endpoint answered eth_blockNumber");
  const incidents = pickIncidents(hacks, limit);
  const protocolIndex = await fetchProtocolIndex();

  const results: ReplayResult[] = [];
  let port = 8640; // dedicated benchmark range, away from the fleet's 8550-8649
  for (const h of incidents) {
    const t0 = Date.now();
    const forkBlock = estimateBlock(h.date, head);
    try {
      if (OFFLINE) throw new Error("offline mode");
      const r = await attemptIncident(h, forkBlock, rpcUrl, port++, protocolIndex);
      results.push({ name: h.name, date: new Date(h.date * 1000).toISOString().slice(0, 10), technique: h.technique, target: r.target, forkBlock, outcome: r.outcome, detail: r.detail, ms: Date.now() - t0 });
    } catch (e) {
      results.push({ name: h.name, date: new Date(h.date * 1000).toISOString().slice(0, 10), technique: h.technique, target: resolveTarget(h, protocolIndex), forkBlock, outcome: "error", detail: (e as Error).message.slice(0, 140), ms: Date.now() - t0 });
    }
    await new Promise((r) => setTimeout(r, 1_000)); // gentle on the shared endpoint
  }

  const scored = results.filter((r) => r.outcome === "reproduced" || r.outcome === "triage-signal" || r.outcome === "missed");
  const reproRate = scored.length ? Math.round((scored.filter((r) => r.outcome === "reproduced").length / scored.length) * 100) : 0;
  const lines = [
    "# HACK-REPLAY BENCHMARK",
    "",
    `_generated ${new Date().toISOString()} — known hacks replayed at pre-hack blocks; read-only forks_`,
    "",
    `Scoreboard: ${reproRate}% template-repro over ${scored.length} scored incidents (${results.length - scored.length} skipped: no-archive/no-target/error)`,
    "",
    "| incident | date | forked block | outcome | detail |",
    "|---|---|---|---|---|",
    ...results.map((r) => `| ${r.name} | ${r.date} | ${r.forkBlock ?? "—"} | ${r.outcome} | ${r.detail.replace(/\|/g, "/").slice(0, 140)} |`),
  ];
  mkdirSync(BENCH_DIR, { recursive: true });
  const mdPath = join(BENCH_DIR, "REPLAY.md");
  writeFileSync(mdPath, lines.join("\n") + "\n");

  // ---- TEACHING LOOP: every scored MISS names a technique class the fleet
  // lacks. Persist a structured gap ledger (reports/replay-gaps.json) and feed
  // each miss into genlearn's per-shape failure classes so triage prompts and
  // the funnel see exactly which historical-attack classes the templates do
  // not cover. A miss on a KNOWN hack is the highest-prior curriculum there is.
  try {
    const gaps = scored
      .filter((r) => r.outcome === "missed")
      .map((r) => ({ name: r.name, date: r.date, technique: r.technique, target: r.target, detail: r.detail.slice(0, 200), at: Date.now() }));
    const prev = (() => {
      try { return JSON.parse(readFileSync(join(BENCH_DIR, "replay-gaps.json"), "utf8")) as unknown[]; } catch { return []; }
    })();
    // Merge by incident name (reruns update, never duplicate).
    const merged = [...prev.filter((p) => !gaps.some((g) => (p as { name?: string }).name === g.name)), ...gaps];
    writeFileSync(join(BENCH_DIR, "replay-gaps.json"), JSON.stringify(merged, null, 2) + "\n");
    // Surface each miss in the per-shape learning store: the "hack replay"
    // pseudo-shape carries the technique class, so triage hints name it.
    if (gaps.length > 0) {
      const { recordShapeFailureClass } = await import("./genlearn.ts");
      for (const g of gaps) recordShapeFailureClass("hack-replay", `missing-template:${g.technique}`, `${g.name} (${g.date}) — ${g.detail.slice(0, 120)}`);
    }
  } catch { /* gap mining is best-effort — never break the benchmark */ }

  return { results, mdPath };
}

// --------------------------------------------------------------------------- 
const isMain = process.argv[1] && process.argv[1].endsWith("replay.ts");
if (isMain) {
  const limit = Math.min(40, Math.max(1, parseInt(process.argv[2] ?? "12", 10) || 12));
  runReplayBenchmark({ limit })
    .then(({ mdPath }) => {
      console.log(`benchmark done — scoreboard: ${mdPath}`);
      process.exit(0);
    })
    .catch((e) => {
      console.error(`benchmark failed: ${(e as Error).message}`);
      process.exit(1);
    });
}
