// LLM triage for the scanner's "unknown shape → no probe" dead end.
//
// When a live target matches no template probe, recon + verified source (or
// raw bytecode when unverified) go to a REASONING step that hypothesizes the
// exploit class and proposes probe parameters. The LLM NEVER executes
// anything: it returns JSON (hypothesis + probe spec), and every probe it
// proposes runs through the same local-fork simulation pipeline as the
// hand-written templates — 127.0.0.1 only, nothing broadcast. The knowledge
// base cross-checks its claims against past wins so the prior beats vibes.
//
// Provider: ANY OpenAI-compatible /chat/completions endpoint (OpenAI,
// OpenRouter, Groq, a local ollama, …) configured via env or key file:
//   NOTE: priors come from DefiLlama's hacks DB (agent/src/hacks.ts); decompiled
//   pseudo-Solidity from heimdall (agent/src/decompile.ts) — both degrade to
//   nothing when unavailable, triage itself never fails because of them.
//   LAB_LLM_KEY   API key — env var, or the file agent/.llm-key (0600, gitignored)
//   LAB_LLM_URL   default https://openrouter.ai/api/v1/chat/completions
//   LAB_LLM_MODEL default nex-agi/nex-n2.5-mini:free (OpenRouter free tier)
//   LAB_LLM_DAILY_MAX  max triage calls/day (default 240; free tiers are limited)
// Free-tier limitations are handled explicitly: reasoning models burn the
// completion budget on hidden thinking (so reasoning is disabled/excluded
// and budgets are generous), 429s trigger a cooldown instead of hammering,
// and a daily counter triages the SCAN queue — prioritizing new targets.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { REPORT_DIR } from "./config.ts";
import { priorWin, sampleWins } from "./knowledge.ts";
import { genLearnHint } from "./genlearn.ts";
import { techniquesHint } from "./techniques.ts";
import { memoryRecall, memoryRemember } from "./memory.ts";

import { categoryPriors } from "./hacks.ts";
import { lzTriageHints } from "./lz.ts";
import { skillHints } from "./skills.ts";

const here = dirname(fileURLToPath(import.meta.url));
// LAB_LLM_KEY_FILE lets a test (or an operator with an unusual layout) point
// at a different key file. Default is unchanged: agent/.llm-key.
const KEY_FILE = process.env.LAB_LLM_KEY_FILE?.trim() || join(here, "..", ".llm-key");

/** All API keys available for rotation.
 * Collects LAB_LLM_KEY, then GROQ_API_KEY_1..12, then CEREBRAS_API_KEY_1..12,
 * then OPENROUTER_API_KEY_1..12, then ALL non-empty lines from the .llm-key
 * file (supports multi-key format). Deduped. Cross-provider routing is by
 * PREFIX (see endpointForKey), never by one shared URL — the 2026-09-17
 * outage was exactly a shared-URL config: OpenRouter keys sent to Groq's
 * endpoint answer 401 forever.
 * DEAD-KEY QUARANTINE: a key rejected with 401/403 is removed from the pool
 * (persisted, shared across the fleet) instead of being retried forever —
 * every retry is a guaranteed 401 that still burns cooldown slots, budget,
 * and the health counters (15+ auth-errors/day were one dead OpenRouter key
 * poisoning rotation). An operator adds the key back to the quarantine
 * file's allowlist (or deletes the file) after fixing it. */
function allApiKeys(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (v: string | undefined) => {
    const k = v?.trim() ?? "";
    if (k.length > 20 && !seen.has(k)) { seen.add(k); out.push(k); }
  };
  add(process.env.LAB_LLM_KEY);
  // Groq keys — fastest free inference, 12 keys from .env (slots 7-12 added
  // 2026-09-28: the 100+ item triage retry queue showed 6 keys/cooldowns was
  // too tight for an 8-daemon fleet; more free keys > more daemons on the RAM
  // budget).
  for (const name of ["GROQ_API_KEY","GROQ_API_KEY_2","GROQ_API_KEY_3","GROQ_API_KEY_4","GROQ_API_KEY_5","GROQ_API_KEY_6","GROQ_API_KEY_7","GROQ_API_KEY_8","GROQ_API_KEY_9","GROQ_API_KEY_10","GROQ_API_KEY_11","GROQ_API_KEY_12"]) {
    add(process.env[name]);
  }
  // Cerebras keys — 1M free tokens/day, csk- prefix routes to their endpoint
  for (const name of ["CEREBRAS_API_KEY","CEREBRAS_API_KEY_2","CEREBRAS_API_KEY_3","CEREBRAS_API_KEY_4","CEREBRAS_API_KEY_5","CEREBRAS_API_KEY_6","CEREBRAS_API_KEY_7","CEREBRAS_API_KEY_8","CEREBRAS_API_KEY_9","CEREBRAS_API_KEY_10","CEREBRAS_API_KEY_11","CEREBRAS_API_KEY_12"]) {
    add(process.env[name]);
  }
  // OpenRouter fallback keys
  for (const name of ["OPENROUTER_API_KEY","OPENROUTER_API_KEY_2","OPENROUTER_API_KEY_3","OPENROUTER_API_KEY_4","OPENROUTER_API_KEY_5","OPENROUTER_API_KEY_6","OPENROUTER_API_KEY_7","OPENROUTER_API_KEY_8","OPENROUTER_API_KEY_9","OPENROUTER_API_KEY_10","OPENROUTER_API_KEY_11","OPENROUTER_API_KEY_12"]) {
    add(process.env[name]);
  }
  // .llm-key file — supports one key per line (multi-key format) or single key.
  // This is the primary source for launchd-managed processes that don't inherit .env.
  try {
    if (existsSync(KEY_FILE)) {
      const lines = readFileSync(KEY_FILE, "utf8").split("\n");
      for (const line of lines) add(line.trim());
    }
  } catch { /* unreadable = skip */ }
  const quarantined = loadQuarantine();
  if (quarantined.size === 0) return out;
  return out.filter((k) => !quarantined.has(k));
}

/** Primary API key (first available). */
function apiKey(): string | null {
  return allApiKeys()[0] ?? null;
}

// ---- dead-key quarantine (fleet-shared, persisted) --------------------------
// A 401/403 is not a rate limit: retrying can never succeed, and with N keys
// behind one wrong URL it fires on EVERY attempt (observed: 15 auth-errors in
// one day, 64 cooldowns stacked on top, rotation degraded for healthy keys).
// Quarantined keys leave the pool until an operator edits the store.
const QUARANTINE_PATH = join(REPORT_DIR, "llm-key-quarantine.json");
const QUARANTINE_TTL_MS = 24 * 60 * 60_000; // self-heal: a fixed key returns next day

interface QuarantineEntry { at: number; status: number; detail?: string }

function loadQuarantine(): Map<string, QuarantineEntry> {
  const out = new Map<string, QuarantineEntry>();
  try {
    const j = JSON.parse(readFileSync(QUARANTINE_PATH, "utf8")) as Record<string, QuarantineEntry>;
    const now = Date.now();
    for (const [k, e] of Object.entries(j ?? {})) {
      if (e && typeof e.at === "number" && now - e.at < QUARANTINE_TTL_MS) out.set(k, e);
    }
  } catch { /* absent/corrupt = empty */ }
  return out;
}

function saveQuarantine(q: Map<string, QuarantineEntry>): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(QUARANTINE_PATH, JSON.stringify(Object.fromEntries(q), null, 2));
  } catch { /* telemetry must never break the pipeline */ }
}

/** Remove a 401/403 key from the pool, fleet-wide (shared file), TTL-bound. */
function quarantineKey(key: string, status: number, detail?: string): void {
  try {
    const q = loadQuarantine();
    q.set(key, { at: Date.now(), status, detail: detail?.slice(0, 160) });
    saveQuarantine(q);
    _keyCooldowns.delete(key); // quarantined keys need no cooldown bookkeeping
  } catch { /* best-effort */ }
}

/** Observability for the monitor/dashboard: which prefixes are quarantined. */
export function quarantinedKeyStats(): { total: number; groq: number; openrouter: number; cerebras: number; other: number } {
  const q = loadQuarantine();
  const stats = { total: q.size, groq: 0, openrouter: 0, cerebras: 0, other: 0 };
  for (const k of q.keys()) {
    if (k.startsWith("gsk_")) stats.groq++;
    else if (k.startsWith("sk-or-")) stats.openrouter++;
    else if (k.startsWith("csk-")) stats.cerebras++;
    else stats.other++;
  }
  return stats;
}

// Round-robin index across available keys (rotates on 429)
let _keyIdx = 0;
function nextKey(bump = false): string | null {
  const keys = allApiKeys();
  if (keys.length === 0) return null;
  if (bump) _keyIdx = (_keyIdx + 1) % keys.length;
  return keys[_keyIdx % keys.length] ?? null;
}

// ---- per-key cooldowns (2026-09-16) -----------------------------------------
// The old design had one process-wide cooldown: the first 429 on the FIRST key
// put every other healthy key to sleep too, so the retry queue (74+ items
// stuck on "rate-limited") never drained even though 11 of 12 keys were fine.
// Now each key earns its own exponential backoff, and requests skip cooling
// keys instead of sleeping the whole pool.
const KEY_COOLDOWN_BASE_MS = 30_000; // 30s after the first 429
const KEY_COOLDOWN_MAX_MS = 30 * 60_000; // cap: 30 min
const _keyCooldowns = new Map<string, { until: number; strikes: number }>();

function markKey429(key: string, retryAfterMs?: number): void {
  const strikes = (_keyCooldowns.get(key)?.strikes ?? 0) + 1;
  const exp = Math.min(KEY_COOLDOWN_MAX_MS, KEY_COOLDOWN_BASE_MS * Math.pow(2, strikes - 1));
  const jitter = 0.8 + Math.random() * 0.4; // ±20% so fleet daemons desync
  // Honor Retry-After when the provider sent one; otherwise exponential.
  const until = Date.now() + Math.max(Number.isFinite(retryAfterMs) ? retryAfterMs! : 0, exp * jitter);
  _keyCooldowns.set(key, { until, strikes });
}

function markKeyOk(key: string): void {
  _keyCooldowns.delete(key);
}

/** Pick the next key that is NOT cooling down (round-robin, fair). Null when
 * every key is in cooldown — the caller reports rate-limited honestly. */
function pickKey(): string | null {
  const keys = allApiKeys();
  if (keys.length === 0) return null;
  const now = Date.now();
  for (let i = 0; i < keys.length; i++) {
    const k = keys[(_keyIdx + i) % keys.length]!;
    if ((_keyCooldowns.get(k)?.until ?? 0) <= now) {
      _keyIdx = (_keyIdx + i + 1) % keys.length; // next call starts after this one
      return k;
    }
  }
  return null;
}

/** Cooldown observability for the monitor/dashboard. */
export function keyCooldownStats(): { keys: number; cooling: number; soonestFreeMs: number } {
  const now = Date.now();
  const cds = [..._keyCooldowns.values()].map((c) => Math.max(0, c.until - now));
  return { keys: allApiKeys().length, cooling: cds.length, soonestFreeMs: cds.length ? Math.min(...cds) : 0 };
}

const TRIAGE_STATE_PATH = join(REPORT_DIR, "triage-state.json");
const TRIAGE_HEALTH_PATH = join(REPORT_DIR, "triage-health.json");

/** Daily budget, persisted so restarts don't reset it. The cap is FLEET-WIDE
 * on purpose (it protects the shared key pool), so the file is shared. The
 * `cooldownUntil` field the old version also wrote here was a bug: a 429 storm
 * in ONE daemon put all five fleet instances to sleep for two minutes, because
 * every process read the shared cooldown before spending budget. Cooldown is
 * now per-process (in memory) — see `_cooldownUntil`. The field is still
 * parsed so an existing file loads cleanly, but it is never consulted. */
interface TriageBudget {
  day: string; // YYYY-MM-DD (UTC)
  calls: number;
  cooldownUntil?: number; // LEGACY — ignored; kept for on-disk compatibility
}

/** Why an analysis ended. Every failure mode is named, because the old code
 * collapsed all of them into one string ("triage unavailable (no LAB_LLM_KEY
 * or API error)") that callers then recorded as the target's durable verdict. */
export type TriageReason =
  | "ok"            // a hypothesis was produced (fresh or from cache)
  | "no-key"        // no API key configured at all — triage is off
  | "no-input"      // neither verified source nor bytecode: nothing to analyse
  | "budget"        // fleet-wide daily cap reached (resets at UTC midnight)
  | "cooldown"      // this process is backing off after 429s
  | "rate-limited"  // every key answered 429 during this attempt
  | "auth-error"    // every key was rejected (401/403) — keys need attention
  | "http-error"    // provider answered with another error status
  | "timeout"       // network failure/timeout across all keys
  | "unparseable";  // model answered, but not with valid JSON

/** Reasons worth re-attempting later. A deferral must be retried, a terminal
 * answer must not be: "no-key" is a configuration fact and "no-input" means
 * there is nothing to read, but budget/cooldown/429/5xx/timeout all mean
 * "ask again when capacity returns". */
const RETRYABLE: Record<TriageReason, boolean> = {
  ok: false, "no-key": false, "no-input": false,
  budget: true, cooldown: true, "rate-limited": true,
  "auth-error": false, "http-error": true, timeout: true, unparseable: true,
};

/** Per-process rate-limit backoff. In memory by design (see TriageBudget). */
let _cooldownUntil = 0;

/** One analysis attempt, for the health record. */
export interface TriageAttempt {
  t: number;
  chainId: string;
  address: string;
  reason: TriageReason;
  status?: number;
  detail?: string;
  ms?: number;
  keysTried?: number;
}

interface TriageHealth {
  day: string;
  counts: Record<string, number>;
  statuses: Record<string, number>;
  lastReason?: string;
  lastDetail?: string;
  lastAt?: number;
  attempts: TriageAttempt[]; // ring buffer, newest last
}

const HEALTH_RING = 40;

function loadHealth(): TriageHealth {
  const day = new Date().toISOString().slice(0, 10);
  try {
    const h = JSON.parse(readFileSync(TRIAGE_HEALTH_PATH, "utf8")) as TriageHealth;
    if (h.day === day) return h;
  } catch {
    // first run of the day
  }
  return { day, counts: {}, statuses: {}, attempts: [] };
}

/** Persist one attempt: rolling per-day counters plus the last N attempts.
 * This is what turns an opaque "triage unavailable" into a named cause —
 * without it there is no way to tell a 429 from a revoked key from a spent
 * budget, which is exactly the situation this module was in. */
export function recordTriageAttempt(a: TriageAttempt): void {
  try {
    const h = loadHealth();
    h.counts[a.reason] = (h.counts[a.reason] ?? 0) + 1;
    if (a.status) h.statuses[String(a.status)] = (h.statuses[String(a.status)] ?? 0) + 1;
    h.lastReason = a.reason;
    h.lastDetail = a.detail?.slice(0, 240);
    h.lastAt = a.t;
    h.attempts.push({ ...a, detail: a.detail?.slice(0, 400) });
    if (h.attempts.length > HEALTH_RING) h.attempts.splice(0, h.attempts.length - HEALTH_RING);
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(TRIAGE_HEALTH_PATH, JSON.stringify(h, null, 2));
  } catch {
    // telemetry is never allowed to break the pipeline
  }
}

/** Read-only health view for the daemon log, the digest and the dashboard. */
export function triageHealth(): {
  day: string;
  counts: Record<string, number>;
  statuses: Record<string, number>;
  ok: number;
  total: number;
  lastReason?: string;
  lastDetail?: string;
  budget: { used: number; max: number; left: number };
  keys: number;
  cooldownMs: number;
  /** Per-key cooldown state (how many keys are rate-limited right now). */
  cooldown: ReturnType<typeof keyCooldownStats>;
  /** Dead keys removed from the pool (401/403 quarantine, fleet-shared). */
  quarantine: ReturnType<typeof quarantinedKeyStats>;
} {
  const h = loadHealth();
  const total = Object.values(h.counts).reduce((a, b) => a + b, 0);
  return {
    day: h.day,
    counts: h.counts,
    statuses: h.statuses,
    ok: h.counts.ok ?? 0,
    total,
    lastReason: h.lastReason,
    lastDetail: h.lastDetail,
    budget: { used: loadBudget().calls, max: dailyMax(), left: budgetLeft() },
    keys: allApiKeys().length,
    cooldownMs: Math.max(0, _cooldownUntil - Date.now()),
    cooldown: keyCooldownStats(),
    quarantine: quarantinedKeyStats(),
  };
}
function loadBudget(): TriageBudget {
  const today = new Date().toISOString().slice(0, 10);
  try {
    const b = JSON.parse(readFileSync(TRIAGE_STATE_PATH, "utf8")) as TriageBudget;
    if (b.day === today) return b;
  } catch {
    // fresh day / first run
  }
  return { day: today, calls: 0, cooldownUntil: 0 };
}
function saveBudget(b: TriageBudget): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(TRIAGE_STATE_PATH, JSON.stringify(b));
  } catch {
    // non-fatal
  }
}
function dailyMax(): number {
  // 2026-09-17: raised from 240. The pool is 12-18 free keys across Groq,
  // Cerebras and OpenRouter; the fleet burned 350+/day with ~60% blocked by
  // cooldowns — the cap protected nothing and starved the triage queue.
  // Free-tier RPM limits are enforced upstream (429s + cooldowns); this cap
  // is only the last-resort fuse. Override with LAB_LLM_DAILY_MAX.
  return parseInt(process.env.LAB_LLM_DAILY_MAX ?? "2400", 10) || 2400;
}

/** Consume one budget slot, or say precisely why not. Never returns a bare
 * boolean: the caller needs the REASON to record an honest outcome. */
function spendBudget(): { ok: true } | { ok: false; reason: "cooldown" | "budget"; detail?: string } {
  if (Date.now() < _cooldownUntil) {
    return { ok: false, reason: "cooldown", detail: `per-process backoff, ${Math.ceil((_cooldownUntil - Date.now()) / 1000)}s left` };
  }
  const b = loadBudget();
  const max = dailyMax();
  if (b.calls >= max) return { ok: false, reason: "budget", detail: `daily cap reached (${b.calls}/${max}, resets 00:00 UTC)` };
  b.calls += 1;
  saveBudget(b);
  return { ok: true };
}

/** Process-local backoff after the whole key pool answered 429. */
function setCooldown(ms: number): void {
  _cooldownUntil = Math.max(_cooldownUntil, Date.now() + ms);
}

/** Give a daily budget slot back: the call failed in a way that can never
 * succeed at the provider (all-keys auth/config/5xx/429) — the slot protects
 * against repeat attempts, and there was no attempt to protect against.
 * Budget reads/writes are per-day files; spendBudget already persisted +1. */
function refundBudget(): void {
  try {
    const b = loadBudget();
    if (b.calls > 0) {
      b.calls -= 1;
      saveBudget(b);
    }
  } catch { /* non-fatal */ }
}

/** Test/maintenance hook: drop this process's rate-limit backoff — BOTH the
 * process-level backoff and every per-key cooldown — so a caller can exercise
 * the pipeline immediately instead of sleeping through it. */
export function clearTriageBackoff(): void {
  _cooldownUntil = 0;
  _keyCooldowns.clear();
}

/** Test/maintenance hook: drop the fleet-shared dead-key quarantine (e.g. an
 * operator fixed/rotated the credentials and wants them back in the pool
 * without waiting out the TTL). */
export function clearKeyQuarantine(): void {
  try { saveQuarantine(new Map()); } catch { /* best-effort */ }
  _keyCooldowns.clear();
}

function budgetLeft(): number {
  const b = loadBudget();
  return Math.max(0, dailyMax() - b.calls);
}

const CACHE_DIR = join(REPORT_DIR, "triage-cache");

// Semaphore: limit concurrent in-flight LLM calls to the number of available
// keys so we maximise throughput without hammering any single endpoint.
// Requests beyond the limit queue and run as slots free up.
let _triageInFlight = 0;
const _triageQueue: Array<() => void> = [];
function triageSlots(): number {
  return Math.max(1, Math.min(allApiKeys().length, 6));
}
async function acquireTriageSlot(): Promise<void> {
  if (_triageInFlight < triageSlots()) { _triageInFlight++; return; }
  await new Promise<void>((resolve) => _triageQueue.push(resolve));
  _triageInFlight++;
}
function releaseTriageSlot(): void {
  _triageInFlight--;
  const next = _triageQueue.shift();
  if (next) next();
}

export interface TriageHypothesis {
  target: string;
  hypothesis: string; // exploit class, human-readable
  technique: string; // machine tag for the KB / reports
  confidence: number; // 0..1 — model self-assessment, cross-checked below
  sourceUsed: "verified-source" | "bytecode" | "decompiled" | "neither";
  detectorSignals: string[]; // detector names that corroborate
  probe: TriageProbe | null; // null when the model proposes none we allow
  notes: string;
  at: number;
}

export interface TriageProbe {
  /** Probe class — only the classes we can actually render+simulate are
   * allowed through. Anything else is recorded as notes, never executed. */
  class: "side-entrance" | "erc4626-inflation" | "flash-arbitrary-call" | "oracle-spot" | "unauthorized-mint" | "lz-governance-replay" | "lz-oft-dust";
  /** Target contract holding the funds (defaults to the pool itself). */
  fundHolder?: string;
  /** Arbitrary-call surface: selector + calldata args (each a 0x… hex word or
   * decimal number string). Executed as pool.call(data) on the local fork. */
  callTarget?: string;
  callSelector?: string; // "0x" + 8 hex
  callArgs?: string[];
  /** Flash-loan asset + size (decimal wei). 0 = flash the pool's own ETH. */
  loanAsset?: string;
  loanAmount?: string;
  /** Extra context for the report, not the sim. */
  rationale?: string;
}

const SYSTEM_PROMPT = `You are a smart-contract security triage analyst. You receive recon
metadata for ONE contract (interface shape, detected selectors, static-detector
hits, and either verified Solidity source or raw bytecode hex). Reply with ONLY
a JSON object (no markdown fence, no prose):

{
  "hypothesis": "<exploit class in one sentence>",
  "technique": "<machine tag, e.g. side-entrance-reentrancy | erc4626-share-inflation | arbitrary-call | oracle-manipulation | none>",
  "confidence": <0..1>,
  "probe": null | {
    "class": "<one of: side-entrance | erc4626-inflation | flash-arbitrary-call | oracle-spot | unauthorized-mint | lz-governance-replay | lz-oft-dust>",
    "callTarget": "<address that should receive the arbitrary call, if any>",
    "callSelector": "<0x + 8 hex chars of the function to call>",
    "callArgs": ["<hex word or decimal number>", ...],
    "loanAsset": "<token address, or null to flash the pool's native/WETH>",
    "loanAmount": "<decimal wei>",
    "rationale": "<why this probe could drain the target>"
  }
}

Rules:
- If a "TECHNIQUES THE FLEET ITSELF PROVED" block is present, treat it as
  evidence from past local simulations: when this target's code matches the
  described pattern, adapt it (parameters differ per contract); if the code
  demonstrably guards against it, say so instead of parroting it.
- If the evidence shows a deposit/withdraw lender with an execute()-style
  callback, propose class "side-entrance".
- If the evidence shows an ERC-4626-style vault computing shares from a raw
  asset balance with no virtual offset, propose class "erc4626-inflation".
- If the source contains an attacker-controlled arbitrary call
  (target.call(data) guarded only by weak checks), propose
  "flash-arbitrary-call" with callTarget/callSelector/callArgs filled in.
- If prices are read from AMM spot reserves, propose "oracle-spot".
- IMPORTANT honesty rule for AMM pairs: if the verified source is ONLY a
  standard AMM pair (e.g. UniswapV2Pair: swap/mint/burn/getReserves with no
  consumer logic), the pair itself is NOT the vulnerability - manipulation
  risk lives in whatever downstream contract READS its reserves. In that
  case return technique "none", probe null, and say in the hypothesis that
  a CONSUMER must be identified before this is exploitable.
- If the deployed bytecode (or verified source) exposes a mint(address,
  uint256) or mint(address,uint256,bytes) entrypoint that can be called
  without access control, propose class "unauthorized-mint".
- If none apply, probe must be null and technique "none" — say so honestly.
- Confidence below 0.5 or probe:null means: needs human analysis.
- NEVER invent function selectors you cannot justify from the evidence.`;

/** Prior win for a target shape, if the KB has one — passed to the model so
 * its hypothesis competes with demonstrated wins, not just plausibility. */
/** Slice verified source down to the token budget by extracting the functions
 * most relevant to the detector signals + shape, instead of a blind head
 * slice (which for a large contract is mostly irrelevant code and wastes the
 * 8k-TPM ceiling on noise). Relevance = name-token overlap with signals
 * (weight 3), risk-keyword names (weight 1), body mentions of a signal
 * token (weight 1). Falls back to the head slice when nothing matches —
 * the heuristic must never make the prompt WORSE. */
export function sliceSourceBySignals(source: string, signals: string[], shape: string, budget: number): string {
  if (source.length <= budget) return source;
  const tokens = new Set(
    [...signals, shape ?? ""]
      .flatMap((s) => (s ?? "").toLowerCase().split(/[^a-z0-9]+/))
      .filter((w) => w.length > 2)
  );
  const RISK = new Set(["claim", "withdraw", "deposit", "mint", "burn", "flash", "oracle", "price", "owner", "onlyowner", "auth", "sig", "permit", "transfer", "approve", "balance", "share", "vault", "pause", "swap"]);
  type Fn = { name: string; start: number; end: number; score: number };
  const fns: Fn[] = [];
  const re = /function\s+([A-Za-z_$][\w$]*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source))) {
    const name = m[1];
    const open = source.indexOf("{", m.index);
    if (open === -1) continue;
    let depth = 0;
    let i = open;
    for (; i < source.length; i++) {
      if (source[i] === "{") depth++;
      else if (source[i] === "}") {
        depth--;
        if (depth === 0) break;
      }
    }
    const end = Math.min(i + 1, source.length);
    const bodyLower = source.slice(m.index, end).toLowerCase();
    const nameTokens = name.toLowerCase().split(/[^a-z0-9]+/);
    let score = 0;
    for (const t of nameTokens) {
      if (tokens.has(t)) score += 3;
      if (RISK.has(t)) score += 1;
    }
    for (const t of tokens) if (bodyLower.includes(t)) score += 1;
    if (score > 0) fns.push({ name, start: m.index, end, score });
  }
  fns.sort((a, b) => b.score - a.score || a.start - b.start);
  const picked: Fn[] = [];
  let used = 0;
  for (const f of fns) {
    if (picked.some((t) => f.start < t.end && t.start < f.end)) continue; // overlap
    if (used + (f.end - f.start) > budget) continue;
    picked.push(f);
    used += f.end - f.start;
  }
  if (picked.length === 0) return source.slice(0, budget);
  picked.sort((a, b) => a.start - b.start);
  return picked.map((f) => source.slice(f.start, f.end)).join("\n\n");
}

/** Few-shot examples from the knowledge base of PROVEN wins, retrieved by
 * token overlap with this target's detector signals + shape. Empty string
 * when nothing overlaps (never fabricate priors). Placed in the prompt
 * BEFORE the source block so the model sees what a technique that actually
 * drained a similar contract looks like — the lab's 13 buckets of proven
 * techniques were previously invisible to the live triage path. */
async function fewShotWinsBlock(shape: string, signals: string[]): Promise<string> {
  try {
    const wins = sampleWins(shape, signals, 3);
    if (wins.length === 0) return "";
    const lines = wins.map(
      (w) => `- "${w.technique}" (${w.wins} proven win(s), params: ${JSON.stringify(w.params).slice(0, 140)})`
    );
    return `PROVEN TECHNIQUES from the knowledge base (drained similar contracts in the lab; ${signals.length ? `retrieved via signals: ${signals.slice(0, 4).join(", ")}` : `related to shape: ${shape}`}). Adapt, do not blindly reuse — parameter names differ per contract:
${lines.join("\n")}`;
  } catch {
    return ""; // knowledge retrieval is best-effort, never a gate
  }
}

function kbHint(shape: string): string {
  try {
    const w = priorWin(shape);
    return w ? `Known-winning technique for a similar shape: "${w.technique}" (${w.wins} recorded win(s)).` : "";
  } catch {
    return "";
  }
}

/** Methodology hints from the repo's Skills/ offensive-security library —
 * best-effort context for the model, never a detector signal. */
function skillsBlock(input: TriageInput): string {
  return skillHints({
    shape: input.shape,
    selectors: input.selectors,
    detectorSignals: input.detectorSignals,
    category: input.category,
  });
}

interface ChatResponse {
  choices?: Array<{ message?: { content?: string } }>;
}

/** Parse a Retry-After header (seconds or HTTP-date) into ms. Null = absent/unparseable. */
function retryAfterMs(v: string | null): number | undefined {
  if (!v) return undefined;
  const sec = Number(v);
  if (Number.isFinite(sec) && sec >= 0) return sec * 1000;
  const d = Date.parse(v);
  return Number.isFinite(d) ? Math.max(0, d - Date.now()) : undefined;
}

/** Why one askLlm call ended. Mirrors TriageReason for the failure subset. */
type LlmFailure = { ok: false; reason: "no-key" | "budget" | "cooldown" | "rate-limited" | "auth-error" | "http-error" | "timeout"; status?: number; detail?: string; keysTried: number };
type LlmResult = { ok: true; content: string } | LlmFailure;

/** Shared LLM plumbing (key rotation, cooldowns, daily budget) for sibling
 * analyzers — attack-ideas uses it with its own separate daily budget so
 * ideas can never starve triage. `system` overrides the default triage
 * system prompt (pass your own contract: JSON-only schema, honesty rules). */
export async function askLlmShared(prompt: string, system?: string): Promise<LlmResult> {
  if (!apiKey()) return { ok: false, reason: "no-key", detail: "no API key configured (LAB_LLM_KEY / agent/.llm-key)", keysTried: 0 };
  // Pre-check BEFORE spending budget: when every key is in per-key cooldown,
  // the call is guaranteed to fail — burning a daily slot for it would let a
  // cooling pool silently eat the triage budget.
  if (pickKey() === null) {
    return { ok: false, reason: "rate-limited", status: 429, detail: "all keys in per-key cooldown (pre-check, budget not spent)", keysTried: 0 };
  }
  const gate = spendBudget();
  if (!gate.ok) return { ok: false, reason: gate.reason, detail: gate.detail, keysTried: 0 };

  const body: Record<string, unknown> = {
    messages: [
      { role: "system", content: system ?? SYSTEM_PROMPT },
      { role: "user", content: prompt },
    ],
    temperature: 0.2,
    max_completion_tokens: 4_000,
    // NOTE: do NOT include OpenRouter's `reasoning` param here unconditionally —
    // Groq rejects it with HTTP 400 ("property 'reasoning' is unsupported"),
    // which silently disabled all triage. It is added per-request below, only
    // when the resolved endpoint actually is OpenRouter.
  };
  // Endpoint ALWAYS derives from the key's prefix: a mixed pool (gsk_ Groq,
  // csk- Cerebras, sk-or- OpenRouter) dies instantly on any single shared
  // URL — the wrong-provider keys answer 401 forever, which read as a dead
  // key pool (the 2026-09-17 auth-error storm: LAB_LLM_URL pinned to Groq
  // while the pool held six OpenRouter keys). LAB_LLM_URL stays available as
  // an explicit per-provider override for its OWN keys only, tagged by
  // LAB_LLM_URL_PROVIDER (default groq).
  const keys = allApiKeys();
  const maxAttempts = Math.max(keys.length * 2, 3);
  let lastStatus = 0;
  let lastDetail = "";
  let tried = 0;
  let sawAuth = 0;
  let sawServer = 0;
  let sawTimeout = 0;
  let rateLimited429 = 0;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const key = pickKey(); // skips cooling keys; null = whole pool cooling
    if (!key) {
      if (rateLimited429 > 0) {
        setCooldown(2 * 60_000); // whole pool cooling — brief process backoff
        return { ok: false, reason: "rate-limited", status: 429, detail: `all ${keys.length} key(s) in per-key cooldown`, keysTried: tried };
      }
      break; // no keys at all
    }
    tried++;
    const url = endpointForKey(key);
    const model = modelForKey(key);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          ...body,
          model,
          ...(url.includes("openrouter.ai") ? { reasoning: { enabled: false, exclude: true } } : {}),
        }),
        signal: AbortSignal.timeout(60_000),
      });
      lastStatus = res.status;
      if (res.status === 429) {
        // Per-key exponential cooldown; try the next healthy key immediately.
        rateLimited429++;
        markKey429(key, retryAfterMs(res.headers.get("retry-after")));
        continue; // next key (pickKey skips the cooling one)
      }
      if (res.status === 401 || res.status === 403) {
        sawAuth++;
        // Cheap, informative body read — invalid-key vs missing-model-scope
        // is the difference between "rotate keys" and "fix the model name".
        const body = (await res.text().catch(() => "")).slice(0, 160);
        lastDetail = `HTTP ${res.status} ${body}`;
        // DEAD-KEY QUARANTINE: a rejected key never recovers by retrying.
        // Remove it from the (fleet-shared) pool immediately so rotation
        // stops paying a guaranteed-401 slot on every call. 429-style
        // quota rejections stay in the pool (cooldown handles them).
        if (!/quota|rate|limit|credit/i.test(body)) quarantineKey(key, res.status, body);
        continue;
      }
      if (res.status >= 500) {
        sawServer++;
        lastDetail = `HTTP ${res.status}`;
        await new Promise((r) => setTimeout(r, 3_000));
        continue;
      }
      if (!res.ok) {
        // 400/402/404 and friends: the request itself is wrong (bad model id,
        // exhausted credits, unknown path). Rotation cannot fix it, so stop
        // immediately and say what the provider said.
        const snippet = (await res.text().catch(() => "")).slice(0, 200);
        return { ok: false, reason: "http-error", status: res.status, detail: `HTTP ${res.status} ${snippet}`, keysTried: tried };
      }
      const j = (await res.json()) as ChatResponse;
      const content = j.choices?.[0]?.message?.content ?? null;
      if (content) {
        markKeyOk(key); // success clears this key's strike count
        return { ok: true, content };
      }
      // Empty content (reasoning-model hidden thinking artifact) — retry
      lastDetail = "empty content in response";
      await new Promise((r) => setTimeout(r, 2_000));
    } catch (e) {
      sawTimeout++;
      lastDetail = `network: ${(e as Error).message.slice(0, 160)}`;
      await new Promise((r) => setTimeout(r, 4_000));
    }
  }
  // SEMANTIC (health-guard): a failure is a config/diagnosis signal when it
  // applies to the WHOLE attempt (all-keys-401, 5xx, all-429, dead network).
  // Router-noise 4xx mixed with real attempts (e.g. one 413) must not poison
  // the health counters or burn a budget slot for a call that never reached
  // the model.
  const semanticFail = rateLimited429 > 0
    || (sawAuth > 0 && sawAuth === tried)
    || (sawServer > 0)
    || tried === 0;
  if (!semanticFail) refundBudget();
  if (rateLimited429 > 0) {
    setCooldown(2 * 60_000); // whole pool hit 429s this round — brief process backoff
    return { ok: false, reason: "rate-limited", status: 429, detail: `all ${keys.length} key(s) rate-limited`, keysTried: tried };
  }
  if (sawAuth > 0 && sawAuth === tried) {
    return { ok: false, reason: "auth-error", status: lastStatus, detail: lastDetail || `all ${tried} key(s) rejected (401/403)`, keysTried: tried };
  }
  if (sawServer > 0) {
    return { ok: false, reason: "http-error", status: lastStatus, detail: lastDetail || `provider ${lastStatus}`, keysTried: tried };
  }
  if (sawTimeout > 0) {
    return { ok: false, reason: "timeout", detail: lastDetail, keysTried: tried };
  }
  return { ok: false, reason: "timeout", detail: lastDetail || "no attempt completed", keysTried: tried };
}

/** Resolve the chat endpoint for ONE key. Exported for tests + the monitor.
 * Provider always follows the key's PREFIX; LAB_LLM_URL only ever overrides
 * the provider named by LAB_LLM_URL_PROVIDER (default groq). */
export function endpointForKey(key: string): string {
  if (key.startsWith("gsk_")) {
    const override = process.env.LAB_LLM_URL?.trim();
    if (override && providerOverride() === "groq") return override;
    return "https://api.groq.com/openai/v1/chat/completions";
  }
  if (key.startsWith("csk-")) return "https://api.cerebras.ai/v1/chat/completions";
  if (key.startsWith("sk-or-")) {
    const override = process.env.LAB_LLM_URL?.trim();
    if (override && providerOverride() === "openrouter") return override;
    return "https://openrouter.ai/api/v1/chat/completions";
  }
  // Unknown prefix: honour the explicit URL, else OpenRouter default.
  return process.env.LAB_LLM_URL?.trim() || "https://openrouter.ai/api/v1/chat/completions";
}

function providerOverride(): string {
  // "||" not "??": a BLANK env var (the launchd default) must fall through to
  // the groq default, not disable the override tag.
  return (process.env.LAB_LLM_URL_PROVIDER || "groq").trim().toLowerCase();
}

/** Resolve the model id for ONE key. Exported for tests + the monitor. */
export function modelForKey(key: string): string {
  const override = process.env.LAB_LLM_MODEL?.trim();
  if (override && providerOverride() !== "openrouter") return override;
  if (key.startsWith("gsk_")) return "openai/gpt-oss-120b"; // llama-3.3-70b-versatile was retired by Groq (2026-09)
  if (key.startsWith("csk-")) return "gpt-oss-120b"; // llama3.3-70b was retired by Cerebras (2026-09)
  return "nex-agi/nex-n2.5-mini:free"; // google/gemma-3-27b-it:free was retired by OpenRouter (2026-09)
}

/** Parse the model's reply: strip fences if any, find the outermost JSON
 * object, and validate every field we actually intend to use. Anything
 * malformed → null (triage records "unparseable", never guesses). */
function parseHypothesis(raw: string): { hypothesis: string; technique: string; confidence: number; probe: TriageProbe | null } | null {
  let text = raw.trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) text = fence[1]!.trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  let j: any;
  try {
    j = JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
  const hypothesis = typeof j.hypothesis === "string" ? j.hypothesis.slice(0, 400) : "";
  const technique = typeof j.technique === "string" ? j.technique.slice(0, 80) : "none";
  const confidence = typeof j.confidence === "number" ? Math.min(1, Math.max(0, j.confidence)) : 0;
  let probe: TriageProbe | null = null;
  const ALLOWED = new Set(["side-entrance", "erc4626-inflation", "flash-arbitrary-call", "oracle-spot", "unauthorized-mint"]);
  if (j.probe && typeof j.probe === "object" && ALLOWED.has(j.probe.class)) {
    const p = j.probe as TriageProbe;
    const hexAddr = /^0x[0-9a-fA-F]{40}$/;
    // Hard validation: only fields that pass are carried through; the rest is
    // dropped so a hallucinated selector can never reach the simulation.
    probe = {
      class: p.class,
      fundHolder: hexAddr.test(p.fundHolder ?? "") ? p.fundHolder : undefined,
      callTarget: hexAddr.test(p.callTarget ?? "") ? p.callTarget : undefined,
      callSelector: /^0x[0-9a-f]{8}$/i.test(p.callSelector ?? "") ? p.callSelector : undefined,
      callArgs: Array.isArray(p.callArgs)
        ? p.callArgs.filter((a: unknown) => typeof a === "string" && /^(0x[0-9a-fA-F]{0,64}|\d{1,40})$/.test(a)).slice(0, 6)
        : undefined,
      loanAsset: hexAddr.test(p.loanAsset ?? "") ? p.loanAsset : undefined,
      loanAmount: /^\d{1,40}$/.test(p.loanAmount ?? "") ? p.loanAmount : undefined,
      rationale: typeof p.rationale === "string" ? p.rationale.slice(0, 500) : undefined,
    };
  }
  return { hypothesis, technique, confidence, probe };
}

function cachePath(chainId: string, address: string): string {
  return join(CACHE_DIR, `triage-${chainId}-${address.toLowerCase()}.json`);
}

export interface TriageInput {
  chainId: string;
  address: string;
  shape: string; // recon shape classification
  selectors: string[];
  ethWei: string;
  wethWei: string;
  detectorSignals: string[]; // e.g. ["reentrancy-eth", "sig-gated-claim"]
  verifiedSource: string | null;
  bytecodeHex: string | null;
  /** DefiLlama protocol category (e.g. "Bridge", "Dexs") — grounds the
   * model's confidence in real-incident priors for the category. */
  category?: string | null;
  /** heimdall-decompiled pseudo-Solidity, when no verified source exists. */
  decompiled?: string | null;
  /** Bounty context when the target is on Immunefi (free, read-only lookup). */
  bountyContext?: string | null;
  /** Decoded revert reason from a failed probe attempt — grounds the model's
   * next probe in WHY the last one died (adaptive re-probe path). */
  revertContext?: string | null;
}

/** Remaining triage calls today (observability for the daemon log). */
export function triageBudgetLeft(): number {
  return budgetLeft();
}

/** One analysis, with the REASON it ended that way. Callers must branch on
 * `reason`: only "ok" is an analysis. Anything with `retryable: true` is work
 * that did not happen yet and must be re-queued, never recorded as a verdict. */
export interface TriageOutcome {
  hypothesis: TriageHypothesis | null;
  reason: TriageReason;
  retryable: boolean;
  status?: number;
  detail?: string;
  keysTried?: number;
  ms?: number;
}

function outcome(partial: Omit<TriageOutcome, "retryable">): TriageOutcome {
  return { ...partial, retryable: RETRYABLE[partial.reason] };
}

/** Run triage for one target, reporting WHY when there is no hypothesis.
 * Respects the parallel-slot semaphore so up to N keys fire at once. */
export async function triageTargetOutcome(input: TriageInput): Promise<TriageOutcome> {
  const started = Date.now();
  const finish = (o: TriageOutcome): TriageOutcome => {
    const withMs = { ...o, ms: Date.now() - started };
    recordTriageAttempt({
      t: Date.now(),
      chainId: input.chainId,
      address: input.address,
      reason: withMs.reason,
      status: withMs.status,
      detail: withMs.detail,
      ms: withMs.ms,
      keysTried: withMs.keysTried,
    });
    return withMs;
  };

  if (!apiKey()) {
    return finish(outcome({ hypothesis: null, reason: "no-key", detail: `no key in LAB_LLM_KEY or ${KEY_FILE}` }));
  }

  // Cache hit — no slot needed, no budget spent. A revertContext run is
  // evidence-driven re-triage: bypass the cache or the old verdict (which
  // produced the reverted probe) would just come back unchanged.
  const cp = cachePath(input.chainId, input.address);
  if (!input.revertContext && existsSync(cp)) {
    try {
      const j = JSON.parse(readFileSync(cp, "utf8")) as TriageHypothesis;
      if (j && typeof j.hypothesis === "string") {
        return finish({ hypothesis: j, reason: "ok", retryable: false, detail: "cache hit" });
      }
    } catch { /* corrupted — re-run */ }
  }

  await acquireTriageSlot();
  try {
    // Body-size ceiling: free providers reject an oversized request with HTTP
    // 413 ("Request too large for model ..."), so the model never read the
    // source at all. Shrink the code excerpt and retry rather than recording a
    // deferral -- the whole pipeline silently depended on this being accepted.
    let last: TriageOutcome | undefined;
    for (const budget of CODE_BUDGETS) {
      const out = await _triageTargetInner(input, cp, budget);
      // A hypothesis, or a failure shrinking cannot fix (bad model id, credits,
      // auth...) -- either way this is the answer.
      if (out.hypothesis || !isPayloadTooLarge(out.reason, out.status, out.detail)) {
        return finish(out);
      }
      last = out;
    }
    return finish(
      last
        ? {
            ...last,
            detail: `${last.detail ?? ""} — retried down to a ${CODE_BUDGETS[CODE_BUDGETS.length - 1]} char excerpt and still refused`,
          }
        : outcome({ hypothesis: null, reason: "http-error", detail: "no attempt completed" })
    );
  } finally {
    releaseTriageSlot();
  }
}

/** Backwards-compatible wrapper: hypothesis or null. Prefer
 * `triageTargetOutcome` — this loses the reason. */
export async function triageTarget(input: TriageInput): Promise<TriageHypothesis | null> {
  return (await triageTargetOutcome(input)).hypothesis;
}

/** Code-excerpt sizes tried in order, in characters.
 *
 * Sized against a MEASURED ceiling: the live provider refuses with
 * "on tokens per minute (TPM): Limit 8000, Requested 8196" / 8155 / 10167, so
 * the full 24k-char excerpt (~6k tokens once escaped, plus the system prompt
 * and target preamble) landed over the limit on essentially every real
 * contract. 12k chars keeps a large contract legible while leaving headroom;
 * the smaller steps are last resorts that still beat not being read at all. */
const CODE_BUDGETS = [12_000, 3_000, 1_200];

/** Did the provider refuse because the request BODY was too large? Distinct
 * from a bad model id / exhausted credits (also http-error), which rotation or
 * shrinking can never fix. */
function isPayloadTooLarge(reason: string, status?: number, detail?: string): boolean {
  if (reason !== "http-error") return false;
  if (status === 413) return true;
  return /too large|maximum context|context length|exceeds|payload|tokens/i.test(detail ?? "");
}

async function _triageTargetInner(input: TriageInput, cp: string, codeBudget: number): Promise<TriageOutcome> {

  // Real-incident priors (DefiLlama hacks DB, cached 24h) — calibration
  // context only; degrades to "" when the DB is unreachable.
  const priors = await categoryPriors(input.category ?? null);
  // Bytecode is huge; when unverified, trim to the selector-dense head which
  // is where dispatch tables and function signatures live.
  const bytecode = input.bytecodeHex
    ? input.bytecodeHex.length > codeBudget
      ? `${input.bytecodeHex.slice(0, codeBudget)}\n…[truncated ${input.bytecodeHex.length} hex chars total]`
      : input.bytecodeHex
    : null;
  if (!input.verifiedSource && !bytecode) {
    // Terminal: there is genuinely nothing to read. Not a deferral.
    return outcome({ hypothesis: null, reason: "no-input", detail: "no verified source and no bytecode" });
  }

  const sourceBlock = input.verifiedSource
    ? (() => {
        const sliced = sliceSourceBySignals(input.verifiedSource, input.detectorSignals, input.shape ?? "", codeBudget);
        const tag = sliced.length < input.verifiedSource.length
          ? `signal-sliced: ${sliced.length} of ${input.verifiedSource.length} chars, functions matching detectors`
          : `first ${Math.min(codeBudget, input.verifiedSource.length)} chars`;
        return `VERIFIED SOURCE (${tag}):\n\`\`\`solidity\n${sliced}\n\`\`\``;
      })()
    : input.decompiled
      ? `DECOMPILED PSEUDO-SOLIDITY (heimdall, from UNVERIFIED bytecode — variable names are guesses, treat as structure hints):
\`\`\`solidity\n${input.decompiled.slice(0, Math.floor(codeBudget * 0.8))}\n\`\`\``
      : `UNVERIFIED BYTECODE (hex, head):\n${bytecode}`;

  // Long-term memory (mem0 sidecar, fully local): past verdicts/lessons about
  // this target or category. Empty when the sidecar is down — never a gate.
  let memoryBlock = "";
  try {
    const mems = await memoryRecall(`${input.category ?? ""} ${input.address} ${input.shape}`.trim(), 4);
    if (mems.length > 0) memoryBlock = `MEMORY from past hunts (treat as hints, verify everything):
- ${mems.join("\n- ")}`;
  } catch { /* memory is best-effort */ }

  const prompt = [
    `TARGET ${input.address} on chain ${input.chainId}${input.category ? ` (category: ${input.category})` : ""}`,
    `Interface shape classification: ${input.shape}`,
    `Detected function selectors: ${input.selectors.join(", ") || "none recognized"}`,
    `Native balance: ${input.ethWei} wei; wrapped-native balance: ${input.wethWei} wei`,
    `Static detector signals: ${input.detectorSignals.join(", ") || "none"}`,
    kbHint(input.shape),
    await fewShotWinsBlock(input.shape, input.detectorSignals),
    (() => { try { return genLearnHint(input.shape); } catch { return ""; } })(),
    // SELF-LEARNED techniques: what the fleet itself PROVED drains targets of
    // this shape (captured verbatim + LLM-generalized). Sits after the KB
    // few-shot block so the model sees both book priors and its own evidence.
    (() => { try { return techniquesHint(input.shape || null, 3); } catch { return ""; } })(),
    ...lzTriageHints(input.selectors),
    skillsBlock(input),
    input.revertContext ? `LAST PROBE ATTEMPT REVERTED WITH: ${input.revertContext.slice(0, 240)}\nUse this decoded revert reason as evidence: choose a probe class whose entry path plausibly avoids this failure (missing approval, wrong entry point, paused state), or return probe null if no class applies.` : "",
    priors,
    memoryBlock,
    input.bountyContext ? `BOUNTY: ${input.bountyContext}` : "",
    sourceBlock,
    `Produce the JSON triage object now.`,
  ].join("\n\n");

  const res = await askLlmShared(prompt);
  if (!res.ok) {
    return outcome({ hypothesis: null, reason: res.reason, status: res.status, detail: res.detail, keysTried: res.keysTried });
  }
  const parsed = parseHypothesis(res.content);
  if (!parsed) {
    return outcome({ hypothesis: null, reason: "unparseable", detail: `model reply was not a valid triage object: ${res.content.slice(0, 120)}` });
  }

  const out: TriageHypothesis = {
    target: input.address,
    hypothesis: parsed.hypothesis,
    technique: parsed.technique,
    confidence: parsed.confidence,
    sourceUsed: input.verifiedSource ? "verified-source" : input.decompiled ? "decompiled" : "bytecode",
    detectorSignals: input.detectorSignals,
    probe: parsed.probe,
    notes: parsed.probe?.rationale ?? "",
    at: Date.now(),
  };
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(cp, JSON.stringify(out, null, 2));
  } catch {
    // cache failure is non-fatal
  }
  // Long-term memory: every verdict becomes retrievable context for future
  // hunts ("we already looked at X, verdict was Y"). Fire-and-forget.
  memoryRemember(
    `Triage ${new Date().toISOString().slice(0, 10)}: ${input.address} (${input.category ?? "uncategorized"}) — technique ${out.technique}, confidence ${out.confidence}, source ${out.sourceUsed}. Hypothesis: ${parsed.hypothesis.slice(0, 300)}`,
    { address: input.address, category: input.category, technique: out.technique, confidence: out.confidence }
  );
  return outcome({ hypothesis: out, reason: "ok" });
}

/** Human-readable one-liner for logs/watchlist/results. */
export function triageSummary(t: TriageHypothesis): string {
  const probeTag = t.probe ? ` +probe(${t.probe.class})` : "";
  return `LLM triage [${t.technique}${probeTag}, conf ${t.confidence.toFixed(2)}, ${t.sourceUsed}]: ${t.hypothesis}`;
}

/** Honest one-liner for a NON-analysis, so a deferral can never be mistaken
 * for a verdict ("triage unavailable" read as "checked, nothing found"). */
export function triageDeferralNote(o: TriageOutcome): string {
  const why = o.detail ? `${o.reason}: ${o.detail}` : o.reason;
  const errTag = o.status ? ` (HTTP ${o.status})` : "";
  if (o.reason === "no-key") return `triage OFF — no API key configured (${o.detail ?? ""})`;
  if (o.reason === "no-input") return "triage skipped — no source or bytecode to read";
  return `triage DEFERRED${errTag} [${why}]${o.retryable ? " — queued for retry" : ""}`;
}
