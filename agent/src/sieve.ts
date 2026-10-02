// Sieve integration — structured, schema-checked web scraping for recon/OSINT.
//
// Why this exists next to firecrawl.ts: Firecrawl answers "what does this page
// say" (raw markdown). Sieve answers "what are the FACTS on this page, as
// columns" — upgrade authority, pause capability, listed audits, admin
// custody — as a schema-validated payload plus delivered files. That is
// exactly the shape a triage prompt consumes.
//
// Same discipline as firecrawl.ts / osint.ts (no second HTTP client, no
// second config system):
//   - plain global fetch with AbortSignal.timeout, REPORT_DIR JSON state,
//     LAB_* tunables, a daily cap, honest degradation.
//   - SIEVE_API_KEY is server-side only. It is read from the process
//     environment (agent/.env is loaded by config.ts) and is never logged,
//     echoed into a report, or shipped to a browser bundle. The only place it
//     travels is an Authorization header on requests to SIEVE_BASE_URL.
//   - LAB_OFFLINE=1 (config.ts OFFLINE) makes the whole module a no-op, so
//     tests and air-gapped runs never touch the network.
//   - no key / offline / budget spent / sieve unreachable -> a typed failure or
//     null. Callers treat Sieve as best-effort context, NEVER as a gate: a
//     Sieve outage must not break unrelated features.
//
// CRASH SAFETY: an accepted run's session_id is written to
// reports/sieve-state.json BEFORE the started run is reported to the caller.
// A daemon restart therefore RESUMES polling an in-flight run instead of
// starting a duplicate (duplicate = a second credit spend).
//
// RETRY POLICY — the one thing that must never be guessed at:
//   POST /api/scrapes has no idempotency key and an accepted call spends
//   credits. On a timeout or network error the first call MAY have succeeded,
//   so it is NEVER retried: the outcome is reported as `mayHaveStarted` and
//   recorded as an orphan start for a human/next-cycle reconciliation. A 429
//   or 5xx IS safe to retry (no run was created). GETs are safe everywhere and
//   retry with exponential backoff.
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { OFFLINE, REPORT_DIR } from "./config.ts";
import { logEvent } from "./bus.ts";

export const SIEVE_DEFAULT_BASE = "https://scrape.usesieve.com";

const STATE_PATH = join(REPORT_DIR, "sieve-state.json");
const ARTIFACT_DIR = join(REPORT_DIR, "sieve");
const REPORT_PATH = join(REPORT_DIR, "SIEVE.md");

/** Per-request socket timeout. Runs legitimately take minutes; that is the
 * POLLING budget, not a socket budget — a single GET/POST should still answer
 * far sooner than this. */
const DEFAULT_START_TIMEOUT_MS = 60_000; // generous: multipart upload of a document
const DEFAULT_GET_TIMEOUT_MS = 30_000;
/** Poll schedule: start at 5s and back off to ~30s (contract). */
const DEFAULT_POLL_START_MS = 5_000;
const DEFAULT_POLL_MAX_MS = 30_000;
const POLL_BACKOFF = 1.5;

// ------------------------------------------------------------------ config

export function sieveBaseUrl(): string {
  const override = (process.env.SIEVE_BASE_URL ?? "").trim().replace(/\/+$/, "");
  return override || SIEVE_DEFAULT_BASE;
}
export function sieveKey(): string {
  return (process.env.SIEVE_API_KEY ?? "").trim();
}
/** Configured AND allowed to make outbound calls. */
export function sieveAvailable(): boolean {
  return !OFFLINE && sieveKey().length > 0;
}
function startTimeoutMs(): number {
  return parseInt(process.env.LAB_SIEVE_START_TIMEOUT_MS ?? "", 10) || DEFAULT_START_TIMEOUT_MS;
}
function getTimeoutMs(): number {
  return parseInt(process.env.LAB_SIEVE_GET_TIMEOUT_MS ?? "", 10) || DEFAULT_GET_TIMEOUT_MS;
}
function pollStartMs(): number {
  return parseInt(process.env.LAB_SIEVE_POLL_START_MS ?? "", 10) || DEFAULT_POLL_START_MS;
}
function pollMaxMs(): number {
  return parseInt(process.env.LAB_SIEVE_POLL_MAX_MS ?? "", 10) || DEFAULT_POLL_MAX_MS;
}
/** Accepted runs per UTC day. Polling is free and is not capped. */
export function sieveDailyMax(): number {
  return parseInt(process.env.LAB_SIEVE_DAILY_MAX ?? "12", 10) || 12;
}

// ------------------------------------------------------------ durable store

export type SieveSessionStatus = "queued" | "running" | "done" | "refused" | "error";

export interface SieveFile {
  name: string;
  size?: number;
  ext?: string;
  /** Relative on the API ("/api/…") — prefix sieveBaseUrl() and send Bearer. */
  url: string;
}

export interface SieveSessionRecord {
  session_id: string;
  instruction: string;
  target_urls?: string[];
  compliance_mode?: string;
  created: number;
  status: SieveSessionStatus;
  /** Follow-up turns completed so far (the turn-advanced check depends on it). */
  turns: number;
  /** Polls issued — drives the 5s→30s schedule across daemon cycles. */
  polls: number;
  lastPolledAt: number;
  lastStatusAt: number;
  conformance?: string;
  /** True only for schema_conformance.status === "pass". A "fail" run is never
   * reported as clean data. */
  clean?: boolean;
  files?: SieveFile[];
  summary?: string;
  /** Inline validated payload returned for a passing output_schema run. */
  result?: unknown;
  refusalCode?: string;
  error?: string;
  /** Where downloaded artifacts / inline result landed under reports/sieve/. */
  resultPath?: string;
}

export interface SieveOrphanStart {
  at: number;
  instruction: string;
  target_urls?: string[];
  reason: string;
}

export interface SieveStore {
  version: 1;
  day: string;
  runsStarted: number;
  sessions: Record<string, SieveSessionRecord>;
  /** Starts whose outcome is UNKNOWN (timeout/network). Never auto-retried —
   * the run may exist and a retry would spend a second time. */
  orphanStarts: SieveOrphanStart[];
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

export function loadSieveStore(): SieveStore {
  const empty: SieveStore = { version: 1, day: today(), runsStarted: 0, sessions: {}, orphanStarts: [] };
  try {
    if (!existsSync(STATE_PATH)) return empty;
    const j = JSON.parse(readFileSync(STATE_PATH, "utf8")) as SieveStore;
    if (!j || typeof j !== "object" || !j.sessions) return empty;
    // A new UTC day resets the accepted-run counter; session history carries on.
    if (j.day !== today()) j.runsStarted = 0;
    j.day = today();
    j.orphanStarts = Array.isArray(j.orphanStarts) ? j.orphanStarts : [];
    return j;
  } catch {
    return empty; // corrupt store = fresh start (sessions are re-pollable by id)
  }
}

export function saveSieveStore(s: SieveStore): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    const tmp = `${STATE_PATH}.tmp`;
    writeFileSync(tmp, JSON.stringify(s));
    renameSync(tmp, STATE_PATH); // atomic — a crash mid-write must not lose run ids
  } catch {
    /* state persistence is best-effort; the caller still gets the session id */
  }
}

export function sieveBudgetUsed(): number {
  return loadSieveStore().runsStarted;
}
export function sieveBudgetLeft(): number {
  return Math.max(0, sieveDailyMax() - sieveBudgetUsed());
}

/** Sessions still worth polling (queued/running). */
export function sievePendingSessions(): SieveSessionRecord[] {
  return Object.values(loadSieveStore().sessions)
    .filter((s) => s.status === "queued" || s.status === "running")
    .sort((a, b) => a.lastPolledAt - b.lastPolledAt);
}

export function sieveStats(): {
  available: boolean;
  base: string;
  runsStartedToday: number;
  dailyMax: number;
  pending: number;
  done: number;
  refused: number;
  errored: number;
  orphanStarts: number;
  clean: number;
  dirty: number;
} {
  const s = loadSieveStore();
  const all = Object.values(s.sessions);
  return {
    available: sieveAvailable(),
    base: sieveBaseUrl(),
    runsStartedToday: s.runsStarted,
    dailyMax: sieveDailyMax(),
    pending: all.filter((r) => r.status === "queued" || r.status === "running").length,
    done: all.filter((r) => r.status === "done").length,
    refused: all.filter((r) => r.status === "refused").length,
    errored: all.filter((r) => r.status === "error").length,
    orphanStarts: s.orphanStarts.length,
    clean: all.filter((r) => r.clean === true).length,
    dirty: all.filter((r) => r.status === "done" && r.clean === false).length,
  };
}

/** The session id is persisted the moment a run is accepted — before the
 * caller learns about it. That single ordering is what makes a crash resume
 * instead of duplicating. */
export function recordSession(rec: SieveSessionRecord): void {
  const s = loadSieveStore();
  s.sessions[rec.session_id] = { ...(s.sessions[rec.session_id] ?? {}), ...rec } as SieveSessionRecord;
  saveSieveStore(s);
}

export function sieveSession(sessionId: string): SieveSessionRecord | null {
  return loadSieveStore().sessions[sessionId] ?? null;
}

// ------------------------------------------------------------- error mapping

export type SieveErrorKind =
  | "unavailable"
  | "budget_exhausted"
  | "bad_request"
  | "unauthorized"
  | "payment_required"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "server"
  | "network"
  | "timeout"
  | "unknown_result";

export interface SieveErrorMeta {
  kind: SieveErrorKind;
  status?: number;
  retryAfterMs?: number;
  /** The API's own message/code, when it sent one. Never contains the key. */
  detail?: string;
  /** POST /api/scrapes only: the request may have been accepted. */
  mayHaveStarted?: boolean;
}

export class SieveError extends Error {
  readonly kind: SieveErrorKind;
  readonly status?: number;
  readonly retryAfterMs?: number;
  readonly detail?: string;
  readonly mayHaveStarted: boolean;
  constructor(meta: SieveErrorMeta) {
    super(`sieve ${meta.kind}${meta.status ? ` (HTTP ${meta.status})` : ""}${meta.detail ? `: ${meta.detail}` : ""}`);
    this.name = "SieveError";
    this.kind = meta.kind;
    this.status = meta.status;
    this.retryAfterMs = meta.retryAfterMs;
    this.detail = meta.detail;
    this.mayHaveStarted = meta.mayHaveStarted === true;
  }
}

/** HTTP status -> typed error. 400/401/402/404 are terminal (retrying cannot
 * help); 429/5xx are retryable on any method. */
export function classifyStatus(status: number, detail?: string, retryAfterMs?: number): SieveError {
  const meta: SieveErrorMeta = { kind: "unknown_result", status, detail, retryAfterMs };
  if (status === 400) meta.kind = "bad_request";
  else if (status === 401) meta.kind = "unauthorized";
  else if (status === 402) meta.kind = "payment_required";
  else if (status === 404) meta.kind = "not_found";
  else if (status === 409) meta.kind = "conflict";
  else if (status === 429) meta.kind = "rate_limited";
  else if (status >= 500) meta.kind = "server";
  return new SieveError(meta);
}

/** 429/5xx = no run was created = safe to retry (contract). */
export function retryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function retryAfterMsOf(res: Response): number | undefined {
  const raw = res.headers.get("retry-after");
  if (!raw) return undefined;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(raw);
  return Number.isFinite(when) ? Math.max(0, when - Date.now()) : undefined;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

// --------------------------------------------------------------- HTTP layer

interface HttpOk {
  ok: true;
  status: number;
  /** Parsed JSON when the body was JSON, else the raw text. */
  body: unknown;
  retryAfterMs?: number;
}
interface HttpErr {
  ok: false;
  error: SieveError;
}
type HttpResult = HttpOk | HttpErr;

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { authorization: `Bearer ${sieveKey()}`, ...extra };
}

function bodyDetail(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as Record<string, unknown>;
  const err = b.error;
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && typeof (err as Record<string, unknown>).message === "string") {
    return (err as Record<string, unknown>).message as string;
  }
  if (typeof b.message === "string") return b.message;
  if (typeof b.code === "string") return b.code;
  return undefined;
}

/** One HTTP round trip. NO retry logic here — callers decide, because the
 * retry rules differ per method (POST /api/scrapes must never be replayed). */
async function requestOnce(
  method: "GET" | "POST",
  path: string,
  init: { headers?: Record<string, string>; body?: BodyInit | null; timeoutMs: number }
): Promise<HttpResult> {
  const url = path.startsWith("http") ? path : `${sieveBaseUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: authHeaders(init.headers),
      body: init.body ?? undefined,
      signal: AbortSignal.timeout(init.timeoutMs),
    });
  } catch (e) {
    const name = (e as { name?: string }).name ?? "";
    const msg = (e as Error).message ?? String(e);
    const timedOut = name === "TimeoutError" || name === "AbortError" || /timeout|aborted/i.test(msg);
    return { ok: false, error: new SieveError({ kind: timedOut ? "timeout" : "network", detail: msg }) };
  }
  const text = await res.text().catch(() => "");
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  const retryAfterMs = retryAfterMsOf(res);
  if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status, body, retryAfterMs };
  return { ok: false, error: classifyStatus(res.status, bodyDetail(body) ?? text.slice(0, 200), retryAfterMs) };
}

/** GET/POST with exponential backoff on 429 and 5xx (and transient network
 * errors on GET only). Reads are always safe to repeat; the caller passes
 * `safeToRetry: false` for POST /api/scrapes. */
async function requestWithRetry(
  method: "GET" | "POST",
  path: string,
  init: { headers?: Record<string, string>; body?: BodyInit | null; timeoutMs: number; safeToRetry: boolean; attempts?: number; baseDelayMs?: number }
): Promise<HttpResult> {
  const attempts = Math.max(1, init.attempts ?? (init.safeToRetry ? 4 : 3));
  const base = init.baseDelayMs ?? 500;
  let last: HttpErr = { ok: false, error: new SieveError({ kind: "network", detail: "no attempt made" }) };
  for (let i = 0; i < attempts; i++) {
    const r = await requestOnce(method, path, init);
    if (r.ok) return r;
    last = r;
    const kind = r.error.kind;
    const retryable = kind === "rate_limited" || kind === "server" || (init.safeToRetry && (kind === "network" || kind === "timeout"));
    if (!retryable || i === attempts - 1) return r;
    const wait = r.error.retryAfterMs ?? Math.min(30_000, base * 2 ** i);
    await sleep(wait);
  }
  return last;
}

// ------------------------------------------------------------ request shape

export interface SieveStartRequest {
  /** Plain-language instruction (required by the API). */
  instruction: string;
  target_urls?: string[];
  /** Expected columns. */
  fields?: string[];
  /** Advisory schema. */
  schema?: unknown;
  /** Strict JSON Schema 2020-12 (<= 32KB) — enables the inline validated
   * `result` and the schema_conformance verdict. */
  output_schema?: unknown;
  table_shape?: "long" | "wide";
  /** "regular" unless the human explicitly chose otherwise ("yolo" relaxes the
   * site-access policy and is their call). */
  compliance_mode?: "conservative" | "regular" | "yolo";
  /** Local path to a document; sent as multipart/form-data under "file". */
  file?: string;
}

/** The JSON body shared by POST /api/scrapes and the follow-up messages
 * endpoint. Pure — the same object drives JSON and multipart requests, so the
 * two paths can never drift. */
export function sievePayload(req: SieveStartRequest): Record<string, unknown> {
  const body: Record<string, unknown> = { instruction: req.instruction };
  if (req.target_urls?.length) body.target_urls = req.target_urls;
  if (req.fields?.length) body.fields = req.fields;
  if (req.schema !== undefined) body.schema = req.schema;
  if (req.output_schema !== undefined) body.output_schema = req.output_schema;
  if (req.table_shape) body.table_shape = req.table_shape;
  body.compliance_mode = req.compliance_mode ?? "regular";
  return body;
}

/** Build the fetch init for a start call. Exported so the request shape is
 * testable at the boundary (auth header, JSON vs multipart, file field). */
export function buildStartInit(req: SieveStartRequest): RequestInit {
  const headers = { authorization: `Bearer ${sieveKey()}` };
  if (req.file) {
    const form = new FormData();
    for (const [k, v] of Object.entries(sievePayload(req))) {
      form.append(k, typeof v === "string" ? v : JSON.stringify(v));
    }
    form.append("file", new Blob([readFileSync(req.file)]), basename(req.file));
    // No content-type: fetch sets the multipart boundary itself.
    return { method: "POST", headers, body: form, signal: AbortSignal.timeout(startTimeoutMs()) };
  }
  return {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(sievePayload(req)),
    signal: AbortSignal.timeout(startTimeoutMs()),
  };
}

// ------------------------------------------------------------------- start

export interface SieveStartOk {
  ok: true;
  session_id: string;
  status: "queued";
  poll?: string;
}
export interface SieveStartErr {
  ok: false;
  error: SieveError;
  /** Safe to call again (429/5xx: no run was created). */
  retryable: boolean;
  /** The request may have been accepted by the API — DO NOT retry blindly. */
  mayHaveStarted: boolean;
}
export type SieveStartResult = SieveStartOk | SieveStartErr;

export interface StartOptions {
  attempts?: number;
  baseDelayMs?: number;
  /** Skip the daily cap (used by the interactive CLI, which the human runs
   * deliberately and sees the result of). */
  ignoreBudget?: boolean;
}

/**
 * POST /api/scrapes. On 202 the session_id is persisted to disk BEFORE this
 * resolves, so a crash right after acceptance still resumes polling.
 *
 * NEVER retried when the outcome is unknown (timeout/network): the first call
 * may have succeeded and a duplicate would spend credits again. Such a call is
 * recorded as an orphan start instead.
 */
export async function startScrape(req: SieveStartRequest, opts: StartOptions = {}): Promise<SieveStartResult> {
  if (!sieveAvailable()) {
    return {
      ok: false,
      error: new SieveError({ kind: "unavailable", detail: OFFLINE ? "LAB_OFFLINE=1" : "no SIEVE_API_KEY" }),
      retryable: false,
      mayHaveStarted: false,
    };
  }
  if (!opts.ignoreBudget && sieveBudgetLeft() <= 0) {
    return {
      ok: false,
      error: new SieveError({ kind: "budget_exhausted", detail: `daily cap ${sieveDailyMax()} reached (LAB_SIEVE_DAILY_MAX)` }),
      retryable: false,
      mayHaveStarted: false,
    };
  }

  const r = await requestWithRetry("POST", "/api/scrapes", {
    ...buildStartInit(req),
    timeoutMs: startTimeoutMs(),
    // 429/5xx retries inside requestWithRetry are safe (no run created); a
    // NETWORK/TIMEOUT failure is NOT retried — see below.
    safeToRetry: false,
    attempts: opts.attempts,
    baseDelayMs: opts.baseDelayMs,
  });

  if (!r.ok) {
    const transient = r.error.kind === "timeout" || r.error.kind === "network";
    if (transient) {
      // OUTCOME UNKNOWN. Do not retry. Record it so the spend is visible.
      const s = loadSieveStore();
      s.orphanStarts.push({ at: Date.now(), instruction: req.instruction, target_urls: req.target_urls, reason: r.error.message });
      if (s.orphanStarts.length > 50) s.orphanStarts.splice(0, s.orphanStarts.length - 50);
      saveSieveStore(s);
      return { ok: false, error: r.error, retryable: false, mayHaveStarted: true };
    }
    return { ok: false, error: r.error, retryable: retryableStatus(r.error.status ?? 0), mayHaveStarted: false };
  }

  const body = (r.body ?? {}) as Record<string, unknown>;
  const sessionId = typeof body.session_id === "string" ? body.session_id : "";
  if (!sessionId) {
    return {
      ok: false,
      error: new SieveError({ kind: "unknown_result", detail: "202 without a session_id" }),
      retryable: false,
      mayHaveStarted: true,
    };
  }
  // Spend only on acceptance, and persist before returning.
  const s = loadSieveStore();
  s.runsStarted += 1;
  s.sessions[sessionId] = {
    session_id: sessionId,
    instruction: req.instruction,
    target_urls: req.target_urls,
    compliance_mode: (body.compliance_mode as string) ?? req.compliance_mode ?? "regular",
    created: Date.now(),
    status: typeof body.status === "string" ? (body.status as SieveSessionStatus) : "queued",
    turns: 0,
    polls: 0,
    lastPolledAt: 0,
    lastStatusAt: Date.now(),
  };
  saveSieveStore(s); // <<< durable BEFORE the caller can act on the session id
  return { ok: true, session_id: sessionId, status: "queued", poll: typeof body.poll === "string" ? body.poll : undefined };
}

// ------------------------------------------------------------------ polling

export interface SieveRefusal {
  code?: string;
  message?: string;
  /** Present when the refusal was a credit/quota limit. */
  quota?: unknown;
}

export interface SieveRunState {
  status: "queued" | "running" | "done" | "refused";
  raw: unknown;
  summary?: string;
  files?: SieveFile[];
  /** schema_conformance.status: pass | partial | fail | not_checkable |
   * no_artifact | none (none = no output_schema was requested/returned). */
  conformance: "pass" | "partial" | "fail" | "not_checkable" | "no_artifact" | "none";
  /** True ONLY for "pass". A "fail" must never be presented as clean data. */
  clean: boolean;
  /** True when the payload may be shown (pass, or partial clearly labeled). */
  acceptable: boolean;
  conformanceNote?: string;
  result?: unknown;
  turns: number;
  refusal?: SieveRefusal;
}

/** Follow-up turn counter. Tolerates the several shapes a run object may use. */
export function turnsOf(body: unknown): number {
  if (!body || typeof body !== "object") return 0;
  const b = body as Record<string, unknown>;
  for (const k of ["turns", "turn_count", "turnCount"]) {
    const v = b[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
  }
  if (Array.isArray(b.messages)) return b.messages.length;
  const conv = b.conversation;
  if (conv && typeof conv === "object" && Array.isArray((conv as Record<string, unknown>).turns)) {
    return ((conv as Record<string, unknown>).turns as unknown[]).length;
  }
  return 0;
}

function parseConformance(body: Record<string, unknown>, expected: boolean): Pick<SieveRunState, "conformance" | "clean" | "acceptable" | "conformanceNote"> {
  const sc = body.schema_conformance;
  const status = sc && typeof sc === "object" ? (sc as Record<string, unknown>).status : sc;
  const noteRaw = sc && typeof sc === "object" ? (sc as Record<string, unknown>).note ?? (sc as Record<string, unknown>).summary : undefined;
  const note = typeof noteRaw === "string" ? noteRaw : undefined;
  if (typeof status !== "string") {
    // Nothing checkable. Without an output_schema that is expected; WITH one it
    // means the artifact is missing, which must not be presented as clean.
    return { conformance: "none", clean: false, acceptable: !expected, conformanceNote: note };
  }
  switch (status) {
    case "pass":
      return { conformance: "pass", clean: true, acceptable: true, conformanceNote: note };
    case "partial":
      // No violations, but declared columns are missing — usable, must be labeled.
      return { conformance: "partial", clean: false, acceptable: true, conformanceNote: note };
    case "fail":
      return { conformance: "fail", clean: false, acceptable: false, conformanceNote: note };
    case "not_checkable":
      return { conformance: "not_checkable", clean: false, acceptable: false, conformanceNote: note };
    case "no_artifact":
      return { conformance: "no_artifact", clean: false, acceptable: false, conformanceNote: note };
    default:
      return { conformance: "none", clean: false, acceptable: false, conformanceNote: note };
  }
}

function parseFiles(body: Record<string, unknown>): SieveFile[] {
  const raw = body.files;
  if (!Array.isArray(raw)) return [];
  const out: SieveFile[] = [];
  for (const f of raw) {
    if (!f || typeof f !== "object") continue;
    const r = f as Record<string, unknown>;
    if (typeof r.url !== "string" || !r.url) continue;
    out.push({
      name: typeof r.name === "string" ? r.name : r.url.split("/").pop() ?? "artifact",
      size: typeof r.size === "number" ? r.size : undefined,
      ext: typeof r.ext === "string" ? r.ext : undefined,
      url: r.url,
    });
  }
  return out;
}

/** Parse a run object. Unknown `status` values are a hard error: the contract
 * lists running/done/refused, and guessing at anything else would silently
 * mis-handle a new state. */
export function parseRunState(body: unknown, opts: { expectSchema?: boolean } = {}): SieveRunState {
  const b = (body ?? {}) as Record<string, unknown>;
  const status = typeof b.status === "string" ? b.status.toLowerCase() : "";
  if (status !== "queued" && status !== "running" && status !== "done" && status !== "refused") {
    throw new SieveError({ kind: "unknown_result", detail: `unexpected run status ${JSON.stringify(status || body)}` });
  }
  const conf = parseConformance(b, opts.expectSchema === true);
  const refusalRaw = b.refusal && typeof b.refusal === "object" ? (b.refusal as Record<string, unknown>) : undefined;
  return {
    status,
    raw: body,
    summary: typeof b.summary === "string" ? b.summary : undefined,
    files: parseFiles(b),
    ...conf,
    result: b.result,
    turns: turnsOf(b),
    refusal: refusalRaw
      ? {
          code: typeof refusalRaw.code === "string" ? refusalRaw.code : undefined,
          message: typeof refusalRaw.message === "string" ? refusalRaw.message : undefined,
          quota: refusalRaw.quota,
        }
      : undefined,
  };
}

/** One GET /api/scrapes/<id>. Retries 429/5xx/network with backoff (safe on a
 * GET) and updates the durable record. */
export async function pollOnce(sessionId: string, opts: { record?: boolean } = {}): Promise<SieveRunState> {
  const r = await requestWithRetry("GET", `/api/scrapes/${encodeURIComponent(sessionId)}`, {
    timeoutMs: getTimeoutMs(),
    safeToRetry: true,
  });
  if (!r.ok) throw r.error;
  const prev = sieveSession(sessionId);
  const state = parseRunState(r.body, { expectSchema: false });
  if (opts.record !== false) {
    // Inline results are persisted so a done run survives a restart; the cap
    // keeps the store small (artifacts live on disk under reports/sieve/).
    let result: unknown;
    if (state.status === "done" && state.result !== undefined) {
      try {
        result = JSON.stringify(state.result).length <= 200_000 ? state.result : undefined;
      } catch {
        result = undefined;
      }
    }
    recordSession({
      ...(prev ?? {
        session_id: sessionId,
        instruction: "",
        created: Date.now(),
        status: "running" as SieveSessionStatus,
        turns: 0,
        polls: 0,
        lastPolledAt: 0,
        lastStatusAt: Date.now(),
      }),
      session_id: sessionId,
      status: state.status === "queued" ? "queued" : state.status,
      turns: Math.max(prev?.turns ?? 0, state.turns),
      polls: (prev?.polls ?? 0) + 1,
      lastPolledAt: Date.now(),
      lastStatusAt: Date.now(),
      conformance: state.conformance,
      clean: state.clean,
      files: state.files,
      summary: state.summary,
      result: result ?? prev?.result,
      refusalCode: state.refusal?.code,
    });
  }
  return state;
}

export interface PollOptions {
  startMs?: number;
  maxMs?: number;
  /** Called on every observed transition (observability + logs). */
  onStatus?: (state: SieveRunState, poll: number) => void;
}

/**
 * Poll a run to completion. Starts at 5s and backs off to ~30s; there is no
 * short timeout — runs take minutes, sometimes longer. Resolves only on
 * done/refused; throws on an unknown status or an unrecoverable transport
 * error (the caller can safely resume later from the durable session_id).
 */
export async function pollScrape(sessionId: string, opts: PollOptions = {}): Promise<SieveRunState> {
  const start = opts.startMs ?? pollStartMs();
  const max = opts.maxMs ?? pollMaxMs();
  let interval = start;
  let poll = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const state = await pollOnce(sessionId);
    poll++;
    opts.onStatus?.(state, poll);
    if (state.status === "done" || state.status === "refused") return state;
    await sleep(interval);
    interval = Math.min(max, Math.round(interval * POLL_BACKOFF));
  }
}

/**
 * Follow-up turn. THE TRAP: with no turns recorded, a naive poll returns the
 * PREVIOUS answer (status is already "done" from the last turn). So we take the
 * turn count first, record it, send the message, and only accept a terminal
 * status whose turn count has ADVANCED.
 */
export async function followUpScrape(
  sessionId: string,
  req: SieveStartRequest,
  opts: PollOptions & { conflictWaitMs?: number; conflictRetries?: number } = {}
): Promise<SieveRunState> {
  // 1) Record turns first — refresh from the API if the store has no count.
  let before = sieveSession(sessionId)?.turns ?? 0;
  const state0 = await pollOnce(sessionId);
  before = Math.max(before, state0.turns);
  const cur = sieveSession(sessionId);
  if (cur && cur.turns !== before) recordSession({ ...cur, turns: before });

  // 2) Send the turn. 409 = a turn is already in flight: wait, then resend.
  const body = JSON.stringify(sievePayload(req));
  const conflictRetries = opts.conflictRetries ?? 12;
  const conflictWait = opts.conflictWaitMs ?? 5_000;
  let sent: HttpResult | null = null;
  for (let attempt = 0; attempt <= conflictRetries; attempt++) {
    const r = await requestWithRetry("POST", `/api/scrapes/${encodeURIComponent(sessionId)}/messages`, {
      headers: { "content-type": "application/json" },
      body,
      timeoutMs: getTimeoutMs(),
      safeToRetry: true, // a turn POST that 5xx'd created no turn server-side
    });
    if (r.ok) {
      sent = r;
      break;
    }
    if (r.error.kind === "conflict") {
      await sleep(r.error.retryAfterMs ?? conflictWait);
      continue;
    }
    throw r.error;
  }
  if (!sent) throw new SieveError({ kind: "conflict", detail: `a turn stayed in flight for ${conflictRetries} resends` });

  // 3) Poll until done AND turns advanced — otherwise we'd read the old answer.
  const start = opts.startMs ?? pollStartMs();
  const max = opts.maxMs ?? pollMaxMs();
  let interval = start;
  let poll = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const state = await pollOnce(sessionId);
    poll++;
    opts.onStatus?.(state, poll);
    const advanced = state.turns > before;
    if ((state.status === "done" || state.status === "refused") && (state.status === "refused" || advanced)) return state;
    await sleep(interval);
    interval = Math.min(max, Math.round(interval * POLL_BACKOFF));
  }
}

// ------------------------------------------------------------------- files

/** files[].url is relative — prefix the base URL and send the Bearer header. */
export function sieveFileUrl(file: SieveFile): string {
  return /^https?:\/\//i.test(file.url) ? file.url : `${sieveBaseUrl()}${file.url.startsWith("/") ? "" : "/"}${file.url}`;
}

export async function downloadSieveFile(file: SieveFile, sessionId: string, dir?: string): Promise<string | null> {
  if (!sieveAvailable()) return null;
  const destDir = dir ?? join(ARTIFACT_DIR, sessionId);
  try {
    const res = await fetch(sieveFileUrl(file), { headers: authHeaders(), signal: AbortSignal.timeout(getTimeoutMs()) });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    mkdirSync(destDir, { recursive: true });
    const safe = (file.name || "artifact").replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120);
    const p = join(destDir, safe);
    writeFileSync(p, buf);
    return p;
  } catch {
    return null; // artifacts are best-effort; the run result still stands
  }
}

export async function downloadSieveFiles(sessionId: string): Promise<string[]> {
  const rec = sieveSession(sessionId);
  if (!rec?.files?.length) return [];
  const out: string[] = [];
  for (const f of rec.files) {
    const p = await downloadSieveFile(f, sessionId);
    if (p) out.push(p);
  }
  const cur = sieveSession(sessionId);
  if (cur && out.length > 0) recordSession({ ...cur, resultPath: out[0] });
  return out;
}

/** GET /api/me/credits — plan, limit, used, remaining. */
export async function sieveCredits(): Promise<{ plan?: string; limit?: number; used?: number; remaining?: number } | null> {
  if (!sieveAvailable()) return null;
  const r = await requestWithRetry("GET", "/api/me/credits", { timeoutMs: getTimeoutMs(), safeToRetry: true });
  if (!r.ok) return null;
  const b = (r.body ?? {}) as Record<string, unknown>;
  return {
    plan: typeof b.plan === "string" ? b.plan : undefined,
    limit: typeof b.limit === "number" ? b.limit : undefined,
    used: typeof b.used === "number" ? b.used : undefined,
    remaining: typeof b.remaining === "number" ? b.remaining : undefined,
  };
}

// ------------------------------------------------- background resume + report

function nextDelayMs(polls: number): number {
  const start = pollStartMs();
  const max = pollMaxMs();
  return Math.min(max, Math.round(start * POLL_BACKOFF ** Math.max(0, polls - 1)));
}

/**
 * The background job the daemon runs each cycle: poll in-flight runs one step
 * each (that IS the 5s→30s schedule, spread across cycles and crash-safe
 * because the schedule lives on disk), download artifacts when a run lands, and
 * refresh reports/SIEVE.md. Bounded so a slow API can never stall the hunt.
 */
export async function resumeSieveRuns(opts: { maxSessions?: number; force?: boolean } = {}): Promise<{
  pending: number;
  polled: number;
  done: number;
  refused: number;
  errors: number;
}> {
  const pending = sievePendingSessions();
  const out = { pending: pending.length, polled: 0, done: 0, refused: 0, errors: 0 };
  if (!sieveAvailable() || pending.length === 0) return out;
  const maxSessions = opts.maxSessions ?? 2;
  let handled = 0;
  for (const rec of pending) {
    if (handled >= maxSessions) break;
    const due = rec.lastPolledAt === 0 || Date.now() - rec.lastPolledAt >= nextDelayMs(rec.polls + 1);
    if (!due && !opts.force) continue;
    handled++;
    try {
      const state = await pollOnce(rec.session_id);
      out.polled++;
      if (state.status === "done") {
        out.done++;
        await downloadSieveFiles(rec.session_id);
        logEvent(
          "scan",
          `sieve run ${rec.session_id} done — ${state.files?.length ?? 0} file(s), schema ${state.conformance}${state.clean ? "" : " (NOT clean — label it)"}`
        );
      } else if (state.status === "refused") {
        out.refused++;
        logEvent("scan", `sieve run ${rec.session_id} refused (${state.refusal?.code ?? "no code"}) — the run never started`);
      }
    } catch (e) {
      out.errors++;
      const err = e as SieveError;
      // Terminal (bad request / unknown status): stop polling this session so
      // it cannot burn a cycle forever.
      if (err.kind === "unknown_result" || err.kind === "unauthorized" || err.kind === "bad_request" || err.kind === "payment_required" || err.kind === "not_found") {
        recordSession({ ...rec, status: "error", error: err.message, lastPolledAt: Date.now() });
      }
    }
  }
  if (out.polled > 0) renderSieveReport();
  return out;
}

/** Renders reports/SIEVE.md: run inventory + structured facts. Never prints the
 * key, and never presents a non-passing schema verdict as clean data. */
export function renderSieveReport(): string {
  const s = loadSieveStore();
  const rows = Object.values(s.sessions).sort((a, b) => b.created - a.created);
  const lines: string[] = [];
  lines.push("# Sieve run inventory");
  lines.push("");
  lines.push(`_generated ${new Date().toISOString()} — base ${sieveBaseUrl()}_`);
  lines.push("");
  lines.push(`- accepted runs today: ${s.runsStarted}/${sieveDailyMax()} (LAB_SIEVE_DAILY_MAX)`);
  lines.push(`- sessions: ${rows.length} (${rows.filter((r) => r.status === "done").length} done, ${rows.filter((r) => r.clean === true).length} schema-clean, ${rows.filter((r) => r.status === "refused").length} refused)`);
  if (s.orphanStarts.length > 0) {
    lines.push(`- UNRESOLVED START OUTCOMES: ${s.orphanStarts.length} — a start timed out or lost the network AFTER sending, so the API may have created the run. It was deliberately NOT retried; check the account's runs before starting another.`);
  }
  lines.push("");
  lines.push("| session_id | status | turns | schema | clean | created | instruction |");
  lines.push("|---|---|---|---|---|---|---|");
  for (const r of rows) {
    lines.push(
      `| \`${r.session_id}\` | ${r.status}${r.refusalCode ? ` (${r.refusalCode})` : ""} | ${r.turns} | ${r.conformance ?? "n/a"} | ${r.clean === true ? "yes" : "no"} | ${new Date(r.created).toISOString()} | ${(r.instruction || "").slice(0, 70).replace(/\|/g, "/")} |`
    );
  }
  const withNotes = rows.filter((r) => r.summary || (r.resultPath && existsSync(r.resultPath)) || r.error);
  if (withNotes.length > 0) {
    lines.push("");
    lines.push("## Run detail");
    for (const r of withNotes) {
      lines.push("");
      lines.push(`### ${r.session_id} — ${r.status} (schema ${r.conformance ?? "n/a"}${r.clean ? ", clean" : ", NOT CLEAN — do not present as validated data"})`);
      if (r.summary) lines.push(`- summary: ${r.summary}`);
      if (r.error) lines.push(`- error: ${r.error}`);
      if (r.result !== undefined) lines.push(`- result: \`${JSON.stringify(r.result).slice(0, 1200)}\``);
      if (r.resultPath && existsSync(r.resultPath)) {
        try {
          lines.push(`- artifact: ${r.resultPath} (${statSync(r.resultPath).size} bytes)`);
        } catch {
          lines.push(`- artifact: ${r.resultPath}`);
        }
      }
      if (r.files?.length) {
        for (const f of r.files) lines.push(`- file: ${f.name}${f.ext ? `.${f.ext}` : ""}${f.size ? ` (${f.size} bytes)` : ""}`);
      }
    }
  }
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(REPORT_PATH, lines.join("\n") + "\n");
  } catch {
    /* observability only */
  }
  return REPORT_PATH;
}

/** One line for INTEL.md's Notes section — integration health, no secrets. */
export function sieveHealthLine(): string {
  if (!sieveAvailable()) return "- sieve: no SIEVE_API_KEY — structured scrape lane off (Markdown-level intel only)";
  const st = sieveStats();
  return `- sieve: enabled (${sieveBaseUrl()}), ${st.runsStartedToday}/${st.dailyMax} runs today, ${st.pending} pending, ${st.done} done (${st.clean} schema-clean, ${st.dirty} NOT clean), ${st.refused} refused${st.orphanStarts > 0 ? `, ${st.orphanStarts} start outcome(s) UNKNOWN (not retried)` : ""}`;
}

// --------------------------------------------------- protocol-intel adapter

/** Columns the recon/triage prompt actually consumes. */
export const SIEVE_PROTOCOL_FIELDS = [
  "item",
  "value",
  "source_url",
] as const;

/** Strict JSON Schema 2020-12 — enables the inline validated `result` and the
 * schema_conformance verdict (so a "fail" can never be mistaken for facts). */
export const SIEVE_PROTOCOL_OUTPUT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    items: {
      type: "array",
      items: {
        type: "object",
        properties: {
          item: { type: "string" },
          value: { type: "string" },
          source_url: { type: "string" },
        },
        required: ["item", "value"],
        additionalProperties: false,
      },
    },
  },
  required: ["items"],
  additionalProperties: false,
} as const;

export function sieveProtocolInstruction(protocol: string): string {
  return (
    `From ${protocol}'s own public website and links reachable from it, extract the security-relevant facts as ` +
    `long-format rows (item/value/source_url): whether the contracts are upgradeable and who can upgrade them; ` +
    `whether the protocol can be paused and who holds that power; every listed audit (auditor, date, url); ` +
    `the bug-bounty program and its maximum payout; the custody of admin keys (multisig address and threshold when ` +
    `stated); where docs, governance, and deployment addresses live; and any public incident, exploit, or ` +
    `post-mortem mentioned. Quote values verbatim and record the exact page they came from. If a fact is not ` +
    `stated anywhere on the site, do not guess it — leave it out.`
  );
}

/**
 * Start one structured recon run for a protocol site and return its session id
 * (results arrive minutes later via resumeSieveRuns → reports/SIEVE.md).
 * Best-effort: null when unconfigured, out of budget, or the start failed.
 */
export async function sieveProtocolIntel(protocol: string, url: string, opts: StartOptions = {}): Promise<string | null> {
  if (!sieveAvailable()) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  const r = await startScrape(
    {
      instruction: sieveProtocolInstruction(protocol),
      target_urls: [url],
      fields: [...SIEVE_PROTOCOL_FIELDS],
      output_schema: SIEVE_PROTOCOL_OUTPUT_SCHEMA,
      table_shape: "long",
      compliance_mode: "regular",
    },
    opts
  );
  return r.ok ? r.session_id : null;
}
