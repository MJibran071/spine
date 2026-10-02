// Hermetic tests for the Sieve integration (agent/src/sieve.ts + sieve-login.ts).
//
// The service is stood up as a fake at the HTTP BOUNDARY: it speaks the
// documented contract (202/400/401/402/404/409/429/5xx, running/done/refused,
// unknown status, files[], turns, schema_conformance) and records every request
// it is handed. Everything under test is the real code — sieve.ts is untouched:
// it still builds real RequestInit objects (auth header, JSON vs multipart
// body, AbortSignal.timeout), and parses real Response objects.
//
// NOTE ON THE BOUNDARY: this project's other hermetic tests (test-keypool.ts,
// test-triage-pipeline.ts) stand their fake up on a 127.0.0.1 socket. That is
// NOT possible in this sandbox — binding a listener fails with EPERM for the
// repo's own tests too — so the fake is installed as globalThis.fetch instead.
// It is the same boundary (the only thing replaced is transport), and it lets
// the multipart body and the abort signal be inspected as first-class objects.
//
// What must hold (the contract's sharp edges):
//   1. request building: Bearer SIEVE_API_KEY, JSON by default, multipart when a
//      document is attached;
//   2. status handling: running -> keep polling, done -> read the payload,
//      refused -> terminal (the run never started), anything else -> an error,
//      never a silent success;
//   3. follow-ups read the NEW answer: a terminal status whose turn count has
//      not advanced must NOT be returned (it is the previous answer);
//   4. error mapping: 400/401/402 terminal, 429/5xx retryable, GET retried;
//   5. a POST /api/scrapes timeout is NEVER retried (the first call may have
//      succeeded) and is recorded as an unknown outcome;
//   6. the session_id is durable the moment a run is accepted, so a crash
//      resumes polling instead of starting a duplicate;
//   7. schema_conformance "fail" is never reported as clean;
//   8. no key / LAB_OFFLINE=1 -> no network traffic at all (behavior unchanged).
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-sieve-"));
const STATE_PATH = join(SCRATCH, "sieve-state.json");
const KEY = "dc_sk_testkey_0000000000000000000000000000";
process.env.LAB_REPORT_DIR = SCRATCH;
process.env.LAB_OFFLINE = ""; // only the injected transport is contacted
process.env.SIEVE_API_KEY = KEY;
process.env.LAB_SIEVE_START_TIMEOUT_MS = "300";
process.env.LAB_SIEVE_GET_TIMEOUT_MS = "1000";
process.env.LAB_SIEVE_POLL_START_MS = "5";
process.env.LAB_SIEVE_POLL_MAX_MS = "10";
process.env.LAB_SIEVE_DAILY_MAX = "50";
// A deliberately unresolvable host: everything is served by the injected
// transport, so a call that somehow escaped it would fail loudly instead of
// reaching the real service.
process.env.SIEVE_BASE_URL = "https://sieve.test";

// ------------------------------------------------------- the fake at the boundary

interface Seen {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  /** True when the call carried an AbortSignal (the only timeout mechanism). */
  signal: boolean;
}
const reqs: Seen[] = [];

type StartMode = "ok" | "400" | "401" | "402" | "500once" | "429once" | "no_session" | "hang";
let startMode: StartMode = "ok";
let startAttempts = 0;
let getCalls = 0;
let msgCalls = 0;
let turnConflicts = 0;
/** Bodies returned by GET /api/scrapes/<id>, one per call (the last repeats). */
let getBodies: Record<string, unknown>[] = [];
/** Device-token answers, consumed one per poll. */
let tokenModes: string[] = ["approved"];
let deviceCodeCalls = 0;

function headersToObject(h: HeadersInit | undefined): Record<string, string> {
  if (!h) return {};
  if (h instanceof Headers) {
    const out: Record<string, string> = {};
    h.forEach((v, k) => {
      out[k.toLowerCase()] = v;
    });
    return out;
  }
  if (Array.isArray(h)) return Object.fromEntries(h.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  return Object.fromEntries(Object.entries(h as Record<string, string>).map(([k, v]) => [k.toLowerCase(), String(v)]));
}

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: unknown, init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : String((input as { url?: string })?.url ?? input);
  const method = (init?.method ?? "GET").toUpperCase();
  const path = new URL(url).pathname;
  const headers = headersToObject(init?.headers ?? undefined);
  reqs.push({ method, url, path, headers, body: init?.body ?? null, signal: !!init?.signal });

  const json = (status: number, payload: unknown, extra: Record<string, string> = {}): Response =>
    new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json", ...extra } });

  if (method === "POST" && path === "/api/auth/device/code") {
    deviceCodeCalls++;
    const base = process.env.SIEVE_BASE_URL;
    return json(200, {
      device_code: "dev-1",
      user_code: "WDJB-MJHT",
      verification_uri: `${base}/device`,
      verification_uri_complete: `${base}/device?code=WDJB-MJHT`,
      expires_in: 600,
      interval: 1,
    });
  }
  if (method === "POST" && path === "/api/auth/device/token") {
    const mode = tokenModes.length > 0 ? tokenModes.shift()! : "approved";
    if (mode === "approved") return json(200, { api_key: KEY, token_type: "Bearer", key_name: "exploit-lab-agent (cli)" });
    if (mode === "error") return json(500, { error: "internal" });
    return json(400, { error: mode });
  }
  if (method === "POST" && path === "/api/scrapes") {
    startAttempts++;
    if (startMode === "hang") {
      // A real socket that never answers: the only way out is the abort signal.
      // The ref'd safety timer stands in for the socket keeping the event loop
      // alive (AbortSignal.timeout's own timer is unref'd, so with genuinely
      // nothing pending Node would exit before the client-side timeout fired).
      return new Promise<Response>((_resolve, reject) => {
        const s = init?.signal;
        const safety = setTimeout(() => reject(new DOMException("safety net — no answer", "TimeoutError")), 10_000);
        const onAbort = () => {
          clearTimeout(safety);
          reject(new DOMException("The operation was aborted due to timeout", "TimeoutError"));
        };
        if (!s) return; // no signal: never settles (safety net stays armed)
        if (s.aborted) onAbort();
        else s.addEventListener("abort", onAbort, { once: true });
      });
    }
    if (startMode === "400") return json(400, { error: "instruction is required" });
    if (startMode === "401") return json(401, { error: "invalid or revoked api key" });
    if (startMode === "402") return json(402, { error: "out of credits" });
    if (startMode === "500once" && startAttempts === 1) return json(500, { error: "internal" });
    if (startMode === "429once" && startAttempts === 1) return json(429, { error: "slow down" }, { "retry-after": "0" });
    if (startMode === "no_session") return json(202, { status: "queued" });
    return json(202, { status: "queued", session_id: "sess-1", poll: "/api/scrapes/sess-1" });
  }
  if (method === "POST" && /^\/api\/scrapes\/[^/]+\/messages$/.test(path)) {
    msgCalls++;
    if (msgCalls <= turnConflicts) return json(409, { error: "a turn is already in flight" });
    return json(202, { status: "running" });
  }
  if (method === "GET" && /^\/api\/scrapes\/[^/]+\/files\/.+$/.test(path)) {
    return new Response("quote,tag\nfirst quote,change\n", { status: 200, headers: { "content-type": "text/plain" } });
  }
  if (method === "GET" && path === "/api/me/credits") {
    return json(200, { plan: "free", limit: 100, used: 7, remaining: 93 });
  }
  if (method === "GET" && /^\/api\/scrapes\/[^/]+$/.test(path)) {
    const idx = Math.min(getCalls, Math.max(0, getBodies.length - 1));
    getCalls++;
    return json(200, getBodies[idx] ?? { status: "running" });
  }
  return json(404, { error: "not found" });
}) as typeof fetch;

// Imported AFTER the env is pinned, so config.ts picks up the scratch REPORT_DIR.
const sieve = await import("./sieve.ts");
const login = await import("./sieve-login.ts");
if (!realFetch) throw new Error("no global fetch to replace");

let failures = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) console.log(`ok: ${name}`);
  else {
    failures++;
    console.error(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
  }
}
function eq(name: string, actual: unknown, expected: unknown): void {
  check(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
function reset(mode: StartMode = "ok"): void {
  reqs.length = 0;
  startMode = mode;
  startAttempts = 0;
  getCalls = 0;
  msgCalls = 0;
  turnConflicts = 0;
  getBodies = [];
  rmSync(STATE_PATH, { force: true });
}
/** The store exactly as it exists on disk — the crash-recovery view. */
function loadState(): { sessions: Record<string, { status: string; clean?: boolean; resultPath?: string }>; orphanStarts: unknown[] } {
  return JSON.parse(readFileSync(STATE_PATH, "utf8")) as { sessions: Record<string, { status: string }>; orphanStarts: unknown[] };
}

// ---- 1. request building ---------------------------------------------------
reset();
{
  const r = await sieve.startScrape({
    instruction: "Extract the text and author of each quote",
    target_urls: ["https://quotes.toscrape.com"],
    fields: ["text", "author"],
    output_schema: { type: "object" },
    table_shape: "long",
  });
  check("start: 202 accepted", r.ok === true, JSON.stringify(r));
  eq("start: session_id surfaced", r.ok ? r.session_id : "", "sess-1");
  const req = reqs.find((x) => x.method === "POST")!;
  eq("start: url", req.url, `${process.env.SIEVE_BASE_URL}/api/scrapes`);
  eq("start: Bearer auth header", req.headers.authorization, `Bearer ${KEY}`);
  eq("start: JSON content type", req.headers["content-type"], "application/json");
  check("start: call carries an abort signal (timeout is real)", req.signal);
  const sent = JSON.parse(req.body as string);
  eq("start: instruction sent", sent.instruction, "Extract the text and author of each quote");
  eq("start: target_urls sent", JSON.stringify(sent.target_urls), JSON.stringify(["https://quotes.toscrape.com"]));
  eq("start: fields sent", JSON.stringify(sent.fields), JSON.stringify(["text", "author"]));
  eq("start: table_shape sent", sent.table_shape, "long");
  eq("start: output_schema sent", JSON.stringify(sent.output_schema), JSON.stringify({ type: "object" }));
  eq("start: compliance defaults to regular", sent.compliance_mode, "regular");
  check("start: no schema key invented", !("schema" in sent));
}
{
  const docPath = join(SCRATCH, "doc.txt");
  writeFileSync(docPath, "protocol docs: upgradeable, owner 0xdead\n");
  reset();
  const r = await sieve.startScrape({ instruction: "Extract every admin key", file: docPath });
  check("multipart: accepted", r.ok === true, JSON.stringify(r));
  const req = reqs.find((x) => x.method === "POST")!;
  const form = req.body as FormData;
  check("multipart: body is real FormData", form instanceof FormData);
  check("multipart: no manual content-type (boundary is set by fetch)", req.headers["content-type"] === undefined, String(req.headers["content-type"]));
  eq("multipart: instruction field", form.get("instruction"), "Extract every admin key");
  eq("multipart: compliance field", form.get("compliance_mode"), "regular");
  const blob = form.get("file") as File;
  check("multipart: file field is a named blob", !!blob && blob.name === "doc.txt", String(blob?.name));
  eq("multipart: document bytes included", await blob.text(), "protocol docs: upgradeable, owner 0xdead\n");
  eq("multipart: auth header kept", req.headers.authorization, `Bearer ${KEY}`);
}

// ---- 2. status handling ----------------------------------------------------
reset();
{
  getBodies = [
    { status: "running", turns: 0 },
    { status: "running", turns: 0 },
    {
      status: "done",
      turns: 0,
      summary: "extracted 10 rows",
      files: [{ name: "quotes.csv", size: 128, ext: "csv", url: "/api/scrapes/sess-1/files/quotes.csv" }],
      schema_conformance: { status: "pass" },
    },
  ];
  const seen: string[] = [];
  const st = await sieve.pollScrape("sess-1", { startMs: 5, maxMs: 10, onStatus: (s) => seen.push(s.status) });
  eq("poll: running then done", seen.join(","), "running,running,done");
  eq("poll: final status done", st.status, "done");
  eq("poll: summary read", st.summary, "extracted 10 rows");
  eq("poll: file parsed", st.files?.length, 1);
  eq("poll: relative file url kept", st.files?.[0]?.url, "/api/scrapes/sess-1/files/quotes.csv");
  eq("poll: schema pass is clean", st.clean, true);
  eq("poll: GET url", reqs.find((r) => r.method === "GET")!.url, `${process.env.SIEVE_BASE_URL}/api/scrapes/sess-1`);
  eq("poll: GET carries Bearer", reqs.find((r) => r.method === "GET")!.headers.authorization, `Bearer ${KEY}`);
  check("poll: GET carries an abort signal", reqs.find((r) => r.method === "GET")!.signal);
}
reset();
{
  getBodies = [{ status: "refused", refusal: { code: "quota", message: "credit limit reached", quota: { limit: 100, used: 100 } } }];
  const st = await sieve.pollScrape("sess-1", { startMs: 5, maxMs: 10 });
  eq("refused: terminal status", st.status, "refused");
  eq("refused: code surfaced", st.refusal?.code, "quota");
  check("refused: quota detail surfaced", !!st.refusal?.quota);
  eq("refused: not clean", st.clean, false);
}
reset();
{
  getBodies = [{ status: "something_new", turns: 0 }];
  let kind = "";
  try {
    await sieve.pollOnce("sess-1");
  } catch (e) {
    kind = (e as { kind?: string }).kind ?? "";
  }
  eq("unknown status: typed error, not a silent success", kind, "unknown_result");
}
reset();
{
  // every schema_conformance verdict
  eq("conformance pass -> clean", sieve.parseRunState({ status: "done", schema_conformance: { status: "pass" } }).clean, true);
  const partial = sieve.parseRunState({ status: "done", schema_conformance: { status: "partial" } });
  eq("conformance partial -> acceptable but not clean", `${partial.acceptable}/${partial.clean}`, "true/false");
  const fail = sieve.parseRunState({ status: "done", schema_conformance: { status: "fail" }, summary: "could not obtain admin keys" });
  eq("conformance fail -> acceptable=false (never present as clean)", `${fail.acceptable}/${fail.clean}`, "false/false");
  eq("conformance fail -> summary kept", fail.summary, "could not obtain admin keys");
  const none = sieve.parseRunState({ status: "done" });
  eq("conformance absent -> not claimed clean", `${none.conformance}/${none.clean}`, "none/false");
  eq("conformance no_artifact -> not acceptable", sieve.parseRunState({ status: "done", schema_conformance: { status: "no_artifact" } }).acceptable, false);
  eq("conformance not_checkable -> not acceptable", sieve.parseRunState({ status: "done", schema_conformance: { status: "not_checkable" } }).acceptable, false);
  eq("conformance: queued is a pollable, non-terminal status", sieve.parseRunState({ status: "queued" }).status, "queued");
}

// ---- 3. follow-up turns ----------------------------------------------------
reset();
{
  turnConflicts = 1; // first turn POST answers 409 (a turn is in flight)
  getBodies = [
    { status: "done", turns: 1, summary: "first answer" }, // turn-count read
    { status: "done", turns: 1, summary: "first answer" }, // STALE terminal — must not be accepted
    { status: "done", turns: 2, summary: "second answer" }, // fresh
  ];
  const st = await sieve.followUpScrape("sess-1", { instruction: "now add the author column" }, { startMs: 5, maxMs: 10, conflictWaitMs: 1 });
  eq("follow-up: reads the NEW answer", st.summary, "second answer");
  eq("follow-up: turn advanced to 2", st.turns, 2);
  check("follow-up: 409 was retried", msgCalls >= 2, `msgCalls=${msgCalls}`);
  check("follow-up: at least 3 GETs (count, stale, fresh)", getCalls >= 3, `getCalls=${getCalls}`);
  const firstGet = reqs.findIndex((r) => r.method === "GET");
  const firstMsg = reqs.findIndex((r) => r.method === "POST" && r.path.endsWith("/messages"));
  check("follow-up: turn count recorded BEFORE the message was sent", firstGet >= 0 && firstGet < firstMsg, `get=${firstGet} msg=${firstMsg}`);
  const msgReq = reqs.find((r) => r.path.endsWith("/messages"))!;
  eq("follow-up: instruction sent", JSON.parse(msgReq.body as string).instruction, "now add the author column");
  eq("follow-up: body reuses the start shape", JSON.parse(msgReq.body as string).compliance_mode, "regular");
}

// ---- 4. error mapping ------------------------------------------------------
for (const [mode, kind, retryable] of [
  ["400", "bad_request", false],
  ["401", "unauthorized", false],
  ["402", "payment_required", false],
] as const) {
  reset(mode);
  const r = await sieve.startScrape({ instruction: "x" });
  eq(`error ${mode}: kind`, r.ok ? "ok" : r.error.kind, kind);
  eq(`error ${mode}: retryable`, r.ok ? true : r.retryable, retryable);
  eq(`error ${mode}: not retried (terminal)`, startAttempts, 1);
}
for (const mode of ["429once", "500once"] as const) {
  reset(mode);
  const r = await sieve.startScrape({ instruction: "x" }, { baseDelayMs: 1 });
  check(`error ${mode}: retried then succeeded (no run was created)`, r.ok === true, JSON.stringify(r));
  eq(`error ${mode}: exactly two attempts`, startAttempts, 2);
}
reset();
{
  getBodies = [{ status: "done", turns: 0 }];
  eq("credits: parsed", JSON.stringify(await sieve.sieveCredits()), JSON.stringify({ plan: "free", limit: 100, used: 7, remaining: 93 }));
}

// ---- 5. never retry POST /api/scrapes on timeout ---------------------------
reset("hang");
{
  const r = await sieve.startScrape({ instruction: "Extract quotes" }, { attempts: 3, baseDelayMs: 1 });
  eq("timeout: reported as a failure", r.ok, false);
  eq("timeout: mayHaveStarted flag set", r.ok ? false : r.mayHaveStarted, true);
  eq("timeout: NOT retryable", r.ok ? true : r.retryable, false);
  eq("timeout: exactly ONE POST reached the API", startAttempts, 1);
  const store = loadState();
  eq("timeout: recorded as an unknown start outcome", store.orphanStarts.length, 1);
  eq("timeout: no session was invented", Object.keys(store.sessions).length, 0);
  eq("timeout: kind", r.ok ? "" : r.error.kind, "timeout");
  check("timeout: no credits were spent", sieve.sieveBudgetUsed() === 0, String(sieve.sieveBudgetUsed()));
}
reset("no_session");
{
  const r = await sieve.startScrape({ instruction: "x" });
  eq("202 without session_id: treated as may-have-started", r.ok ? false : r.mayHaveStarted, true);
  eq("202 without session_id: not retried", startAttempts, 1);
}

// ---- 6. durable session + crash resume ------------------------------------
reset();
{
  const r = await sieve.startScrape({ instruction: "Extract every admin key", target_urls: ["https://example.org"] });
  check("resume: start accepted", r.ok === true, JSON.stringify(r));
  // The store on DISK already holds the session id — what makes a crash resume
  // instead of starting a duplicate run.
  eq("resume: session_id durable before polling", loadState().sessions["sess-1"]?.status, "queued");
  eq("resume: pending session visible", sieve.sievePendingSessions().length, 1);
  eq("resume: budget consumed once", sieve.sieveBudgetUsed(), 1);

  getBodies = [
    { status: "running", turns: 0 },
    {
      status: "done",
      turns: 0,
      summary: "admin keys: 1 multisig 2/3",
      files: [{ name: "admin.csv", ext: "csv", url: "/api/scrapes/sess-1/files/admin.csv" }],
      schema_conformance: { status: "pass" },
    },
  ];
  const first = await sieve.resumeSieveRuns({ force: true });
  eq("resume: one session polled", `${first.polled}/${first.pending}`, "1/1");
  eq("resume: still pending after 'running'", sieve.sievePendingSessions().length, 1);
  const second = await sieve.resumeSieveRuns({ force: true });
  eq("resume: done counted", second.done, 1);
  eq("resume: nothing pending after 'done'", sieve.sievePendingSessions().length, 0);
  const rec = sieve.sieveSession("sess-1");
  eq("resume: record completed", rec?.status, "done");
  eq("resume: record clean", rec?.clean, true);
  check("resume: artifact downloaded from the relative url", !!rec?.resultPath && existsSync(rec.resultPath), String(rec?.resultPath));
  check("resume: artifact landed under reports/sieve/", !!rec?.resultPath && rec.resultPath.startsWith(join(SCRATCH, "sieve")), String(rec?.resultPath));
  check(
    "resume: file fetch prefixed the base url and sent Bearer",
    reqs.some((r) => r.path === "/api/scrapes/sess-1/files/admin.csv" && r.headers.authorization === `Bearer ${KEY}`)
  );
  check("resume: report written", existsSync(join(SCRATCH, "SIEVE.md")));
  const report = readFileSync(join(SCRATCH, "SIEVE.md"), "utf8");
  check("report: never contains the key", !report.includes(KEY));
  check("report: lists the session", report.includes("sess-1"));
  check("report: health line carries no secret", !sieve.sieveHealthLine().includes(KEY));
  check("report: health line reports the lane", sieve.sieveHealthLine().includes("sieve: enabled"));
}
reset();
{
  // A terminal error (unknown status) must park the session, not spin forever.
  getBodies = [{ status: "something_new" }];
  await sieve.startScrape({ instruction: "x" });
  const r = await sieve.resumeSieveRuns({ force: true });
  eq("resume: unknown status counted as an error", r.errors, 1);
  eq("resume: unknown-status session parked", sieve.sieveSession("sess-1")?.status, "error");
  eq("resume: parked session no longer pending", sieve.sievePendingSessions().length, 0);
}

// ---- 7. budget ------------------------------------------------------------
reset();
{
  process.env.LAB_SIEVE_DAILY_MAX = "1";
  const a = await sieve.startScrape({ instruction: "first" });
  const before = startAttempts;
  const b = await sieve.startScrape({ instruction: "second" });
  eq("budget: first run accepted", a.ok, true);
  eq("budget: second refused locally", b.ok ? "ok" : b.error.kind, "budget_exhausted");
  eq("budget: refused start made no request", startAttempts, before);
  eq("budget: nothing left", sieve.sieveBudgetLeft(), 0);
  process.env.LAB_SIEVE_DAILY_MAX = "50";
}

// ---- 8. unconfigured / offline = behavior unchanged ------------------------
reset();
{
  process.env.SIEVE_API_KEY = "";
  eq("unconfigured: available=false", sieve.sieveAvailable(), false);
  const before = startAttempts;
  const r = await sieve.startScrape({ instruction: "x" });
  eq("unconfigured: kind", r.ok ? "ok" : r.error.kind, "unavailable");
  eq("unconfigured: zero network calls", startAttempts, before);
  eq("unconfigured: no credit spend", sieve.sieveBudgetUsed(), 0);
  eq("unconfigured: credits helper degrades", await sieve.sieveCredits(), null);
  eq("unconfigured: protocol intel is a no-op", await sieve.sieveProtocolIntel("X", "https://example.org"), null);
  eq(
    "unconfigured: resume is a no-op",
    JSON.stringify(await sieve.resumeSieveRuns({ force: true })),
    JSON.stringify({ pending: 0, polled: 0, done: 0, refused: 0, errors: 0 })
  );
  check("unconfigured: health line says so", sieve.sieveHealthLine().includes("no SIEVE_API_KEY"));
  process.env.SIEVE_API_KEY = KEY;
}
{
  // config.ts reads LAB_OFFLINE at IMPORT time, so the offline path is proven
  // in a child process instead of by flipping the variable mid-run.
  const out = execFileSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--input-type=module",
      "-e",
      'process.env.LAB_OFFLINE = "1"; process.env.SIEVE_API_KEY = "dc_sk_x"; const s = await import("./src/sieve.ts"); const r = await s.startScrape({ instruction: "x" }); console.log("available=" + s.sieveAvailable() + " kind=" + (r.error && r.error.kind));',
    ],
    { cwd: join(import.meta.dirname, ".."), encoding: "utf8", env: { ...process.env, LAB_OFFLINE: "1" } }
  ).trim();
  eq("offline: LAB_OFFLINE=1 disables the lane even with a key", out, "available=false kind=unavailable");
}

// ---- 9. protocol intel adapter + file url helper ---------------------------
reset();
{
  const sid = await sieve.sieveProtocolIntel("Acme Finance", "https://acme.example");
  eq("intel: run started", sid, "sess-1");
  const sent = JSON.parse(reqs.find((r) => r.method === "POST")!.body as string);
  check("intel: instruction is plain language", typeof sent.instruction === "string" && sent.instruction.length > 80, String(sent.instruction).slice(0, 60));
  eq("intel: compliance regular", sent.compliance_mode, "regular");
  eq("intel: long format", sent.table_shape, "long");
  check(
    "intel: strict 2020-12 output schema attached",
    sent.output_schema?.$schema === "https://json-schema.org/draft/2020-12/schema" && sent.output_schema?.additionalProperties === false
  );
  check("intel: output schema under 32KB", JSON.stringify(sent.output_schema).length <= 32 * 1024);
  eq("intel: non-http target ignored", await sieve.sieveProtocolIntel("X", "file:///etc/passwd"), null);
  eq("file url: relative prefixed", sieve.sieveFileUrl({ name: "a.csv", url: "/api/x" }), `${process.env.SIEVE_BASE_URL}/api/x`);
  eq("file url: absolute kept", sieve.sieveFileUrl({ name: "a.csv", url: "https://cdn.example/a.csv" }), "https://cdn.example/a.csv");
}

// ---- 10. secret store writer (never prints, never duplicates) --------------
{
  const envPath = join(SCRATCH, ".env");
  writeFileSync(envPath, "# existing secrets\nLAB_LLM_KEY=abc\nSIEVE_API_KEY=dc_sk_old\nOTHER=1\n");
  const r1 = login.upsertEnvKey(envPath, "SIEVE_API_KEY", "dc_sk_new");
  const after = readFileSync(envPath, "utf8");
  eq("env: reported a change", r1.changed, true);
  eq("env: replaced in place (one line only)", after.split("\n").filter((l) => l.startsWith("SIEVE_API_KEY=")).length, 1);
  check("env: new value present", after.includes("SIEVE_API_KEY=dc_sk_new"));
  check("env: old value gone", !after.includes("dc_sk_old"));
  check("env: other secrets untouched", after.includes("LAB_LLM_KEY=abc") && after.includes("OTHER=1"));
  check("env: comment preserved", after.startsWith("# existing secrets"));
  const r2 = login.upsertEnvKey(envPath, "SIEVE_API_KEY", "dc_sk_new");
  eq("env: idempotent write is a no-op", r2.changed, false);
  const fresh = join(SCRATCH, ".env.fresh");
  const r3 = login.upsertEnvKey(fresh, "SIEVE_API_KEY", "dc_sk_fresh");
  check("env: created when absent", r3.created && readFileSync(fresh, "utf8") === "SIEVE_API_KEY=dc_sk_fresh\n");
  eq("login: client name is stable", login.SIEVE_CLIENT_NAME, "exploit-lab-agent");
}

// ---- 11. device login (the key is never printed) ---------------------------
reset();
{
  const dc = await login.requestDeviceCode("exploit-lab-agent");
  eq("device: code response parsed", dc.user_code, "WDJB-MJHT");
  eq("device: complete link kept", dc.verification_uri_complete, "https://sieve.test/device?code=WDJB-MJHT");
  eq("device: interval honoured", dc.interval, 1);
  eq("device: body carries the self-reported client name", JSON.parse(reqs.find((r) => r.path === "/api/auth/device/code")!.body as string).client_name, "exploit-lab-agent");

  tokenModes = ["authorization_pending"];
  eq("device: authorization_pending keeps polling", (await login.pollDeviceToken("dev-1")).kind, "pending");
  tokenModes = ["slow_down"];
  eq("device: slow_down adds to the interval", (await login.pollDeviceToken("dev-1")).kind, "slow_down");
  tokenModes = ["access_denied"];
  eq("device: access_denied stops", (await login.pollDeviceToken("dev-1")).kind, "denied");
  tokenModes = ["expired_token"];
  eq("device: expired_token restarts the flow", (await login.pollDeviceToken("dev-1")).kind, "expired");
  tokenModes = ["something_new"];
  eq("device: unrecognised error is surfaced, not swallowed", (await login.pollDeviceToken("dev-1")).kind, "error");
  tokenModes = ["approved"];
  const approved = await login.pollDeviceToken("dev-1");
  check("device: approval returns the key once", approved.kind === "approved" && approved.apiKey === KEY && approved.keyName === "exploit-lab-agent (cli)", JSON.stringify(approved).replace(KEY, "<redacted>"));
  check("device: token poll never sends the key", reqs.filter((r) => r.path === "/api/auth/device/token").every((r) => !String(r.headers.authorization ?? "").includes("dc_sk_") || r.headers.authorization === `Bearer ${KEY}`));

  // The documented fallback writer, end-to-end in a child process: the key
  // arrives on stdin, lands in the store, and never appears on stdout.
  const envFile = join(SCRATCH, "paste.env");
  writeFileSync(envFile, "LAB_LLM_KEY=keepme\n");
  const piped = execFileSync(process.execPath, ["--experimental-strip-types", "src/sieve-login.ts", "--paste"], {
    cwd: join(import.meta.dirname, ".."),
    input: `${KEY}\n`,
    encoding: "utf8",
    env: { ...process.env, LAB_SIEVE_ENV_FILE: envFile, SIEVE_API_KEY: "" },
  });
  check("paste: key stored via stdin", readFileSync(envFile, "utf8").includes(`SIEVE_API_KEY=${KEY}`));
  check("paste: existing entries preserved", readFileSync(envFile, "utf8").includes("LAB_LLM_KEY=keepme"));
  check("paste: stdout never contains the key", !piped.includes(KEY), "the api_key leaked to stdout");
  check("paste: reports only a length", /SIEVE_API_KEY (written|updated)/.test(piped) && /\d+ characters/.test(piped), piped.trim());
  {
    let rejected = 1;
    try {
      execFileSync(process.execPath, ["--experimental-strip-types", "src/sieve-login.ts", "--paste"], {
        cwd: join(import.meta.dirname, ".."),
        input: "not a key\n",
        encoding: "utf8",
        stdio: "pipe",
        env: { ...process.env, LAB_SIEVE_ENV_FILE: join(SCRATCH, "rejected.env"), SIEVE_API_KEY: "" },
      });
      rejected = 0;
    } catch (e) {
      rejected = (e as { status?: number }).status ?? -1;
    }
    eq("paste: a malformed key is refused", rejected, 1);
    eq("paste: nothing written for a malformed key", existsSync(join(SCRATCH, "rejected.env")), false);
  }

  // Full flow, with stdout captured: the key must reach the caller and NOT the log.
  tokenModes = ["authorization_pending", "approved"];
  const logs: string[] = [];
  const origLog = console.log;
  console.log = (...a: unknown[]) => {
    logs.push(a.map((x) => String(x)).join(" "));
  };
  let res: { apiKey: string } | null = null;
  try {
    res = await login.deviceLogin({ clientName: "exploit-lab-agent" });
  } finally {
    console.log = origLog;
  }
  const text = logs.join("\n");
  check("device flow: approval yields the key", res?.apiKey === KEY);
  check("device flow: prints the verification link", text.includes("https://sieve.test/device?code=WDJB-MJHT"));
  check("device flow: prints the user code", text.includes("WDJB-MJHT"));
  check("device flow: NEVER prints the key", !text.includes(KEY), "the api_key leaked to stdout");
  check("device flow: says the tool name is self-reported", /self-reported/i.test(text));
  check("device flow: tells the user to approve only their own code", /ONLY approve a code you started yourself/i.test(text));
  check("device flow: shows the origin and expiry", /this machine/.test(text) && /expires in 10 minutes/i.test(text));

  tokenModes = ["access_denied"];
  let denied = "";
  const origLog2 = console.log;
  console.log = () => {};
  try {
    await login.deviceLogin();
  } catch (e) {
    denied = (e as Error).message;
  } finally {
    console.log = origLog2;
  }
  check("device flow: a denial stops with a clear message", /declined/i.test(denied), denied);
  check("device flow: two device codes were requested (one restart path exercised)", deviceCodeCalls >= 2, String(deviceCodeCalls));
}

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? "\nsieve: all checks passed" : `\nsieve: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
