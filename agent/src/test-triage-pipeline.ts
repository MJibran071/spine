// Hermetic test for the TRIAGE PIPELINE fix.
//
// The bug this pins down: triage capacity is finite but the watchlist is not,
// and every way a triage could fail (no key, spent budget, rate limit, revoked
// key, provider error, timeout, unparseable reply) was collapsed into ONE
// string — "triage unavailable (no LAB_LLM_KEY or API error)" — which callers
// wrote onto the target's watchlist row as if it were a verdict, and never
// revisited. 510 of 808 live targets sat in that state.
//
// What must hold now:
//   1. every failure mode has its own reason code, so the cause is knowable;
//   2. deferrable reasons are retryable + queued, terminal ones are not;
//   3. a 429 storm in ONE process must not put the whole fleet to sleep
//      (the shared cooldown was written to a file all five daemons read);
//   4. the queue backs off, retries, resolves, and eventually gives up;
//   5. a deferral can never be phrased like a verdict.
//
// A local fake provider stands in for Groq/OpenRouter, so the whole path
// (rotation, status handling, parsing, caching, telemetry) runs offline.
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-triage-"));
process.env.LAB_REPORT_DIR = SCRATCH;
process.env.LAB_OFFLINE = "1"; // no DefiLlama/mem0 traffic from a test
process.env.LAB_LLM_KEY_FILE = join(SCRATCH, "no-such-key-file");
// Neutralise every key source that is not the fake provider: config.ts calls
// loadDotEnv() at import time and only fills variables that are still
// undefined, so blanking the names from agent/.env here (before the imports)
// makes this test hermetic instead of accidentally using the operator's keys.
const REAL_KEY = "gsk_test_key_long_enough_for_the_min_length_check";
try {
  const dotenv = readFileSync(join(import.meta.dirname, "..", ".env"), "utf8");
  for (const line of dotenv.split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
    // CEREBRAS included: the key pool now carries those keys too, and a real
    // one slipping through answers 402 against the live API mid-test.
    if (m && /(LAB_LLM|GROQ|OPENROUTER|CEREBRAS|LLM)/.test(m[1]!)) process.env[m[1]!] = "";
  }
} catch { /* no .env — nothing to neutralise */ }
for (const n of ["GROQ_API_KEY", "GROQ_API_KEY_1", "OPENROUTER_API_KEY_1", "LAB_LLM_MODEL", "LAB_LLM_DAILY_MAX"]) process.env[n] = "";
process.env.LAB_LLM_KEY = REAL_KEY;

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

// ---- fake provider --------------------------------------------------------
type Mode = "ok" | "rate" | "auth" | "badreq" | "garbage" | "too-large" | "always-413";
let mode: Mode = "ok";
let hits = 0;
/** Body sizes of every request served, so the 413 shrink-retry is provable. */
const bodySizes: number[] = [];
/** What the real Groq free tier does: reject the request BODY above a size,
 * regardless of whether the model name, key and prompt are all fine. */
const OVERSIZE_BODY = 12_000;

const GOOD_REPLY = JSON.stringify({
  hypothesis: "The vault computes shares from a raw asset balance with no virtual offset.",
  technique: "erc4626-share-inflation",
  confidence: 0.82,
  probe: { class: "erc4626-inflation", rationale: "donation skews the share price" },
});

const server = createServer((req, res) => {
  hits++;
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    bodySizes.push(body.length);
    if (mode === "always-413" || (mode === "too-large" && body.length > OVERSIZE_BODY)) {
      res.writeHead(413, { "content-type": "application/json" }).end(
        JSON.stringify({ error: { message: "Request too large for model `openai/gpt-oss-120b` in organization org_test" } })
      );
      return;
    }
    if (mode === "rate") {
      res.writeHead(429, { "content-type": "application/json" }).end(JSON.stringify({ error: "rate limit exceeded" }));
      return;
    }
    if (mode === "auth") {
      res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid api key" }));
      return;
    }
    if (mode === "badreq") {
      res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "model openai/gpt-oss-120b does not exist" }));
      return;
    }
    const content = mode === "garbage" ? "I could not find anything wrong here." : GOOD_REPLY;
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ choices: [{ message: { content } }] }));
  });
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
const port = (server.address() as { port: number }).port;
process.env.LAB_LLM_URL = `http://127.0.0.1:${port}/v1/chat/completions`;

// Import AFTER env is set (config reads env at module load).
const { triageTargetOutcome, triageDeferralNote, triageHealth, clearTriageBackoff, clearKeyQuarantine } = await import("./triage.ts");
const { enqueueTriage, dueTriage, resolveTriage, triageQueueStats, TRIAGE_MAX_ATTEMPTS } = await import("./triageQueue.ts");
const { OFFLINE } = await import("./config.ts");

check("offline mode is active for the test", OFFLINE === true);

const input = (addr: string) => ({
  chainId: "1",
  address: addr,
  shape: "erc-4626-style vault (convertToShares/maxRedeem)",
  selectors: ["0x6e553f65", "0xb3d7f3b8"],
  ethWei: "1000000000000000000",
  wethWei: "0",
  detectorSignals: ["reentrancy-eth"],
  verifiedSource: "contract Vault { function redeem(uint256 s) external { payable(msg.sender).transfer(s); } }",
  bytecodeHex: null,
});

// ---- 1. the happy path ----------------------------------------------------
let out = await triageTargetOutcome(input("0x1111111111111111111111111111111111111111"));
console.log("DBG-OUT", JSON.stringify(out).slice(0, 500));
eq("ok: reason is ok", out.reason, "ok");
check("ok: hypothesis returned", out.hypothesis?.technique === "erc4626-share-inflation", out.hypothesis?.technique);
check("ok: not retryable", out.retryable === false);
check("ok: cached for later cycles", readFileSync(join(SCRATCH, "triage-cache", "triage-1-0x1111111111111111111111111111111111111111.json"), "utf8").includes("share-inflation"));
const cached = await triageTargetOutcome(input("0x1111111111111111111111111111111111111111"));
eq("ok: second call is served from cache", cached.detail, "cache hit");

// ---- 2. rate limited across the whole key pool ---------------------------
mode = "rate";
out = await triageTargetOutcome(input("0x2222222222222222222222222222222222222222"));
eq("429: reason is rate-limited", out.reason, "rate-limited");
check("429: retryable", out.retryable === true);
eq("429: status captured", out.status, 429);
const budgetFile = JSON.parse(readFileSync(join(SCRATCH, "triage-state.json"), "utf8")) as { cooldownUntil?: number };
check("429: did NOT write a fleet-wide cooldown to the shared file", !budgetFile.cooldownUntil, `cooldownUntil=${budgetFile.cooldownUntil}`);
const h429 = triageHealth();
check("429: per-process backoff is active", h429.cooldownMs > 0, `cooldownMs=${h429.cooldownMs}`);

// The old code's fleet-wide cooldown, already sitting on disk, must not
// silence this process: with our own backoff cleared, a call must go through.
clearTriageBackoff();
writeFileSync(join(SCRATCH, "triage-state.json"), JSON.stringify({ day: new Date().toISOString().slice(0, 10), calls: 0, cooldownUntil: Date.now() + 600_000 }));
mode = "ok";
const afterLegacyCooldown = await triageTargetOutcome(input("0x9999999999999999999999999999999999999999"));
eq("legacy shared cooldown on disk is ignored (fleet no longer blinded by one daemon)", afterLegacyCooldown.reason, "ok");

// ---- 3. revoked key ------------------------------------------------------
mode = "auth";
clearTriageBackoff();
const authOut = await triageTargetOutcome(input("0x3333333333333333333333333333333333333333"));
eq("401: classified as auth-error", authOut.reason, "auth-error");
eq("401: status captured", authOut.status, 401);
check("401: provider body preserved", String(authOut.detail).includes("invalid api key"), authOut.detail);
check("401: terminal — a revoked key needs a human, not a retry", authOut.retryable === false);
// DEAD-KEY QUARANTINE: the rejected key must leave the pool (no repeated
// guaranteed-401 slots on later calls), and an operator must be able to
// restore it after fixing the credential.
check("401: the dead key was removed from the pool", triageHealth().keys === 0, `keys=${triageHealth().keys}`);
clearKeyQuarantine();
check("401: quarantine cleared — the key is live again", triageHealth().keys === 1, `keys=${triageHealth().keys}`);

// ---- 4. provider rejects the request (bad model) --------------------------
mode = "badreq";
clearTriageBackoff();
const badOut = await triageTargetOutcome(input("0x4444444444444444444444444444444444444444"));
eq("400: classified as http-error", badOut.reason, "http-error");
eq("400: status captured", badOut.status, 400);
check("400: provider body preserved for diagnosis", String(badOut.detail).includes("does not exist"), badOut.detail);
check("400: retryable (a wrong model name is fixable without code changes)", badOut.retryable === true);

// ---- 4b. provider refuses the BODY size (413) ----------------------------
// Live finding: "triage health: 1/3 ok | blocked: http-error=2 | HTTP413=2"
// with "HTTP 413 Request too large for model openai/gpt-oss-120b". Every
// triage of a real contract was being rejected unread — and before
// reason-coded outcomes that recorded as a clean-looking "no primitive".
mode = "too-large";
clearTriageBackoff();
const bigSource = `contract BigVault {\n${'    uint256 public slot; // filler line to make the source large\n'.repeat(3000)}}`;
const beforeOversize = bodySizes.length;
const bigOut = await triageTargetOutcome({
  ...input("0x4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a"),
  verifiedSource: bigSource,
});
const oversizeAttempts = bodySizes.slice(beforeOversize);
eq("413: the oversized body is retried smaller and then succeeds", bigOut.reason, "ok");
check("413: a hypothesis came back despite the size ceiling", !!bigOut.hypothesis, JSON.stringify(bigOut).slice(0, 160));
check("413: more than one request was made (the first was refused)", oversizeAttempts.length >= 2, JSON.stringify(oversizeAttempts));
check(
  "413: the retry shrank the request body",
  oversizeAttempts.length >= 2 && oversizeAttempts[1]! < oversizeAttempts[0]!,
  JSON.stringify(oversizeAttempts)
);
check(
  "413: the first attempt really was over the ceiling",
  oversizeAttempts[0]! > OVERSIZE_BODY,
  `first=${oversizeAttempts[0]} limit=${OVERSIZE_BODY}`
);
// Exhausting the ladder: a provider that refuses EVERY size must leave a
// deferral (retryable, queued), never a clean-looking verdict, and must have
// actually tried the smaller budgets rather than giving up on the first 413.
mode = "always-413";
clearTriageBackoff();
const beforeHopeless = bodySizes.length;
const stillTooLarge = await triageTargetOutcome({
  ...input("0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"),
  verifiedSource: bigSource,
});
eq("413 (hopeless): still classified as http-error", stillTooLarge.reason, "http-error");
eq("413 (hopeless): status captured", stillTooLarge.status, 413);
check("413 (hopeless): retryable — a size ceiling is not a finding", stillTooLarge.retryable === true);
check(
  "413 (hopeless): says it shrank and was still refused",
  String(stillTooLarge.detail).includes("still refused"),
  String(stillTooLarge.detail)
);
const hopelessAttempts = bodySizes.slice(beforeHopeless);
check(
  "413 (hopeless): tried the smaller budgets instead of one attempt",
  hopelessAttempts.length >= 3,
  JSON.stringify(hopelessAttempts)
);
check(
  "413 (hopeless): each attempt strictly smaller than the last",
  hopelessAttempts.every((n, i) => i === 0 || n < hopelessAttempts[i - 1]!),
  JSON.stringify(hopelessAttempts)
);
mode = "ok";

// ---- 5. unparseable reply -------------------------------------------------
mode = "garbage";
clearTriageBackoff();
const garbleOut = await triageTargetOutcome(input("0x5555555555555555555555555555555555555555"));
eq("garbage: classified as unparseable", garbleOut.reason, "unparseable");
check("garbage: the offending reply is kept as evidence", String(garbleOut.detail).includes("could not find anything"), garbleOut.detail);
check("garbage: retryable (the prompt may land better next time)", garbleOut.retryable === true);

// ---- 6. no key at all -----------------------------------------------------
clearTriageBackoff();
process.env.LAB_LLM_KEY = "";
const noKeyOut = await triageTargetOutcome(input("0x6666666666666666666666666666666666666666"));
eq("no key: reason is no-key", noKeyOut.reason, "no-key");
check("no key: terminal, never queued", noKeyOut.retryable === false);
process.env.LAB_LLM_KEY = REAL_KEY;

// ---- 7. the retry queue ---------------------------------------------------
const q1 = enqueueTriage("1", "0x7777777777777777777777777777777777777777", "rate-limited");
check("queue: first deferral is queued with backoff", q1.queued && q1.nextRetryMs > 0, JSON.stringify(q1));
eq("queue: attempt counter is 1", q1.attempts, 1);
eq("queue: not due yet", dueTriage().length, 0);
// Hand-write an overdue item: the daemon's view must pick it up.
const qfile = join(SCRATCH, "triage-queue.json");
const raw = JSON.parse(readFileSync(qfile, "utf8"));
raw["1:0x8888888888888888888888888888888888888888"] = { key: "1:0x8888888888888888888888888888888888888888", chainId: "1", address: "0x8888888888888888888888888888888888888888", attempts: 2, firstQueuedAt: Date.now() - 1000, nextAt: Date.now() - 1000, reason: "budget" };
writeFileSync(qfile, JSON.stringify(raw));
const due = dueTriage();
eq("queue: overdue item is due", due.length, 1);
eq("queue: due item carries its address", due[0]!.address, "0x8888888888888888888888888888888888888888");
check("queue: stats report size and reasons", triageQueueStats().size === 2 && Object.keys(triageQueueStats().byReason).length >= 2);
check("queue: resolve removes the item", resolveTriage("1", "0x8888888888888888888888888888888888888888") === true);
eq("queue: size drops after resolve", triageQueueStats().size, 1);
check("queue: resolve is idempotent", resolveTriage("1", "0x8888888888888888888888888888888888888888") === false);
// Give-up: attempts beyond the limit are dropped instead of spinning forever.
let gaveUpSeen = false;
for (let i = 0; i < TRIAGE_MAX_ATTEMPTS + 2; i++) {
  const r = enqueueTriage("1", "0x7777777777777777777777777777777777777777", "rate-limited");
  if (r.gaveUp) { gaveUpSeen = true; break; }
}
check("queue: gives up after the attempt limit", gaveUpSeen === true);
eq("queue: a given-up target leaves the queue", triageQueueStats().size, 0);

// ---- 8. wording: a deferral must never read like a verdict ---------------
const note = triageDeferralNote({ hypothesis: null, reason: "cooldown", retryable: true, detail: "per-process backoff, 90s left" });
check("wording: deferral is explicit", note.includes("DEFERRED") && note.includes("queued for retry"), note);
check("wording: never says a bare 'unavailable' (which read as checked-and-clean)", !/^triage unavailable/.test(note), note);
const offNote = triageDeferralNote({ hypothesis: null, reason: "no-key", retryable: false, detail: "no key configured" });
check("wording: a disabled pipeline says OFF, not 'unavailable'", offNote.includes("OFF"), offNote);
const noInputNote = triageDeferralNote({ hypothesis: null, reason: "no-input", retryable: false });
check("wording: nothing-to-read is distinguished from no-capacity", noInputNote.includes("skipped"), noInputNote);

// ---- 9. telemetry records the causes ------------------------------------
const health = triageHealth();
check("health: counters cover the day's attempts", health.total >= 5, `total=${health.total}`);
check("health: reasons are named, not collapsed", Object.keys(health.counts).length >= 3, JSON.stringify(health.counts));
check("health: budget is reported", health.budget.max > 0, JSON.stringify(health.budget));
check("health: key count is reported", health.keys === 1, String(health.keys));
check("health: status codes captured", Object.keys(health.statuses).length >= 1, JSON.stringify(health.statuses));
console.log(`health snapshot: ${JSON.stringify(health.counts)} statuses ${JSON.stringify(health.statuses)}`);
console.log(`fake provider served ${hits} request(s)`);

server.close();
rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? "\ntriage pipeline: all checks passed" : `\ntriage pipeline: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
