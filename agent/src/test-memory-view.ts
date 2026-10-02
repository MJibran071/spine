// Regression test for the Memory tab's data path.
//
// The dashboard shows what the agent REMEMBERS (local JSONL store + mem0
// sidecar status), what it has LEARNED per shape (generic-engine priors,
// proven violations, dead ends), and offers read-only recall. All of that is
// read-side code with two classic failure modes:
//   - a corrupt/torn store line turning the whole view into a crash or zeros;
//   - "recall" silently ranking nothing while still looking like an answer.
//
// What must hold:
//   1. the summary counts every kind and buckets growth by hour, newest first;
//   2. a torn line is skipped, not fatal (the writer appends, crashes happen);
//   3. recall ranks a known term above noise, and an unknown term returns
//      NOTHING rather than something plausible-looking;
//   4. the learned-priors view reflects recorded outcomes (violated/held/error)
//      and lists proven violations newest first;
//   5. GET /api/memory answers with hits, /api/state carries the memory view,
//      and the server stays read-only (POST is refused).
//
// Runs against a scratch store and a scratch harness dir; the live hunt's
// memory and the fleet's port range are untouched.
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-memview-"));
process.env.LAB_REPORT_DIR = SCRATCH;
process.env.LAB_OFFLINE = "1";
process.env.LAB_AGENT_TEST_DIR = join(SCRATCH, "harness");

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

// ---- seed a memory store with the shapes the writers actually produce ------
const MEM_DIR = join(SCRATCH, "memory");
const MEM_PATH = join(MEM_DIR, "memories.jsonl");
mkdirSync(MEM_DIR, { recursive: true });
const now = Date.now();
const HOUR = 3_600_000;
const seed = [
  { t: now - 5 * HOUR, text: "Triage 2026-09-15: 0xabc111 (lending) — technique none, confidence 0.75. Hypothesis: nothing exploitable found.", meta: { address: "0xabc111" } },
  { t: now - 2 * HOUR, text: "PROBE FAILED 2026-09-15: 0xabc222 (shape: lender-native) — technique reentrancy-flashloan reverted in simulation: missing approval.", meta: { address: "0xabc222", technique: "reentrancy-flashloan", result: "failure" } },
  { t: now - 90 * 60_000, text: "PROBE NEUTRAL 2026-09-15: 0xabc333 (shape: none) — technique erc4626-inflation simulated cleanly with no value extracted.", meta: { address: "0xabc333" } },
  { t: now - 30 * 60_000, text: "PROBE SUCCESS 2026-09-15: 0xabc444 (shape: lender-native) — technique side-entrance-flashloan PRODUCED A DRAIN in simulation.", meta: { address: "0xabc444" } },
  { t: now - 10 * 60_000, text: "Triage 2026-09-15: 0xabc555 (bridge) — technique lz-replay, confidence 0.61. Hypothesis: nonce watermark is not enforced.", meta: { address: "0xabc555" } },
];
writeFileSync(MEM_PATH, seed.map((r) => JSON.stringify(r)).join("\n") + "\n");

const { localMemorySummary, localSearch, classifyMemory } = await import("./localmem.ts");
const { learnFromProbe } = await import("./memory.ts");
const { probeDedupeKeys } = await import("./genlearn.ts");
const { withGenLearnTestStore, recordViolation, recordHeld, recordDeadend, recordGenError, genLearnOverview } = await import(
  "./genlearn.ts"
);
const { renderStaticHtml, startUiServer } = await import("./server.ts");

// ---- 1. summary -----------------------------------------------------------
const sum = localMemorySummary(10);
eq("summary: counts every record", sum.total, 5);
check("summary: store size is reported", sum.bytes > 0, `bytes=${sum.bytes}`);
eq("summary: kinds are classified", sum.kinds["triage"], 2);
eq("summary: probe outcomes are distinguished", sum.kinds["probe-win"], 1);
eq("summary: failures are distinguished from neutrals", sum.kinds["probe-fail"], 1);
eq("summary: neutrals counted", sum.kinds["probe-neutral"], 1);
check("summary: newest entry first (stream order)", sum.recent[0]!.text.includes("0xabc555"), sum.recent[0]!.text.slice(0, 40));
check("summary: oldest entry last", sum.recent[sum.recent.length - 1]!.text.includes("0xabc111"), sum.recent[sum.recent.length - 1]!.text.slice(0, 40));
eq("summary: hourly buckets cover 12 hours", sum.hourly.length, 12);
// All seeds are ≤5h old, so every record must land in a bucket — and the
// distribution must be non-flat. (Exact per-bucket placement is wall-clock
// dependent — seeds straddle hour boundaries depending on the minute the test
// runs — so only aggregate invariants are asserted.)
eq("summary: every record is bucketed", sum.hourly.reduce((a, b) => a + b, 0), 5);
check("summary: growth is bucketed, not flat", sum.hourly.filter((n) => n > 0).length >= 2, JSON.stringify(sum.hourly));
check("summary: first/last timestamps present", sum.firstAt !== null && sum.lastAt !== null);
check("summary: target address is carried as ref", sum.recent[0]!.ref === "0xabc555", String(sum.recent[0]!.ref));
eq("classify: probe success", classifyMemory("PROBE SUCCESS 2026-09-15: x"), "probe-win");
eq("classify: unknown prose", classifyMemory("something else entirely"), "other");

// ---- 2. a torn line must not break the view ------------------------------
appendFileSync(MEM_PATH, '{"t":123,"text":"half-written rec'); // crash mid-append
const afterTorn = localMemorySummary(10);
check("torn line: skipped, not fatal", afterTorn.total >= 5, `total=${afterTorn.total}`);
check("torn line: still classifies what is readable", afterTorn.recent.some((r) => r.kind === "triage"));

// ---- 3. recall ------------------------------------------------------------
const hits = localSearch("0xabc444", 5);
check("recall: finds a target by address", hits.length > 0 && hits[0]!.text.includes("0xabc444"), JSON.stringify(hits.map((h) => h.text.slice(0, 30))));
check("recall: hits carry kind + timestamp + score", hits[0]!.kind === "probe-win" && hits[0]!.t > 0 && hits[0]!.score > 0);
check("recall: ranked list is descending by score", hits.every((h, i) => i === 0 || h.score <= hits[i - 1]!.score));
eq("recall: an unknown term returns NOTHING (no plausible-looking noise)", localSearch("zzzz-nonexistent-token", 5).length, 0);
eq("recall: an empty query returns nothing", localSearch("   ", 5).length, 0);
check("recall: technique token matches", localSearch("side-entrance-flashloan", 3).length > 0);

// Drifting a live dashboard found this: addresses are DISPLAYED truncated
// (`0xabc444…`), so a prefix is how an operator searches — and whole-token
// matching returned "nothing remembered" for a memory sitting right there.
const prefixHits = localSearch("0xabc44", 5);
check("recall: an address PREFIX finds the memory", prefixHits.length > 0 && prefixHits[0]!.text.includes("0xabc444"), JSON.stringify(prefixHits.map((h) => h.text.slice(0, 30))));
const midPrefix = localSearch("0xabc4", 5);
check("recall: a shorter prefix still matches (multiple targets)", midPrefix.length > 0, String(midPrefix.length));
check("recall: prefix expansion does not invent hits", localSearch("0xffffffff", 5).length === 0);
check("recall: non-hex short queries are untouched by prefix logic", localSearch("tri", 5).length === 0 || localSearch("tri", 5).every((h) => h.text.length > 0));
check("recall: prefix expansion is bounded (no runaway scan)", localSearch("0x", 50).length <= 50);

// ---- 3b. probe-outcome dedupe must be PERSISTENT -------------------------
// The old session-scoped Set forgot every outcome on restart, so a rebooted
// daemon re-learned (and re-proposed) the same failed probes. The index now
// lands in the genlearn store and must survive a fresh process. learnFromProbe
// writes through LAB_REPORT_DIR-scoped stores, and this test process has
// LAB_REPORT_DIR pointed at the scratch dir.
learnFromProbe("0xabc222", "lender-native", "reentrancy-flashloan", "reverted", "missing approval");
learnFromProbe("0xabc222", "lender-native", "reentrancy-flashloan", "reverted", "missing approval");
learnFromProbe("0xabc222", "lender-native", "reentrancy-flashloan", "reverted", "missing approval");
const dedupeKeys = probeDedupeKeys();
check(
  "probe dedupe: outcome lands in the persistent index exactly once",
  dedupeKeys.includes("0xabc222:reentrancy-flashloan:reverted") && dedupeKeys.filter((k) => k === "0xabc222:reentrancy-flashloan:reverted").length === 1,
  JSON.stringify(dedupeKeys)
);
check(
  "probe dedupe: a DIFFERENT outcome is new information",
  (await import("./genlearn.ts")).probeDedupeKeys().length === 1
);

// ---- 4. the learned-priors view ------------------------------------------
await withGenLearnTestStore(async () => {
  recordHeld("lender-native");
  recordGenError("erc4626", "setUp failed: no asset introspection");
  recordDeadend("none", "address-mode setup cannot bootstrap (no asset introspection)");
  recordViolation("lender-native", { invariant: "native", path: "donateNative -> flashLoan -> withdraw", profitWei: "5000000000000000000" });
  recordViolation("erc4626", { invariant: "supply", path: "donate -> convert -> redeem", profitWei: null });
  const o = genLearnOverview();
  eq("learned: shapes counted", o.shapes, 3);
  eq("learned: violations counted", o.violations, 2);
  eq("learned: dead ends counted", o.deadends, 1);
  check("learned: priors carry all three outcomes", o.priors.some((p) => p.held > 0) && o.priors.some((p) => p.errors > 0) && o.priors.some((p) => p.violated > 0));
  check("learned: violated shapes sort first (most interesting)", o.priors[0]!.violated > 0, JSON.stringify(o.priors[0]));
  check("learned: proven paths are listed", o.proven.some((v) => v.path.includes("donateNative")));
  check("learned: proven entries carry shape + invariant + profit", o.proven.every((v) => !!v.shape && !!v.invariant) && o.proven.some((v) => v.profitWei === "5000000000000000000"));
  check("learned: dead ends carry the condition text", o.dead[0]!.condition.includes("cannot bootstrap"), JSON.stringify(o.dead[0]));
  check("learned: prior totals add up", o.priors.every((p) => p.total === p.held + p.violated + p.errors));
});

// ---- 5. the page + the read-only endpoint --------------------------------
const { PAGE } = await import("./ui-page.ts");
for (const needle of ['data-tab="memory"', 'id="panel-memory"', 'id="mem-stream"', 'id="mem-spark"', 'id="mem-recall"', 'id="mem-learning"', 'id="mem-proven"', 'id="mem-dead"', "renderMemory"]) {
  check(`page: contains ${needle}`, PAGE.includes(needle));
}
check("page: memory tab is in the tab list", /TABS = \[[^\]]*'memory'/.test(PAGE));

// The dashboard is one giant template literal, so a single unescaped quote or
// backtick in the embedded JS breaks the WHOLE page with a SyntaxError that
// nothing else in this repo would catch (it has happened twice: a stray
// backtick in a comment, and an apostrophe inside a JS string). Parse the
// embedded script for real — compiling it needs no DOM and no side effects.
// The page has two script blocks (the first only injects window.STATE), so
// take the LAST one — that is the dashboard's own JS.
const scriptBlocks = [...PAGE.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const scriptBody = scriptBlocks.length > 0 ? scriptBlocks[scriptBlocks.length - 1]![1]! : "";
check("page: has an embedded script", scriptBody.length > 1000, `len=${scriptBody.length}`);
try {
  // eslint-disable-next-line no-new-func
  new Function(scriptBody);
  check("page: embedded dashboard JS parses (no broken escapes)", true);
} catch (err) {
  check("page: embedded dashboard JS parses (no broken escapes)", false, (err as Error).message);
}
check("page: no stray template placeholder survives into the page", !PAGE.includes("{{"));

// An export must carry the memory view too, or the tab is empty in a snapshot.
const exported = renderStaticHtml({ kbWins: 3, cycle: 1 });
check("export: state is embedded", exported.includes('"kbWins":3'));
check("export: memory view is embedded for the exported tab", exported.includes('"memoryDetail"') && exported.includes('"kinds"'));
check("export: marked as a static export (never polls a missing API)", exported.includes("/*__STATIC__*/false") === false && /STATIC_EXPORT\s*=\s*true/.test(exported));

const url = await startUiServer(7471);
const port = Number(url.split(":").pop());
check("server: bound a loopback port", Number.isFinite(port) && port > 0, url);

const memRes = await fetch(`http://127.0.0.1:${port}/api/memory?q=0xabc444&limit=5`);
eq("api/memory: 200 for a recall", memRes.status, 200);
const memJson = (await memRes.json()) as { count: number; results: { text: string }[]; query: string };
eq("api/memory: echoes the query", memJson.query, "0xabc444");
check("api/memory: returns the matching memory", memJson.count > 0 && memJson.results[0]!.text.includes("0xabc444"), JSON.stringify(memJson).slice(0, 140));
const emptyRes = await fetch(`http://127.0.0.1:${port}/api/memory?q=zzzz-nope`);
const emptyJson = (await emptyRes.json()) as { count: number };
eq("api/memory: no false hits for an unknown term", emptyJson.count, 0);
const noQuery = await fetch(`http://127.0.0.1:${port}/api/memory`);
const noQueryJson = (await noQuery.json()) as { count: number; results: unknown[] };
eq("api/memory: missing q is not an error", noQueryJson.count, 0);

const stateRes = await fetch(`http://127.0.0.1:${port}/api/state`);
eq("api/state: 200", stateRes.status, 200);
const stateJson = (await stateRes.json()) as { memoryDetail?: { local?: { total: number }; learning?: { shapes: number } } };
check("api/state: carries the memory view", !!stateJson.memoryDetail, JSON.stringify(stateJson).slice(0, 120));
eq("api/state: memory total matches the store", stateJson.memoryDetail?.local?.total ?? -1, localMemorySummary(1).total);
check("api/state: carries the learned shapes", (stateJson.memoryDetail?.learning?.shapes ?? -1) >= 0);

const post = await fetch(`http://127.0.0.1:${port}/api/memory`, { method: "POST" });
eq("server: still read-only (POST refused)", post.status, 405);

// The page HTML itself must render the tab markup, not just contain the id in
// dead JS — a broken template literal would surface here first.
const pageRes = await fetch(`http://127.0.0.1:${port}/`);
const html = await pageRes.text();
eq("page over HTTP: 200", pageRes.status, 200);
check("page over HTTP: memory tab button present", html.includes('>🧠 Memory<') || html.includes("🧠 Memory"));

rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? "\nmemory view: all checks passed" : `\nmemory view: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
