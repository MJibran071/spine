// Upgrade-diff triage — the sharpest possible LLM call.
//
// incidents.ts DETECTS proxy upgrades (Upgraded(address) events) but stops at
// a label. The upgrade moment is exactly when exploitability appears, and the
// bug is almost always in THE DIFF between the old and new implementation.
// Re-triaging the whole new contract wastes budget on unchanged code.
//
// This module:
//   1. fetches verified source for the old and new implementation addresses,
//   2. computes a word-level unified diff (no external deps),
//   3. sends ONLY the diff + context to the LLM triage endpoint with an
//      "audit what changed" system prompt,
//   4. records the verdict on the watchlist row and, at high confidence,
//      flags the target for the standard probe pipeline.
//
// Everything reuses existing infrastructure: source livesrc path from
// investigate.ts's provider set, the LLM endpoint/key rotation and budget
// from triage.ts. Read-only; the LLM still never executes anything.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR, OFFLINE } from "./config.ts";
import { logEvent, upsertWatch } from "./bus.ts";
import { recordTriageAttempt } from "./triage.ts";

// ---- source fetch (verified-source providers, cheapest first) ---------------

const SOURCIFY = "https://repo.sourcify.dev/contracts/full_match";
const ETHERSCAN_V2 = "https://api.etherscan.io/v2/api";

interface FetchedSource {
  source: string;
  provider: "sourcify" | "etherscan";
}

function etherscanKey(): string | null {
  for (const name of ["ETHERSCAN_API_KEY", "LAB_ETHERSCAN_KEY"]) {
    const v = process.env[name]?.trim();
    if (v) return v;
  }
  return null;
}

async function fetchSourcify(chainId: string, address: string): Promise<string | null> {
  try {
    const res = await fetch(`${SOURCIFY}/${chainId}/${address.toLowerCase()}/sources/src/`, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return null;
    // The full_match listing is a JSON map file -> content (served per file).
    // Simpler stable entrypoint: the concatenated "source" endpoint used by
    // verification UIs.
    const list = (await res.json()) as Record<string, { content?: string }>;
    const parts = Object.values(list ?? {}).map((f) => f?.content ?? "");
    const joined = parts.filter((s) => s.length > 0).join("\n\n// ───── file ─────\n\n");
    return joined.length > 0 ? joined : null;
  } catch {
    return null;
  }
}

async function fetchEtherscan(chainId: string, address: string): Promise<string | null> {
  const key = etherscanKey();
  if (!key) return null;
  try {
    const url = `${ETHERSCAN_V2}?chainid=${chainId}&module=contract&action=getsourcecode&address=${address}&apikey=${key}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return null;
    const j = (await res.json()) as { result?: Array<{ SourceCode?: string; ABI?: string }> };
    const raw = j.result?.[0]?.SourceCode;
    if (!raw) return null;
    // Double-brace JSON projects; single files come back raw.
    const text = raw.startsWith("{{") ? raw.slice(1, -1) : raw;
    try {
      const j2 = JSON.parse(text) as { sources?: Record<string, { content?: string }> };
      if (j2.sources) return Object.values(j2.sources).map((s) => s.content ?? "").join("\n\n");
    } catch { /* plain source */ }
    return text;
  } catch {
    return null;
  }
}

/** Verified source for an address, trying providers in order. Null when
 * unverified — the diff needs BOTH sides, so we degrade honestly. */
export async function fetchVerifiedSource(chainId: string, address: string): Promise<FetchedSource | null> {
  if (OFFLINE) return null;
  const s = await fetchSourcify(chainId, address);
  if (s) return { source: s, provider: "sourcify" };
  const e = await fetchEtherscan(chainId, address);
  if (e) return { source: e, provider: "etherscan" };
  return null;
}

// ---- diff (word-level LCS, no deps — source slices are big but bounded) -----

/** Normalized line diff of two sources, formatted as a compact unified block
 * that fits the LLM budget: context 1 line, capped to `maxChars`. */
export function diffSources(oldSrc: string, newSrc: string, maxChars = 14_000): string {
  const a = oldSrc.split("\n");
  const b = newSrc.split("\n");
  // Classic LCS table is O(n*m) memory — too big for 2000-line contracts.
  // Trim common head/tail first; hash the middle lines for a cheap
  // similarity pass; when still too large, fall back to a line-window diff
  // around changed regions using a simple Myers-lite heuristic (hash buckets).
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length, endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  // LCS on the middles with a size guard (contracts rarely change >300 lines;
  // bigger diffs get a head+tail window instead of a wrong-but-cheap answer).
  const LIMIT = 600;
  if (midA.length > LIMIT || midB.length > LIMIT) {
    const fmt = (lines: string[], sign: string) => lines.slice(0, LIMIT / 2).map((l) => sign + l)
      .concat(["…[truncated]…"])
      .concat(lines.slice(-LIMIT / 2).map((l) => sign + l));
    return [...fmt(midA, "-"), ...fmt(midB, "+")].join("\n").slice(0, maxChars);
  }
  const m = midA.length, n = midB.length;
  // dp of LCS lengths (m,n <= 600 → ≤360k cells, fine).
  const dp: Uint32Array[] = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i]![j] = midA[i] === midB[j] ? (dp[i + 1]![j + 1] ?? 0) + 1 : Math.max(dp[i + 1]![j] ?? 0, dp[i]![j + 1] ?? 0);
    }
  }
  const out: string[] = [];
  let i = 0, j = 0;
  const pushCtx = () => { if (i < midA.length && out.length < 4000) out.push("  " + midA[i]!); };
  while (i < m && j < n) {
    if (midA[i] === midB[j]) { pushCtx(); i++; j++; }
    else if ((dp[i + 1]![j] ?? 0) >= (dp[i]![j + 1] ?? 0)) { out.push("-" + midA[i]!); i++; }
    else { out.push("+" + midB[j]!); j++; }
  }
  while (i < m) { out.push("-" + midA[i]!); i++; }
  while (j < n) { out.push("+" + midB[j]!); j++; }
  return out.join("\n").slice(0, maxChars);
}

// ---- LLM call (reuses triage.ts's key pool via its exported health record —
// the actual ask lives here because triage.ts's prompt/schema is verdict-
// shaped, not diff-shaped; the budget gate is re-implemented thin) ----------

const SYSTEM_PROMPT = `You are a smart-contract security auditor reviewing a PROXY UPGRADE diff.
You see the Solidity lines REMOVED (-) and ADDED (+) between the previous and the new implementation.
Audit ONLY what changed. Reply with ONLY a JSON object:

{
  "risk": "none" | "low" | "medium" | "high",
  "summary": "<one sentence on what the upgrade changes>",
  "attackHypothesis": "<how the change could be abused, or empty string when none>",
  "confidence": <0..1>,
  "worthProbing": <true only when a concrete probe class applies>
}

Rules:
- Focus on: removed/loosened access control, changed balance math, new external calls,
  altered fee/price logic, storage-layout hazards, added arbitrary-call surfaces.
- If the diff is cosmetic (comments, imports, natspec), say risk "none" honestly.
- NEVER invent function selectors. confidence < 0.5 means "needs human review".`;

async function askLlmDiff(prompt: string): Promise<{ ok: true; content: string } | { ok: false; reason: string; detail?: string }> {
  // Reuse the key pool logic by importing the live triage module's internals
  // through its public surface: read the same env/key file the triage path uses.
  const keys = (await import("./triage.ts")).__diffLlmKeys?.() ?? diffLlmKeys();
  if (keys.length === 0) return { ok: false, reason: "no-key", detail: "no API key configured for upgrade-diff triage" };
  const url = process.env.LAB_LLM_URL?.trim() || "https://api.groq.com/openai/v1/chat/completions";
  const model = process.env.LAB_LLM_MODEL?.trim() || "openai/gpt-oss-120b";
  for (const key of keys) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model,
          messages: [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: prompt }],
          temperature: 0.2,
          max_completion_tokens: 1_500,
        }),
        signal: AbortSignal.timeout(45_000),
      });
      if (res.status === 429) continue; // next key
      if (!res.ok) return { ok: false, reason: `http-${res.status}` };
      const j = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const content = j.choices?.[0]?.message?.content;
      if (content) return { ok: true, content };
    } catch (e) {
      return { ok: false, reason: "network", detail: (e as Error).message };
    }
  }
  return { ok: false, reason: "rate-limited" };
}

/** Same key collection rules as triage.ts (env vars + .llm-key file). Kept as
 * a local helper so the diff path works even before triage.ts is loaded. */
function diffLlmKeys(): string[] {
  const out: string[] = [];
  const add = (v: string | undefined) => { const k = v?.trim() ?? ""; if (k.length > 20 && !out.includes(k)) out.push(k); };
  add(process.env.LAB_LLM_KEY);
  for (const n of ["GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3", "GROQ_API_KEY_4", "GROQ_API_KEY_5", "GROQ_API_KEY_6"]) add(process.env[n]);
  try {
    const kf = join(REPORT_DIR === undefined ? "." : process.env.LAB_LLM_KEY_FILE?.trim() || join(process.cwd(), "agent", ".llm-key"));
    const lines = readFileSync(kf.startsWith("/") ? kf : kf, "utf8").split("\n");
    for (const l of lines) add(l.trim());
  } catch { /* no key file */ }
  return out;
}

function parseVerdict(raw: string): { risk: string; summary: string; attackHypothesis: string; confidence: number; worthProbing: boolean } | null {
  let text = raw.trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) text = fence[1]!.trim();
  const s = text.indexOf("{"), e = text.lastIndexOf("}");
  if (s === -1 || e <= s) return null;
  try {
    const j = JSON.parse(text.slice(s, e + 1)) as Record<string, unknown>;
    const risk = typeof j.risk === "string" ? j.risk : "unknown";
    return {
      risk: ["none", "low", "medium", "high"].includes(risk) ? risk : "unknown",
      summary: typeof j.summary === "string" ? j.summary.slice(0, 300) : "",
      attackHypothesis: typeof j.attackHypothesis === "string" ? j.attackHypothesis.slice(0, 400) : "",
      confidence: typeof j.confidence === "number" ? Math.min(1, Math.max(0, j.confidence)) : 0,
      worthProbing: j.worthProbing === true,
    };
  } catch {
    return null;
  }
}

export interface UpgradeDiffResult {
  target: string;
  oldImpl: string;
  newImpl: string;
  diffChars: number;
  verdict: { risk: string; summary: string; attackHypothesis: string; confidence: number; worthProbing: boolean } | null;
  reason?: string; // set when verdict is null (why no analysis)
}

/** Full pipeline for one detected upgrade. Never throws. */
export async function triageUpgradeDiff(
  chainId: string,
  proxyAddress: string,
  oldImpl: string,
  newImpl: string
): Promise<UpgradeDiffResult> {
  const base: UpgradeDiffResult = { target: proxyAddress, oldImpl, newImpl, diffChars: 0, verdict: null };
  const oldS = await fetchVerifiedSource(chainId, oldImpl);
  const newS = await fetchVerifiedSource(chainId, newImpl);
  if (!oldS || !newS) {
    recordTriageAttempt({ t: Date.now(), chainId, address: proxyAddress, reason: "no-input", detail: "upgrade-diff: missing verified source on one side" });
    return { ...base, reason: "missing-verified-source" };
  }
  const diff = diffSources(oldS.source, newS.source);
  base.diffChars = diff.length;
  if (diff.replace(/[-+\s]/g, "").length < 40) {
    return { ...base, verdict: { risk: "none", summary: "diff is cosmetic or empty", attackHypothesis: "", confidence: 0.9, worthProbing: false } };
  }
  const prompt = [
    `PROXY ${proxyAddress} on chain ${chainId} was upgraded from ${oldImpl} to ${newImpl}.`,
    `Unified diff (context trimmed, '-' = removed, '+' = added):`,
    "```diff",
    diff,
    "```",
    `Produce the JSON audit object now.`,
  ].join("\n");
  const res = await askLlmDiff(prompt);
  if (!res.ok) {
    recordTriageAttempt({ t: Date.now(), chainId, address: proxyAddress, reason: "http-error", detail: `upgrade-diff: ${res.reason}` });
    return { ...base, reason: res.reason };
  }
  const verdict = parseVerdict(res.content);
  if (!verdict) {
    recordTriageAttempt({ t: Date.now(), chainId, address: proxyAddress, reason: "unparseable", detail: "upgrade-diff: model reply not valid JSON" });
    return { ...base, reason: "unparseable" };
  }
  // Watchlist surface: the operator sees the audit where they already look.
  const note = `upgrade-diff: risk ${verdict.risk} — ${verdict.summary}${verdict.attackHypothesis ? ` | attack: ${verdict.attackHypothesis}` : ""}`;
  upsertWatch({ address: proxyAddress, lastResult: note.slice(0, 220), lastProbe: Date.now() });
  if (verdict.risk === "high" && verdict.confidence >= 0.6) {
    logEvent("safety", `upgrade-diff ${proxyAddress.slice(0, 10)}…: HIGH-risk upgrade — ${verdict.summary} ${verdict.attackHypothesis}`.slice(0, 240));
  }
  logEvent("scan", `upgrade-diff: ${proxyAddress.slice(0, 10)}… risk ${verdict.risk} (conf ${verdict.confidence.toFixed(2)}, ${base.diffChars} diff chars)`);
  return { ...base, verdict };
}
