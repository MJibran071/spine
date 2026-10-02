// Attack-idea generator — the agent writes down HOW it would attack a target,
// even when no template probe applies.
//
// Why: triage answers "is there an executable probe class for this?" — a narrow
// question. A target that gets `none` still has structure an auditor would
// reason about (upgradeable admin plane, odd role setup, oracle dependency).
// Those ideas currently die inside the model's head. This module asks the LLM
// one extra question per target — "as an attacker, what would you try first,
// second, third?" — and PERSISTS the ranked answer to the dashboard.
//
// Hard rails (same doctrine as triage.ts):
//   - IDEAS ONLY. Nothing here executes. The only path to execution is the
//     existing local-fork probe pipeline; an idea with technique "none" is a
//     human-read note, never a queued probe.
//   - Defensive, read-only framing in the system prompt: exploit *concepts*
//     for a bug-bounty workflow, local simulation only, nothing broadcast.
//   - Output is strictly validated JSON; hallucinated fields dropped, sizes
//     capped, one idea per (target, ideaKey) — regeneration overwrites.
//   - Shares the triage key rotation / cooldown pool via askLlm, but has its
//     own small daily budget so ideas can never starve triage (default 40).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { askLlmShared, sliceSourceBySignals } from "./triage.ts";
import { ensureHypotheses } from "./ledger.ts";

const IDEAS_PATH = join(REPORT_DIR, "attack-ideas.json");
const IDEAS_BUDGET_PATH = join(REPORT_DIR, "attack-ideas-budget.json");
const DAILY_IDEAS_BUDGET = Number(process.env.LAB_IDEAS_DAILY_BUDGET ?? 40);
/** Cap per target: the model returns up to 3, we keep at most 3. */
const MAX_IDEAS_PER_TARGET = 3;
const MAX_IDEAS_STORED = 300;

/** Idea slug → deterministic, regex-validated hypothesis-technique tag. The
 * ledger joins hypotheses to probe renderers by tag ("erc4626", "mint",
 * "reentrancy"… all appear in the daemon's fallback-probe matcher), so a
 * seeded idea with a "vault"-ish slug is EXECUTABLE by the existing
 * hypothesis-fallback probe path — the idea stops being prose and becomes a
 * refuted-or-proven row. Unmapped slugs still seed: an untested hypothesis
 * is recorded evidence, and the matcher learns new tokens cheaply. */
const IDEA_SLUG_MAP: [RegExp, string][] = [
  [/share[- ]?price|share[- ]?inflation|4626|donation|virtual[- ]?(share|asset)|first[- ]?depositor/i, "erc4626-share-inflation"],
  [/reentra|side[- ]?entr|callback/i, "side-entrance-reentrancy"],
  [/arbitrary[- ]?call|exec(ute)?\s*\(|generic\s*call|delegatecall/i, "flash-arbitrary-call"],
  [/oracle|spot[- ]?price|price[- ]?manip|reserve[- ]?ratio/i, "oracle-spot-price"],
  [/unauthori[sz]ed[- ]?mint|mint\b/i, "unauthorized-mint"],
];

/** Exported for tests + the dashboard (idea rows carry the slug as their
 * ledger technique). */
export function ideaSlug(title: string, attackPath: string): string {
  const text = `${title} ${attackPath}`;
  for (const [re, tag] of IDEA_SLUG_MAP) if (re.test(text)) return tag;
  const words = (title.toLowerCase().match(/[a-z0-9]{3,}/g) ?? []).slice(0, 3).join("-");
  return `idea-${words || "uncategorized"}`;
}

export interface AttackIdea {
  ideaKey: string;
  chainId: string;
  address: string;
  name?: string;
  title: string;
  rank: 1 | 2 | 3;
  attackPath: string;   // the "how" — 1-3 sentences
  preconditions: string;
  whyHard: string;      // what makes it non-trivial / likely blocked
  confidence: number;   // model's self-assessed plausibility 0..1
  t: number;
}

interface IdeaStore {
  version: 1;
  ideas: Record<string, AttackIdea>; // ideaKey -> idea
}

interface BudgetStore { day: string; used: number }

function load(): IdeaStore {
  try {
    if (existsSync(IDEAS_PATH)) {
      const j = JSON.parse(readFileSync(IDEAS_PATH, "utf8")) as IdeaStore;
      if (j && j.ideas && typeof j.ideas === "object") return j;
    }
  } catch { /* corrupt → fresh */ }
  return { version: 1, ideas: {} };
}

function save(s: IdeaStore): void {
  mkdirSync(REPORT_DIR, { recursive: true });
  writeFileSync(IDEAS_PATH, JSON.stringify(s));
}

function spendIdeaBudget(): boolean {
  const day = new Date().toISOString().slice(0, 10);
  let b: BudgetStore = { day, used: 0 };
  try {
    if (existsSync(IDEAS_BUDGET_PATH)) {
      const j = JSON.parse(readFileSync(IDEAS_BUDGET_PATH, "utf8")) as BudgetStore;
      if (j && j.day === day) b = j;
    }
  } catch { /* fresh */ }
  if (b.used >= DAILY_IDEAS_BUDGET) return false;
  b.used += 1;
  writeFileSync(IDEAS_BUDGET_PATH, JSON.stringify(b));
  return true;
}

export function ideasBudgetLeft(): number {
  const day = new Date().toISOString().slice(0, 10);
  try {
    if (existsSync(IDEAS_BUDGET_PATH)) {
      const j = JSON.parse(readFileSync(IDEAS_BUDGET_PATH, "utf8")) as BudgetStore;
      if (j.day === day) return Math.max(0, DAILY_IDEAS_BUDGET - j.used);
    }
  } catch { /* fresh */ }
  return DAILY_IDEAS_BUDGET;
}

const SYSTEM_PROMPT = `You are a senior smart-contract security researcher supporting an AUTHORIZED bug-bounty hunting workflow. All testing is done on LOCAL read-only forks; nothing is ever broadcast.

For the contract given, produce your top attack IDEAS ranked by expected value — the plan a skilled attacker would try first, second, third. These are hypotheses for review and local simulation, not exploits to run.

Rules:
- Respond with JSON ONLY, no prose, no markdown fences:
{"ideas":[{"title":"...","attackPath":"...","preconditions":"...","whyHard":"...","confidence":0.0-1.0}]}
- 1 to 3 ideas, best first. If the contract genuinely looks sound, return ONE idea with the most plausible residual risk, or {"ideas":[]} if truly nothing.
- attackPath: the concrete sequence (who calls what, in what order, with what funds). Max 3 sentences.
- preconditions: what must be true (roles, liquidity, price state, upgrade schedule).
- whyHard: the honest obstacles — what likely blocks it (access control, oracle sanity checks, reentrancy guards).
- Base ideas on the GIVEN code only. Do not invent functions that are not visible.
- Plain AMM pairs are not vulnerabilities by themselves — say so via whyHard if relevant.`;

export interface IdeaInput {
  chainId: string;
  address: string;
  name?: string;
  shape: string;
  selectors: string[];
  detectorSignals: string[];
  verifiedSource: string | null;
  category?: string | null;
  /** Privilege intel from the toolbox — who holds the keys. Grounds the LLM's
   * ideas in reality: an EOA admin suggests key-compromise paths; a timelock
   * suggests upgrade paths are slow; no admin suggests immutability. */
  privilegeIntel?: string | null;
}

export interface IdeasOutcome {
  ideas: AttackIdea[];
  reason: "ok" | "no-key" | "budget" | "rate-limited" | "auth-error" | "http-error" | "timeout" | "unparseable" | "no-input";
  detail?: string;
}

/** Clamp + validate one model-returned idea. Returns null on garbage. */
function sanitizeIdea(raw: unknown, rank: number): AttackIdea | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const title = typeof r.title === "string" ? r.title.trim().slice(0, 120) : "";
  const attackPath = typeof r.attackPath === "string" ? r.attackPath.trim().slice(0, 600) : "";
  const preconditions = typeof r.preconditions === "string" ? r.preconditions.trim().slice(0, 300) : "";
  const whyHard = typeof r.whyHard === "string" ? r.whyHard.trim().slice(0, 300) : "";
  const confidence = typeof r.confidence === "number" && r.confidence >= 0 && r.confidence <= 1 ? r.confidence : 0.5;
  if (!title || !attackPath) return null;
  return { title, attackPath, preconditions, whyHard, confidence, rank: (Math.min(Math.max(rank, 1), 3) as 1 | 2 | 3) };
}

function ideaKeyFor(chainId: string, address: string, rank: number): string {
  return `${chainId}:${address.toLowerCase()}:${rank}`;
}

/** Generate + persist attack ideas for one target. One LLM call. */
export async function suggestAttackIdeas(input: IdeaInput): Promise<IdeasOutcome> {
  if (!input.verifiedSource || input.verifiedSource.length < 200) {
    return { ideas: [], reason: "no-input", detail: "no verified source — ideas need real code to reason about" };
  }
  if (!spendIdeaBudget()) {
    return { ideas: [], reason: "budget", detail: `daily ideas budget (${DAILY_IDEAS_BUDGET}) spent` };
  }

  const excerpt = sliceSourceBySignals(
    input.verifiedSource,
    input.detectorSignals,
    input.shape,
    9_000
  );
  const prompt = [
    `Chain: ${input.chainId}`,
    `Address: ${input.address}`,
    input.name ? `Name: ${input.name}` : "",
    `Shape: ${input.shape}`,
    input.category ? `Category: ${input.category}` : "",
    input.detectorSignals.length ? `Detector signals: ${input.detectorSignals.join(", ")}` : "",
    `Selectors: ${input.selectors.slice(0, 24).join(", ")}`,
    input.privilegeIntel ? `Privilege intel (from local-fork toolbox): ${input.privilegeIntel}` : "",
    "",
    "Verified source:",
    excerpt,
  ].filter(Boolean).join("\n");

  const res = await askLlmShared(prompt, SYSTEM_PROMPT);
  if (!res.ok) return { ideas: [], reason: res.reason, detail: res.detail };

  // Defensive parse: strip fences, find the outermost JSON object.
  const text = res.content.replace(/```(?:json)?/g, "").trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return { ideas: [], reason: "unparseable", detail: `no JSON in reply (${text.slice(0, 80)}…)` };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(start, end + 1));
  } catch {
    return { ideas: [], reason: "unparseable", detail: "reply was not valid JSON" };
  }
  // Tolerant shape extraction: some models return the array bare, or wrap it
  // one level down (ideas / attackIdeas / result). Take whichever is an array.
  const p = parsed as Record<string, unknown>;
  const rawIdeas = Array.isArray(parsed)
    ? (parsed as unknown[])
    : Array.isArray(p.ideas)
      ? p.ideas
      : Array.isArray(p.attackIdeas)
        ? p.attackIdeas
        : Array.isArray(p.result)
          ? p.result
          : null;
  if (!rawIdeas) {
    return { ideas: [], reason: "unparseable", detail: `no ideas[] in reply: ${res.content.slice(0, 120)}` };
  }

  const now = Date.now();
  const store = load();
  const kept: AttackIdea[] = [];
  rawIdeas.slice(0, MAX_IDEAS_PER_TARGET).forEach((raw, i) => {
    const idea = sanitizeIdea(raw, i + 1);
    if (!idea) return;
    const full: AttackIdea = {
      ...idea,
      ideaKey: ideaKeyFor(input.chainId, input.address, idea.rank),
      chainId: input.chainId,
      address: input.address,
      name: input.name,
      t: now,
    };
    store.ideas[full.ideaKey] = full; // overwrite same rank — regeneration replaces
    kept.push(full);
  });

  // IDEA → LEDGER: persist every idea as a NAMED, testable hypothesis row
  // (origin "idea"). This closes the idea→execution loop: the daemon's fork
  // watch already prioritizes targets with untested hypotheses and its
  // hypothesis-fallback probe executes the classes the slugs map to — an
  // idea becomes a simulated, refuted-or-proven row instead of prose on the
  // dashboard. Ledger failure must never break idea persistence.
  if (kept.length > 0) {
    try {
      const added = ensureHypotheses(
        input.chainId,
        input.address,
        kept.map((i) => ({ technique: ideaSlug(i.title, i.attackPath), origin: "idea" as const }))
      );
      if (added > 0) {
        // Fire-and-forget visibility: the operator sees ideas became work.
        try {
          const { logEvent } = await import("./bus.ts");
          logEvent("scan", `attack ideas: ${added} hypothesis row(s) seeded from ${kept.length} idea(s) for ${input.chainId}:${input.address.slice(0, 10)}…`);
        } catch { /* logging is cosmetic */ }
      }
    } catch { /* ledger is best-effort */ }
  }

  // Bounded store: drop oldest beyond the cap.
  const all = Object.values(store.ideas).sort((a, b) => b.t - a.t);
  if (all.length > MAX_IDEAS_STORED) {
    store.ideas = Object.fromEntries(all.slice(0, MAX_IDEAS_STORED).map((i) => [i.ideaKey, i]));
  }
  save(store);
  return { ideas: kept, reason: "ok" };
}

/** All ideas, newest target first, rank ascending within a target. */
export function allAttackIdeas(): AttackIdea[] {
  return Object.values(load().ideas).sort(
    (a, b) => b.t - a.t || a.rank - b.rank
  );
}

export function ideasFor(chainId: string, address: string): AttackIdea[] {
  const lower = address.toLowerCase();
  return allAttackIdeas().filter(
    (i) => i.chainId === chainId && i.address.toLowerCase() === lower
  );
}

export function ideasStats(): { total: number; targets: number; budgetLeft: number } {
  const all = Object.values(load().ideas);
  return {
    total: all.length,
    targets: new Set(all.map((i) => `${i.chainId}:${i.address.toLowerCase()}`)).size,
    budgetLeft: ideasBudgetLeft(),
  };
}
