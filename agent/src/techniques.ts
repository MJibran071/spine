// SELF-LEARNED TECHNIQUE LIBRARY — the agent learns hacking techniques on its
// own, from its own work, and reuses them.
//
// The lab already learns in several places: knowledge.ts stores a winning
// technique per challenge feature-signature, genlearn.ts keeps per-shape
// priors, memory.ts recalls probe outcomes into triage prompts. What was
// missing is a TECHNIQUE LIBRARY: a durable, retrievable list of "how to
// drain X" recipes written from evidence the fleet itself produced, that
// feeds back into future hunting everywhere.
//
// Two ways a technique is learned:
//   1. CAPTURE (always on, zero LLM calls): every proven drain — template
//      win, fuzz-synthesis path, generic-invariant violation, triage probe —
//      is recorded verbatim with its step path, shape and profit.
//   2. DISTILL (when LAB_LLM_KEY is set): captured observations on a shape
//      are handed to the LLM ONCE per (shape, observation) to be rewritten
//      as a generalized, transferable technique ("works on any lender whose
//      flashLoan callback forgets to credit the caller"). The model writes
//      the note; the FLEET's proven evidence wrote the lesson. Distilled
//      notes never outrank proven facts — proven techniques always win the
//      ranking, and a distill that would have generalized a drain still
//      leaves the original in place.
//
// Feeds back through three channels:
//   - topTechniques() / techniquesHint() -> LLM triage + attack-idea prompts
//   - derivedQuestions() -> the curiosity engine asks NEW questions it
//     learned from past drains (self-growing question catalog)
//   - dashboard memoryDetail -> the operator sees the library grow live
//
// All persistence is synchronous JSON under reports/ (same doctrine as
// knowledge.ts and genlearn.ts); every failure degrades to "no learning",
// never blocks a hunt.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

let LIB_PATH = join(REPORT_DIR, "techniques.json");

export interface LearnedTechnique {
  /** Stable id: the observation fingerprint (shape + technique + first path). */
  id: string;
  /** Where the knowledge came from. */
  origin: "template" | "synthesis" | "generic-invariant" | "triage-probe" | "distilled";
  /** Machine technique tag (strategy id / invariant / triage class). */
  technique: string;
  /** Contract shape this was proven against ("" when the shape is unknown). */
  shape: string;
  /** Human one-liner of the bug class. */
  observation: string;
  /** The concrete path that produced the drain ("a -> b -> c"). */
  path: string;
  /** Extracted profit in wei at proof time. */
  profitWei: string;
  /** The challenge or live target it was proven on (lab name or 0x…). */
  provenOn: string;
  /** LLM generalization (empty until distilled). */
  generalization: string;
  /** Prose reuse hint for triage prompts (empty until distilled). */
  reuse: string;
  /** How many times this exact technique has been re-proven. */
  wins: number;
  /** Other shapes the same technique class later drained (transfer evidence). */
  transferredTo: string[];
  first: number;
  last: number;
}

interface Library {
  version: 1;
  techniques: Record<string, LearnedTechnique>;
  /** Fingerprint of observations already sent to the LLM for distillation. */
  distilled: Record<string, number>; // fp -> epoch ms
}

let cache: Library | null = null;

function load(): Library {
  if (cache) return cache;
  try {
    if (existsSync(LIB_PATH)) {
      const j = JSON.parse(readFileSync(LIB_PATH, "utf8")) as Library;
      if (j && typeof j === "object" && j.techniques) {
        cache = { version: 1, techniques: j.techniques ?? {}, distilled: j.distilled ?? {} };
        return cache;
      }
    }
  } catch {
    // corrupt store = fresh start (same policy as knowledge.ts)
  }
  cache = { version: 1, techniques: {}, distilled: {} };
  return cache;
}

function save(): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(LIB_PATH, JSON.stringify(cache ?? { version: 1, techniques: {}, distilled: {} }, null, 2));
  } catch {
    // losing one learn beat is never worth crashing a hunt
  }
}

/** Test isolation: swap to a scratch store for the duration of cb. The PATH
 * swaps too — save() writes the live cache to LIB_PATH, so without this a
 * test capture would overwrite the fleet's real library (same trap
 * genlearn.ts guards with its own scratch path). */
export async function withTechniquesTestStore<T>(cb: () => Promise<T>): Promise<T> {
  const prev = cache;
  const prevPath = LIB_PATH;
  cache = { version: 1, techniques: {}, distilled: {} };
  LIB_PATH = join(REPORT_DIR, "techniques.test.json");
  try {
    return await cb();
  } finally {
    cache = prev;
    LIB_PATH = prevPath;
  }
}

// ---------------------------------------------------------------- capture

function cleanStepPath(path: string): string {
  return path
    .split("->")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.replace(/^fuzz_/, ""))
    .join(" -> ")
    .slice(0, 200);
}

function techniqueId(shape: string, technique: string, path: string): string {
  const raw = `${shape.toLowerCase().replace(/[^a-z0-9]+/g, "-")}|${technique.toLowerCase().replace(/[^a-z0-9:_-]+/g, "-")}|${path.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  // 64 chars keeps the id readable and unique enough for this store's size.
  return raw.slice(0, 96);
}

/** Capture a PROVEN drain (any pipeline) as a reusable technique. Returns
 * the technique id. Deduped: re-proving an identical (shape, technique,
 * path) bumps `wins` and refreshes `last` instead of adding noise. */
export function captureProvenDrain(input: {
  origin: LearnedTechnique["origin"];
  technique: string;
  shape?: string;
  observation?: string;
  path?: string;
  profitWei?: string | null;
  provenOn?: string;
}): string | null {
  const t = (input.technique ?? "").trim().slice(0, 90);
  if (!t) return null;
  const shape = (input.shape ?? "").trim().slice(0, 80);
  const path = cleanStepPath(input.path ?? "");
  const id = techniqueId(shape, t, path);
  const lib = load();
  const existing = lib.techniques[id];
  if (existing) {
    existing.wins += 1;
    existing.last = Date.now();
    if (input.profitWei && BigInt(input.profitWei) > BigInt(existing.profitWei || "0")) {
      existing.profitWei = input.profitWei.slice(0, 60);
    }
    if (input.provenOn && input.provenOn !== existing.provenOn && !existing.transferredTo.includes(input.provenOn)) {
      existing.transferredTo.push(input.provenOn.slice(0, 60));
      if (existing.transferredTo.length > 8) existing.transferredTo.shift();
    }
    save();
    return id;
  }
  lib.techniques[id] = {
    id,
    origin: input.origin,
    technique: t,
    shape,
    observation: (input.observation ?? "").slice(0, 300),
    path,
    profitWei: (input.profitWei ?? "0").slice(0, 60),
    provenOn: (input.provenOn ?? "").slice(0, 60),
    generalization: "",
    reuse: "",
    wins: 1,
    transferredTo: [],
    first: Date.now(),
    last: Date.now(),
  };
  // Bound the library: keep the 300 most valuable entries (see scoreOf).
  const all = Object.values(lib.techniques);
  if (all.length > 300) {
    all.sort((a, b) => scoreOf(b) - scoreOf(a));
    lib.techniques = Object.fromEntries(all.slice(0, 300).map((x) => [x.id, x]));
  }
  save();
  return id;
}

/** Importance score (also the eviction order): proven wins dominate, multi-shape
 * transfer and LLM distillation add value, recency matters a little. */
function scoreOf(t: LearnedTechnique): number {
  let s = t.wins * 2;
  if (t.reuse) s += 2;
  s += Math.min(4, t.transferredTo.length);
  s -= (Date.now() - t.last) / (30 * 24 * 3_600_000); // decay ~1/30d
  return s;
}

// ---------------------------------------------------------------- readers

export function allTechniques(): LearnedTechnique[] {
  return Object.values(load().techniques).sort((a, b) => scoreOf(b) - scoreOf(a));
}

/** Top techniques for a shape (or overall), proven first, then distilled.
 * Shape relevance is deliberately loose: lab captures use compact tags
 * ("lender-native") while live recon shapes are prose ("side-entrance-style
 * lender (flashLoan(uint256)+deposit+withdraw)"), so exact equality would
 * almost never fire on live targets. Scoring: exact match > token overlap >
 * shape-agnostic entries; ties break by proven value. */
export function topTechniques(shape: string | null, k = 5): LearnedTechnique[] {
  const all = allTechniques();
  if (!shape) return all.slice(0, k);
  const norm = (s: string) => new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 3));
  const want = norm(shape);
  const scored = all.map((t) => {
    let rel = 0;
    if (t.shape) {
      if (t.shape === shape) rel = 4;
      else {
        const overlap = [...norm(t.shape)].filter((w) => want.has(w)).length;
        rel = overlap > 0 ? 2 + Math.min(1.5, overlap * 0.5) : 0;
      }
    } else {
      rel = 0.5; // shape-agnostic knowledge still worth surfacing
    }
    // generalized notes lead within the same relevance band
    return { t, rank: rel * 10 + (t.reuse ? 1 : 0) };
  });
  return scored
    .filter((s) => s.rank > 0.5)
    .sort((a, b) => b.rank - a.rank || scoreOf(b.t) - scoreOf(a.t))
    .slice(0, k)
    .map((s) => s.t);
}

/** Compact prose block for LLM prompts: what the fleet PROVED works.
 * Empty string when the library is empty — never fabricate prior wins. */
export function techniquesHint(shape: string | null, k = 3): string {
  try {
    const tops = topTechniques(shape, k);
    if (tops.length === 0) return "";
    const lines = tops.map((t) => {
      const proof = [
        t.reuse || t.observation || t.technique,
        t.path ? `path: ${t.path}` : "",
        t.profitWei && t.profitWei !== "0" ? `profit ${t.profitWei} wei` : "",
        t.wins > 1 ? `proven ${t.wins}x` : "proven once",
        t.transferredTo.length > 0 ? `also drained: ${t.transferredTo.slice(0, 2).join(", ")}` : "",
      ].filter(Boolean);
      return `- ${proof.join(" · ")}`;
    });
    return `TECHNIQUES THE FLEET ITSELF PROVED (local simulations only — adapt parameters to this target, do not blindly reuse):
${lines.join("\n")}`;
  } catch {
    return "";
  }
}

export function techniquesStats(): { total: number; distilled: number; proven: number; shapes: number } {
  const lib = load();
  const all = Object.values(lib.techniques);
  return {
    total: all.length,
    distilled: all.filter((t) => t.reuse).length,
    proven: all.reduce((n, t) => n + t.wins, 0),
    shapes: new Set(all.map((t) => t.shape).filter(Boolean)).size,
  };
}

// ---------------------------------------------------------------- distill

const DISTILL_SYSTEM = `You convert PROVEN smart-contract exploit evidence into generalized, transferable hacking techniques for an authorized local-only bug-bounty hunt (read-only forks; nothing is ever broadcast).

Reply with ONLY JSON: {"generalization":"<the technique in one or two sentences, abstracted away from the specific target>","reuse":"<imperative one-liner: when to try this and what to check first>"}
- Generalize the PATTERN, not the instance ("a lender whose flashLoan callback credits deposits without checking msg.sender can be re-entered from the callback").
- reuse must be actionable for a future agent facing a DIFFERENT contract of the same class.
- Do not invent facts that are not in the evidence.`;

/** Distill one captured observation into a generalized technique (one LLM
 * call). Skips observations that are already distilled or too thin to
 * generalize. Best-effort: any failure just leaves the proven fact in place. */
export async function distillTechnique(t: LearnedTechnique): Promise<boolean> {
  const { askLlmShared } = await import("./triage.ts");
  const prompt = [
    `Proven exploit evidence (local simulation):`,
    `- technique tag: ${t.technique}`,
    t.shape ? `- contract shape: ${t.shape}` : "",
    `- observation: ${t.observation || t.technique}`,
    t.path ? `- attack path that produced the drain: ${t.path}` : "",
    t.profitWei && t.profitWei !== "0" ? `- profit: ${t.profitWei} wei` : "",
    `- proven on: ${t.provenOn}`,
    "",
    "Generalize this into a reusable technique.",
  ].filter(Boolean).join("\n");
  const res = await askLlmShared(prompt, DISTILL_SYSTEM);
  if (!res.ok) return false;
  const text = res.content.replace(/```(?:json)?/g, "").trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return false;
  let j: { generalization?: unknown; reuse?: unknown };
  try {
    j = JSON.parse(text.slice(start, end + 1));
  } catch {
    return false;
  }
  const g = typeof j.generalization === "string" ? j.generalization.trim().slice(0, 400) : "";
  const r = typeof j.reuse === "string" ? j.reuse.trim().slice(0, 300) : "";
  if (!g) return false;
  const lib = load();
  const cur = lib.techniques[t.id];
  if (!cur) return false;
  cur.generalization = g;
  cur.reuse = r || g.slice(0, 300);
  save();
  return true;
}

/** Distill every captured-but-not-yet-distilled observation, bounded per call
 * so a fleet flush never spends the whole daily LLM budget at once. */
export async function distillPending(max = 2): Promise<number> {
  const lib = load();
  const pending = Object.values(lib.techniques)
    .filter((t) => !t.reuse)
    .sort((a, b) => scoreOf(b) - scoreOf(a))
    .slice(0, max);
  let done = 0;
  for (const t of pending) {
    try {
      if (await distillTechnique(t)) done++;
    } catch {
      // one bad distill must not stop the batch
    }
  }
  return done;
}

// --------------------------------------------- self-growing question catalog

/** NEW curiosity questions DERIVED from the fleet's own proven drains: for
 * every learned technique, ask the same question about targets that have not
 * been tested for that technique class. This is the question catalog growing
 * itself from experience instead of only from hand-written entries.
 * Shape matching is deliberately loose (keyword containment) — live shapes
 * carry prose ("side-entrance-style lender (…)") that never matches exactly. */
export function derivedQuestions(): { id: string; wondering: string; weight: number; technique: string; shape: string }[] {
  const out: { id: string; wondering: string; weight: number; technique: string; shape: string }[] = [];
  const seen = new Set<string>();
  for (const t of allTechniques()) {
    const key = t.technique.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const what = t.reuse || t.generalization || t.observation || t.technique;
    out.push({
      id: `derived:${key}`,
      wondering: `Could what drained ${t.provenOn || "a past target"} work here? — ${what}`,
      weight: 1.3 + Math.min(0.7, t.wins * 0.2),
      technique: t.technique,
      shape: t.shape,
    });
  }
  return out;
}
