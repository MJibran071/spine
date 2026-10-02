// Skills-library integration: the repo's Skills/ tree (claude-red offensive
// security library, 78 SKILL.md files across 23 categories) becomes a
// retrieval source for the hunt. Triage prompts get the 2-3 most relevant
// methodologies injected as compact hints — free context, no LLM calls.
//
// Design constraints:
//   FAIL-SOFT — any error returns "" and the hunt proceeds without hints.
//   CHEAP     — frontmatter parsed once per process, in-memory keyword scoring.
//   HONEST    — hints are methodology (how to think about the bug class),
//               never presented as a detector signal or a verdict.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // agent/src -> agent -> repo root
const SKILLS_DIR = join(ROOT, "Skills");

interface SkillDoc {
  id: string;
  category: string;
  description: string;
  path: string;
}

let cache: { at: number; docs: SkillDoc[] } | null = null;
const TTL_MS = 10 * 60_000;

/** Parse one SKILL.md in either of the library's two shapes:
 *  1. YAML frontmatter (name: / description: "...")
 *  2. Checklist style: `# SKILL: <title>` + `## Description` section. */
function parseSkillDoc(text: string): { name: string; description: string } {
  const fm = /^---\n([\s\S]*?)\n---/.exec(text);
  if (fm) {
    const block = fm[1];
    const name = /(?:^|\n)name:\s*"?([^"\n]+)"?/.exec(block)?.[1]?.trim() ?? "";
    const quoted = /(?:^|\n)description:\s*"([\s\S]*)"/.exec(block)?.[1];
    const bare = /(?:^|\n)description:\s*([^\n]+)/.exec(block)?.[1];
    return { name, description: (quoted ?? bare ?? "").replace(/\s+/g, " ").trim() };
  }
  // Checklist shape: name from metadata line or title; description = the
  // section body after `## Description` up to the next heading.
  const title = /^#\s*SKILL:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? "";
  const metaName = /\*\*Skill Name\*\*:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? title;
  const descM = /^##\s+Description\s*$\n([\s\S]*?)(?=\n##\s|$(?!\n))/m.exec(text);
  const desc = (descM?.[1] ?? "").replace(/[#*`>]/g, "").replace(/\s+/g, " ").trim();
  return { name: metaName, description: desc };
}

function loadDocs(): SkillDoc[] {
  if (cache && Date.now() - cache.at < TTL_MS) return cache.docs;
  const docs: SkillDoc[] = [];
  try {
    if (!existsSync(SKILLS_DIR)) {
      cache = { at: Date.now(), docs };
      return docs;
    }
    for (const cat of listCategories()) {
      if (NOISE_CATEGORIES.has(cat)) continue;
      const catDir = join(SKILLS_DIR, cat);
      for (const skill of safeReaddir(catDir)) {
        const p = join(catDir, skill, "SKILL.md");
        if (!existsSync(p)) continue;
        const { name, description } = parseSkillDoc(readFileSync(p, "utf8"));
        if (!description) continue;
        docs.push({ id: name || skill, category: cat, description, path: p });
      }
    }
  } catch {
    // library missing/unreadable — hints simply stay empty
  }
  cache = { at: Date.now(), docs };
  return docs;
}

function listCategories(): string[] {
  try {
    return (readdirSyncRaw(SKILLS_DIR) ?? []).filter((d) => !d.startsWith("."));
  } catch {
    return [];
  }
}

// Node type-stripping friendly wrappers (import once, use sync APIs)
import { readdirSync } from "node:fs";
function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir).filter((d) => !d.startsWith("."));
  } catch {
    return [];
  }
}
function readdirSyncRaw(dir: string): string[] | null {
  try {
    return readdirSync(dir);
  } catch {
    return null;
  }
}

/** Vocabulary bridge: hunt-side concepts -> skill-library vocabulary.
 * Only cross-domain concepts that genuinely transfer — not generic words
 * ("replay", "oracle", "auth") that drag in IT-security noise like TLS or
 * phishing. */
const SYNONYMS: Record<string, string[]> = {
  reentrancy: ["race condition", "toctou", "time-of-check", "concurrency"],
  "erc4626-inflation": ["rounding", "numeric", "precision", "accounting"],
  "lz-oft-dust": ["rounding", "numeric", "integer overflow", "precision"],
  "flash-arbitrary-call": ["injection", "arbitrary execution", "callback", "deserialization"],
  "unauthorized-mint": ["access control", "authorization bypass", "privilege escalation"],
  // PortSwigger Academy bridge (2026-10): on-chain concepts -> the Academy's
  // web methodology. The new Skills/web entries carry the deep checklists;
  // these mappings make an on-chain triage context reach them.
  "signature-replay": ["jwt", "token tampering", "csrf", "forged request"],
  "access-control": ["broken access control", "idor", "privilege escalation"],
  "price-oracle": ["cache poisoning", "race condition", "manipulation"],
  "arbitrary-call": ["ssrf", "server-side request forgery", "open redirect"],
  "governance": ["access control", "authorization bypass", "csrf"],
  "bridge": ["request smuggling", "desync", "message validation"],
  "vault-share": ["prototype pollution", "accounting", "numeric"],
  "proxy-upgrade": ["deserialization", "object injection", "initialization"],
};

/** Categories that never help an on-chain hunt — excluded outright. */
const NOISE_CATEGORIES = new Set(["wireless", "mobile", "iot", "social-engineering", "network", "cloud", "container", "active-directory", "forensics", "cicd"]);

export interface SkillHintInput {
  shape?: string;
  selectors?: string[];
  detectorSignals?: string[];
  technique?: string;
  category?: string;
  max?: number;
}

/** Extract hunt-relevant keywords from a triage context. */
export function keywordsFor(input: SkillHintInput): string[] {
  const raw = [
    input.shape ?? "",
    ...(input.selectors ?? []),
    ...(input.detectorSignals ?? []),
    input.technique ?? "",
    input.category ?? "",
  ]
    .join(" ")
    .toLowerCase();
  const kws = new Set<string>();
  for (const w of raw.match(/([a-z][a-z-]{3,})/g) ?? []) kws.add(w);
  for (const [k, syns] of Object.entries(SYNONYMS)) {
    if (raw.includes(k)) for (const s of syns) kws.add(s);
  }
  // generic stop-words that would match every skill
  for (const stop of ["function", "external", "public", "address", "contract", "call", "balance", "view"]) kws.delete(stop);
  return [...kws];
}

const SENTENCE_SPLIT = /(?<=[.!?])\s+/;

/** Compact methodology hints for a triage prompt. "" when nothing matches
 * or the library is unavailable — callers must treat this as best-effort. */
export function skillHints(input: SkillHintInput): string {
  try {
    const docs = loadDocs();
    if (docs.length === 0) return "";
    const kws = keywordsFor(input);
    if (kws.length === 0) return "";
    const scored = docs
      .map((d) => {
        const text = `${d.id} ${d.category} ${d.description}`.toLowerCase();
        let score = 0;
        for (const k of kws) {
          if (text.includes(k)) score += k.includes(" ") ? 3 : 2;
        }
        return { d, score };
      })
      .filter((s) => s.score >= 4) // require at least 2 distinct hits or one phrase hit
      .sort((a, b) => b.score - a.score)
      .slice(0, input.max ?? 3);
    if (scored.length === 0) return "";
    const lines = scored.map(({ d }) => {
      // pull the description sentences that actually contain the keywords
      const sents = d.description.split(SENTENCE_SPLIT).filter((s) => {
        const low = s.toLowerCase();
        return kws.some((k) => low.includes(k));
      });
      const chosen = (sents.length ? sents : d.description.split(SENTENCE_SPLIT)).slice(0, 2).join(" ");
      return `- [${d.category}] ${d.id}: ${chosen.slice(0, 380)}`;
    });
    return `METHODOLOGY HINTS (from the skills library; background only, not detector output):\n${lines.join("\n")}`;
  } catch {
    return "";
  }
}

/** Number of indexed skills — for boot logging / health lines. */
export function skillCount(): number {
  return loadDocs().length;
}
