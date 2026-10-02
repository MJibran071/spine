// Fills agent templates and writes generated test files.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { AGENT_TEST_DIR } from "./config.ts";
import type { Strategy } from "./strategies.ts";
import type { Challenge } from "./discovery.ts";

export interface Generated {
  contractName: string;
  filePath: string;
}

/**
 * Raised when a template cannot be rendered into a *compilable* harness for the
 * current target. Callers must SKIP the strategy and continue -- never write the
 * file, never treat it as a failed attempt.
 *
 * Why this is fatal rather than cosmetic: forge compiles the entire `test/`
 * tree in a single pass, so ONE uncompilable harness in `test/agent` makes every
 * other harness in the run report "failed to compile". That silently blanks out
 * the whole lab (and, via the live hunt's misattribution guard, can read as a
 * fleet-wide lockout) instead of a single skipped technique.
 */
export class TemplateUnsatisfiableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TemplateUnsatisfiableError";
  }
}

/** A real deployed-address literal. Templates that cast one to a contract type
 * need this; an offline challenge has no address, only a contract name. */
const ADDRESS_LITERAL = /^0x[0-9a-fA-F]{40}$/;

export function renderTemplate(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => {
    if (!(key in values)) {
      throw new TemplateUnsatisfiableError(`template placeholder not provided: ${key}`);
    }
    return values[key]!;
  });
}

/** Placeholders a template actually requires to be filled. */
export function templatePlaceholders(template: string): string[] {
  return [...new Set([...template.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]!))];
}

/**
 * Every identifier that appears in a declaration or import position anywhere in
 * the file. Deliberately permissive (a false "declared" only weakens the check
 * below, it never rejects a good harness).
 */
function declaredIdentifiers(src: string): Set<string> {
  const out = new Set<string>();
  const addWords = (s?: string): void => {
    for (const w of (s ?? "").split(/[^A-Za-z0-9_$]+/)) {
      if (/^[A-Za-z_$][\w$]*$/.test(w)) out.add(w);
    }
  };

  // type declarations: contract/interface/library/struct/enum/event/error
  for (const m of src.matchAll(/\b(?:abstract\s+)?(?:contract|interface|library|struct|enum|event|error)\s+([A-Za-z_$][\w$]*)/g)) {
    addWords(m[1]);
  }
  // imports: `import {A, B} from "..."` and bare `import "..."`
  for (const m of src.matchAll(/\bimport\b[^;]*/g)) addWords(m[0]);
  for (const m of src.matchAll(/\b(?:using|pragma)\b[^;]*/g)) addWords(m[0]);
  // function names
  for (const m of src.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)/g)) addWords(m[1]);
  // declaration-ish pairs: `Type name;` / `Type modifier name =` / `Type name)`
  for (const m of src.matchAll(/([A-Za-z_$][\w$]*)\s+(?:memory\s+|calldata\s+|storage\s+)?([A-Za-z_$][\w$]*)\s*[;=)]/g)) {
    addWords(m[1]);
    addWords(m[2]);
  }
  return out;
}

/**
 * Reject a rendered harness that cannot possibly compile.
 *
 * This is the class-level guard, not a check for one bad template: it catches a
 * `address(<Identifier>)` cast whose operand is declared nowhere in the file --
 * the exact shape produced when a template expecting a deployed pool address is
 * handed a contract *name* instead (e.g. `IUniswapV2Pair(address(PuppetPool))`).
 */
export function validateHarness(content: string, contractName = "harness"): void {
  const leftover = content.match(/\{\{\w+\}\}/);
  if (leftover) {
    throw new TemplateUnsatisfiableError(`${contractName}: unfilled placeholder ${leftover[0]}`);
  }

  const declared = declaredIdentifiers(content);
  const undeclared = new Set<string>();
  for (const m of content.matchAll(/\baddress\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    const id = m[1]!;
    if (id === "this" || declared.has(id)) continue;
    undeclared.add(id);
  }
  if (undeclared.size > 0) {
    const names = [...undeclared].join(", ");
    throw new TemplateUnsatisfiableError(
      `${contractName}: reference to undeclared identifier ${names} -- ` +
        `the template needs a real deployed address, not a contract name`
    );
  }
}

export function generateTest(
  challenge: Challenge,
  strategy: Strategy,
  params: Record<string, string>,
  variantIdx: number
): Generated {
  const templatePath = join(import.meta.dirname ?? ".", "..", "templates", `${strategy.template}.tmpl.sol`);
  const tpl = readFileSync(templatePath, "utf8");

  // Solidity identifiers cannot contain hyphens -- sanitize.
  const contractName =
    `Agent_${challenge.name}_${strategy.id}_v${variantIdx}`.replace(/[^A-Za-z0-9_]/g, "_");

  // A template that casts a deployed address to a contract type can only run
  // against a live/forked target. An offline challenge is a *name*, so there is
  // nothing truthful to inject here: refuse instead of writing a harness that
  // cannot compile. (Previously this injected `challenge.name`, which produced
  // `IUniswapV2Pair(address(PuppetPool))` -- an undeclared identifier that
  // poisoned every harness in the same forge run.)
  const required = templatePlaceholders(tpl);
  if (required.includes("POOL_ADDRESS")) {
    const supplied = params.POOL_ADDRESS?.trim();
    if (!supplied || !ADDRESS_LITERAL.test(supplied)) {
      throw new TemplateUnsatisfiableError(
        `template '${strategy.template}' needs a deployed pool address (POOL_ADDRESS); ` +
          `got ${supplied ? `'${supplied}'` : "no address"} for offline challenge ${challenge.name}`
      );
    }
  }

  const content = renderTemplate(tpl, {
    STRATEGY_ID: strategy.id,
    CHALLENGE_NAME: challenge.name,
    TEST_CONTRACT: contractName,
    // Build-time constant naming the challenge this harness was generated FOR.
    // Available to any template that wants to embed it; the misattribution
    // guard itself reads the harness on disk and requires a *semantic*
    // reference to the assigned challenge (import / `new X` / `X.` / `is X`),
    // so a self-contained harness that passes without touching its target is
    // rejected rather than banked as a discovery.
    ASSIGNED_CHALLENGE: challenge.name,
    ...params,
  });

  // Validate BEFORE writing: an invalid harness must never reach test/agent.
  validateHarness(content, contractName);

  mkdirSync(AGENT_TEST_DIR, { recursive: true });
  const filePath = join(AGENT_TEST_DIR, `${contractName}.t.sol`);
  writeFileSync(filePath, content);
  return { contractName, filePath };
}
