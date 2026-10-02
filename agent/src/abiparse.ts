// Solidity source ABI extraction for the generic invariant engine.
// Regex-based (same doctrine as the rest of the agent: zero deps, honest
// best-effort). Output is a conservative superset of the contract's callable
// surface — good enough to drive fuzz primitives, never used for execution
// decisions on live targets (that stays with the compiled harness + fork).
//
// Limitations stated up front: tuple params with nested commas, function-type
// params, and inline assembly-heavy sources may parse imperfectly. The harness
// generator bounds every primitive and low-level-calls the target, so a
// imperfect parse degrades to "fewer primitives", never to a wrong verdict.

/** Strip comments and string literals so pattern matching sees code only. */
export function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/[^\n]*/g, " ")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
}

export interface Param {
  type: string; // normalized: no data-location, no trailing "payable"
  name: string;
}

export interface FnAbi {
  name: string;
  params: Param[];
  visibility: "external" | "public" | "internal" | "private";
  mutability: "payable" | "view" | "pure" | "nonpayable";
  /** Declared return values (types only; names dropped for interfaces). */
  returns: Param[];
  /** Function body (or modifier list) shows an authorization gate. */
  guarded: boolean;
}

export interface VarAbi {
  name: string;
  type: string;
  isMapping: boolean;
  /** For mappings: the declared key type ("address", "uint256", ...). */
  keyType?: string;
}

export interface ParsedAbi {
  functions: FnAbi[];
  publicVars: VarAbi[];
  constructorParams: Param[];
  hasReceive: boolean;
  hasFallback: boolean;
}

/** Split a parameter list on top-level commas (respects nested parens). */
function splitParams(list: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of list) {
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.filter((p) => p.trim().length > 0);
}

/** Normalize one parameter declaration "uint256 calldata amount" -> type+name. */
function parseParam(decl: string): Param {
  const words = decl.trim().split(/\s+/).filter(Boolean);
  // Drop data locations; last word is the name when there are >1 words and it
  // is an identifier (handles unnamed params "(uint256)").
  const locs = new Set(["memory", "calldata", "storage", "payable"]);
  const kept = words.filter((w) => !locs.has(w));
  let type = kept.join(" ");
  let name = "";
  if (kept.length >= 2 && /^[a-zA-Z_$][\w$]*$/.test(kept[kept.length - 1]!) && !isTypeWord(kept[kept.length - 1]!)) {
    name = kept.pop()!;
    type = kept.join(" ");
  }
  return { type: type.replace(/\s+/g, " ").trim(), name };
}

function isTypeWord(w: string): boolean {
  return /^(u?int\d*|address|bool|bytes\d*|bytes|string|mapping|function)$/.test(w);
}

/** Does this function body/modifier region carry an auth gate? */
function detectGuard(region: string): boolean {
  return /only[A-Z]|require\s*\(\s*(msg\.sender|_msgSender\(\))\s*==|hasRole\s*\(|_checkRole\s*\(|_authorizeUpgrade\s*\(|\bauth\b\s*\(|whenNotPaused|nonReentrant\b/.test(region);
}

/** Extract the balanced-brace body starting at `src[index] === "{"`. */
function extractBody(src: string, openBraceIdx: number): string {
  let depth = 0;
  for (let i = openBraceIdx; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) return src.slice(openBraceIdx + 1, i);
    }
  }
  return src.slice(openBraceIdx, openBraceIdx + 2000); // unbalanced — degraded but bounded
}

export function parseSolidityAbi(source: string): ParsedAbi {
  const code = stripComments(source);
  const functions: FnAbi[] = [];

  const fnRe = /function\s+([A-Za-z_$][\w$]*)\s*\(/g;
  for (const m of code.matchAll(fnRe)) {
    const name = m[1]!;
    const openParen = m.index! + m[0].length - 1;
    // Find the matching close paren of the parameter list.
    let depth = 0;
    let closeParen = -1;
    for (let i = openParen; i < code.length; i++) {
      if (code[i] === "(") depth++;
      else if (code[i] === ")") {
        depth--;
        if (depth === 0) {
          closeParen = i;
          break;
        }
      }
    }
    if (closeParen === -1) continue;

    const params = splitParams(code.slice(openParen + 1, closeParen)).map(parseParam);

    // Modifier/mutability region runs to the first { or ; at depth 0.
    let end = closeParen + 1;
    let d2 = 0;
    for (let i = closeParen + 1; i < code.length; i++) {
      if (code[i] === "(") d2++;
      else if (code[i] === ")") d2--;
      else if (d2 === 0 && (code[i] === "{" || code[i] === ";")) {
        end = i;
        break;
      }
    }
    const region = code.slice(closeParen + 1, end);
    if (code[end] === ";") continue; // declaration only (interface) — not callable here

    const vis = /\bexternal\b/.test(region)
      ? "external"
      : /\bpublic\b/.test(region)
        ? "public"
        : /\bprivate\b/.test(region)
          ? "private"
          : "internal";
    const mut = /\bpayable\b/.test(region)
      ? "payable"
      : /\bview\b/.test(region)
        ? "view"
        : /\bpure\b/.test(region)
          ? "pure"
          : "nonpayable";

    const body = code[end] === "{" ? extractBody(code, end) : region;
    // Declared returns (named or unnamed) — needed for interface codegen and
    // try-catch compatibility. Unnamed kept as {type, name:""}.
    const retMatch = region.match(/returns\s*\(([^)]*)\)/);
    const returns: Param[] = retMatch ? splitParams(retMatch[1]!).map(parseParam) : [];
    functions.push({ name, params, visibility: vis as FnAbi["visibility"], mutability: mut as FnAbi["mutability"], returns, guarded: detectGuard(region + " " + body) });
  }

  // Public state variables (these generate getters — usable in invariants).
  const publicVars: VarAbi[] = [];
  const varRe = /\b(mapping\s*\([^=>]*=>\s*[^;]*?\)|[\w\[\]$.]+)\s+(?:immutable\s+|constant\s+)*public\s+([A-Za-z_$][\w$]*)\s*(?:=|;)/g;
  for (const m of code.matchAll(varRe)) {
    const rawType = m[1]!.trim();
    const isMapping = rawType.startsWith("mapping");
    const key = isMapping ? (rawType.match(/mapping\s*\(\s*([^=>]+?)\s*=>/)?.[1]?.trim() ?? "address") : undefined;
    publicVars.push({ name: m[2]!, type: rawType.replace(/\s+/g, " "), isMapping, keyType: key });
  }

  // Constructor parameter list (asset hints for harness setup).
  const ctorParams: Param[] = [];
  const ctor = code.match(/constructor\s*\(([^)]*)\)/);
  if (ctor) ctorParams.push(...splitParams(ctor[1]!).map(parseParam));

  return {
    functions,
    publicVars,
    constructorParams: ctorParams,
    hasReceive: /\breceive\s*\(\s*\)\s*external\s+payable/.test(code),
    hasFallback: /\bfallback\s*\(\s*\)/.test(code),
  };
}

/** Canonical external signature "name(type1,type2)" (selector preimage). */
export function sigOf(fn: FnAbi): string {
  return `${fn.name}(${fn.params.map((p) => p.type).join(",")})`;
}

/** Callable entrypoints the fuzzer may drive (external/public, non-view). */
export function entrypoints(abi: ParsedAbi): FnAbi[] {
  return abi.functions.filter((f) => (f.visibility === "external" || f.visibility === "public") && f.mutability !== "view" && f.mutability !== "pure");
}

/** View getters usable inside invariants. */
export function views(abi: ParsedAbi): FnAbi[] {
  return abi.functions.filter((f) => (f.visibility === "external" || f.visibility === "public") && (f.mutability === "view" || f.mutability === "pure"));
}
