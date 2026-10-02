// Regression test for the harness generator's compile guard.
//
// The live defect this pins: the spot-oracle strategy's `uniswap_pair` template
// casts a DEPLOYED POOL ADDRESS, but the generator injected `challenge.name`,
// emitting `IUniswapV2Pair(address(PuppetPool))` -- an undeclared identifier.
// Because forge compiles the whole test/ tree in one pass, that single file made
// EVERY generated harness in the run report "failed to compile" (123-129 lines
// per hunt log, labelled by the log itself as an agent bug), so the lab looked
// like it could not compile anything instead of failing one technique.
//
// What must hold now:
//   1. An address-hungry template is REFUSED for an offline challenge, and no
//      file is written at all (no harness in the tree => no compile lockout).
//   2. validateHarness rejects a rendered harness that references an identifier
//      declared nowhere -- a class-level guard, not a patch for one template.
//   3. Legitimate casts still pass (locals, `address(this)`), so the guard does
//      not reject working harnesses.
//   4. Every shipped template renders into compilable Solidity when given the
//      inputs it actually requires, so no template can reintroduce the poison.
//   5. A satisfiable template still generates and writes normally.
//
// Runs entirely against a scratch harness dir: the live test/agent tree the
// fleet is compiling is never touched.
import { mkdtempSync, readdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url)); // agent/src
const TPL_DIR = join(HERE, "..", "templates");
const SCRATCH = mkdtempSync(join(tmpdir(), "harness-guard-"));

// config.ts reads its dirs at module load, so retarget before importing it.
process.env.LAB_AGENT_TEST_DIR = SCRATCH;
process.env.LAB_REPORT_DIR = join(SCRATCH, "reports");
process.env.LAB_OFFLINE = "1";

const { generateTest, validateHarness, renderTemplate, templatePlaceholders, TemplateUnsatisfiableError } = await import(
  "./generator.ts"
);
type Challenge = import("./discovery.ts").Challenge;
type Strategy = import("./strategies.ts").Strategy;

let checks = 0;
function ok(msg: string): void {
  checks++;
  console.log(`ok: ${msg}`);
}
function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  rmSync(SCRATCH, { recursive: true, force: true });
  process.exit(1);
}

function makeChallenge(name: string): Challenge {
  return { name, testFile: "", sources: [], features: {} } as unknown as Challenge;
}
function makeStrategy(id: string, template: string, baseParams: Record<string, string[]> = {}): Strategy {
  return { id, technique: id, reason: "test", template, baseParams, matches: () => 0 };
}

const ADDR = `0x${"12ab34cd".repeat(5)}`; // 40 hex chars

/** Inputs a template needs, derived from its own placeholder names. */
function autoValue(key: string): string {
  if (key === "POOL_ADDRESS") return ADDR;
  if (key === "TEST_CONTRACT") return "Agent_Harness_Test_v0";
  if (key === "STRATEGY_ID") return "spot-oracle-manipulation";
  if (key === "CHALLENGE_NAME" || key === "ASSIGNED_CHALLENGE") return "PuppetPool";
  if (/COUNT|ITER/.test(key)) return "10";
  if (/AMOUNT|DUMP|STAKE|VALUE|GRIEF/.test(key)) return "1e18";
  return "1";
}

// ---- 1. the exact historical defect ----------------------------------------
// The old generator injected the challenge NAME as POOL_ADDRESS and wrote the
// result to test/agent, where it broke every other harness in the run.
const uniswap = makeStrategy("spot-oracle-manipulation", "uniswap_pair");
let refused = false;
let refusalMsg = "";
try {
  generateTest(makeChallenge("PuppetPool"), uniswap, {}, 0);
} catch (err) {
  refused = err instanceof TemplateUnsatisfiableError;
  refusalMsg = err instanceof Error ? err.message : String(err);
}
if (!refused) fail("address-hungry template for an offline challenge was NOT refused");
ok(`refused an address-only template for an offline challenge (${refusalMsg.slice(0, 64)}...)`);

if (!/POOL_ADDRESS/.test(refusalMsg)) {
  fail(`refusal should name the missing input; got: ${refusalMsg}`);
}
const poisonName = "Agent_PuppetPool_spot_oracle_manipulation_v0.t.sol";
if (existsSync(join(SCRATCH, poisonName))) {
  fail(`generator wrote ${poisonName} despite refusing it (would poison the whole compile)`);
}
if (readdirSync(SCRATCH).length !== 0) {
  fail(`refusal must write NOTHING; scratch dir holds: ${readdirSync(SCRATCH).join(", ")}`);
}
ok("no file written for the refused template (nothing to poison the test tree)");

// ---- 2. the class-level guard ----------------------------------------------
// Reproduce the exact broken output the old code produced and prove the guard
// catches it without knowing anything about the uniswap template.
const tplText = readFileSync(join(TPL_DIR, "uniswap_pair.tmpl.sol"), "utf8");
const brokenSource = renderTemplate(tplText, {
  POOL_ADDRESS: "PuppetPool",
  TEST_CONTRACT: "Agent_Broken_v0",
  STRATEGY_ID: "spot-oracle-manipulation",
  CHALLENGE_NAME: "PuppetPool",
});
let caughtUndeclared = "";
try {
  validateHarness(brokenSource, "Agent_Broken_v0");
} catch (err) {
  if (!(err instanceof TemplateUnsatisfiableError)) throw err;
  caughtUndeclared = err.message;
}
if (!/undeclared identifier/.test(caughtUndeclared) || !/PuppetPool/.test(caughtUndeclared)) {
  fail(`guard did not flag address(PuppetPool) as undeclared; got: ${caughtUndeclared || "(no throw)"}`);
}
ok("guard rejects a cast to an identifier declared nowhere in the file");

// Unfilled placeholders are refused too (a second way to ship broken Solidity).
let caughtUnfilled = false;
try {
  validateHarness("contract X { function f() public { uint a = {{MISSING}}; } }", "X");
} catch (err) {
  caughtUnfilled = err instanceof TemplateUnsatisfiableError;
}
if (!caughtUnfilled) fail("guard accepted a harness with an unfilled {{PLACEHOLDER}}");
ok("guard rejects unfilled template placeholders");

// A template missing a required input fails loudly rather than silently.
let caughtMissing = false;
try {
  renderTemplate(readFileSync(join(TPL_DIR, "side-entrance.tmpl.sol"), "utf8"), { TEST_CONTRACT: "X" });
} catch (err) {
  caughtMissing = err instanceof TemplateUnsatisfiableError;
}
if (!caughtMissing) fail("renderTemplate accepted a template with a missing placeholder value");
ok("renderTemplate fails loudly on a missing placeholder value");

// ---- 3. legitimate casts must still pass -----------------------------------
const legit = [
  "// SPDX-License-Identifier: MIT",
  "pragma solidity ^0.8.13;",
  'import {Test} from "forge-std/Test.sol";',
  'import {IERC20Lite} from "../../src/IERC20Lite.sol";',
  "interface IUniswapV2Pair { function token0() external view returns (address); }",
  "contract Agent_Legit_v0 is Test {",
  "    IUniswapV2Pair public target;",
  "    IERC20Lite public token;",
  "    function setUp() public {",
  `        target = IUniswapV2Pair(address(${ADDR}));`,
  "        token = IERC20Lite(address(target.token0()));",
  "        deal(address(token), address(this), 1e24);",
  "        token.approve(address(target), type(uint256).max);",
  "    }",
  "}",
].join("\n");
try {
  validateHarness(legit, "Agent_Legit_v0");
  ok("legitimate casts pass (address literal, local var, imported type, address(this))");
} catch (err) {
  fail(`guard rejected a valid harness (false positive): ${err instanceof Error ? err.message : String(err)}`);
}

// ---- 4. every shipped template renders compilably --------------------------
const templates = readdirSync(TPL_DIR).filter((f) => f.endsWith(".tmpl.sol"));
if (templates.length === 0) fail("no templates found -- test is not looking at the real dir");
for (const file of templates) {
  const text = readFileSync(join(TPL_DIR, file), "utf8");
  const values: Record<string, string> = {};
  for (const key of templatePlaceholders(text)) values[key] = autoValue(key);
  let content: string;
  try {
    content = renderTemplate(text, values);
  } catch (err) {
    fail(`${file}: could not render with its own placeholders: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    validateHarness(content, file);
  } catch (err) {
    fail(`${file}: would emit uncompilable Solidity -- ${err instanceof Error ? err.message : String(err)}`);
  }
}
ok(`all ${templates.length} templates render into compilable Solidity`);

// Every template that names a contract must use the generated contract name --
// a hardcoded `contract Harness_X` is invisible to the runner, which executes
// `Agent_<Challenge>_<strategy>_v<n>` and would report nothing at all.
for (const file of templates) {
  const text = readFileSync(join(TPL_DIR, file), "utf8");
  const decl = text.match(/^\s*contract\s+(\S+)/m);
  if (!decl) fail(`${file}: no contract declaration found`);
  if (decl[1] !== "{{TEST_CONTRACT}}") {
    fail(`${file}: hardcodes contract name '${decl[1]}' instead of {{TEST_CONTRACT}} -- runner can never match it`);
  }
}
ok("every template declares {{TEST_CONTRACT}} (runner-attributable)");

// ---- 5. a satisfiable template still generates and writes -------------------
// `truster` needs no params beyond the standard fills, so it proves the happy
// path (and the scratch-dir write) still works after adding the guard.
const gen = generateTest(makeChallenge("TrusterLenderPool"), makeStrategy("arbitrary-call", "truster"), {}, 0);
if (!existsSync(gen.filePath)) fail(`generator did not write ${gen.filePath}`);
if (dirname(gen.filePath) !== SCRATCH) fail(`generator wrote outside the scratch dir: ${gen.filePath}`);
const written = readFileSync(gen.filePath, "utf8");
if (!written.includes(`contract ${gen.contractName} is Test`)) {
  fail("generated harness does not declare the expected contract name");
}
validateHarness(written, gen.contractName);
ok(`satisfiable template still generates and writes (${gen.contractName})`);

// A challenge name that is not a valid Solidity identifier must not leak into
// the file as a bare identifier (the original defect's mechanism).
const weird = generateTest(makeChallenge("Weird-Name.sol"), makeStrategy("arbitrary-call", "truster"), {}, 0);
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(weird.contractName)) {
  fail(`contract name is not a valid Solidity identifier: ${weird.contractName}`);
}
ok("contract names are sanitized to valid Solidity identifiers");

rmSync(SCRATCH, { recursive: true, force: true });
console.log(`\nharness-guard: ${checks} checks passed`);
