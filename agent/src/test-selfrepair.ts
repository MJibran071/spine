// Self-repair loop tests: quarantine agent-generated compile offenders,
// retry once, never touch repo-owned files, record failure classes.
// Run: node --experimental-strip-types src/test-selfrepair.ts
//
// NOTE: scratch dirs are set via env BEFORE dynamic imports — ESM hoists
// static imports, so config.ts would capture the real env too early.
process.env.LAB_REPORT_DIR = "/tmp/selfrepair-test-reports";
process.env.LAB_AGENT_TEST_DIR = "/tmp/selfrepair-test-reports/test/agent";

const { mkdirSync, writeFileSync, existsSync, readdirSync, rmSync } = await import("node:fs");
const {
  isAgentGenerated,
  firstErrorLocation,
  compileFailureClass,
  quarantineFile,
  repairFromCompileOutput,
  forgeWithSelfRepair,
  repairLedger,
} = await import("./selfrepair.ts");
const { topCompileClasses } = await import("./genlearn.ts");

let pass = 0;
let fail = 0;
function check(name, cond, extra = ""): void {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name} ${extra}`);
  }
}

// fresh scratch dirs
rmSync("/tmp/selfrepair-test-reports", { recursive: true, force: true });
mkdirSync("/tmp/selfrepair-test-reports/test/agent", { recursive: true });
mkdirSync("/tmp/selfrepair-test-reports/gen", { recursive: true });

const GEN_FILE = "/tmp/selfrepair-test-reports/test/agent/GenFork_0xdead_v0.t.sol";
const GEN2_FILE = "/tmp/selfrepair-test-reports/gen/Other_v1.t.sol";

// Out-of-root agent dirs (the scratch layout here) make solc print ABSOLUTE
// paths; in-root dirs print LAB_ROOT-relative — both must quarantine.
const COMPILE_OUTPUT = `Error:
Compiler run failed
Error (2314): Expected ')' but got '>'
  --> ${GEN_FILE}:42:25
`;

console.log("== classification ==");
const loc = firstErrorLocation(COMPILE_OUTPUT);
check("parses error location", loc?.path === GEN_FILE && loc?.line === 42, JSON.stringify(loc));
check("failure class extracted", compileFailureClass(COMPILE_OUTPUT) === "solc2314(Expected ')' but got '>')", compileFailureClass(COMPILE_OUTPUT));
check("no-location output -> null", firstErrorLocation("Error: something vague") === null);
check("class for output without error code", compileFailureClass("Compiler run failed\nError:") === "solc-unknown-parse");

console.log("== agent-generated boundary ==");
check("test/agent file is agent-generated", isAgentGenerated(GEN_FILE));
check("reports/gen file is agent-generated", isAgentGenerated(GEN2_FILE));
check("repo-owned src file is NOT", !isAgentGenerated("src/challenges/SideEntranceLenderPool.sol"));
check("lib file is NOT", !isAgentGenerated("lib/forge-std/src/Test.sol"));
check("script dir is NOT", !isAgentGenerated("script/Deploy.s.sol"));

console.log("== quarantine ==");
writeFileSync(GEN_FILE, "pragma solidity ^0.8.0; // broken agent artifact");
const q1 = quarantineFile(GEN_FILE, "test");
check("quarantine moves the file", q1 === true && !existsSync(GEN_FILE));
const qdir = "/tmp/selfrepair-test-reports/quarantine";
check("file landed in quarantine dir", existsSync(qdir) && readdirSync(qdir).length === 1);
const q2 = quarantineFile(GEN_FILE, "again");
check("missing file -> false", q2 === false);
const q3 = quarantineFile("package.json", "must-fail");
check("repo-owned file REFUSED", q3 === false && existsSync("package.json"));

console.log("== repairFromCompileOutput ==");
writeFileSync(GEN_FILE, "pragma solidity ^0.8.0; // broken agent artifact 2");
const r1 = repairFromCompileOutput(COMPILE_OUTPUT);
check("quarantines agent offender", r1.repaired === true && !existsSync(GEN_FILE), JSON.stringify(r1));
const r2 = repairFromCompileOutput(COMPILE_OUTPUT.replace("test/agent/GenFork_0xdead_v0.t.sol", "src/other/File.sol"));
check("repo-owned error -> no repair", r2.repaired === false && r2.detail.includes("repo-owned"), JSON.stringify(r2));
const r3 = repairFromCompileOutput("Error: no location at all");
check("no location -> no repair", r3.repaired === false);

console.log("== forgeWithSelfRepair (retry flow) ==");
// Scenario A: first run fails with agent-generated offender -> quarantined -> retry passes.
writeFileSync(GEN_FILE, "pragma solidity ^0.8.0; // broken agent artifact 3");
let runs = 0;
const a = await forgeWithSelfRepair(async () => {
  runs++;
  return runs === 1
    ? { code: 1, output: COMPILE_OUTPUT }
    : { code: 0, output: "Ran 1 test: ok" };
}, "scenario-a");
check("retry passes after quarantine", a.code === 0 && a.repaired === true && runs === 2, JSON.stringify({ code: a.code, repaired: a.repaired, runs }));

// Scenario B: failure with no location -> no retry, returned as-is.
runs = 0;
const b = await forgeWithSelfRepair(async () => {
  runs++;
  return { code: 1, output: "Error: vague failure without location" };
}, "scenario-b");
check("no-location failure returns without retry", b.code === 1 && b.repaired === false && runs === 1, JSON.stringify({ runs }));

// Scenario C: multi-file poisoning -> second quarantine attempt -> third run passes.
writeFileSync(GEN_FILE, "pragma solidity ^0.8.0; // broken agent artifact 4");
const OUT2 = `Error:
Compiler run failed
Error (2314): Expected ')' but got '>'
  --> ${GEN2_FILE}:7:1
`;
writeFileSync(GEN2_FILE, "pragma solidity ^0.8.0; // broken 2");
runs = 0;
const c = await forgeWithSelfRepair(async () => {
  runs++;
  if (runs === 1) return { code: 1, output: COMPILE_OUTPUT };
  if (runs === 2) return { code: 1, output: OUT2 };
  return { code: 0, output: "ok" };
}, "scenario-c");
check("multi-offender repair drains both", c.code === 0 && runs === 3 && !existsSync(GEN2_FILE), JSON.stringify({ runs }));

// Scenario D: success path is untouched (single run).
runs = 0;
const d = await forgeWithSelfRepair(async () => {
  runs++;
  return { code: 0, output: "clean" };
}, "scenario-d");
check("clean run not wrapped/retried", d.code === 0 && d.repaired === false && runs === 1);

console.log("== ledger + class recording ==");
const ledger = repairLedger(50);
check("ledger recorded repairs", ledger.some((l) => l.includes("quarantine")));
const classes = topCompileClasses(5);
check("genlearn recorded solc2314 class", classes.some((x) => x.failureClass.startsWith("solc2314")), JSON.stringify(classes));

console.log(`\nself-repair: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
