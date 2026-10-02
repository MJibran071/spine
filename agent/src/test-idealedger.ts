// Hermetic test for the IDEA → LEDGER WIRING.
//
// The problem this pins down: attack ideas died as prose on the dashboard.
// suggestAttackIdeas persisted ranked, LLM-reasoned attack paths to
// attack-ideas.json — and nothing ever scheduled, executed, or refuted them.
// The hypothesis-ledger machinery already existed (ensureHypotheses, the
// untested-first scheduler, the hypothesis-fallback probe) but ideas never
// fed it.
//
// What must hold now:
//   1. every persisted idea seeds a hypothesis row (origin "idea");
//   2. share-math/reentrancy/oracle/mint ideas map to EXECUTABLE technique
//      tags — the daemon's fallback-probe matcher renders those classes;
//   3. rows enter as "untested", so the daemon's ledger-aware scheduler
//      prioritizes the target on its next cycle;
//   4. re-suggested ideas MIGRATE their row (refined slug) instead of
//      piling up duplicate open rows;
//   5. ledgerStats exposes the idea funnel (total/refuted/actionable).
//
// Fresh LAB_REPORT_DIR per run: the live hunt's ledger is never touched.
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCRATCH = mkdtempSync(join(tmpdir(), "lab-idealedger-"));
process.env.LAB_REPORT_DIR = SCRATCH;
process.env.LAB_OFFLINE = "1";
process.env.LAB_LLM_KEY_FILE = join(SCRATCH, "no-such-key-file");

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

const { ensureHypotheses, markHypothesis, ledgerStats, nextHypothesis, allHypotheses } = await import("./ledger.ts");
const { ideaSlug } = await import("./attackideas.ts");

// ---- 1. slug mapping: prose ideas → executable technique tags --------------
eq("slug: share-inflation prose → erc4626 tag", ideaSlug("Share price inflation via donation", "donate assets to skew convertToShares"), "erc4626-share-inflation");
eq("slug: first-depositor phrasing → erc4626 tag", ideaSlug("First depositor share-price attack", "seed supply with 1 wei"), "erc4626-share-inflation");
eq("slug: reentrancy prose → side-entrance tag", ideaSlug("Reentrancy in the withdraw path", "re-enter via the ERC-777 hook"), "side-entrance-reentrancy");
eq("slug: oracle prose → oracle tag", ideaSlug("Spot price manipulation", "flash-loan dump on the AMM pair"), "oracle-spot-price");
eq("slug: mint prose → mint tag", ideaSlug("Unauthorized mint", "call mint without access control"), "unauthorized-mint");
eq("slug: arbitrary-call prose → its tag", ideaSlug("Generic call sink", "execute arbitrary calldata from pool context"), "flash-arbitrary-call");
check("slug: unmapped prose falls back to a deterministic idea-* tag", /^idea-[a-z0-9-]+$/.test(ideaSlug("Zombie consensus drift", "vote twice")), ideaSlug("Zombie consensus drift", "vote twice"));

// ---- 2. seeding: ideas become untested ledger rows -------------------------
const CH = "8453";
const ADDR = "0xbeef010f9cb27031ad51e3333f9af9c6b1228183";
const added = ensureHypotheses(CH, ADDR, [
  { technique: ideaSlug("Share price inflation via donation", "donate to skew shares"), origin: "idea" },
]);
eq("seed: one idea row added", added, 1);
const h = nextHypothesis(CH, ADDR);
check("seed: the idea row enters as UNTESTED (scheduler will prioritize it)", h !== null && h.status === "untested", JSON.stringify(h));
eq("seed: origin is 'idea'", h?.origin, "idea");
eq("seed: the slug maps to an executable class", h?.technique, "erc4626-share-inflation");

// ---- 3. the loop closes: refuted-or-proven bookkeeping on the idea row -----
check("loop: the row is markable (probe path records refuted/held/actionable)", markHypothesis(CH, ADDR, "erc4626-share-inflation", "refuted", "probe ran clean: no violation observed"));
eq("loop: status flipped to refuted", allHypotheses().find((x) => x.key === `${CH}:${ADDR}:erc4626-share-inflation`)?.status, "refuted");

// ---- 4. migration: re-suggested ideas replace stale open rows, never pile up
const added2 = ensureHypotheses(CH, "0x7bfa7c4f149e7415b73bdedfe609237e29cbf34a", [
  { technique: "idea-rough-first-guess", origin: "idea" },
]);
eq("migrate: first suggestion seeds", added2, 1);
const added3 = ensureHypotheses(CH, "0x7bfa7c4f149e7415b73bdedfe609237e29cbf34a", [
  { technique: "erc4626-share-inflation", origin: "idea" },
]);
eq("migrate: refined suggestion adds one row", added3, 1);
const open = allHypotheses().filter((x) => x.address === "0x7bfa7c4f149e7415b73bdedfe609237e29cbf34a" && x.status === "untested");
eq("migrate: exactly ONE open idea row remains (old slug replaced)", open.length, 1);
eq("migrate: the surviving row is the refined slug", open[0]?.technique, "erc4626-share-inflation");
// Tested (refuted) idea rows are EVIDENCE — they must never be auto-deleted
// by a regeneration pass.
check("migrate: a refuted idea row survives regeneration", allHypotheses().some((x) => x.address === ADDR && x.status === "refuted" && x.origin === "idea"));

// ---- 5. funnel: ledgerStats exposes the idea conversion --------------------
const st = ledgerStats();
check("funnel: ideas block present with the same statuses as hypotheses", !!st.ideas && typeof st.ideas.total === "number" && st.ideas.refuted >= 1, JSON.stringify(st.ideas));
eq("funnel: total idea rows counted", st.ideas.total, 2);

check("scratch: report dir was isolated", !existsSync(join(SCRATCH, "..", "..", "Desktop")), SCRATCH);
rmSync(SCRATCH, { recursive: true, force: true });
console.log(failures === 0 ? "\nidea → ledger: all checks passed" : `\nidea → ledger: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
