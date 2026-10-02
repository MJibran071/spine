// CURIOSITY ENGINE — the agent asks questions about live targets instead of
// only re-probing known shapes.
//
// The existing pipeline answers ONE implicit question per target ("does the
// known probe drain it?"). Real bug discovery is question-driven: a swap fee
// nobody ever collected, an unbond that pays from the balance the stake funds,
// an OFT adapter with a live inbound surface, an oracle nobody sanitizes. This
// module turns "I wonder…" into scheduled, budgeted, read-only experiments
// that run on the daemon's local fork every cycle.
//
// WHY SCORED CURIOSITY instead of random probing:
//   - Novelty  : the same question on the same target every cycle is spam;
//                ask-count decays the score over time.
//   - Wealth   : experiments on targets holding more value carry more upside.
//   - Success  : question classes with recorded PROBE SUCCESS wins stay hot
//                (fed from long-term memory, not hardcoded).
//   - Bounty   : live Immunefi-program targets double the value of an answer.
//   - Mutability: first-sighting targets ask first (fresh code answers more).
//
// SAFETY: every experiment is an eth_call / eth_getCode / eth_getBalance on
// the LOCAL FORK — RPC semantics are read-only (no state can persist), and
// fork.ts's loopback-only rails already apply. Money visibility is native ETH
// (the responder's WETH/USDC/USDT/DAI asset sweep is future work — honest
// scope, not faked). A question is asked at most once per ASK_COOLDOWN_MS per
// target; every answer (signal or nothing) lands in long-term memory so later
// triage recalls it, and a SIGNAL re-flags the target for the EXISTING
// probe+verify+bounty-draft pipeline instead of inventing a new action path.
import { join } from "node:path";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { REPORT_DIR } from "./config.ts";
import type { AnvilFork } from "./fork.ts";
import { toChecksumAddress } from "./fork.ts";
import { logEvent, upsertWatch, snapshot } from "./bus.ts";
import { memoryRecall, memoryRemember } from "./memory.ts";
import { derivedQuestions } from "./techniques.ts";

const CURIOSITY_PATH = join(REPORT_DIR, "curiosity.json");

// --------------------------------------------------------------- primitives

const HEX = (s: string) => s.replace(/^0x/i, "");

/** Runtime bytecode of the target at fork head ("" on failure). */
async function codeAt(fork: AnvilFork, address: string): Promise<string> {
  try {
    const c = await fork.rpc("eth_getCode", [address, "latest"]);
    return typeof c === "string" ? c : "";
  } catch {
    return "";
  }
}

/** Native balance of the target at fork head (0n on failure). */
async function nativeWei(fork: AnvilFork, address: string): Promise<bigint> {
  try {
    const b = await fork.rpc("eth_getBalance", [address, "latest"]);
    return BigInt(b as string);
  } catch {
    return 0n;
  }
}

/** Read-only eth_call at fork head — returns raw hex ("0x" on revert). */
async function callRead(fork: AnvilFork, address: string, data: string): Promise<string> {
  try {
    const r = await fork.rpc("eth_call", [{ to: address, data }, "latest"]);
    return typeof r === "string" ? r : "0x";
  } catch {
    return "0x";
  }
}

/** Does the runtime bytecode contain the selector (PUSH4 immediate)? */
function exposes(codeHex: string, selector: string): boolean {
  return codeHex.includes(HEX(selector).slice(0, 8));
}

// Curated selectors (question catalog is hand-built, not generated):
const SEL_GET_RESERVES = "0x0902f1ac"; // Uniswap V2 pair.getReserves()
const SEL_SLOT0 = "0x3850c7bd"; // Uniswap V3 pool.slot0()
const SEL_LZ_RECEIVE_V2 = "0x0c0c389e"; // EndpointV2.lzReceive (Kelp incident entry)
const SEL_OAPP_RECEIVE = "0x13137d65"; // OAppReceiver.lzReceive
const SEL_COLLECT = "0xbc64bb81";
// Unbond-family entry selectors (cast sig): withdraw() 0x3ccfd60b,
// withdraw(uint256) 0x2e1a7d4d, unbond(uint256) 0x27de9e32,
// unstake(uint256) 0x2e17de78, redeem(uint256) 0xdb006a75, exit(uint256) 0x7f8661a1
const UNBOND_SELECTORS = ["0x3ccfd60b", "0x2e1a7d4d", "0x27de9e32", "0x2e17de78", "0xdb006a75", "0x7f8661a1"]; // Uniswap V1 exchange.collect() — degrades honestly if never matched

// ---------------------------------------------------------------- questions

export interface ExperimentResult {
  /** Does the answer look interesting enough to count as a signal? */
  interesting: boolean;
  /** What the experiment saw (goes into memory + logs). */
  observation: string;
  /** Nonzero extracted delta (wei-ish) when the question found value motion. */
  delta: string;
}

export interface CuriosityQuestion {
  id: string;
  /** What we're wondering, in one sentence — shown in logs/memory. */
  wondering: string;
  /** Base score multiplier for the class. */
  weight: number;
  experiment: (fork: AnvilFork, address: string) => Promise<ExperimentResult>;
}

export const QUESTIONS: CuriosityQuestion[] = [
  {
    id: "q-collectable-fees",
    weight: 1.4,
    wondering: "Has value pooled in a fee faucet anyone can sweep?",
    experiment: async (fork, address) => {
      const c = await codeAt(fork, address);
      if (!exposes(c, SEL_COLLECT)) return { interesting: false, observation: "no collect() surface", delta: "0" };
      // eth_call simulates collect() WITHOUT committing: the return value is
      // exactly "what a sweep would pay out" — a pure question, no state change.
      const out = await callRead(fork, address, SEL_COLLECT);
      const words = HEX(out).match(/.{64}/g) ?? [];
      const vals = words.map((w) => BigInt("0x" + w));
      const max = vals.reduce((a, b) => (b > a ? b : a), 0n);
      if (max <= 1000n) return { interesting: false, observation: "collect() reads zero", delta: "0" };
      return {
        interesting: max > 10n ** 15n,
        observation: `collect() would sweep ${max} wei — value pooled in a fee faucet`,
        delta: max.toString(),
      };
    },
  },
  {
    id: "q-unsanitized-oracle",
    weight: 1.6,
    wondering: "Does the target read an AMM spot price it never sanitizes?",
    experiment: async (fork, address) => {
      const c = await codeAt(fork, address);
      const reserves = exposes(c, SEL_GET_RESERVES);
      const slot0 = exposes(c, SEL_SLOT0);
      if (!reserves && !slot0) return { interesting: false, observation: "no AMM spot-oracle reads in bytecode", delta: "0" };
      const w = await nativeWei(fork, address);
      return {
        interesting: w > 10n ** 15n,
        observation: `bytecode reads ${reserves ? "getReserves()" : "slot0()"} (manipulable spot price) while holding ${w} wei native`,
        delta: w > 10n ** 15n ? w.toString() : "0",
      };
    },
  },
  {
    id: "q-oft-live-adapter",
    weight: 1.5,
    wondering: "Is this a live OFT/bridge adapter whose credit path is reachable?",
    experiment: async (fork, address) => {
      const c = await codeAt(fork, address);
      const isLz = exposes(c, SEL_LZ_RECEIVE_V2) || exposes(c, SEL_OAPP_RECEIVE) || c.includes("oAppVersion");
      if (!isLz) return { interesting: false, observation: "no LayerZero inbound surface in bytecode", delta: "0" };
      const w = await nativeWei(fork, address);
      return {
        interesting: w > 10n ** 17n,
        observation: `LayerZero inbound surface (lzReceive family) present; adapter holds ${w} wei native — endpoint-core question class`,
        delta: w.toString(),
      };
    },
  },
  {
    id: "q-selfpaying-unbond",
    weight: 1.7,
    wondering: "Does unbonding pay FROM the same balance the stake funds?",
    experiment: async (fork, address) => {
      const c = await codeAt(fork, address);
      // Selector-level detection: ASCII names are keccak-hashed away in
      // runtime bytecode, so match the canonical 4-byte entries instead.
      const hits = UNBOND_SELECTORS.filter((s) => exposes(c, s));
      if (hits.length === 0) return { interesting: false, observation: "no unbond-family surface", delta: "0" };
      const w = await nativeWei(fork, address);
      const labels: Record<string, string> = {
        "0x3ccfd60b": "withdraw()",
        "0x2e1a7d4d": "withdraw(uint256)",
        "0x27de9e32": "unbond(uint256)",
        "0x2e17de78": "unstake(uint256)",
        "0xdb006a75": "redeem(uint256)",
        "0x7f8661a1": "exit(uint256)",
      };
      return {
        interesting: w > 5n * 10n ** 17n,
        observation: `unbond-family surface (${hits.map((s) => labels[s] ?? s).join(", ")}) over a ${w} wei native float — self-paying-unbond question class`,
        delta: w > 5n * 10n ** 17n ? w.toString() : "0",
      };
    },
  },
  {
    id: "q-approval-honeypot",
    weight: 1.2,
    wondering: "Is this target a router holding lifetime approvals worth stealing?",
    experiment: async (fork, address) => {
      const c = await codeAt(fork, address);
      if (c.length < 200) return { interesting: false, observation: "no meaningful runtime code", delta: "0" };
      const ROUTERS = [
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", // Uniswap Universal Router
        "0xdef1c0ded9bec7f1a1670819833240f027b25eff", // 0x Exchange Proxy
      ];
      const isRouter = ROUTERS.includes(address.toLowerCase());
      const w = await nativeWei(fork, address);
      return {
        interesting: isRouter && w > 10n ** 18n,
        observation: isRouter
          ? `major router (lifetime approvals) holding ${w} wei native`
          : "not a major approval router",
        delta: "0",
      };
    },
  },
];

// ------------------------------------------------ derived questions (self-learned)

/** Turn the fleet's proven drains into askable curiosity questions: for every
 * learned technique, the catalog gains "could what drained X work here?".
 * The experiment is an honest pre-screen, not a verdict: it flags targets
 * whose KNOWN shape shares keywords with the shape the technique was proven
 * on (or whose shape is unknown) AND that hold meaningful value — a SIGNAL
 * re-flags the target for the real probe pipeline, which owns verification.
 * The catalog therefore grows itself from experience instead of only from
 * hand-written entries. */
function derivedAsCuriosityQuestions(): CuriosityQuestion[] {
  return derivedQuestions().map((dq) => ({
    id: dq.id,
    weight: dq.weight,
    wondering: dq.wondering,
    experiment: async (fork: AnvilFork, address: string): Promise<ExperimentResult> => {
      const c = await codeAt(fork, address);
      if (c.length < 100) return { interesting: false, observation: "no runtime code", delta: "0" };
      const w = await nativeWei(fork, address);
      if (w <= 5n * 10n ** 17n) {
        return { interesting: false, observation: `target holds ${w} wei native — below the derived-question value bar`, delta: "0" };
      }
      // Shape similarity: keyword overlap between this target's known shape
      // and the shape the technique was proven on. Unknown shapes still pass
      // (they are exactly the ones worth re-flagging for investigation).
      const meta = snapshot().watchlist[address] ?? snapshot().watchlist[address.toLowerCase()];
      const shape = String(meta?.shape ?? "").toLowerCase();
      const words = (s: string) => new Set(s.split(/[^a-z0-9]+/).filter((t) => t.length > 4));
      const overlap = [...words(dq.shape ?? "")].filter((t) => words(shape).has(t));
      if (shape && !shape.includes("unknown") && overlap.length === 0) {
        return { interesting: false, observation: `shape "${shape.slice(0, 60)}" shares nothing with the proven shape`, delta: "0" };
      }
      return {
        interesting: true,
        observation: `technique class "${dq.technique}" (proven on ${dq.shape || "a past target"}) applies to a ${shape ? `"${shape.slice(0, 60)}"` : "shape-unknown"} target holding ${w} wei — re-flag for the probe pipeline`,
        delta: w.toString(),
      };
    },
  }));
}

// --------------------------------------------------------------- scheduling

interface AskRecord {
  when: number;
  count: number; // total asks of this question on this target (novelty decay)
  answer: string;
  delta: string;
  signal: boolean;
}

interface CuriosityStore {
  asked: Record<string, Record<string, AskRecord>>; // address -> question id -> last ask
  stats: { asked: number; signals: number; lastSignalAt: number };
}

function loadStore(): CuriosityStore {
  try {
    if (existsSync(CURIOSITY_PATH)) {
      const j = JSON.parse(readFileSync(CURIOSITY_PATH, "utf8")) as CuriosityStore;
      return { asked: j.asked ?? {}, stats: j.stats ?? { asked: 0, signals: 0, lastSignalAt: 0 } };
    }
  } catch {
    // corrupt store = fresh start
  }
  return { asked: {}, stats: { asked: 0, signals: 0, lastSignalAt: 0 } };
}

function saveStore(s: CuriosityStore): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(CURIOSITY_PATH, JSON.stringify(s, null, 2));
  } catch {
    // best-effort persistence
  }
}

/** Re-ask a question on the same target only after this long (~25 daemon cycles). */
const ASK_COOLDOWN_MS = 25 * 60_000;

/** Per-cycle ask budget — curiosity must never crowd out the probe pipeline. */
const ASKS_PER_CYCLE = 3;

// ------------------------------------------------------------------- scoring

/** Wealth in ETH, log-scaled so a whale contract doesn't fully dominate. */
function wealthScore(wei: bigint): number {
  const eth = Number(wei / 10n ** 15n) / 1000;
  return 1 + Math.max(0, Math.log10(1 + eth)) * 0.35;
}

async function scoreQuestion(inp: {
  q: CuriosityQuestion;
  wealth: bigint;
  bounty: boolean;
  askCount: number;
  memoryWins: number;
  freshCode: boolean;
}): Promise<number> {
  const { q, wealth, bounty, askCount, memoryWins, freshCode } = inp;
  const novelty = 1 / (1 + 0.7 * Math.log1p(askCount));
  const success = 1 + Math.min(memoryWins, 5) * 0.3;
  const mutability = freshCode ? 1.5 : 1;
  return q.weight * novelty * wealthScore(wealth) * success * mutability * (bounty ? 2 : 1);
}

// ----------------------------------------------------------------- the cycle

export interface CuriosityOutcome {
  asked: number;
  signals: number;
  notes: string[];
}

/** Run one curiosity cycle over candidate addresses on a live local fork.
 * Every experiment is read-only at fork head; signals re-flag targets for the
 * standard probe+verify pipeline (which owns verify + bounty drafting). */
export async function runCuriosityCycle(
  fork: AnvilFork,
  candidates: string[],
  opts: { budget?: number; bountySet?: Set<string> } = {}
): Promise<CuriosityOutcome> {
  const store = loadStore();
  const out: CuriosityOutcome = { asked: 0, signals: 0, notes: [] };
  const budget = Math.max(0, opts.budget ?? ASKS_PER_CYCLE);
  const bountySet = opts.bountySet ?? new Set<string>();
  if (budget === 0 || candidates.length === 0) return out;

  const snap = snapshot();
  const scored: Array<{ address: string; q: CuriosityQuestion; score: number }> = [];
  // The catalog = hand-written questions + questions the fleet LEARNED from
  // its own proven drains. Same scoring, same budget, same cooldowns.
  const catalog = [...QUESTIONS, ...derivedAsCuriosityQuestions()];

  for (const raw of candidates) {
    let address: string;
    try {
      address = toChecksumAddress(raw);
    } catch {
      continue;
    }
    const meta = snap.watchlist[address] ?? snap.watchlist[address.toLowerCase()];
    const [w, c] = await Promise.all([nativeWei(fork, address), codeAt(fork, address)]);
    if (c.length < 100) continue; // EOA / empty — nothing to wonder about
    let memoryWins = 0;
    try {
      const mems = await memoryRecall(`PROBE SUCCESS ${address}`, 3);
      memoryWins = mems.filter((m) => m.includes("PROBE SUCCESS")).length;
    } catch {
      memoryWins = 0;
    }
    const askedMap = store.asked[address] ?? {};
    for (const q of catalog) {
      const rec = askedMap[q.id];
      const cooled = !rec || Date.now() - rec.when > ASK_COOLDOWN_MS;
      if (!cooled) continue;
      const score = await scoreQuestion({
        q,
        wealth: w,
        bounty: bountySet.has(address.toLowerCase()) || meta?.bounty === true,
        askCount: rec?.count ?? 0,
        memoryWins,
        freshCode: !rec,
      });
      scored.push({ address, q, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);

  for (const { address, q } of scored.slice(0, budget)) {
    try {
      const res = await q.experiment(fork, address);
      const prev = store.asked[address]?.[q.id];
      const rec: AskRecord = {
        when: Date.now(),
        count: (prev?.count ?? 0) + 1,
        answer: res.observation.slice(0, 200),
        delta: res.delta,
        signal: res.interesting && res.delta !== "0",
      };
      store.asked[address] = store.asked[address] ?? {};
      store.asked[address]![q.id] = rec;
      store.stats.asked++;
      out.asked++;
      if (rec.signal) {
        store.stats.signals++;
        store.stats.lastSignalAt = Date.now();
        out.signals++;
      }
      out.notes.push(`${address.slice(0, 10)}… ${q.id}: ${rec.answer}${rec.signal ? " [SIGNAL]" : ""}`);
      // Every answer becomes retrievable memory — the agent remembers what it
      // wondered and what it saw, per question class and target.
      memoryRemember(
        `CURIOSITY ${rec.signal ? "SIGNAL" : "asked"} ${new Date().toISOString().slice(0, 10)}: ${q.id} on ${address} — ${rec.answer}`,
        { address, question: q.id, signal: rec.signal, delta: rec.delta }
      );
      if (rec.signal) {
        logEvent("scan", `CURIOSITY SIGNAL ${q.id} on ${address}: ${rec.answer}`);
        // Promote: re-flag for the standard probe pipeline next cycle (it owns
        // verify-on-fresh-forks + the bounty-draft machinery).
        upsertWatch({ address, lastResult: `curiosity signal: ${q.id} — ${rec.answer}`, finding: false });
      }
    } catch (e) {
      out.notes.push(`${address.slice(0, 10)}… ${q.id}: experiment error ${(e as Error).message.slice(0, 80)}`);
    }
  }

  saveStore(store);
  return out;
}

export function curiosityStats(): { asked: number; signals: number; lastSignalAt: number } {
  return loadStore().stats;
}
