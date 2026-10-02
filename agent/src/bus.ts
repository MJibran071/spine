// Tiny event bus + state store backing the live dashboard.
// All agent modes publish here; the UI server serves snapshots.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { notifyFinding } from "./notify.ts";
import { DAEMON_COUNT } from "./config.ts";

export interface BusEvent {
  t: number; // epoch ms
  kind: string; // lab | fork | daemon | finding | safety | scan
  msg: string;
  data?: unknown;
}

export interface ChallengeState {
  name: string;
  status: "pending" | "solved" | "failed" | "no-strategy";
  technique?: string;
  attempts?: number;
  note?: string;
}

export interface WatchState {
  address: string;
  shape?: string;
  lastProbe?: number;
  lastResult?: string;
  finding?: boolean;
  /** Block number (decimal, as string) at which the target was first seen —
   * the freshness dimension. Targets first seen within the last few days are
   * the highest base-rate bug candidates and jump the probe queue. */
  firstSeenBlock?: string;
  /** Set when the target is genuinely new (first seen < FRESH_BLOCKS). */
  fresh?: boolean;
  /** Set by the scanner when a live target is worth continuous re-probing
   * (recognized probeable class, e.g. an ERC-4626 vault). The daemon's fork
   * watch picks these up automatically each cycle. */
  enlisted?: boolean;
  /** True when the entry came from OSINT watchlist auto-seeding (INTEL.md
   * candidates). Used to cap how many seeds are probed at once. */
  seeded?: boolean;
  /** Protocol name + DefiLlama category captured at seed time — survives
   * lastResult overwrites so triage enrichment and bounty lookups keep
   * working across probe cycles. */
  name?: string;
  category?: string;
  /** Live Immunefi bounty descriptor, e.g. "max $15,000,000" — detected
   * during investigation (or OSINT annotation) and shown in the UI. */
  bounty?: string;
}

export interface GenResult {
  shape: string; // detected shape, or "none"
  result: "discovered" | "held" | "error" | "skipped";
  invariant?: string; // violated universal property (when discovered)
  note?: string;
  t: number;
}

export interface GenEngineState {
  results: Record<string, GenResult>;
  harnessable: number;
  discoveries: number;
}

/** One running daemon instance. Written by the daemon each cycle; the UI
 * drops entries whose heartbeat has gone stale, so killed daemons age out
 * instead of lingering as ghosts. */
export interface DaemonInfo {
  id: string; // --daemon-id (default "default")
  pid: number;
  host: string;
  startedAt: number;
  lastBeat: number;
  cycle: number;
  mode: string;
  /** Dashboard port this instance owns, or null when started without --ui. */
  uiPort: number | null;
  intervalSec: number;
  mainnetOnly: boolean;
  watchlistSize: number;
  /** This instance's chain shard (rotating scan slice), e.g. "ethereum,bsc". */
  chains?: string;
}

// Cycles can legitimately run long (fork spawns, osint, governance scans),
// so the TTL must clear the worst cycle, not the average one.
const DAEMON_HEARTBEAT_TTL_MS = 5 * 60_000;

interface State {
  mode: string;
  startedAt: number;
  cycle: number;
  challenges: Record<string, ChallengeState>;
  watchlist: Record<string, WatchState>;
  findings: BusEvent[];
  events: BusEvent[];
  kbWins: number;
  daemonCount: number;
  genEngine: GenEngineState;
  /** Live daemon instances (multi-daemon hunt), pruned by heartbeat TTL. */
  daemons: Record<string, DaemonInfo>;
}

const MAX_EVENTS = 400;

const g = globalThis as unknown as { __labBus?: State };
function state(): State {
  if (!g.__labBus) {
    g.__labBus = {
      mode: "idle",
      startedAt: Date.now(),
      cycle: 0,
      daemonCount: DAEMON_COUNT,
      challenges: {},
      watchlist: {},
      findings: [],
      events: [],
      kbWins: 0,
      genEngine: { results: {}, harnessable: 0, discoveries: 0 },
      daemons: {},
    };
  }
  return g.__labBus;
}

export function setMode(mode: string): void {
  state().mode = mode;
  logEvent("daemon", `mode: ${mode}`);
}

export function setCycle(n: number): void {
  state().cycle = n;
}

/** This process's own registry entry as registered at startup. daemonHeartbeat
 * used to update only an EXISTING entry — but snapshot()'s 5-minute prune
 * deletes the entry from this process's own in-memory map the moment a cycle
 * runs long (lab builds regularly exceed 5 min), and after that the heartbeat
 * silently no-oped forever: the daemon hunted on, visible nowhere. Remembering
 * the registration lets the heartbeat resurrect the entry — the fixed-interval
 * beat in daemon.ts exists precisely so long cycles cannot read as death. */
const selfRegistrations = new Map<string, Omit<DaemonInfo, "lastBeat">>();

/** Mark this process as a live daemon instance (call once at startup). */
export function registerDaemon(info: Omit<DaemonInfo, "lastBeat">): void {
  selfRegistrations.set(info.id, { ...info });
  const d = state().daemons[info.id] ?? { ...info, lastBeat: Date.now() };
  state().daemons[info.id] = { ...d, ...info, lastBeat: Date.now() };
  persistSnapshot();
}

/** Per-cycle heartbeat so the UI can age out dead instances. UPSERTS: a
 * mid-cycle prune must never turn into a permanent disappearance (see
 * selfRegistrations above). */
export function daemonHeartbeat(id: string, cycle: number): void {
  const s = state();
  const d = s.daemons[id];
  if (d) {
    d.lastBeat = Date.now();
    d.cycle = cycle;
    d.watchlistSize = Object.keys(s.watchlist).length;
    // Persist the beat (throttled): the monitor and sibling dashboards only
    // see DISK, so a long quiet phase (lab build, no logEvents) must not read
    // as death there. logEvent-driven persists cover busy phases; this covers
    // silent ones.
    const now = Date.now();
    if (now - _lastBeatPersist > 20_000) {
      _lastBeatPersist = now;
      persistSnapshot();
    }
    return;
  }
  const self = selfRegistrations.get(id);
  if (self) {
    s.daemons[id] = {
      ...self,
      lastBeat: Date.now(),
      cycle,
      watchlistSize: Object.keys(s.watchlist).length,
    };
    _lastBeatPersist = Date.now();
    persistSnapshot(); // resurrect on disk too, not just in this process's view
  }
}
let _lastBeatPersist = 0;

/** Drop daemon entries whose heartbeat is older than the TTL (called from
 * snapshot() so every consumer — UI, digest, state.json — sees the same view). */
function pruneStaleDaemons(): void {
  const s = state();
  const now = Date.now();
  for (const [id, d] of Object.entries(s.daemons)) {
    if (now - d.lastBeat > DAEMON_HEARTBEAT_TTL_MS) delete s.daemons[id];
  }
}

export function upsertChallenge(c: ChallengeState): void {
  state().challenges[c.name] = c;
}

export function upsertWatch(w: WatchState): void {
  // Chokepoint: dev fixtures never enter the watchlist, flagged or not.
  if (DEV_FIXTURE_ADDRESSES.has((w.address ?? "").toLowerCase())) {
    if (w.finding) logEvent("safety", `upsertWatch: ignored finding-flag on dev fixture ${w.address} — local chains cannot produce findings`);
    return;
  }
  // Chokepoint: a truncated display label is not an identity. It cannot be
  // resolved on a fork, so it can never be probed — accepting it would add a
  // permanent dead row, double the watchlist, and split one target's evidence
  // across two entries (which is exactly how ~730 phantom rows accumulated).
  if (isPhantomWatchKey(w.address)) {
    logEvent("safety", `upsertWatch: refused display-truncated watch key "${w.address}" — use the full address (callers: pass a resolvable key)`);
    return;
  }
  state().watchlist[w.address] = { ...state().watchlist[w.address], ...w };
}

/** True for watch keys that are human-readable elisions rather than addresses
 * (`ethereum:0x7d2768dE…`, `0x1234…abcd`). Probes, fork lookups, incident
 * sweeps and the responder all need a full address, so such a key is dead
 * weight the moment it is written. ELISION_MARKS covers the ASCII three-dot
 * form and U+2026, the character the agent's own shorten() helpers emit. */
const ELISION_MARKS = ["\u2026", "..."];
export function isPhantomWatchKey(key: unknown): boolean {
  if (typeof key !== "string" || key.length === 0) return true;
  return ELISION_MARKS.some((m) => key.includes(m));
}

/** The watchlist key an observation about a target belongs to. Callers that
 * already own a canonical row pass their own key (so one target keeps ONE row
 * and its triage summary merges with its probe result); the fallback is the
 * `chain:lowercased-address` form the scanner uses. A display label
 * (`ethereum:0x7d2768dE…`) must never reach this: it cannot be resolved on a
 * fork, so it can never be probed — see isPhantomWatchKey. */
export function watchKeyOf(chainName: string, address: string, override?: string): string {
  return override?.trim() || `${chainName}:${address.toLowerCase()}`;
}

/** Drop already-persisted phantom rows (and any whose address field is one).
 * Idempotent; returns how many were removed so callers can report it. */
export function prunePhantomWatchKeys(): number {
  const s = state();
  let removed = 0;
  for (const [key, entry] of Object.entries(s.watchlist)) {
    if (isPhantomWatchKey(key) || isPhantomWatchKey(entry?.address)) {
      delete s.watchlist[key];
      removed++;
    }
  }
  return removed;
}

export function setKbWins(n: number): void {
  state().kbWins = n;
  logEvent("daemon", `knowledge base: ${n} win(s) on record`);
}

export function logEvent(kind: "lab" | "fork" | "daemon" | "finding" | "safety" | "scan" | "gov", msg: string, data?: unknown): void {
  const s = state();
  const ev: BusEvent = { t: Date.now(), kind, msg, data };
  s.events.push(ev);
  if (s.events.length > MAX_EVENTS) s.events.splice(0, s.events.length - MAX_EVENTS);
  if (kind === "finding") {
    // Hygiene FIRST, then push: the scrub retires findings on hand-resolved
    // targets at hydrate/persist-merge time — but this push happens on the
    // LIVE path, and a resolved-target drop raised mid-run rendered on the
    // board forever until the next daemon restart (verified live: the
    // syrupUSDC card on 2026-09-28, target already in RESOLVED_FINDING_TARGETS).
    // The alert still fires — the operator just doesn't get a permanent card
    // for a class already adjudicated.
    if (!isResolvedFinding(msg)) {
      s.findings.push(ev);
      if (s.findings.length > 50) s.findings.splice(0, s.findings.length - 50);
    }
    // Real finding: alert the user immediately (desktop + optional webhook).
    // Fire-and-forget, fully isolated — notification problems must never be
    // able to disturb the hunt.
    void notifyFinding("Exploit-lab finding", msg).catch(() => {});
  }
  persistSnapshot();
}

/** Best-effort persistence so `npm run ui` can show the last session.
 * Fully guarded: persistence must never be able to kill the hunt.
 *
 * MULTI-DAEMON SAFE: with N daemons sharing one state.json, a naive
 * write of this process's in-memory copy would erase whatever the others
 * persisted since our last read (it already deleted OSINT seeds once).
 * Instead: read what's on disk NOW and merge before writing —
 *   daemons   : union, fresher heartbeat wins (existing rule)
 *   watchlist : union; per-entry FIELD merge (booleans sticky, max lastProbe,
 *               prefer whichever side actually has name/bounty data)
 *   events    : union by (t,kind,msg), keep the most recent tail from either
 *   scalars   : keep ours (mode/cycle/kbWins are per-process facts) */
/** Force a write of the current in-memory state to reports/state.json.
 * Used by tooling paths (the heal entry point) that mutate state outside the
 * ordinary upsert/log flow and need the change on disk immediately. */
export function persistSnapshot(): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    const path = join(REPORT_DIR, "state.json");
    const disk = mergeableDiskState(path);
    const payload = JSON.stringify(disk ? mergeIntoOurs(disk) : snapshot(), null, 2);
    // Atomic swap: a concurrent reader must never see a half-written file
    // (rename is atomic on POSIX). Tmp name is pid-unique so two daemons
    // persisting at the same instant don't fight over one tmp file.
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, payload);
    renameSync(tmp, path);
  } catch {
    // ignore
  }
}

/** Read the on-disk state (null when absent/corrupt). Skips the prune that
 * snapshot() does — we only need the raw persisted shape. */
function mergeableDiskState(path: string): State | null {
  try {
    const j = JSON.parse(readFileSync(path, "utf8")) as State;
    return j && typeof j === "object" ? j : null;
  } catch {
    return null;
  }
}

/** Merge freshly-read disk state under our in-memory state. Only fields where
 * another process can be strictly ahead are merged; everything else stays
 * ours. Never mutates the in-memory state. */
function mergeIntoOurs(disk: State): State {
  const s = snapshot();
  // Daemons: union, fresher heartbeat wins — but ONLY live rows. Without the
  // TTL gate a dead row on disk resurrects itself forever: every daemon's
  // persist re-imports it before the next write (exactly how stale rows
  // survived 10 hours on disk while every in-memory view pruned them).
  const mergeNow = Date.now();
  for (const [id, d] of Object.entries(disk.daemons ?? {})) {
    if (mergeNow - d.lastBeat > DAEMON_HEARTBEAT_TTL_MS) continue; // dead row: let it die
    if (!s.daemons[id] || d.lastBeat > s.daemons[id].lastBeat) s.daemons[id] = d;
  }
  // Watchlist: union with per-entry field merge — booleans are sticky
  // (another daemon's enlisted/seeded/finding must survive our persist),
  // lastProbe takes the max, and string metadata prefers whichever side
  // actually carries a value (ours wins conflicts — it is fresher by
  // construction: we just wrote our own probe results).
  for (const [k, w] of Object.entries(disk.watchlist ?? {})) {
    // A stale file must not be able to re-import the phantom rows we just
    // pruned (they can still be on disk from an older session).
    if (isPhantomWatchKey(k) || isPhantomWatchKey(w?.address)) continue;
    const mine = s.watchlist[k];
    if (!mine) {
      s.watchlist[k] = w;
      continue;
    }
    const diskNewer = (w.lastProbe ?? 0) > (mine.lastProbe ?? 0);
    mine.lastProbe = Math.max(mine.lastProbe ?? 0, w.lastProbe ?? 0) || undefined;
    mine.enlisted = mine.enlisted || w.enlisted;
    mine.seeded = mine.seeded || w.seeded;
    mine.finding = mine.finding || w.finding;
    if (diskNewer) mine.shape = w.shape ?? mine.shape;
    mine.lastResult = diskNewer ? (w.lastResult ?? mine.lastResult) : (mine.lastResult ?? w.lastResult);
    mine.name = mine.name ?? w.name;
    mine.category = mine.category ?? w.category;
    mine.bounty = mine.bounty ?? w.bounty;
    if (!mine.address) mine.address = w.address;
  }
  // Events + findings: union by (t,kind,msg), capped to the newest tail.
  const mergeEvents = (ours: BusEvent[], theirs: BusEvent[]): BusEvent[] => {
    const key = (e: BusEvent) => `${e.t}:${e.kind}:${e.msg}`;
    const byKey = new Map<string, BusEvent>();
    for (const e of ours) byKey.set(key(e), e);
    for (const e of theirs) if (!byKey.has(key(e))) byKey.set(key(e), e);
    return [...byKey.values()].sort((a, b) => b.t - a.t).slice(0, 400);
  };
  s.events = mergeEvents(s.events, disk.events ?? []);
  s.findings = mergeEvents(s.findings, disk.findings ?? []);
  // Hygiene, LAST: the disk file may still carry pre-classification noise and
  // sticky finding-flags from older sessions — it must not resurrect them into
  // the merged payload we are about to persist. Running after every merge is
  // what makes the scrub final rather than a delay.
  scrubFindingsHygiene(s);
  return s;
}

/** Record one target's generic-invariant-engine outcome (lab or fork mode).
 * Coverage counts are derived from the recorded results, so the dashboard
 * never drifts from what was actually probed. */
export function recordGenResult(name: string, r: Omit<GenResult, "t">): void {
  const gen = state().genEngine;
  gen.results[name] = { ...r, t: Date.now() };
  const all = Object.values(gen.results);
  gen.harnessable = all.filter((x) => x.shape !== "none").length;
  gen.discoveries = all.filter((x) => x.result === "discovered").length;
  persistSnapshot();
}

export function snapshot(): State {
  pruneStaleDaemons();
  return JSON.parse(JSON.stringify(state()));
}

/** Merge a persisted state file into memory without losing live data. Used
 * by daemon startup: several daemons share one state.json, and a naive
 * hydrate would let the second daemon's copy of `daemons` erase the first's
 * entry (each process only knows its own registry). Whichever side has a
 * fresher heartbeat per daemon id wins. */
/** Findings hygiene, shared by the hydrate path AND the persist-merge.
 *
 * Two jobs:
 *   1. Drop findings/finding-events recorded under the RETIRED
 *      "BALANCE DROP on " prefix — the pre-classification fleet logged raw
 *      (mostly benign) balance drops there. startsWith, not includes: the new
 *      "UNCLASSIFIED BALANCE DROP on" message CONTAINS the old prefix as a
 *      substring, and a genuine future signal must never match.
 *   2. Clear DRAIN flags that contradict the row's own "probe ran clean"
 *      lastResult — a pill that lies is worse than no pill.
 *
 * Running it at MERGE time too is what makes the scrub final: persistSnapshot
 * re-reads the disk file, and without this the old fakes would be merged back
 * into every write forever.
 */
function scrubFindingsHygiene(s: State): { findings: number; staleFlags: number; resolved: number; expired: number } {
  const isPreClassification = (m: string) => m.startsWith(PRE_CLASSIFICATION_PREFIX);
  const scrubbedFindings = s.findings.filter((f) => isPreClassification(String(f.msg))).length
    + s.events.filter((e) => e.kind === "finding" && isPreClassification(String(e.msg))).length;
  // Hand-classified verdicts (see RESOLVED_FINDING_MESSAGES): exact-message
  // removal from BOTH the findings feed and the event stream — the merge path
  // re-imports the disk tail on every persist, so this must run at merge time
  // too or the row would resurrect forever from every daemon's memory.
  const resolved = s.findings.filter((f) => isResolvedFinding(String(f.msg))).length
    + s.events.filter((e) => e.kind === "finding" && isResolvedFinding(String(e.msg))).length;
  s.findings = s.findings.filter((f) => !isPreClassification(String(f.msg)) && !isResolvedFinding(String(f.msg)));
  s.events = s.events.filter((e) => !(e.kind === "finding" && (isPreClassification(String(e.msg)) || isResolvedFinding(String(e.msg)))));
  let staleFlags = 0;
  for (const [k, w] of Object.entries(s.watchlist ?? {})) {
    const last = String(w.lastResult ?? "");
    const isRefusalOrClean =
      last.startsWith("probe ran clean") ||
      last.startsWith("probe blocked by vault gating") ||
      // A "probe reverted" note can never back a flag: isActionableFinding
      // refuses reverted probes, so a DRAIN pill on such a row is residue of
      // the old custom-error mislabel (e.g. Maple syrupUSDT's own
      // access-control revert read as a drain).
      last.startsWith("probe reverted:");
    const isResolvedTarget = RESOLVED_FINDING_TARGETS.some((a) => k.toLowerCase().includes(a));
    if (w.finding && (isRefusalOrClean || isResolvedTarget)) {
      w.finding = false;
      staleFlags++;
    }
  }
  // Collapse EXACT-duplicate findings (same kind+message, different t): the
  // responder's baseline race re-fired the identical incident message minutes
  // apart (verified live 13:25 and 13:38 on 0x9396…71ef), and two identical
  // cards read as two incidents. A genuinely new incident has different
  // amounts and therefore a different message — it always survives. Keep the
  // FIRST copy (the true opening time).
  const seenFindingMsgs = new Set<string>();
  const beforeFindings = s.findings.length;
  s.findings = s.findings.filter((f) => {
    const k = `${f.kind}:${f.msg}`;
    if (seenFindingMsgs.has(k)) return false;
    seenFindingMsgs.add(k);
    return true;
  });
  // Events keep full history; the findings FEED (what the board renders) is
  // what gets deduplicated.
  // UNCLASSIFIED findings age out of the FEED after UNCLASSIFIED_FEED_TTL_MS:
  // an incident that stayed unconfirmed for a week was (empirically, the Sep
  // 2026 sessions) a public-RPC classification failure on benign flow, and a
  // stale card the operator can never resolve is noise, not vigilance. Event
  // history keeps the full record; a genuinely new drop on the same target
  // has a fresh timestamp and is never affected.
  const nowMs = Date.now();
  const beforeTtl = s.findings.length;
  s.findings = s.findings.filter(
    (f) => !(String(f.msg).startsWith("UNCLASSIFIED BALANCE DROP on ") && f.t > 0 && nowMs - f.t > UNCLASSIFIED_FEED_TTL_MS)
  );
  return { findings: scrubbedFindings + (beforeFindings - s.findings.length) + (beforeTtl - s.findings.length), staleFlags, resolved, expired: beforeTtl - s.findings.length };
}

const UNCLASSIFIED_FEED_TTL_MS = 7 * 86_400_000;

const PRE_CLASSIFICATION_PREFIX = "BALANCE DROP on ";

/** Findings that were raised UNCLASSIFIED and have since been CLASSIFIED by
 * hand against live chain data — the message text is stored EXACTLY, so only
 * that one alert is retired and a genuinely new finding (different vault,
 * different amounts) can never be swallowed by a substring accident.
 *
 * 0x9396…71ef (Gearbox PoolV3): the -25.07 WETH drop was traced to tx
 * 0x31ef6a22…fecb — a standard ERC4626 redeem(shares, receiver, owner) where
 * owner == receiver == tx.from, emitting the canonical Withdraw event. The
 * user withdrew their own LP position; the vault refilled above pre-drop
 * levels within hours (depositors' inflow), share price stayed healthy.
 * An "UNCLASSIFIED" label on a classified-benign event is a lie on the board. */
const RESOLVED_FINDING_MESSAGES: ReadonlySet<string> = new Set([
  "UNCLASSIFIED BALANCE DROP on auto-enlisted live vault (0x9396dcbf78fc526bb003665337c5e73b699571ef) WETH: -25073165982900038238 (220023619929654875202 -> 194950453946754836964) — opening incident",
]);

function isResolvedFinding(m: string): boolean {
  if (RESOLVED_FINDING_MESSAGES.has(String(m))) return true;
  return RESOLVED_FINDING_TARGETS.some((a) => String(m).includes(a));
}

/** Targets whose UNCLASSIFIED findings were hand-classified BENIGN against
 * live chain data (2026-09-24 session — every address verified on-chain:
 * totalAssets healthy, no real-world incident reported for the protocol in
 * the incident window):
 *   0x356b…d5ba7d  syrupUSDT (Maple)        — probe gate-refusal, TVL 252.7M USDT
 *   0x9396…9571ef  kpkWETH (Maple WETH Mkt) — gate refusals + user redeems, 1,102 WETH
 *   0x80ac…f5cc0b  syrupUSDC (Maple)        — probe gate-refusal, TVL 1.0B USDC
 *   0xe2e7…e3c372  spUSDT (Spark Savings)   — savings-vault flow, TVL 389M USDT;
 *                  re-triaged 2026-09-28: the 51.9M USDT OUTs were executed BY the
 *                  2/2 operator Safe with funds flowing BOTH directions (same
 *                  counterparties deposited 3.8M USDT + 1288 WETH) — treasury ops
 *   0xfe6e…09b8f  spETH (Spark Savings)    — re-triaged 2026-09-28: the -149 WETH
 *                  drop was tx 0xbcb07d61…, a canonical ERC-4626 redeem() with the
 *                  vault's own Withdraw event + 1416.8 share burn from the redeemer;
 *                  the escalation was a classifier blind spot (4626 event dialect
 *                  + endpoint rate limit), both since fixed in responder.ts
 *   0x4f95…3bd87c  Frax frxUSD USDC custodian — float sweeps to exactly 500k USDC
 *   0xd5cc…eaa13   KPK USDC Yield (Karpatkey VaultV2) — balance swept to 0 by the
 *                  manager and LATER REFILLED (10,058 USDC held today); a drain
 *                  does not give the money back
 * A finding card mentioning one of these addresses is retired WHOLESALE: an
 * address cannot collide with another target's message. New drops on these
 * targets carry fresh timestamps and flow through the ordinary pipeline.
 * Event history is retained (the scrub only removes kind=="finding" events). */
const RESOLVED_FINDING_TARGETS: readonly string[] = [
  "0x356b8d89c1e1239cbbb9de4815c39a1474d5ba7d",
  "0x9396dcbf78fc526bb003665337c5e73b699571ef",
  "0x80ac24aa929eaf5013f6436cda2a7ba190f5cc0b",
  "0xe2e7a17dff93280dec073c995595155283e3c372",
  "0xfe6eb3b609a7c8352a241f7f3a21cea4e9209b8f",
  "0x4f95c5ba0c7c69fb2f9340e190ccee890b3bd87c",
  "0xd5cce260e7a755ddf0fb9cdf06443d593aaeaa13",
];

function hydrateFromState(persisted: Partial<State>): void {
  const s = state();
  for (const [k, v] of Object.entries(persisted)) {
    if (k === "daemons") continue; // merged below with freshness conflict resolution
    (s as unknown as Record<string, unknown>)[k] = v;
  }
  // Migration: sessions written before the label-key bug was fixed carry
  // unprobeable display-truncated rows. Every consumer (UI, digest, daemon
  // shard scheduler) hydrates through here, so this is the one place a stale
  // file can be healed before it is believed.
  const phantom = prunePhantomWatchKeys();
  if (phantom > 0) {
    logEvent("safety", `hydrate: dropped ${phantom} unprobeable display-truncated watchlist row(s) from the persisted session`);
  }
  // Migration: sessions written before the responder classified drops carried
  // raw balance-drop "findings" that were mostly ordinary user withdrawals
  // (verified live: a vault printing -50 WETH, +17, +8 within a day). Those
  // rows poison the findings feed and paint DRAIN pills onto innocent targets.
  // The filtering lives in scrubFindingsHygiene (shared with the persist-merge
  // so a stale file cannot resurrect the rows into future writes).
  const scrubbed = scrubFindingsHygiene(s);
  if (scrubbed.findings > 0) {
    logEvent("safety", `hydrate: scrubbed ${scrubbed.findings} pre-classification balance-drop "finding(s)" — recorded before drops were classified against on-chain activity`);
  }
  if (scrubbed.resolved > 0) {
    logEvent("safety", `hydrate: retired ${scrubbed.resolved} hand-resolved finding(s) — classified benign against on-chain data (see RESOLVED_FINDING_MESSAGES in bus.ts)`);
  }
  if (scrubbed.staleFlags > 0) {
    logEvent("safety", `hydrate: cleared ${scrubbed.staleFlags} stale DRAIN flag(s) whose lastResult shows a clean probe or a probe the target refused`);
  }
  if (scrubbed.expired > 0) {
    logEvent("safety", `hydrate: retired ${scrubbed.expired} UNCLASSIFIED finding(s) older than 7 days from the findings feed (event history retained)`);
  }
  const persistedDaemons = (persisted.daemons ?? {}) as Record<string, DaemonInfo>;
  for (const [id, d] of Object.entries(persistedDaemons)) {
    const mine = s.daemons[id];
    if (!mine || d.lastBeat > mine.lastBeat) s.daemons[id] = d;
  }
}

/** Load the last persisted session (used by standalone `npm run ui`). */
export function hydrateFromDisk(): boolean {
  try {
    const persisted = JSON.parse(readFileSync(join(REPORT_DIR, "state.json"), "utf8")) as Partial<State>;
    hydrateFromState(persisted);
    return true;
  } catch {
    return false;
  }
}

const LOCAL_LAB_POOL = /^0x5[fF]b[dD]b2315678afecb367f032d93[fF]642f64180aa3$/i;

/** Canonical deterministic dev-chain deploy addresses (hardhat/anvil first
 * contracts). These can never hold a production finding — they only ever
 * exist on local test chains. Enforced as a chokepoint in upsertWatch so
 * no caller (probe, verifier, triage) can flag them, and in pruneDemoState
 * so stale flags from older runs cannot persist. */
const DEV_FIXTURE_ADDRESSES = new Set(
  [
    "0x5fbdb2315678afecb367f032d93f642f64180aa3",
    "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
    "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
    "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
    "0xdc64a140aa3e981100a9beca4246856ee12ad9ee",
    "0x0165878a594ca255338adfa4d48449f69242eb8f",
    "0xa513e6e4b8f2a923d98304ec85f60c26d806b169",
    "0x322813fd9a801c5507c9de605d63cea4f2ce6c44",
  ]
);

/** Remove demo/local noise before a production-only hunt. */
export function pruneDemoState(): void {
  const s = state();
  prunePhantomWatchKeys();
  for (const key of Object.keys(s.watchlist)) {
    const addr = s.watchlist[key]?.address ?? key;
    if (
      LOCAL_LAB_POOL.test(addr) || LOCAL_LAB_POOL.test(key) ||
      DEV_FIXTURE_ADDRESSES.has(addr.toLowerCase()) || DEV_FIXTURE_ADDRESSES.has(key.toLowerCase())
    ) delete s.watchlist[key];
  }
  for (const fx of DEV_FIXTURE_ADDRESSES) {
    s.findings = s.findings.filter((f) => !JSON.stringify(f).toLowerCase().includes(fx));
    s.events = s.events.filter((e) => !JSON.stringify(e).toLowerCase().includes(fx));
  }
  s.findings = s.findings.filter((f) => !String(f.msg).includes("0x5FbDB231") && !String(f.msg).includes("GENERIC DISCOVERY"));
  s.events = s.events.filter((e) => !String(e.msg).includes("0x5FbDB231"));
  persistSnapshot();
}
