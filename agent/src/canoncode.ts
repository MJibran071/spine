// Canonical-code classifier — the highest-leverage prioritization tool.
//
// THE BASE-RATE TRUTH the fleet was ignoring: public mainnet is ~95% stock
// code (Uniswap pairs, OZ proxies, Aave markets, standard ERC-4626 shells).
// Stock code is tested by thousands of eyes and pays ~zero bugs. Real bugs
// ship in (a) FORK DELTAS — a team forks a proven protocol and customizes
// the accounting (Mango, Euler, bZx were all forks), and (b) SMALL CUSTOM
// protocols with novel logic. This classifier puts every verified target
// into one of three classes from FLEET-WIDE EVIDENCE, not vibes:
//
//   boilerplate  — most of its contracts' names are seen across many other
//                  targets in the fleet (the fleet itself IS the corpus)
//   fork-delta   — mix: a known base (frequent names) PLUS rare custom
//                  contract names riding on it (the classic fork)
//   custom       — predominantly rare names: novel protocol
//
// Persistence: reports/canoncode.json — one row per target, updated when a
// target's verified source is (re)fetched. The scanner/investigate paths call
// classifyTarget after source pull; the daemon's campaign pass and the
// funnel read the persisted store.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

export type CodeClass = "boilerplate" | "fork-delta" | "custom";

export interface CanonRow {
  chainId: string;
  address: string; // lowercase
  codeClass: CodeClass;
  /** Total distinct contract declarations found in the verified source. */
  contracts: number;
  /** How many of those names the fleet has seen on OTHER targets too. */
  shared: number;
  /** 0..1 — share of declarations that are fleet-rare (custom signal). */
  customShare: number;
  /** Short, human-readable reason for the classification. */
  reason: string;
  t: number;
  /** Set when a harness build proved this exact source unharnessable — the
   * on-ramp skips re-attempts (idempotent; a source upgrade resets it). */
  unharnessableSourceLen?: number;
}

const STORE_PATH = join(REPORT_DIR, "canoncode.json");
const FREQUENCY_PATH = join(REPORT_DIR, "canoncode-names.json");

interface NameFreq {
  /** contract-name(lowercased) -> number of DISTINCT targets declaring it */
  [name: string]: number;
}

function loadFreq(): NameFreq {
  try {
    return JSON.parse(readFileSync(FREQUENCY_PATH, "utf8")) as NameFreq;
  } catch {
    return {};
  }
}

function saveFreq(f: NameFreq): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(FREQUENCY_PATH, JSON.stringify(f));
  } catch {
    /* stats must never break the hunt */
  }
}

function loadStore(): Record<string, CanonRow> {
  try {
    return JSON.parse(readFileSync(STORE_PATH, "utf8")) as Record<string, CanonRow>;
  } catch {
    return {};
  }
}

function saveStore(s: Record<string, CanonRow>): void {
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(STORE_PATH, JSON.stringify(s));
  } catch {
    /* best-effort */
  }
}

/** Distinct contract/interface/library names a source pulls into its type
 * graph: declared names PLUS inheritance bases (`contract X is ERC20, Ownable`)
 * and library usages (`using SafeMath for uint256`). Inheritance matters: a
 * lone `MyVault is ERC20` IS a fork of shared base code, and without scanning
 * the `is` list the classifier would call it 100% custom. */
export function declaredContractNames(source: string): string[] {
  const out = new Set<string>();
  for (const m of source.matchAll(/\b(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:is\s+([^{;]+))?/g)) {
    out.add(m[1]!.toLowerCase());
    if (m[2]) {
      for (const base of m[2].split(",")) {
        const name = base.trim().split(/[\s(]/)[0]!;
        if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) out.add(name.toLowerCase());
      }
    }
  }
  for (const m of source.matchAll(/\busing\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+for\b/g)) out.add(m[1]!.toLowerCase());
  return [...out];
}

// Names that are ALWAYS boilerplate regardless of frequency — every proxy,
// every token, every OZ import declares one of these somewhere.
const ALWAYS_SHARED = new Set([
  "ownable", "ownable2step", "context", "erc20", "ierc20", "erc20permit", "ierc20permit",
  "erc4626", "ierc4626", "reentrancyguard", "pausable", "accesscontrol", "iauthority",
  "initializable", "uupsupgradeable", "transparentupgradeableproxy", "proxyadmin",
  "erc1967proxy", "address", "storageslot", "clones", "safemath", "math", "signedmath",
  "multicall", "abief", "iweth", "weth", "weth9", "erc20burnable", "erc20capped",
  "erc20flashmintable", "erc165", "ierc165", "ierc721", "erc721", "ierc1155", "erc1155",
  "univ2pair", "univ2factory", "uniswapv2pair", "uniswapv2factory", "uniswapv2router02",
  "iuniswapv2pair", "iuniswapv2factory", "iuniswapv2router", "iuniswapv3pool",
  "iuniswapv3factory", "iswaprouter", "token", "vault", "itesttoken", "testtoken",
]);

/** Classify one target's verified source against the fleet corpus.
 * Mutates the name-frequency store (the corpus grows with every observation). */
export function classifyTarget(chainId: string, address: string, source: string): CanonRow {
  const key = `${chainId}:${address.toLowerCase()}`;
  const names = declaredContractNames(source);
  const freq = loadFreq();
  const store = loadStore();

  // ---- update the corpus: each name gains this target as a declaring site ----
  const prev = store[key];
  if (prev) {
    // If we classified this target before, remove its old name contributions
    // first so a re-classification never double-counts it in the corpus.
    for (const n of declaredContractNames(String(prev.reason ?? ""))) { /* no-op: names are not stored in reason */ }
  }
  // Contribution tracking is implicit: frequency counts distinct DECLARING
  // TARGETS per name. To keep that honest we store per-target name lists.
  const namesPath = join(REPORT_DIR, "canoncode-target-names.json");
  let perTarget: Record<string, string[]> = {};
  try {
    perTarget = JSON.parse(readFileSync(namesPath, "utf8")) as Record<string, string[]>;
  } catch { /* first run */ }
  const oldNames = perTarget[key] ?? [];
  for (const n of oldNames) if (freq[n]) freq[n] = Math.max(0, freq[n] - 1);
  for (const n of names) freq[n] = (freq[n] ?? 0) + 1;
  perTarget[key] = names;
  saveFreq(freq);
  try {
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(namesPath, JSON.stringify(perTarget));
  } catch { /* best-effort */ }

  // ---- classify ----
  const sharedCount = names.filter((n) => ALWAYS_SHARED.has(n) || (freq[n] ?? 0) >= FLEET_SHARED_THRESHOLD).length;
  const rareCount = names.length - sharedCount;
  const customShare = names.length === 0 ? 0 : rareCount / names.length;

  let codeClass: CodeClass;
  let reason: string;
  if (names.length === 0) {
    codeClass = "boilerplate";
    reason = "no contract declarations found in verified source";
  } else if (customShare >= CUSTOM_SHARE_MIN) {
    codeClass = "custom";
    reason = `${rareCount}/${names.length} contract name(s) fleet-rare (novel protocol surface)`;
  } else if (sharedCount >= 2 && rareCount >= 1) {
    codeClass = "fork-delta";
    reason = `${sharedCount} fleet-shared base name(s) + ${rareCount} custom addition(s) — fork with custom logic`;
  } else {
    codeClass = "boilerplate";
    reason = `${sharedCount}/${names.length} name(s) fleet-shared and no custom surface`;
  }

  const row: CanonRow = {
    chainId,
    address: address.toLowerCase(),
    codeClass,
    contracts: names.length,
    shared: sharedCount,
    customShare: Math.round(customShare * 100) / 100,
    reason,
    t: Date.now(),
  };
  store[key] = row;
  saveStore(store);
  return row;
}

/** A name seen on this many DISTINCT targets (inclusive) is "fleet-shared" —
 * two independent deployments declaring the same name is already a fleet
 * pattern (canonical or copy-fork), not bespoke code. */
const FLEET_SHARED_THRESHOLD = 2;
/** Rare-name share above which a target is wholly custom. */
const CUSTOM_SHARE_MIN = 0.5;

export function getCanon(chainId: string, address: string): CanonRow | null {
  return loadStore()[`${chainId}:${address.toLowerCase()}`] ?? null;
}

/** Persist arbitrary patches to a campaign row (used by the slice runner for
 * build-failure counters; getCampaign returns a FRESH parse, so mutating its
 * result is a silent no-op). */
export function patchCanon(chainId: string, address: string, patch: Partial<CanonRow>): void {
  const key = `${chainId}:${address.toLowerCase()}`;
  const store = loadStore();
  const row = store[key];
  if (!row) return; // nothing classified yet — nothing to patch
  store[key] = { ...row, ...patch };
  saveStore(store);
}

/** Persisted rows, optionally filtered to a class — the daemon campaign pass
 * and the funnel read this. */
export function rowsByClass(codeClass?: CodeClass): CanonRow[] {
  const all = Object.values(loadStore());
  return codeClass ? all.filter((r) => r.codeClass === codeClass) : all;
}

export function canonStats(): { total: number; boilerplate: number; forkDelta: number; custom: number } {
  const all = Object.values(loadStore());
  return {
    total: all.length,
    boilerplate: all.filter((r) => r.codeClass === "boilerplate").length,
    forkDelta: all.filter((r) => r.codeClass === "fork-delta").length,
    custom: all.filter((r) => r.codeClass === "custom").length,
  };
}

/** Campaign priority: custom > fork-delta > boilerplate. Untested targets
 * first; then oldest-tested (accrue fuzz hours everywhere eventually). */
export function campaignPriority(a: CanonRow, b: CanonRow): number {
  const rank = (c: CodeClass) => (c === "custom" ? 2 : c === "fork-delta" ? 1 : 0);
  return rank(b.codeClass) - rank(a.codeClass) || a.t - b.t;
}
