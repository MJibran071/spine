// Governance / admin / multisig analyzer — READ-ONLY public-state analysis.
//
// What this does: follows the authority graph of a target contract (EIP-1967
// slots, admin()/getRoles) and classifies every authority it finds: Gnosis
// Safe (threshold + owner concentration + EOA hot-key exposure), timelocks,
// proxy admins. This is the same class of analysis published by L2BEAT and
// DeFiSafety — it evaluates OTHER PEOPLE'S PUBLISHED CONFIGURATION. It never
// touches keys, never broadcasts, and cannot influence anything: the entire
// module is eth_call / eth_getStorageAt over public endpoints.
//
// No memory-trusted addresses: authorities are discovered by following slots
// from on-chain-verified seeds (SEED_TARGETS), and a contract is only called
// a "Safe" if it ANSWERS getOwners()/getThreshold() (behavioral verification).
import { CHAINS, SEED_TARGETS, infraRpcWithFailover, wrappedBalanceWei, type ChainSpec } from "./scan.ts";
import { logEvent } from "./bus.ts";
import { BOUNTY_PAYOUT_ADDRESS } from "./config.ts";

// function selectors (cast-verified at build time; see verify script)
const SEL_GET_OWNERS = "0xa0e67e2b"; // getOwners() — Safe
const SEL_GET_THRESHOLD = "0xe75235b8"; // getThreshold() — Safe
const SEL_VERSION = "0xffa1ad74"; // VERSION() — Safe
const SEL_GET_MIN_DELAY = "0xf27a0c92"; // getMinDelay() — TimelockController (cast-verified)
const SEL_ADMIN = "0xf851a440"; // admin() — Compound-style Timelock
const SEL_DELAY = "0x6a42b8f8"; // delay() — Compound-style Timelock (cast-verified)
const SEL_OWNER = "0x8da5cb5b"; // owner() — Ownable (cast-verified)
const SEL_GET_ROLE_MEMBER = "0x9010d07c"; // getRoleMember(bytes32,uint256) — OZ AccessControl
const SEL_GET_ROLE_MEMBER_COUNT = "0xca15c873"; // getRoleMemberCount(bytes32) — OZ AccessControl
const SEL_HAS_ROLE = "0x91d14854"; // hasRole(bytes32,address) — OZ AccessControl
// Well-known OZ AccessControl roles (keccak256 of name, verified)
const ROLE_DEFAULT_ADMIN = "0x0000000000000000000000000000000000000000000000000000000000000000";
const ROLE_PAUSER = "0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a"; // PAUSER_ROLE
const ROLE_UPGRADER = "0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3"; // UPGRADER_ROLE

// EIP-1967 slots (keccak("eip1967.proxy.implementation") - 1 etc.)
const SLOT_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

export interface AuthorityFinding {
  kind: "safe" | "timelock" | "eoa-admin" | "contract-admin" | "no-admin";
  address: string;
  label: string;
  /** Safe-only facts */
  owners?: string[];
  threshold?: number;
  /** Filled only by eth_getCode — an owner with no code is an EOA (hot key). */
  eoaOwners?: number;
  risks: string[];
}

export interface GovernanceReport {
  chain: string;
  seed: string;
  authorities: AuthorityFinding[];
  /** owner addresses shared between >=2 distinct safes in this report */
  sharedOwners: string[];
}

const wordToAddr = (hex: string): string | null => {
  if (typeof hex !== "string" || hex.length < 66) return null;
  const word = hex.slice(-64);
  if (/^0+$/.test(word)) return null; // zero slot = no admin
  const addr = "0x" + word.slice(-40);
  return /^0x[0-9a-fA-F]{40}$/.test(addr) ? addr : null;
};

async function callContract(chain: ChainSpec, to: string, data: string): Promise<string | null> {
  try {
    const r = (await infraRpcWithFailover(chain, "eth_call", [{ to, data }, "latest"])) as string;
    return typeof r === "string" && r.length >= 2 ? r : null;
  } catch {
    return null;
  }
}

async function hasCode(chain: ChainSpec, address: string): Promise<boolean> {
  try {
    const c = (await infraRpcWithFailover(chain, "eth_getCode", [address, "latest"])) as string;
    return typeof c === "string" && c.length > 2;
  } catch {
    return false;
  }
}

async function getStorage(chain: ChainSpec, address: string, slot: string): Promise<string | null> {
  try {
    const r = (await infraRpcWithFailover(chain, "eth_getStorageAt", [address, slot, "latest"])) as string;
    return typeof r === "string" ? r : null;
  } catch {
    return null;
  }
}

/** Behavioral Safe detection: it's a Safe iff it ANSWERS getOwners + getThreshold. */
async function trySafe(chain: ChainSpec, address: string): Promise<{ owners: string[]; threshold: number } | null> {
  const ownersRaw = await callContract(chain, address, SEL_GET_OWNERS);
  if (!ownersRaw || ownersRaw.length < 130) return null;
  try {
    const offset = BigInt(ownersRaw.slice(0, 66));
    const len = BigInt("0x" + ownersRaw.slice(66, 130));
    if (offset !== 32n || len === 0n || len > 100n) return null;
    const owners: string[] = [];
    // ownersRaw keeps its 0x prefix (2 chars). Word w occupies
    // [2 + w*64, 2 + (w+1)*64). Owner words are words 2..2+n (after the
    // offset word and the length word), so owner i starts at char 130 + i*64.
    for (let i = 0n; i < len; i++) {
      const start = 130 + Number(i) * 64;
      const word = ownersRaw.slice(start, start + 64);
      if (!/^[0-9a-fA-F]{64}$/.test(word)) return null;
      owners.push("0x" + word.slice(-40));
    }
    const thrRaw = await callContract(chain, address, SEL_GET_THRESHOLD);
    if (!thrRaw || thrRaw.length < 66) return null;
    const threshold = Number(BigInt(thrRaw));
    if (threshold < 1 || threshold > owners.length) return null;
    return { owners, threshold };
  } catch {
    return null;
  }
}

async function tryTimelock(chain: ChainSpec, address: string): Promise<{ delaySeconds: number; kind: string } | null> {
  const minDelay = await callContract(chain, address, SEL_GET_MIN_DELAY);
  if (minDelay && minDelay.length >= 66) {
    return { delaySeconds: Number(BigInt(minDelay)), kind: "TimelockController" };
  }
  const delay = await callContract(chain, address, SEL_DELAY);
  if (delay && delay.length >= 66) {
    return { delaySeconds: Number(BigInt(delay)), kind: "compound-style" };
  }
  return null;
}

/** Analyze one authority address into a finding (behavior-verified). */
export async function analyzeAuthority(chain: ChainSpec, address: string, label: string): Promise<AuthorityFinding> {
  const addr = address.toLowerCase();
  const risks: string[] = [];

  const isContract = await hasCode(chain, addr);
  if (!isContract) {
    return { kind: "eoa-admin", address: addr, label, risks: ["authority is an EOA — a single compromised key has full control"] };
  }

  const safe = await trySafe(chain, addr);
  if (safe) {
    let eoaOwners = 0;
    for (const o of safe.owners) if (!(await hasCode(chain, o))) eoaOwners++;
    const ratio = safe.threshold / safe.owners.length;
    if (safe.threshold === 1) risks.push("threshold 1 — any single owner can act alone");
    else if (ratio < 1 / 3) risks.push(`low threshold ${safe.threshold}/${safe.owners.length} (<1/3)`);
    if (eoaOwners > 0) risks.push(`${eoaOwners}/${safe.owners.length} owners are EOAs (hot-key exposure)`);
    if (safe.owners.length <= 3) risks.push(`small owner set (${safe.owners.length}) — concentration risk`);
    return { kind: "safe", address: addr, label, owners: safe.owners, threshold: safe.threshold, eoaOwners, risks };
  }

  const timelock = await tryTimelock(chain, addr);
  if (timelock) {
    if (timelock.delaySeconds < 3600) risks.push(`timelock delay only ${timelock.delaySeconds}s`);
    return { kind: "timelock", address: addr, label, risks };
  }

  // Ownable.owner() — plain Ownable contracts are not Safes or timelocks but
  // their owner may be an EOA. Detect this explicitly instead of silently
  // classifying as "contract-admin (unrecognised)".
  const ownerRaw = await callContract(chain, addr, SEL_OWNER);
  if (ownerRaw && ownerRaw.length >= 66) {
    const ownerAddr = wordToAddr(ownerRaw);
    if (ownerAddr) {
      const ownerIsEoa = !(await hasCode(chain, ownerAddr));
      if (ownerIsEoa) {
        return {
          kind: "eoa-admin",
          address: addr,
          label: `${label} (Ownable, owner: ${ownerAddr})`,
          risks: [`Ownable with EOA owner ${ownerAddr} — single key controls the contract`],
        };
      } else {
        return {
          kind: "contract-admin",
          address: addr,
          label: `${label} (Ownable, owner contract: ${ownerAddr})`,
          risks: [`Ownable with contract owner ${ownerAddr} — inspect the owner contract`],
        };
      }
    }
  }

  // OZ AccessControl — enumerate DEFAULT_ADMIN_ROLE members.
  const accessRoles = await tryAccessControl(chain, addr);
  if (accessRoles.length > 0) {
    const eoaAdmins = accessRoles.filter((m) => m.isEoa);
    if (eoaAdmins.length > 0)
      risks.push(`AccessControl DEFAULT_ADMIN role has ${eoaAdmins.length} EOA holder(s): ${eoaAdmins.map((m) => m.address).join(", ")}`);
    risks.push(`AccessControl roles: ${accessRoles.length} admin member(s) total`);
    return {
      kind: eoaAdmins.length > 0 ? "eoa-admin" : "contract-admin",
      address: addr,
      label: `${label} (AccessControl)`,
      owners: accessRoles.map((m) => m.address),
      risks,
    };
  }

  return { kind: "contract-admin", address: addr, label, risks: ["admin contract (unrecognized interface) — inspect manually"] };
}

/** OZ AccessControl enumeration — returns members of DEFAULT_ADMIN_ROLE (and
 * PAUSER/UPGRADER if present). Best-effort: returns [] on any failure. */
async function tryAccessControl(
  chain: ChainSpec,
  address: string
): Promise<{ address: string; isEoa: boolean }[]> {
  try {
    // getRoleMemberCount(DEFAULT_ADMIN_ROLE)
    const countRaw = await callContract(
      chain,
      address,
      `${SEL_GET_ROLE_MEMBER_COUNT}${ROLE_DEFAULT_ADMIN.slice(2)}`
    );
    if (!countRaw || countRaw.length < 66) return [];
    const count = Number(BigInt(countRaw));
    if (count === 0 || count > 20) return []; // 0 = not AccessControl; >20 = too large
    const members: { address: string; isEoa: boolean }[] = [];
    for (let i = 0; i < count; i++) {
      const idx = i.toString(16).padStart(64, "0");
      const memberRaw = await callContract(
        chain,
        address,
        `${SEL_GET_ROLE_MEMBER}${ROLE_DEFAULT_ADMIN.slice(2)}${idx}`
      );
      const memberAddr = memberRaw ? wordToAddr(memberRaw) : null;
      if (!memberAddr) continue;
      const isEoa = !(await hasCode(chain, memberAddr));
      members.push({ address: memberAddr, isEoa });
    }
    return members;
  } catch {
    return [];
  }
}

/** Follow EIP-1967 authority pointers from a target contract. */
export async function analyzeTarget(chain: ChainSpec, address: string, label: string): Promise<AuthorityFinding[]> {
  const findings: AuthorityFinding[] = [];
  const visited = new Set<string>();

  const slots: [string, string][] = [
    [SLOT_ADMIN, "proxy admin"],
    [SLOT_IMPLEMENTATION, "implementation"],
    [SLOT_BEACON, "beacon"],
  ];
  const candidates: { addr: string; label: string }[] = [];
  for (const [slot, what] of slots) {
    const raw = await getStorage(chain, address, slot);
    const a = raw ? wordToAddr(raw) : null;
    if (a && !visited.has(a.toLowerCase())) {
      visited.add(a.toLowerCase());
      candidates.push({ addr: a, label: `${what} (${a})` });
    }
  }
  // many authority contracts also expose admin() (Compound-style) — cheap to ask
  const adminCall = await callContract(chain, address, SEL_ADMIN);
  if (adminCall && adminCall.length >= 66) {
    const a = wordToAddr(adminCall);
    if (a && !visited.has(a.toLowerCase())) {
      visited.add(a.toLowerCase());
      candidates.push({ addr: a, label: `admin() (${a})` });
    }
  }

  for (const c of candidates.slice(0, 10)) {  // expanded from 6 → 10 authority candidates
    findings.push(await analyzeAuthority(chain, c.addr, c.label));
  }
  if (findings.length === 0) {
    findings.push({ kind: "no-admin", address, label, risks: ["no EIP-1967 admin/implementation pointers found — immutable or custom authority"] });
  }
  return findings;
}

/** Wall-clock budget for one governance scan. Each RPC is bounded (12s per
 * endpoint, 8-endpoint failover), but a scan composes HUNDREDS of sequential
 * calls — on degraded endpoints that compounds into hours and freezes the
 * daemon cycle (the 2026-09-16 mainnet-1 wedge: 5.7h stuck here). The budget
 * stops starting new seeds once exceeded; partial reports are still returned. */
export const GOV_SCAN_BUDGET_MS = (parseInt(process.env.GOV_SCAN_BUDGET_MIN ?? "10", 10) || 10) * 60_000;

/** Analyze the authority graph of every verified seed on a chain. */
export async function runGovernanceScan(
  chainNames: string[] = [],
  opts: { budgetMs?: number; onProgress?: () => void } = {}
): Promise<GovernanceReport[]> {
  const budgetMs = opts.budgetMs ?? GOV_SCAN_BUDGET_MS;
  const t0 = Date.now();
  const reports: GovernanceReport[] = [];
  const safeOwners: Map<string, { chain: string; label: string }[]> = new Map();

  for (const chain of CHAINS) {
    if (Date.now() - t0 > budgetMs) {
      logEvent("gov", `governance scan hit ${Math.round(budgetMs / 60_000)}min budget — ${reports.length} target(s) analyzed so far (will resume next scheduled cycle)`);
      break;
    }
    if (chainNames.length && !chainNames.includes(chain.name)) continue;
    const seeds = SEED_TARGETS[chain.id] ?? [];
    if (!seeds.length) continue;
    for (const seed of seeds.slice(0, 4)) {  // expanded from 2 → 4 seeds per chain
      if (Date.now() - t0 > budgetMs) {
        logEvent("gov", `governance scan hit ${Math.round(budgetMs / 60_000)}min budget — ${reports.length} target(s) analyzed so far (will resume next scheduled cycle)`);
        break;
      }
      const authorities = await analyzeTarget(chain, seed, "seed");
      opts.onProgress?.();
      reports.push({ chain: chain.name, seed, authorities, sharedOwners: [] });
      for (const f of authorities) {
        if (f.kind === "safe" && f.owners) {
          for (const o of f.owners) {
            const list = safeOwners.get(o.toLowerCase()) ?? [];
            list.push({ chain: chain.name, label: `${f.label}` });
            safeOwners.set(o.toLowerCase(), list);
          }
        }
      }
      // small residual value check on the admin contract itself (read-only)
      for (const f of authorities) {
        if (f.kind === "safe") {
          const bal = await wrappedBalanceWei(chain, f.address);
          if (bal > 0n) f.risks.push(`admin multisig itself holds wrapped-native value (${bal} wei) — key compromise drains treasury`);
        }
      }
    }
  }

  if (opts.onProgress) opts.onProgress();
  // operator overlap across every Safe seen in this run
  for (const r of reports) {
    r.sharedOwners = [...safeOwners.entries()].filter(([_, refs]) => refs.length >= 2).map(([o]) => o);
    if (r.sharedOwners.length) {
      for (const f of r.authorities) {
        if (f.kind === "safe") f.risks.push(`shares ${r.sharedOwners.length} owner address(es) with other multisigs — correlated key risk`);
      }
    }
  }
  logEvent("gov", `governance scan: ${reports.length} targets analyzed`);
  return reports;
}

export function writeGovernanceReport(reports: GovernanceReport[]): string {
  const lines = [
    "# Governance / Admin Risk Report",
    "",
    `_generated ${new Date().toISOString()} — read-only public-state analysis; nothing broadcast_`,
    ``,
    `Submit access-control findings through the project's official bounty program. Researcher payout address for rewards: \`${BOUNTY_PAYOUT_ADDRESS}\``,
    "",
  ];
  for (const r of reports) {
    lines.push(`## ${r.chain} — seed ${r.seed}`, "");
    for (const f of r.authorities) {
      lines.push(`- **${f.kind}** ${f.label}`);
      if (f.threshold !== undefined) lines.push(`  - threshold ${f.threshold}/${f.owners!.length}, EOAs: ${f.eoaOwners ?? "?"}`);
      for (const risk of f.risks) lines.push(`  - risk: ${risk}`);
    }
    if (r.sharedOwners.length) lines.push(`- shared owners across multisigs: ${r.sharedOwners.join(", ")}`);
    lines.push("");
  }
  return lines.join("\n");
}
