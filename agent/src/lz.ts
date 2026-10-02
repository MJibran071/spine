// LayerZero cross-chain threat model: endpoint registry, challenge catalog,
// and triage hints. The classes below come from the public LayerZero /
// Immunefi threat model (replay, nonce ordering, OFT accounting, malicious
// destination, compose reentrancy, sender/endpoint authz, DVN config,
// library versioning, gas griefing, cross-chain governance, address-format
// confusion, upgrade/init). Each is flagged honestly:
//   probeable — the agent can demonstrate the class against a local fork
//               (its own generated OApp or the target's inbound surface);
//   intel     — needs infra, docs, or cross-chain context the fork cannot
//               provide (tracked via OSINT instead, never faked).

/** Verified LayerZero endpoint deployments (EVM). */
import { memoryRecall, memoryRemember } from "./memory.ts";

export const LZ_ENDPOINTS: Record<number, { v2: string; v1?: string }> = {
  1: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0x66A71Dcef29A0fFB85E97464912382aC1F7d123b" },
  10: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0x3c2269811836af69497E5F486A85D7316753cf62" },
  56: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0x672a23D619fd6AdE61be5d7114b986e0Bab42a5D" },
  100: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  137: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0xb6319cC6c8c27A8F5dAF0dD3DF91EA35Cf971BF0" },
  250: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  8453: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0xb6319cC6c8c27A8F5dAF0dD3DF91EA35Cf971BF0" },
  42161: { v2: "0x1a44076050125825900e736c501f859c50fE728c", v1: "0x3c2269811836af69497E5F486A85D7316753cf62" },
  43114: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  59144: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  534352: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  80094: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
  81457: { v2: "0x1a44076050125825900e736c501f859c50fE728c" },
};

/** LayerZero endpoint ids (eid) for the chains the hunt covers. */
export const LZ_EIDS: Record<number, number> = {
  1: 30101, 10: 30111, 56: 30102, 100: 30146, 137: 30109,
  250: 30112, 8453: 30184, 42161: 30110, 43114: 30106,
  59144: 30183, 534352: 30193, 80094: 30338, 81457: 30340,
};

export interface LzClass {
  id: string;            // machine tag
  name: string;          // human title
  summary: string;       // one-sentence attack shape
  probeable: boolean;    // can the local-fork pipeline demonstrate it?
  lesson: string;        // what a secure implementation must do instead
}

/** The 14 cross-chain classes from the LayerZero/Immunefi threat model. */
export const LZ_CLASSES: LzClass[] = [
  {
    id: "lz-endpoint-replay", name: "Endpoint packet-hash lifecycle / re-staging",
    summary: "A consumed nonce can be re-staged with a fresh payload hash in the endpoint — one permissionless lzReceive then replays the side effect (KelpDAO rsETH class, Apr 2026, ~$290M).",
    probeable: true,
    lesson: "The packet-hash lifecycle is the defense, not the OApp peer check: a nonce must be verifiable exactly once (consumed => never re-stage), delivery clears the staged hash BEFORE the side effect, and OApps keep an independent claim-once guard (defense in depth). See src/lz/LzEndpointTestbed.sol + test/11_LayerZeroEndpointCore.t.sol.",
  },
  {
    id: "lz-message-replay", name: "Cross-chain message replay",
    summary: "Same (srcEid, sender, nonce, payload) executes twice — double payout on payment-style OApps.",
    probeable: true,
    lesson: "Consume the nonce atomically with the side effect (check nonce > inboundNonce BEFORE mutating, store first).",
  },
  {
    id: "lz-nonce-ordering", name: "Nonce-ordering bypass",
    summary: "App assumes sequential delivery; out-of-order/duplicate/gapped nonces corrupt state or skip checks.",
    probeable: true,
    lesson: "Never assume ordering — validate (srcEid, sender, nonce) as an unordered key with explicit gap handling.",
  },
  {
    id: "lz-oft-accounting", name: "OFT token accounting / decimals",
    summary: "amountLD/amountSD conversion and dual-ledger credit can mint twice, lock, or lose tokens on failure paths.",
    probeable: true,
    lesson: "Debit source BEFORE credit destination semantics; handle failed delivery with explicit refund/queue, test 6↔18 decimals and dust.",
  },
  {
    id: "lz-compose-reentrancy", name: "Compose-message reentrancy",
    summary: "lzReceive→lzCompose chains let a malicious composer reenter before state updates.",
    probeable: true,
    lesson: "Complete all state changes before compose; add reentrancy guards across the receive/compose pair.",
  },
  {
    id: "lz-malicious-destination", name: "Malicious destination / failed delivery",
    summary: "Reverting lzReceive, gas bombs, or reentry can wedge queues or strand retry state.",
    probeable: true,
    lesson: "Handle non-blocking delivery (try/catch + NativeDrop/queue) and make retries idempotent.",
  },
  {
    id: "lz-sender-authz", name: "Unauthorized sender / peer bypass",
    summary: "Validating only srcEid (or only sender), or casting bytes32(0)→address(0) as 'valid', lets forged origins execute.",
    probeable: true,
    lesson: "Require BOTH srcEid and sender to equal the configured peer for every inbound message, no zero exceptions.",
  },
  {
    id: "lz-dvn-config", name: "DVN / security-stack misconfiguration",
    summary: "Single-DVN stacks, low thresholds, or config changes mid-flight deliver messages under weaker security than intended.",
    probeable: false,
    lesson: "Enforce required DVN counts/thresholds on both chains; block sends when configs diverge; timelock config changes.",
  },
  {
    id: "lz-library-versioning", name: "Message-library version mismatch",
    summary: "Send/receive library drift or migration with pending messages authenticates under the wrong rules.",
    probeable: false,
    lesson: "Pin library versions per chain, drain pending messages before migration, verify both sides agree.",
  },
  {
    id: "lz-gas-griefing", name: "Gas griefing / executor options",
    summary: "Malformed options or gas floors let attackers strand user messages or drain executor allowances.",
    probeable: false,
    lesson: "Validate option encoding, set sane gas ceilings, never let one user's message block others.",
  },
  {
    id: "lz-governance-bridge", name: "Cross-chain governance replay",
    summary: "Governance messages replayed, expired, or executed out-of-order control upgrades/treasury cross-chain.",
    probeable: true,
    lesson: "Bind governance messages to (nonce, expiry, chain pair) and consume them exactly once with timelocks.",
  },
  {
    id: "lz-address-encoding", name: "Address-format / eid confusion",
    summary: "Non-EVM address encodings and eid-vs-chainId confusion break peer equality checks.",
    probeable: true,
    lesson: "Canonicalize remote addresses to bytes32 before comparing; never compare raw strings or mixed widths.",
  },
  {
    id: "lz-upgrade-init", name: "Upgrade / initialization gaps",
    summary: "Uninitialized implementations, double-init, or unprotected setPeer let anyone rewire the bridge.",
    probeable: true,
    lesson: "Initializable + initializer modifier on every proxy path, access-controlled config, storage-layout review.",
  },
];

/** Triage hint lines for a target that exposes an lzReceive-style surface. */
/** Seed the 12 cross-chain classes into long-term memory once. Idempotent:
 * skips when an lz-class lesson is already stored (the daemon boots often). */
export async function seedLzKnowledge(): Promise<number> {
  try {
    const existing = await memoryRecall("threat class lz-message-replay LayerZero", 1);
    if (existing.some((m) => m.includes("threat class lz-"))) return 0;
  } catch {
    return 0; // memory unavailable — skip silently
  }
  let n = 0;
  for (const c of LZ_CLASSES) {
    memoryRemember(
      `LayerZero threat class ${c.id} (${c.name}): ${c.summary} Secure pattern: ${c.lesson} ` +
        `Probeable on local fork: ${c.probeable ? "yes" : "no — needs infra/OSINT context"}.`,
      { kind: "lz-class", class: c.id }
    );
    n++;
  }
  return n;
}
export function lzTriageHints(selectors: string[]): string[] {
  const hints: string[] = [];
  const hasV2 = selectors.includes("lzReceiveV2") || selectors.includes("oAppVersion");
  const hasV1 = selectors.includes("lzReceiveV1") || selectors.includes("trustedRemote");
  if (hasV2 || hasV1) {
    hints.push(
      "LayerZero OApp inbound surface detected: the vulnerability classes that matter are (a) inbound " +
      "authorization — lzReceive must require Origin.srcEid AND Origin.sender to match the configured peer " +
      "exactly (watch for empty/bytes32(0) peers or sender-vs-peer comparison omissions), (b) replay — " +
      "nonce consumption must gate execution, not just be recorded, (c) compose reentrancy if lzCompose " +
      "chaining exists. Class tags: lz-sender-authz, lz-message-replay, lz-compose-reentrancy."
    );
  }
  if (selectors.includes("setPeer") || selectors.includes("setTrustedRemote")) {
    hints.push(
      "Peer/trusted-remote configuration functions present: check access control — an unprotected setPeer " +
      "lets anyone rewire the trusted sender and then pass lzReceive validation legitimately."
    );
  }
  if (selectors.includes("lzCompose")) {
    hints.push(
      "Compose surface present: receiving a message that triggers further cross-chain work is a reentrancy " +
      "and state-partial-update risk (lz-compose-reentrancy)."
    );
  }
  return hints;
}
