// Safety rails for the lab agent.
//
// The agent is permitted to:
//   - run forge test / forge build against the LOCAL workspace
//   - spawn a LOCAL anvil (optionally forked from a read-only remote RPC)
//   - send JSON-RPC to 127.0.0.1 / ::1 / localhost ONLY
// The agent must never:
//   - broadcast transactions to a live chain
//   - handle private keys
//   - talk RPC to any non-local endpoint
export const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0"]);

/** Forbidden flags that could broadcast or sign. (--sender only SELECTS an
 * account — it neither holds nor uses a key — so it stays allowed.) */
const FORBIDDEN_FLAGS = [
  "--broadcast",
  "--private-key",
  "--interactive",
  "--ledger",
  "--trezor",
  "--keystore",
  "--aws-signer",
];

export function isLocalRpc(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    return LOCAL_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

export function assertLocalRpc(url: string, what: string): void {
  if (!isLocalRpc(url)) {
    throw new Error(
      `SAFETY REFUSAL: ${what} must be a local RPC (127.0.0.1/localhost). Got: ${url}\n` +
        `The agent only talks to chains it runs itself. Use --fork-url to let ANVIL fork a remote chain read-only.`
    );
  }
}

export function assertSafeArgs(argv: string[], what: string): void {
  for (const arg of argv) {
    for (const bad of FORBIDDEN_FLAGS) {
      if (arg === bad || arg.startsWith(`${bad}=`)) {
        throw new Error(`SAFETY REFUSAL: ${what} would use forbidden flag "${bad}". The agent cannot broadcast or sign.`);
      }
    }
  }
}

/** Redact credentials embedded in an RPC URL before it lands in ANY artifact
 * (incident reports, daemon logs, digests — all shareable). Private endpoints
 * carry keys in the URL itself (Alchemy style …/v2/<key>), and an incident
 * report is exactly the file that gets pasted into a bounty chat. The host is
 * kept so an operator can still tell WHICH endpoint served the fork. */
export function redactRpcUrl(url: string): string {
  try {
    const u = new URL(url);
    // Path-embedded keys: the last path segment when it looks like a secret
    // (v2/<key>, <key>, api-key-<key>) — keep the path shape, drop the secret.
    const segs = u.pathname.split("/").filter(Boolean);
    if (segs.length > 0) {
      const last = segs[segs.length - 1]!;
      if (/^[A-Za-z0-9_-]{16,}$/.test(last) && !/\.eth$|rpc$/i.test(last)) {
        segs[segs.length - 1] = "<redacted>";
        u.pathname = segs.join("/");
      }
    }
    // Query-embedded keys (?api_key=… / ?key=…) — redact their values.
    for (const p of new Set(u.searchParams.keys())) {
      if (/key|token|secret|password/i.test(p)) u.searchParams.set(p, "<redacted>");
    }
    // URL serialization percent-encodes the marker's angle brackets — restore
    // them so the artifact reads `…/v2/<redacted>`, not `%3Credacted%3E`.
    return u.toString().replace(/%3Credacted%3E/g, "<redacted>").replace(/\/$/, "");
  } catch {
    return "<unparseable-rpc-url>"; // never render an unparseable URL raw
  }
}

/** Self-check printed by `npm run safety`. */
export function safetySummary(): string {
  return [
    "Lab agent safety configuration",
    "------------------------------",
    "RPC allowlist (agent -> chain):  127.0.0.1, localhost, ::1 ONLY",
    "Remote chains:                   forked read-only by ANVIL (never by the agent)",
    "Transaction broadcast:           DISABLED (no --broadcast, no signing path)",
    "Private keys:                    NONE handled; fork sims use anvil impersonation",
    "Attacker funds in sims:          anvil_setBalance (ephemeral, local state)",
    "Findings:                        written to reports/ as bug-bounty drafts",
    "Secret hygiene:                  RPC keys redacted in every report/log line",
    "Legal note:                      draining live pools you do not own is theft;",
    "                                 findings belong in a bug bounty, not a drain.",
  ].join("\n");
}
