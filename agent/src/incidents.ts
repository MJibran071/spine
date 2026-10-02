// EVM incident surveillance — the twin of the Solana watcher. Scans recent
// logs of watched targets for ADMIN-PLANE state changes: ownership transfers,
// proxy upgrades, admin changes, role grants. This is the "something just
// changed, watch this protocol" signal: the upgrade/config window is where
// most live exploitability appears (new code, new keys, new permissions),
// and it is invisible to shape recon and spot probes.
//
// Read-only over the same free endpoints the scanner uses. Nothing here
// executes anything on-chain. Findings are surveillance notes, NOT drain
// findings — they set watchlist flags and surface in the feed for attention.
import { logEvent, upsertWatch, snapshot } from "./bus.ts";
import { notifyFinding } from "./notify.ts";
import { getLogsWithFailover, type ChainSpec, CHAINS } from "./scan.ts";

// Event topics (cast keccak-verified at build time, see repo history;
// timelock/pause topics re-verified 2026-09-17 via `cast sig-event`):
const TOPICS = {
  ownership: "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0", // OwnershipTransferred(address,address)
  upgraded: "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b", // Upgraded(address)
  adminChanged: "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f", // AdminChanged(address,address)
  roleGranted: "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d", // RoleGranted(bytes32,address,address)
  roleRevoked: "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b", // RoleRevoked(bytes32,address,address)
  callScheduled: "0xc79899d0c7e1d377f7cf56e2bab27419b4a5fc3c3a856d7977533544842ab318", // CallScheduled(bytes32,uint256,address,bytes,bytes32,uint256)
  paused: "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258", // Paused(address)
  unpaused: "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa", // Unpaused(address)
} as const;

const LABELS: Record<string, string> = {
  [TOPICS.ownership]: "ownership transfer",
  [TOPICS.upgraded]: "PROXY UPGRADE (new implementation)",
  [TOPICS.adminChanged]: "proxy admin change",
  [TOPICS.roleGranted]: "role granted",
  [TOPICS.roleRevoked]: "role revoked",
  [TOPICS.callScheduled]: "TIMELOCK CALL SCHEDULED (upgrade/config window open)",
  [TOPICS.paused]: "contract PAUSED",
  [TOPICS.unpaused]: "contract UNPAUSED",
};

/** Events worth an out-of-band ping to the operator. A scheduled timelock
 * call on a watched target means new code/config is INBOUND — the window
 * where exploitability changes and first responders earn premiums. A pause is
 * either defense (something went wrong) or prep for an upgrade; both matter. */
const NOTIFY_TOPICS = new Set([TOPICS.upgraded, TOPICS.callScheduled, TOPICS.paused]);

/** Watched targets grouped by the chain they live on. Watchlist keys for EVM
 * targets are either bare addresses (Ethereum enlistment) or "chain:0x…" /
 * "chainName:0x…" labels; Solana keys ("solana:…") are skipped. */
function targetsByChain(): Map<ChainSpec, string[]> {
  const byName = new Map(CHAINS.map((c) => [c.name.toLowerCase(), c]));
  const out = new Map<ChainSpec, Set<string>>();
  for (const [key, w] of Object.entries(snapshot().watchlist)) {
    if (!key.includes("0x")) continue;
    const [chainPart, addr] = key.includes(":") ? [key.slice(0, key.indexOf(":")), key.slice(key.indexOf(":") + 1)] : ["ethereum", key];
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) continue;
    const chain = byName.get(chainPart.toLowerCase()) ?? (chainPart === "ethereum" || !key.includes(":") ? byName.get("ethereum") : undefined);
    if (!chain) continue; // unknown chain label — the sharded scanner owns those
    if (!out.has(chain)) out.set(chain, new Set());
    out.get(chain)!.add(addr.toLowerCase());
  }
  return new Map([...out.entries()].map(([c, s]) => [c, [...s]]));
}

/** One sweep pass. Returns the number of upgrade incidents seen. Per-chain
 * failures are contained: one dead endpoint never kills the sweep. */
export async function runIncidentSweep(blocksBack = 3_000): Promise<number> {
  const byChain = targetsByChain();
  let incidents = 0;
  const sweeps = [...byChain.entries()].map(async ([chain, addrs]) => {
    if (addrs.length === 0) return;
    // Chunk addresses (eth_getLogs accepts bounded address lists). The failover
    // helper computes fromBlock from its own tip read and shrinks the window
    // automatically when endpoints reject deep queries.
    for (let i = 0; i < addrs.length; i += 40) {
      const chunk = addrs.slice(i, i + 40);
      try {
        const { logs } = await getLogsWithFailover(chain, {
          address: chunk,
          topics: [[TOPICS.ownership, TOPICS.upgraded, TOPICS.adminChanged, TOPICS.roleGranted, TOPICS.roleRevoked, TOPICS.callScheduled, TOPICS.paused, TOPICS.unpaused]],
        }, blocksBack);
        for (const log of logs) {
          const topic = (log.topics ?? [])[0]?.toLowerCase() ?? "";
          const label = LABELS[topic] ?? topic.slice(0, 18);
          const bn = BigInt(log.blockNumber).toString();
          const key = Object.entries(snapshot().watchlist).find(([k]) => k.toLowerCase().includes(log.address.toLowerCase()))?.[0] ?? log.address;
          const newImpl = topic === TOPICS.upgraded ? ` -> ${"0x" + (log.topics?.[1] ?? "").slice(-40)}` : "";
          // A timelock schedule names the implementation contract being called
          // (topics[3] for CallScheduled) — surfacing it makes the row
          // actionable ("which contract is about to change").
          const schedTarget = topic === TOPICS.callScheduled && log.topics?.[3] ? ` target ${"0x" + log.topics[3].slice(-40)}` : "";
          upsertWatch({
            address: key,
            lastResult: `incident @ block ${bn}: ${label}${newImpl}${schedTarget} (tx ${String(log.transactionHash).slice(0, 14)}…)`,
            lastProbe: Date.now(),
          });
          logEvent("scan", `incident-watch ${chain.name}: ${key.slice(0, 22)}… — ${label}${newImpl}${schedTarget} @ block ${bn}`);
          if (topic === TOPICS.upgraded) incidents++;
          if (NOTIFY_TOPICS.has(topic)) {
            void notifyFinding(
              `Admin-plane event on watched protocol`,
              `${key.slice(0, 22)}… (${chain.name}): ${label}${newImpl}${schedTarget} at block ${bn}`
            );
          }
        }
      } catch {
        // endpoint refused the batch (too wide / rate limit) — next pass retries
      }
      await new Promise((r) => setTimeout(r, 250)); // stay under burst limits
    }
  });
  await Promise.allSettled(sweeps);
  return incidents;
}
