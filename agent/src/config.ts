// Central config for the lab agent.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Repository root (agent/src -> agent -> root). */
export const LAB_ROOT = resolve(here, "..", "..");

/** Minimal .env loader: start.sh sources agent/.env, but direct node
 * invocations (CLI modes, hand-started daemons) never see those variables.
 * Load the file ourselves, once, at import time — without overriding anything
 * already present in the real environment (exported vars always win). */
function loadDotEnv(): void {
  try {
    const p = join(LAB_ROOT, "agent", ".env");
    if (!existsSync(p)) return;
    for (const raw of readFileSync(p, "utf8").split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (key && process.env[key] === undefined) process.env[key] = val;
    }
  } catch {
    /* .env is optional — never block startup on it */
  }
}
loadDotEnv();

/** Foundry binaries installed under ~/.foundry/bin. */
export const FOUNDRY_BIN = join(homedir(), ".foundry", "bin");

/** `LAB_OFFLINE=1` makes every optional outbound call (DefiLlama hacks priors,
 * the mem0 sidecar, external caches) a no-op, so tests and air-gapped runs are
 * deterministic and cannot write into live stores. Core hunting is unaffected:
 * forked RPC access and the triage endpoint are still used when configured. */
export const OFFLINE = process.env.LAB_OFFLINE === "1";

/** Agent-generated test output dir + report dir. `LAB_REPORT_DIR` retargets
 * the report/state directory so tests can run against a scratch store instead
 * of overwriting the live hunt's state.json (default unchanged).
 * `LAB_AGENT_TEST_DIR` does the same for generated harnesses: forge compiles
 * the whole `test/agent` tree in one pass, so a test must never write a probe
 * harness into the live tree the running fleet is compiling. */
export const AGENT_TEST_DIR = process.env.LAB_AGENT_TEST_DIR?.trim() || join(LAB_ROOT, "test", "agent");
export const REPORT_DIR = process.env.LAB_REPORT_DIR?.trim() || join(LAB_ROOT, "reports");

/** Max attempts per challenge in the mutation loop. */
export const MAX_ATTEMPTS = 3;

/** Payout address written into bounty reports as the researcher's reward
 * destination. This is where a bounty PROGRAM sends a reward — the agent
 * itself never moves funds and nothing here is ever broadcast. Override with
 * LAB_BOUNTY_PAYOUT env var. */
export const BOUNTY_PAYOUT_ADDRESS = (process.env.LAB_BOUNTY_PAYOUT ?? "0xA214A65F599063bF29c6110d94d4FB7d463685A8").trim();

/** Basic sanity check for the configured payout address (format only). */
export function payoutAddressValid(): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(BOUNTY_PAYOUT_ADDRESS);
}

/** Production chain IDs the 24/7 hunt treats as real bounty targets. */
export const PRODUCTION_CHAIN_IDS = new Set([
  "1", // Ethereum
  "56", // BNB
  "43114", // Avalanche
  "146", // Sonic
  "100", // Gnosis
  "8453", // Base
  "42161", // Arbitrum
  "10", // Optimism
  "137", // Polygon
  "250", // Fantom
  "42220", // Celo
  "9000", // Evmos
  "59144", // Linea
  "534352", // Scroll
  "80094", // Berachain
  "81457", // Blast
  "999", // HyperEVM (Hyperliquid) — real mainnet id, verified live
  "4663", // Robinhood Chain (Arbitrum Orbit L2) — verified live 2026-09-18: rpc.mainnet.chain.robinhood.com, PancakeSwap V3 factory with 374 live pools
]);

/** Number of parallel daemon instances (run_multiple_daemons.sh). */
export const DAEMON_COUNT = Number(process.env.DAEMON_COUNT ?? 1);

/** Local / test chains — never generate findings or bounty drafts.
 * NOTE: HyperEVM mainnet has chainId 999 (verified live 2026-09-14) — it is a
 * PRODUCTION chain, so 999 must NOT appear here. */
export const LOCAL_CHAIN_IDS = new Set(["31337", "1337", "31338"]);

export function isProductionChain(chainId: string): boolean {
  return PRODUCTION_CHAIN_IDS.has(chainId);
}

/** Default fork source for the daemon/scanner. Free public Ethereum RPCs
 * mostly refuse fork-grade fetches now (2026-09-11 survey: only flashbots
 * still serves them); override with LAB_FORK_URL — a private endpoint
 * (Alchemy/Infura/QuickNode) is strongly recommended for reliability. */
export const DEFAULT_FORK_RPC = process.env.LAB_FORK_URL?.trim() || "https://rpc.flashbots.net";

/** Spawn env with foundry on PATH. */
export function forgeEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PATH: `${FOUNDRY_BIN}:${process.env.PATH ?? ""}`,
  };
}
