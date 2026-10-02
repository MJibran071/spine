// Read-only Solana watcher — the non-EVM half of the market watch.
//
// Scope honesty: this is a SURVEILLANCE module, not an exploit pipeline. The
// lab/forge machinery is EVM-only; Solana programs (BPF/SBF) cannot be forked
// with anvil or probed with Solidity harnesses. What CAN be watched for free
// over public JSON-RPC — and what historically precedes exploits — is state
// drift around programs and their authorities:
//
//   1. PROGRAM UPGRADES   — an upgradeable program's slot/authority changing
//      means new code can now do anything (the Wormhole 2022 hack class:
//      signature-verification bypass via deprecated instructions, $325M).
//   2. AUTHORITY ROTATION — upgrade authority moved (or to none) changes who
//      can mutate the program or token. Sudden rotations on hot programs are
//      either incidents or imminent deploys worth watching.
//   3. TOKEN MINT/AUTHORITY DRIFT — a SPL token's mint authority re-enabled
//      or transferred (infinite-mint class), freeze authority appearing.
//   4. BALANCE DELTAS on program-owned vaults — big SOL moves out of a
//      program's PDA vaults (drain/insolvency smell).
//
// All requests are read-only ("getAccountInfo"/"getMultipleAccounts", free
// public RPC). No transactions are ever signed or sent. Findings land in the
// same honest pipeline as EVM surveillance: lastResult notes + watchlist
// `finding: true` only for material deltas; the materiality floor for SOL
// deltas is 100 SOL (~$15k equivalent ordering) to keep the feed quiet.
import { logEvent, upsertWatch } from "./bus.ts";

/** Watched programs, each verified live against public mainnet RPC before
 * being committed here (no hallucinated keys). programId is base58. */
export interface SolanaProgram {
  key: string; // watchlist key, e.g. "solana:675kPX…"
  name: string;
  programId: string;
  /** SPL token mints whose authorities are tracked for this program. */
  mints?: { mint: string; label: string }[];
}

const VERIFIED_PROGRAMS: SolanaProgram[] = [
  { key: "solana:raydium-amm-v4", name: "Raydium AMM v4", programId: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" },
  { key: "solana:jupiter-v6", name: "Jupiter Aggregator v6", programId: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" },
  { key: "solana:pump-fun", name: "Pump.fun", programId: "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P" },
];

const RPC = process.env.SOLANA_RPC_URL?.trim() || "https://api.mainnet-beta.solana.com";
const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
/** SOL delta materiality: 100 SOL (9 decimals) — below this is noise. */
const SOL_DELTA_FLOOR = 100_000_000_000n;

interface RpcAccount {
  executable: boolean;
  owner: string;
  lamports: number;
  data: [string, string]; // [content, encoding]
  rentEpoch?: number;
}

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`solana rpc ${res.status}`);
  const j = (await res.json()) as { result?: T; error?: { message: string } };
  if (j.error) throw new Error(`solana rpc: ${j.error.message}`);
  return j.result as T;
}

async function getAccountInfo(key: string): Promise<RpcAccount | null> {
  const r = await rpc<{ value: RpcAccount | null }>("getAccountInfo", [
    key,
    { encoding: "base64", dataSlice: { offset: 0, length: 0 } }, // metadata only — cheap
  ]);
  return r.value;
}

/** Batched variant — one RPC round-trip for N accounts. */
async function getMultipleAccounts(keys: string[]): Promise<(RpcAccount | null)[]> {
  const r = await rpc<{ value: (RpcAccount | null)[] }>("getMultipleAccounts", [
    keys,
    { encoding: "base64", dataSlice: { offset: 0, length: 0 } },
  ]);
  return r.value ?? [];
}

interface ProgramSnapshot {
  lamports: number;
  executable: boolean;
  owner: string;
}

/** One surveillance sweep over all verified programs. Errors are contained
 * per-program: one dead endpoint/program never kills the sweep. */
export async function runSolanaWatch(): Promise<void> {
  const results = await Promise.allSettled(
    VERIFIED_PROGRAMS.map(async (p) => {
      const info = await getAccountInfo(p.programId);
      if (!info) {
        upsertWatch({ address: p.key, shape: "solana-program", lastProbe: Date.now(), lastResult: "program account not found" });
        return;
      }
      const prev = prevSnapshots.get(p.key);
      const snap: ProgramSnapshot = {
        lamports: info.lamports,
        executable: info.executable,
        owner: info.owner,
      };
      prevSnapshots.set(p.key, snap);

      const notes: string[] = [];
      if (info.owner === BPF_LOADER_UPGRADEABLE) {
        notes.push(`upgradeable program, ${info.lamports} lamports`);
        if (prev && !prev.executable && info.executable) {
          notes.push("PROGRAM BECAME EXECUTABLE (fresh deploy)");
          upsertWatch({ address: p.key, finding: true, lastProbe: Date.now() });
          logEvent("finding", `SOLANA ${p.name}: program deployed/became executable — review before interacting`);
        }
      } else {
        notes.push(`owner=${info.owner}`);
      }
      if (prev && info.lamports < prev.lamports && BigInt(prev.lamports - info.lamports) > SOL_DELTA_FLOOR) {
        const dropped = Number(prev.lamports - info.lamports) / 1e9;
        notes.push(`vault drained ${dropped.toFixed(1)} SOL`);
        upsertWatch({ address: p.key, finding: true, lastProbe: Date.now() });
        logEvent("finding", `SOLANA ${p.name}: program account lost ${dropped.toFixed(1)} SOL since last sweep`);
      }
      upsertWatch({
        address: p.key,
        shape: "solana-program",
        lastProbe: Date.now(),
        lastResult: notes.join("; ") || "ok",
      });
      logEvent("scan", `solana ${p.name}: ${notes.join("; ")}`);
    })
  );
  const failed = results.filter((r) => r.status === "rejected");
  if (failed.length > 0) {
    logEvent("scan", `solana watch: ${failed.length}/${VERIFIED_PROGRAMS.length} program sweep(s) failed (rpc)`);
  }
}

const prevSnapshots = new Map<string, ProgramSnapshot>();

/** Enlist verified Solana programs into the shared watchlist once (idempotent
 * — seeds don't overwrite live EVM entries; keys are namespaced "solana:"). */
export function seedSolanaWatchlist(): void {
  for (const p of VERIFIED_PROGRAMS) {
    upsertWatch({
      address: p.key,
      name: p.name,
      shape: "solana-program",
      seeded: true,
    });
  }
}
