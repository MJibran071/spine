// Finding verification pipeline: a probe hit on one fork is a SIGNAL; this
// module decides whether it is a FINDING. Every actionable production hit is
// re-run on N freshly-spawned forks (independent anvil processes, independent
// upstream state). Only when it reproduces on every attempt does the pipeline
// produce evidence + an Immunefi-ready draft + the 🚨 alert. Non-reproducing
// hits are downgraded to monitoring — honest silence instead of a false alarm.
//
// Why 2/2: probe hits can be flukes (mid-reorg state, RPC-cache artifacts,
// transient fork noise). One confirmation run doubles the evidence bar at the
// cost of seconds; the alternative is reporting a ghost to a bounty program.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnForkWithFailover, reconPool, simulateOnFork, type AnvilFork, type ForkFinding, type PoolRecon } from "./fork.ts";
import { isActionableFinding } from "./findings.ts";
import { writeBountyReport } from "./bounty.ts";
import { REPORT_DIR, DEFAULT_FORK_RPC, isProductionChain } from "./config.ts";
import { logEvent, upsertWatch } from "./bus.ts";

export interface VerificationAttempt {
  ok: boolean;
  profitWei: string;
  notes: string;
  blockNumber?: string;
  forkRpc?: string; // upstream RPC the fresh fork boot from
  error?: string;
}

export interface VerificationReport {
  address: string;
  chainId: string;
  technique: string;
  /** True only when EVERY attempt reproduced the actionable finding. */
  confirmed: boolean;
  attempts: VerificationAttempt[];
  bountyPath?: string;
  evidencePath?: string;
  verifiedAt: number;
  note: string;
}

const VERIFY_ATTEMPTS = 2;

async function fetchBlockNumber(localRpc: string): Promise<string | undefined> {
  try {
    const res = await fetch(localRpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
      signal: AbortSignal.timeout(5_000),
    });
    const j = (await res.json()) as { result?: string };
    return j.result ? parseInt(j.result, 16).toString(10) : undefined;
  } catch {
    return undefined;
  }
}

async function fetchChainId(localRpc: string): Promise<string | undefined> {
  try {
    const res = await fetch(localRpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(5_000),
    });
    const j = (await res.json()) as { result?: string };
    return j.result ? BigInt(j.result).toString() : undefined;
  } catch {
    return undefined;
  }
}

/** Verify one actionable production finding on fresh forks and, on 2/2
 * reproduction, write the evidence file + bounty draft. Never throws: all
 * failure modes return a VerificationReport with confirmed=false. */
export async function verifyAndReport(params: {
  poolAddr: string;
  chainId: string;
  finding: ForkFinding;
  recon: PoolRecon; // recon from the ORIGINAL probe fork (shape + selectors)
  forkUrl?: string; // preferred upstream fork source
  label: string; // human label for logs, e.g. "gnosis:0xabc… [hot]"
}): Promise<VerificationReport> {
  const { poolAddr, chainId, finding, recon, label } = params;
  const source = params.forkUrl?.trim() || DEFAULT_FORK_RPC;
  const attempts: VerificationAttempt[] = [];
  let lastRecon: PoolRecon | null = null;

  for (let i = 1; i <= VERIFY_ATTEMPTS; i++) {
    let fork: AnvilFork | null = null;
    try {
      // Fresh anvil process + port (8546+i avoids the daemon's ranges), so
      // the re-probe shares NOTHING with the original hit's environment.
      fork = await spawnForkWithFailover(source, 8546 + i, []);
      const blockNumber = await fetchBlockNumber(fork.localRpc);
      // The fork's OWN chain id must match the claimed one — a caller (or a
      // test) cannot manufacture a production-chain finding by labeling a
      // local-chain fork differently.
      const actualChainId = await fetchChainId(fork.localRpc);
      if (actualChainId !== chainId) {
        attempts.push({ ok: false, profitWei: "0", notes: "", blockNumber, forkRpc: fork.forkUrl, error: `chain id mismatch: fork is ${actualChainId}, claimed ${chainId}` });
        continue;
      }
      const r = await reconPool(fork, poolAddr);
      lastRecon = r;
      const f = await simulateOnFork(fork, r, finding.technique);
      const ok = isActionableFinding(f);
      attempts.push({
        ok,
        profitWei: f.profitWei,
        notes: f.notes.slice(0, 400),
        blockNumber,
        forkRpc: fork.forkUrl,
      });
      if (!ok) {
        attempts[attempts.length - 1]!.error = "not actionable on fresh fork";
      }
    } catch (e) {
      attempts.push({ ok: false, profitWei: "0", notes: "", error: (e as Error).message.slice(0, 200) });
    } finally {
      fork?.stop();
    }
  }

  const confirmed = attempts.length > 0 && attempts.every((a) => a.ok);
  const hits = attempts.filter((a) => a.ok).length;
  const base = { address: poolAddr, chainId, technique: finding.technique, attempts, verifiedAt: Date.now() };

  if (!confirmed) {
    const note = `${label}: probe hit did NOT reproduce on fresh forks (${hits}/${attempts.length}) — downgraded to monitoring, no report`;
    upsertWatch({ address: poolAddr, finding: false, lastResult: `verification failed ${hits}/${attempts.length}: ${attempts.find((a) => !a.ok)?.error ?? attempts.find((a) => !a.ok)?.notes ?? "non-reproducible"}` });
    logEvent("scan", `verification: ${note}`);
    return { ...base, confirmed: false, note };
  }

  // Confirmed: evidence bundle always; the 🚨 alert + bounty draft only on a
  // PRODUCTION chain (read back from the forks themselves, not the caller).
  const evidencePath = writeEvidence(base, lastRecon, source);
  const production = isProductionChain(chainId);
  let bountyPath: string | undefined;
  let draftError: string | undefined;
  if (production) {
    try {
      bountyPath = writeBountyReport(recon ?? lastRecon!, finding, `${source} via verified local fork (2/2 reproduction)`);
    } catch (e) {
      draftError = (e as Error).message;
    }
  }

  const note = `FINDING VERIFIED on ${label} (chain ${chainId}${production ? "" : " — NON-PRODUCTION, lab fixture"}) — 2/2 fresh forks reproduced, ${finding.technique}, profit ${finding.profitWei} wei${bountyPath ? ` — report: ${bountyPath}` : draftError ? ` — draft skipped: ${draftError}` : production ? "" : " — no draft (non-production chain)"}`;
  upsertWatch({ address: poolAddr, finding: production, lastResult: `VERIFIED 2/2 — ${finding.notes.slice(0, 160)}` });
  // Production chains alert; lab-fixture chains land in the lab feed so test
  // runs can never masquerade as hunt findings.
  logEvent(production ? "finding" : "lab", note);
  logEvent("fork", `verification evidence: ${evidencePath}`);

  return { ...base, confirmed: true, bountyPath, evidencePath, note };
}

function writeEvidence(
  base: Omit<VerificationReport, "bountyPath" | "evidencePath">,
  recon: PoolRecon | null,
  source: string
): string {
  const dir = join(REPORT_DIR, "verification");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${base.chainId}-${base.address.slice(0, 14).toLowerCase()}-${base.verifiedAt}.json`);
  writeFileSync(
    path,
    JSON.stringify(
      {
        ...base,
        forkSource: source,
        recon: recon ? { shape: recon.shape, selectors: recon.selectors, chainId: recon.chainId } : null,
        reproduction: {
          tool: "anvil fork + forge sim (agent pipeline)",
          note: "Each attempt spawns a FRESH anvil fork from upstream state and re-runs the technique probe. 2/2 reproduction is the pipeline's bar for a verified finding.",
        },
        disclaimer: "Local fork evidence only. Submit through the project's official bug-bounty program. Never execute against live contracts.",
      },
      null,
      2
    )
  );
  return path;
}
