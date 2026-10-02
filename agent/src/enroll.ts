// Source→classify→register: the on-ramp that turns probe-able watch targets
// (ERC-4626 vaults auto-enlisted by the scanner) into campaign targets.
//
// THE LEAK THIS CLOSES (measured by the funnel, 2026-09-24): 2,437 targets
// probed, ONE with verified source. Known-shape vaults take the template-probe
// path and never reach investigateUnknownShape — so nothing ever classifies
// their code, and nothing ever fuzzes it. This module gives the vault loop a
// cheap pass: fetch verified source (cached by livesrc), classify it into the
// canoncode store, and register an accumulating campaign when the code has a
// custom/fork-delta surface worth fuzzing.
import { classifyTarget, getCanon, type CanonRow } from "./canoncode.ts";
import { upsertCampaign, getCampaign } from "./campaigns.ts";
import { fetchLiveSource } from "./livesrc.ts";
import { buildHarness } from "./genharness.ts";

export interface EnrollResult {
  ok: boolean;
  note: string;
  canon?: CanonRow;
  campaignRegistered?: boolean;
}

/** One target's on-ramp. Never throws; every outcome is a note. */
export async function enrollTargetForCampaign(chainId: string, address: string): Promise<EnrollResult> {
  try {
    // 1. verified source (livesrc caches; repeat calls are disk-cheap)
    let source = "";
    try {
      const live = await fetchLiveSource(chainId, address);
      source = live.source ?? "";
    } catch {
      return { ok: false, note: "source fetch failed (endpoint rate-limit or unverified contract)" };
    }
    if (!source) return { ok: false, note: "no verified source available (unverified bytecode)" };

    // 2. classify (idempotent; refreshes the fleet corpus)
    const canon = classifyTarget(chainId, address, source);

    // 3. register a campaign iff a harness can exist for this shape.
    //    Boilerplate stock code is still classified (funnel honesty) but does
    //    NOT get a campaign: thousands of eyes already test stock code.
    if (canon.codeClass === "boilerplate") {
      return { ok: true, canon, campaignRegistered: false, note: `classified ${canon.codeClass}: ${canon.reason} — no campaign (stock surface)` };
    }
    const gen = buildHarness(
      { challengeName: `enroll-${chainId}-${address.slice(0, 10)}`, sources: [source], mode: "address", bindAddress: address, chainId },
      0
    );
    if (!gen) {
      // Stamp the canon row itself (survives the fleet's genlearn.json
      // last-writer-wins race because classifyTarget rewrites the full row).
      // A re-verified upgrade (different source length) resets the flag.
      try {
        const { patchCanon } = await import("./canoncode.ts");
        patchCanon(chainId, address, { unharnessableSourceLen: source.length });
      } catch { /* best-effort */ }
      return { ok: true, canon, campaignRegistered: false, note: `classified ${canon.codeClass} but no harnessable shape from source` };
    }
    const prev = getCampaign(chainId, address);
    upsertCampaign({ chainId, address, shape: gen.shape });
    return {
      ok: true,
      canon,
      campaignRegistered: true,
      note: `classified ${canon.codeClass} (${canon.reason}) — campaign ${prev ? "already" : "now"} registered (${gen.shape})`,
    };
  } catch (e) {
    return { ok: false, note: `enroll error: ${(e as Error).message.slice(0, 140)}` };
  }
}

/** Convenience: is this target already classified? (callers skip the fetch) */
export function isEnrolled(chainId: string, address: string): boolean {
  return getCanon(chainId, address) !== null;
}
