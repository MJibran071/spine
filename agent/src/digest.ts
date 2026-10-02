// Daily digest: what the 24/7 hunt actually did in the last N hours, written
// to reports/ so the operator gets a complete picture without tailing logs.
// Everything is sourced from the live bus state — no canned content.
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";
import { snapshot, hydrateFromDisk } from "./bus.ts";

export function writeDigest(hours: number): string {
  const since = Date.now() - hours * 3_600_000;
  // Inside the daemon the bus is live. Standalone, it starts empty — hydrate
  // from the persisted session so the digest reflects reality. The guard
  // (idle + cycle 0) guarantees we never clobber live state with stale disk.
  const pre = snapshot();
  if (pre.mode === "idle" && pre.cycle === 0 && Object.keys(pre.challenges).length === 0) {
    hydrateFromDisk();
  }
  const s = snapshot();
  const recent = s.events.filter((e) => e.t >= since);
  const findings = s.findings.filter((f) => f.t >= since);
  const scans = recent.filter((e) => e.kind === "scan");
  const gov = recent.filter((e) => e.kind === "gov");
  const watch = Object.values(s.watchlist);
  const enlisted = watch.filter((w) => w.enlisted);
  const drafts = existsSync(REPORT_DIR)
    ? readdirSync(REPORT_DIR)
        .filter((f) => f.startsWith("bounty-draft-"))
        .map((f) => ({ name: f, mtime: statSync(join(REPORT_DIR, f)).mtimeMs }))
        .filter((d) => d.mtime >= since)
    : [];

  const lines = [
    "# Hunt Digest",
    "",
    `_window: last ${hours}h — generated ${new Date().toISOString()}_`,
    `_mode: ${s.mode} (cycle ${s.cycle})_`,
    "",
    "## Findings",
    ...(findings.length
      ? findings.map((f) => `- ${new Date(f.t).toISOString()} — ${f.msg}`)
      : ["- none (every probe ran clean or was honestly inconclusive)"]),
    "",
    "## Bounty drafts written",
    ...(drafts.length ? drafts.map((d) => `- ${d.name}`) : ["- none"]),
    "",
    `## Live watchlist (${watch.length} entries, ${enlisted.length} auto-enlisted)`,
    "",
    "| Address | Shape | Finding | Last probe |",
    "|---|---|---|---|",
    ...watch.map(
      (w) =>
        `| ${w.address} | ${w.shape ?? "?"} | ${w.finding ? "**YES**" : "no"} | ${w.lastProbe ? new Date(w.lastProbe).toISOString().slice(0, 16).replace("T", " ") : "never"} |`
    ),
    "",
    `## Scan activity (${scans.length} events)`,
    ...scans.slice(-15).map((e) => `- ${new Date(e.t).toISOString().slice(11, 19)} ${e.msg}`),
    "",
    `## Governance (${gov.length} events)`,
    ...(gov.length ? gov.slice(-5).map((e) => `- ${new Date(e.t).toISOString().slice(11, 19)} ${e.msg}`) : ["- none this window"]),
    "",
    "## Challenge lab status",
    ...Object.values(s.challenges).map((c) => `- ${c.name}: ${c.status}${c.technique ? ` (${c.technique})` : ""}`),
    "",
  ];

  mkdirSync(REPORT_DIR, { recursive: true });
  const date = new Date().toISOString().slice(0, 10);
  const path = join(REPORT_DIR, `DIGEST-${date}.md`);
  writeFileSync(path, lines.join("\n"));
  writeFileSync(join(REPORT_DIR, "DIGEST-LATEST.md"), lines.join("\n"));
  return path;
}
