// Out-of-band notification for REAL findings — the moment the hunt turns
// something up, the user hears about it without tailing a log. Two channels:
//   1. macOS desktop notification (osascript — free, local, no deps)
//   2. Optional webhook (LAB_WEBHOOK_URL) for phone/remote alerting
// Everything here is best-effort: a notification failure must NEVER be able
// to kill the hunt (same doctrine as the bus's persistence guard).
import { execFile } from "node:child_process";

let lastNotifyAt = 0;
const MIN_GAP_MS = 60_000; // never spam: at most one ping per minute

export async function notifyFinding(title: string, body: string): Promise<void> {
  const now = Date.now();
  if (now - lastNotifyAt < MIN_GAP_MS) return;
  lastNotifyAt = now;

  // Desktop (macOS). Silently a no-op elsewhere or when osascript fails.
  try {
    if (process.platform === "darwin") {
      execFile("osascript", ["-e", `display notification ${JSON.stringify(body.slice(0, 200))} with title ${JSON.stringify(title)} sound name "Glass"`]);
    }
  } catch {
    // ignore — never kill the hunt over a notification
  }

  // Webhook (Slack/Discord/phone via LAB_WEBHOOK_URL). Payload shape is kept
  // generic: { content } works for Discord; Slack accepts { text } — send both.
  const url = process.env.LAB_WEBHOOK_URL?.trim();
  if (url && /^https?:\/\//.test(url)) {
    try {
      await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ content: `**${title}**\n${body.slice(0, 400)}`, text: `**${title}**\n${body.slice(0, 400)}` }),
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      // ignore
    }
  }
}
