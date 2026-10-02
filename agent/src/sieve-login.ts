// Sieve device login — one interactive run, then the key lives in agent/.env.
//
//   npm run sieve-login
//
// The device-code flow exists so a human approves the key in a browser exactly
// once instead of pasting a secret into a terminal. This script never opens the
// link, never signs in, and never approves: it only prints the verification URL
// + user code and waits.
//
// Phishing defence (attackers have been starting device-code flows themselves
// and talking users into approving the ATTACKER's code), so the whole flow is
// printed with the guardrails spelled out: the tool name is self-reported by
// this client, the code was requested from this machine, and the user must only
// approve a code they started themselves. Approval on the server side is always
// an explicit click and the code expires in 10 minutes and works once.
//
// The accepted api_key is written straight into the project's secret store
// (agent/.env — already gitignored) as SIEVE_API_KEY and is never printed,
// logged, or echoed: the only things that reach stdout are the verification URL,
// the user code, and the key's NAME and LENGTH.
//
// `--paste` is the documented fallback for a deployment where the device
// endpoint is unavailable: create the key in the app (Settings -> API keys, it
// is shown once) and pipe it in — `pbpaste | npm run sieve-login -- --paste` —
// so it never appears in argv, shell history, or the transcript.
import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { hostname } from "node:os";
import { LAB_ROOT } from "./config.ts";
import { sieveBaseUrl, sleep, sieveKey } from "./sieve.ts";

export const SIEVE_CLIENT_NAME = "exploit-lab-agent";

/** The dotenv file the key is written to (agent/.env — gitignored). Overridable
 * so a test can prove the writer against a scratch store. */
export function sieveEnvPath(): string {
  return (process.env.LAB_SIEVE_ENV_FILE ?? "").trim() || join(LAB_ROOT, "agent", ".env");
}

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

function detailOf(body: unknown, fallback: string): string {
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    const e = b.error;
    if (typeof e === "string") return e;
    if (e && typeof e === "object" && typeof (e as Record<string, unknown>).message === "string") {
      return (e as Record<string, unknown>).message as string;
    }
    if (typeof b.message === "string") return b.message;
  }
  return fallback;
}

async function postJson(path: string, payload: unknown): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${sieveBaseUrl()}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text().catch(() => "");
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

export async function requestDeviceCode(clientName = SIEVE_CLIENT_NAME): Promise<DeviceCodeResponse> {
  const { status, body } = await postJson("/api/auth/device/code", { client_name: clientName });
  if (status >= 300) throw new Error(`device code request failed (HTTP ${status}): ${detailOf(body, "unknown error")}`);
  const b = (body ?? {}) as Record<string, unknown>;
  const dc = typeof b.device_code === "string" ? b.device_code : "";
  const uc = typeof b.user_code === "string" ? b.user_code : "";
  if (!dc || !uc) throw new Error("device code request returned no device_code/user_code");
  return {
    device_code: dc,
    user_code: uc,
    verification_uri: typeof b.verification_uri === "string" ? b.verification_uri : `${sieveBaseUrl()}/device`,
    verification_uri_complete: typeof b.verification_uri_complete === "string" ? b.verification_uri_complete : "",
    expires_in: typeof b.expires_in === "number" ? b.expires_in : 600,
    interval: typeof b.interval === "number" && b.interval > 0 ? b.interval : 5,
  };
}

export type TokenPoll =
  | { kind: "approved"; apiKey: string; keyName?: string; tokenType?: string }
  | { kind: "pending" }
  | { kind: "slow_down" }
  | { kind: "denied" }
  | { kind: "expired" }
  | { kind: "error"; message: string };

/** One POST /api/auth/device/token. Never retried on a timeout — the token is
 * issued exactly once, so a retry after an unknown outcome could look like a
 * reuse; a fresh poll is the honest move. */
export async function pollDeviceToken(deviceCode: string): Promise<TokenPoll> {
  const { status, body } = await postJson("/api/auth/device/token", { device_code: deviceCode });
  const b = (body ?? {}) as Record<string, unknown>;
  if (status === 200 || (status < 300 && typeof b.api_key === "string")) {
    const apiKey = typeof b.api_key === "string" ? b.api_key : "";
    if (!apiKey) return { kind: "error", message: "approved response carried no api_key" };
    return {
      kind: "approved",
      apiKey,
      keyName: typeof b.key_name === "string" ? b.key_name : undefined,
      tokenType: typeof b.token_type === "string" ? b.token_type : undefined,
    };
  }
  const err = typeof b.error === "string" ? b.error : "";
  switch (err) {
    case "authorization_pending":
      return { kind: "pending" };
    case "slow_down":
      return { kind: "slow_down" };
    case "access_denied":
      return { kind: "denied" };
    case "expired_token":
      return { kind: "expired" };
    default:
      return { kind: "error", message: `HTTP ${status}${err ? ` ${err}` : ""}: ${detailOf(body, "unknown error")}` };
  }
}

/**
 * Write (or replace) one KEY=value line in a dotenv-format secret store.
 * Atomic (tmp + rename) so a crash cannot leave a half-written .env, and the
 * VALUE is never returned or logged — only whether it changed.
 */
export function upsertEnvKey(envPath: string, name: string, value: string): { changed: boolean; created: boolean } {
  let text = "";
  let existed = false;
  let mode = 0o600;
  try {
    if (existsSync(envPath)) {
      text = readFileSync(envPath, "utf8");
      existed = true;
      mode = statSync(envPath).mode & 0o777;
    }
  } catch {
    /* unreadable existing file: fall through and write it fresh */
  }
  // dotenv files break on unquoted whitespace / comment characters.
  const encoded = /[\s#'"]/.test(value) ? `"${value.replace(/"/g, '\\"')}"` : value;
  const lines = text.length > 0 ? text.split("\n") : [];
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  let found = false;
  const re = new RegExp(`^\\s*(export\\s+)?${name}\\s*=`);
  const next = lines.map((l) => {
    if (!re.test(l)) return l;
    found = true;
    return `${name}=${encoded}`;
  });
  if (!found) next.push(`${name}=${encoded}`);
  const out = `${next.join("\n")}\n`;
  if (existed && out === text) return { changed: false, created: false };
  const tmp = `${envPath}.tmp`;
  writeFileSync(tmp, out, { mode });
  renameSync(tmp, envPath);
  return { changed: true, created: !existed };
}

function printInstructions(dc: DeviceCodeResponse, clientName: string): void {
  const where = `${hostname()} (this machine)`;
  console.log("\n──────────────────────────────────────────────────────────────");
  console.log(" Approve this Sieve key in your browser — nothing is opened for you.");
  console.log("──────────────────────────────────────────────────────────────");
  console.log(`\n  1. Open:  ${dc.verification_uri_complete || dc.verification_uri}`);
  console.log(`  2. Sign in or sign up (Google or email).`);
  console.log(`  3. Check the page shows code:  ${dc.user_code}`);
  console.log(`  4. Click Approve.\n`);
  console.log(`  Code expires in ${Math.round(dc.expires_in / 60)} minutes and works once.`);
  console.log(`  Requested from: ${where}`);
  console.log(`  Tool name:      ${clientName}  (self-reported by this client, not verified by Sieve)`);
  console.log("");
  console.log("  ONLY approve a code you started yourself, in THIS terminal.");
  console.log("  If you did not just run npm run sieve-login, do not approve — someone");
  console.log("  else may have asked Sieve for that code. Decline instead.");
  console.log("");
}

export interface LoginResult {
  apiKey: string;
  keyName?: string;
  deviceCode: DeviceCodeResponse;
}

/**
 * Run the whole device flow. Prints the verification URL and polls until the
 * user approves. `expired_token` restarts the flow (bounded) per the contract;
 * `slow_down` adds 5s to the interval.
 */
export async function deviceLogin(opts: { clientName?: string; maxRestarts?: number } = {}): Promise<LoginResult> {
  const clientName = opts.clientName ?? SIEVE_CLIENT_NAME;
  const maxRestarts = opts.maxRestarts ?? 2;
  for (let round = 0; round <= maxRestarts; round++) {
    const dc = await requestDeviceCode(clientName);
    printInstructions(dc, clientName);
    console.log(`  Polling every ${dc.interval}s… (Ctrl-C to cancel)`);
    const deadline = Date.now() + dc.expires_in * 1000;
    let interval = dc.interval;
    while (Date.now() < deadline) {
      await sleep(interval * 1000);
      const r = await pollDeviceToken(dc.device_code);
      if (r.kind === "approved") return { apiKey: r.apiKey, keyName: r.keyName, deviceCode: dc };
      if (r.kind === "denied") throw new Error("access_denied — you declined the code. Nothing was stored; re-run when you want to approve one.");
      if (r.kind === "slow_down") {
        interval += 5;
        continue;
      }
      if (r.kind === "expired") {
        console.log("\n  The code expired before it was approved — starting over with a fresh code.");
        break;
      }
      if (r.kind === "pending") continue;
      throw new Error(r.message);
    }
    if (Date.now() >= deadline && round === maxRestarts) throw new Error(`device code expired (${Math.round(dc.expires_in / 60)} min) without approval`);
  }
  throw new Error("device login did not complete");
}

/** Read the whole of stdin (one line is used). Never echoed. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.from(c as Uint8Array));
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const nameIdx = args.indexOf("--client-name");
  const clientName = nameIdx >= 0 ? args[nameIdx + 1] || SIEVE_CLIENT_NAME : SIEVE_CLIENT_NAME;

  // Fallback path, exactly as the API docs describe it: the user creates a key
  // in the app (Settings -> API keys, shown once) and pipes it in. Same secret
  // store, same writer, and still never printed: useful when the device
  // endpoint is unavailable for this deployment.
  if (args.includes("--paste") || args.includes("--key-stdin")) {
    const key = (await readStdin())
      .split(/\r?\n/)
      .map((s) => s.trim())
      .find((s) => s.length > 0) ?? "";
    if (key.length < 20 || /\s/.test(key)) {
      console.error("No usable key on stdin. Create one in the app under Settings -> API keys, then: pbpaste | npm run sieve-login -- --paste");
      return 1;
    }
    const envPath = sieveEnvPath();
    const { created } = upsertEnvKey(envPath, "SIEVE_API_KEY", key);
    console.log(`SIEVE_API_KEY ${created ? "written to" : "updated in"} agent/.env (${key.length} characters). The value was never printed and agent/.env is gitignored.`);
    console.log("Next: `npm run sieve -- status` to confirm the store is wired up.");
    return 0;
  }

  if (sieveKey().length > 0 && !args.includes("--force")) {
    console.log("SIEVE_API_KEY is already set (agent/.env or the environment). Re-run with --force to replace it.");
    return 0;
  }
  try {
    const r = await deviceLogin({ clientName });
    const envPath = sieveEnvPath();
    const { created } = upsertEnvKey(envPath, "SIEVE_API_KEY", r.apiKey);
    console.log(`\nApproved${r.keyName ? ` — key "${r.keyName}"` : ""}.`);
    console.log(`SIEVE_API_KEY ${created ? "written to" : "updated in"} agent/.env (${r.apiKey.length} characters). The value was never printed and is not in git (.env is ignored).`);
    console.log("Next: `npm run sieve -- status` to confirm the store is wired up.");
    return 0;
  } catch (e) {
    console.error(`\nsieve login failed: ${(e as Error).message}`);
    console.error("If the device endpoint is unavailable on this deployment, create a key in the app");
    console.error("(Settings -> API keys, shown once) and store it without echoing it:");
    console.error("  pbpaste | npm run sieve-login -- --paste");
    return 1;
  }
}

const isMain = process.argv[1] && basename(process.argv[1]) === "sieve-login.ts";
if (isMain) process.exit(await main());
