// Bytecode decompilation via heimdall-rs (https://github.com/Jon-Becker/heimdall-rs).
//
// Targets WITHOUT verified source were untriageable ("no verified source" and
// done). heimdall decompiles raw runtime bytecode into pseudo-Solidity the LLM
// can reason about, converting the biggest blind spot into signal. Fully
// local: the binary does the work, no network beyond the one-time download.
//
// Binary resolution order: LAB_HEIMDALL_PATH env -> PATH -> agent/.bin/heimdall
// (auto-downloaded from the official GitHub release on first use, arm64/amd64
// darwin+linux).
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { REPORT_DIR } from "./config.ts";

const BIN_DIR = join(homedir(), ".local", "share", "heimdall-lab");
const BIN_PATH = join(BIN_DIR, "heimdall");
const DECOMPILE_CACHE_DIR = join(REPORT_DIR, "decompile-cache");

function log(msg: string): void {
  try {
    appendFileSync(join(REPORT_DIR, "daemon.log"), `[decompile] ${msg}\n`);
  } catch { /* best-effort */ }
}

function run(cmd: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(err);
      else resolve(String(stdout ?? "") + (String(stderr ?? "").trim() ? `\n${stderr}` : ""));
    });
  });
}

function pathHeimdall(): string | null {
  return process.env.LAB_HEIMDALL_PATH?.trim() || null;
}

/** Locate or install the heimdall binary. Returns the path, or null when
 * unavailable and installation is refused/failed. Never throws. */
export async function ensureHeimdall(): Promise<string | null> {
  const override = pathHeimdall();
  if (override) return existsSync(override) ? override : null;
  try {
    await run("which", ["heimdall"], 5_000);
    return "heimdall"; // on PATH
  } catch { /* not on PATH */ }
  if (existsSync(BIN_PATH)) return BIN_PATH;
  try {
    const res = await fetch("https://api.github.com/repos/Jon-Becker/heimdall-rs/releases/latest", {
      headers: { "user-agent": "ExploitLab-Agent (read-only release fetch)" },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) return null;
    const rel = (await res.json()) as { assets?: Array<{ name: string; browser_download_url: string }> };
    const platform = process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : null;
    const arch = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "amd64" : null;
    if (!platform || !arch) return null;
    const asset = rel.assets?.find((a) => a.name === `heimdall-${platform}-${arch}`);
    if (!asset) return null;
    log(`installing heimdall from ${asset.browser_download_url} (~40MB, one-time)`);
    const bin = await fetch(asset.browser_download_url, { signal: AbortSignal.timeout(300_000) });
    if (!bin.ok) return null;
    mkdirSync(BIN_DIR, { recursive: true });
    writeFileSync(BIN_PATH, Buffer.from(await bin.arrayBuffer()));
    chmodSync(BIN_PATH, 0o755);
    const version = await run(BIN_PATH, ["--version"], 10_000).catch(() => "?");
    log(`heimdall installed (${version.trim().split("\n")[0] ?? "?"})`);
    return BIN_PATH;
  } catch (e) {
    log(`heimdall install failed: ${(e as Error).message.slice(0, 120)}`);
    return null;
  }
}

/** Decompile runtime bytecode into pseudo-Solidity. Results cached on disk per
 * bytecode hash (decompilation is deterministic + expensive). Null on any
 * failure — callers fall back to raw-hex triage. */
export async function decompileBytecode(bytecodeHex: string, address: string): Promise<string | null> {
  if (!bytecodeHex || bytecodeHex.length < 40) return null; // empty/minimal runtime
  const bin = await ensureHeimdall();
  if (!bin) return null;

  // Deterministic cache key: hash of the bytecode itself (an address can be
  // redeployed with different code; the CODE is the thing we cache).
  let key = "";
  try {
    const { createHash } = await import("node:crypto");
    key = createHash("sha256").update(bytecodeHex).digest("hex").slice(0, 24);
  } catch { key = `${bytecodeHex.length}`; }

  const cacheFile = join(DECOMPILE_CACHE_DIR, `${address.toLowerCase()}-${key}.sol`);
  if (existsSync(cacheFile)) {
    try {
      const cached = readFileSync(cacheFile, "utf8");
      if (cached.length > 50) return cached;
    } catch { /* re-decompile */ }
  }

  // heimdall v0.9 CLI: bytecode is the POSITIONAL target; outputs are files
  // under --output (-o). `-d` auto-accepts default prompts (non-interactive).
  // NOTE: heimdall sometimes exits non-zero (e.g. one function's symbolic
  // execution times out) while still writing a valid decompiled.sol — so the
  // FILE, not the exit status, decides success.
  const workDir = join(tmpdir(), `heimdall-${address.toLowerCase().slice(0, 12)}-${Date.now()}`);
  try {
    await run(bin, ["decompile", bytecodeHex, "-d", "--include-sol", "-o", workDir], 120_000);
  } catch (e) {
    log(`decompile ${address.slice(0, 10)} exited non-zero (${(e as Error).message.slice(0, 80)}); checking output file anyway`);
  }
  const solPath = join(workDir, "decompiled.sol");
  let out: string | null = null;
  try {
    if (existsSync(solPath)) out = readFileSync(solPath, "utf8");
  } catch { /* read raced — treated as failure below */ }
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch { /* temp dir cleanup is best-effort */ }
  if (!out || out.length < 50) {
    log(`decompile ${address.slice(0, 10)} produced no usable output`);
    return null;
  }
  try {
    mkdirSync(DECOMPILE_CACHE_DIR, { recursive: true });
    writeFileSync(cacheFile, out);
  } catch { /* cache failure is non-fatal */ }
  return out;
}
