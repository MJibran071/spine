#!/usr/bin/env bash
# Start the exploit-lab agent + live dashboard.
# Usage:
#   ./start.sh                # one lab run + dashboard (practice mode)
#   ./start.sh daemon         # 24/7 MAINNET hunt (default — no demo/lab noise)
#   ./start.sh lab            # explicit lab-only run + dashboard
#
# Dashboard: http://127.0.0.1:7333 (read-only, loopback only).
# Optional env: LAB_FORK_URL (fork RPC; default blastapi — set a PRIVATE
#   endpoint like Alchemy/Infura for reliability), LAB_WATCH_POOL (default
#   Aave V2), LAB_WEBHOOK_URL (findings webhook: Slack/Discord/phone).
set -euo pipefail
cd "$(dirname "$0")"

# ── Load .env if present (dotenv not bundled; source it manually) ──────────
if [ -f ".env" ]; then
  set -o allexport
  # shellcheck disable=SC1091
  source .env
  set +o allexport
fi

export PATH="$HOME/.foundry/bin:$PATH"
RPC="${LAB_FORK_URL:-https://eth-mainnet.public.blastapi.io}"
WATCH_POOL="${LAB_WATCH_POOL:-0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9}"

# ── Wire API keys from .env into the variables the agent actually reads ────
if [ -z "${LAB_LLM_KEY:-}" ]; then
  for k in GROQ_API_KEY GROQ_API_KEY_2 GROQ_API_KEY_3 GROQ_API_KEY_4 GROQ_API_KEY_5 GROQ_API_KEY_6 \
           OPENROUTER_API_KEY OPENROUTER_API_KEY_2 OPENROUTER_API_KEY_3; do
    v="${!k:-}"
    if [ -n "$v" ]; then
      export LAB_LLM_KEY="$v"
      break
    fi
  done
fi
if [ -z "${LAB_LLM_URL:-}" ] && [ -n "${GROQ_API_KEY:-}" ]; then
  export LAB_LLM_KEY="${LAB_LLM_KEY:-$GROQ_API_KEY}"
  export LAB_LLM_URL="https://api.groq.com/openai/v1/chat/completions"
  export LAB_LLM_MODEL="${LAB_LLM_MODEL:-openai/gpt-oss-120b}"
elif [ -z "${LAB_LLM_URL:-}" ]; then
  export LAB_LLM_URL="https://openrouter.ai/api/v1/chat/completions"
  export LAB_LLM_MODEL="${LAB_LLM_MODEL:-google/gemma-3-27b-it:free}"
fi

export LAB_ETHERSCAN_KEY="${LAB_ETHERSCAN_KEY:-}"

echo "[start.sh] LLM key set: $([ -n "${LAB_LLM_KEY:-}" ] && echo yes || echo NO — triage disabled)"
echo "[start.sh] LLM url   : ${LAB_LLM_URL:-}"
echo "[start.sh] LLM model : ${LAB_LLM_MODEL:-}"
echo "[start.sh] Fork RPC  : $RPC"

MODE="${1:-daemon}"

if [ "$MODE" = "lab" ]; then
  echo "Starting lab practice run + dashboard..."
  echo
  exec node --experimental-strip-types src/index.ts lab --ui
fi

if [ "$MODE" = "daemon" ]; then
  echo "Starting 24/7 MAINNET hunt + live dashboard..."
  echo "  mode      : mainnet-only (no lab/demo)"
  echo "  watchlist : $WATCH_POOL (Aave V2 LendingPool — plus auto-enlisted vaults)"
  echo "  fork rpc  : $RPC (anvil forks read-only; agent stays on 127.0.0.1)"
  echo "  rotation  : 9 chains, every cycle, top-${LAB_SCAN_TOP:-10} probes"
  echo "  workers   : ${LAB_PROBE_WORKERS:-4} parallel fork probes"
  echo "  interval  : ${LAB_INTERVAL:-45}s between cycles"
  echo "  instance  : ${LAB_DAEMON_ID:-default} (dashboard :${LAB_UI_PORT:-7333} — auto-increments if busy)"
  echo
  exec node --experimental-strip-types src/index.ts daemon \
    --mainnet-only \
    --daemon-id "${LAB_DAEMON_ID:-default}" \
    --ui-port "${LAB_UI_PORT:-7333}" \
    --interval "${LAB_INTERVAL:-45}" --ui \
    --max-attempts 8 \
    --workers "${LAB_WORKERS:-4}" \
    --probe-workers "${LAB_PROBE_WORKERS:-4}" \
    --scan-every "${LAB_SCAN_EVERY:-1}" \
    --scan-top "${LAB_SCAN_TOP:-8}" \
    --scan-blocks "${LAB_SCAN_BLOCKS:-60000}" \
    --gov-every "${LAB_GOV_EVERY:-3}" \
    --osint-every "${LAB_OSINT_EVERY:-12}" \
    --digest-hours "${LAB_DIGEST_HOURS:-12}" \
    --respond "${LAB_RESPOND:-1}" \
    --fork-url "$RPC" \
    --watch "$WATCH_POOL"
fi

echo "Unknown mode: $MODE (use: daemon | lab)"
exit 1
