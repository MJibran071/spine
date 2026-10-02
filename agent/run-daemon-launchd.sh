#!/bin/bash
# launchd wrapper for the exploit-lab daemon: logs the REAL exit code and
# captures stderr separately so EX_CONFIG-class mysteries are diagnosable.
export PATH="/Users/jfx/.foundry/bin:/Users/jfx/.local/bin:/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
export HOME="/Users/jfx"
export LAB_FORK_URL="https://eth-mainnet.public.blastapi.io"
export LAB_LLM_DAILY_MAX="2400"
cd /Users/jfx/Desktop/spine/agent
{
  echo "[wrapper] starting $(date) uid=$(id -u) node=$(/Users/jfx/.local/bin/node -v 2>&1)"
} >> /Users/jfx/Desktop/spine/reports/daemon-wrapper.log 2>&1
/Users/jfx/.local/bin/node --experimental-strip-types \
  /Users/jfx/Desktop/spine/agent/src/index.ts daemon \
  --interval 120 --ui --max-attempts 8 --workers 4 --probe-workers 2 \
  --scan-every 6 --gov-every 12 --mainnet-only --no-lab \
  --fork-url https://eth-mainnet.public.blastapi.io
CODE=$?
{
  echo "[wrapper] daemon exited code=$CODE at $(date)"
  # exit 78 = EX_CONFIG — dump what launchd's environment was missing
  if [ "$CODE" -eq 78 ]; then
    echo "[wrapper] EX_CONFIG diagnostic: id=$(id) ; TMPDIR=$TMPDIR ; XPC_SERVICE_NAME=$XPC_SERVICE_NAME"
  fi
} >> /Users/jfx/Desktop/spine/reports/daemon-wrapper.log 2>&1
exit "$CODE"
