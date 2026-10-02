#!/usr/bin/env bash
# Single-instance 24/7 mainnet daemon supervisor.
set -euo pipefail
cd "$(dirname "$0")"

# Kill stale instances (ignore if none).
pkill -f "Desktop/spine/agent.*index.ts" 2>/dev/null || true
pkill -f "anvil --fork-url" 2>/dev/null || true
sleep 2

LOG="../reports/daemon.console.log"
echo "[run-daemon] starting $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
exec ./start.sh daemon >> "$LOG" 2>&1
