#!/usr/bin/env bash
# Launch N detached hunt daemons with distinct ids, dashboard ports, and
# chain-scan offsets (so N instances cover different chains first instead of
# scanning in lockstep). Each survives the launching shell (double-fork via
# setsid), logs to reports/daemon-<id>.log, and skips if already running.
#
# Usage: run-multi.sh [N]   (default 8)
# Env overrides: LAB_INTERVAL (cycle seconds, default 45)
set -u
cd "$(dirname "$0")"

N="${1:-8}"
IDS=(mainnet-1 hunt-2 hunt-3 hunt-4 hunt-5 hunt-6 hunt-7 hunt-8)
INTERVAL="${LAB_INTERVAL:-45}"

# Load .env (keys, fork URL, tunables) so direct ./run-multi.sh runs see the
# same config as start.sh. Values already exported in the environment win.
if [ -f ".env" ]; then set -a; . ./.env; set +a; fi

for i in $(seq 0 $((N - 1))); do
  ID="${IDS[$i]:-hunt-$((i + 1))}"
  PORT=$((7333 + i))
  OFFSET="$i"

  # Skip if this id is already hunting. NOTE: BSD pgrep ERE has no \b — use
  # an explicit space/end alternative; the launcher always passes more args
  # after --daemon-id, so the space form matches our own launches.
  if pgrep -f "index.ts daemon.*--daemon-id ${ID}([[:space:]]|$)" >/dev/null 2>&1; then
    echo "skip ${ID} (already running)"
    continue
  fi

  LOG="../reports/daemon-${ID}.log"
  mkdir -p ../reports
  # Double-fork + setsid: fully detached, survives this shell (this is how
  # previous restarts stayed alive through tool timeouts).
  python3 - "$ID" "$PORT" "$OFFSET" "$LOG" "$INTERVAL" "$N" "$i" <<'PYEOF'
import os, sys
did, port, off, log, interval, fleet, idx = sys.argv[1:8]
labflag = [] if idx == "0" else ["--no-lab"]
pid = os.fork()
if pid == 0:
    os.setsid()
    pid2 = os.fork()
    if pid2 == 0:
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        devnull = os.open("/dev/null", os.O_RDONLY)
        os.dup2(devnull, 0)
        env = dict(os.environ)
        env["LAB_DAEMON_ID"] = did
        env["LAB_UI_PORT"] = port
        env["LAB_FLEET_SIZE"] = fleet  # market sharding: index % N == i
        args = [
            "node", "--experimental-strip-types", "src/index.ts", "daemon",
            # Lab+mainnet: challenges train the KB AND mainnet hunting runs.
            # Lab work is SINGLE-OWNER: mainnet-1 (i=0) solves challenges;
            # hunt-2..5 pass --no-lab so the shared test/agent dir never has
            # two fleets compiling/archiving in it (race = misattribution).
            *labflag,
            "--interval", interval, "--ui",
            "--daemon-id", did, "--ui-port", port,
            # RAM guard: 8 daemons x 4 probe-workers = ~32 concurrent anvil
            # forks, which would swap an 8GB Mac into a full hang. 2 per daemon
            # (worst case ~16 transient forks) plus the monitor's 15%-free
            # warning keeps the fleet inside the box.
            "--max-attempts", "8", "--workers", "4", "--probe-workers", "2",
            "--scan-every", "2", "--scan-top", "16", "--scan-blocks", "60000",
            "--gov-every", "3", "--osint-every", "12", "--digest-hours", "12",
            "--respond", "1", "--chain-offset", off,
        ]
        env["LAB_FORK_URL"] = env.get("LAB_FORK_URL", "https://eth-mainnet.public.blastapi.io")
        os.execvpe(args[0], args, env)
    os._exit(0)
os.waitpid(pid, 0)
PYEOF
  echo "launched ${ID} (port ${PORT}, chain-offset ${OFFSET})"
  sleep 2
done
echo "--- running daemons:"
pgrep -fl 'index.ts daemon' | sed 's/ --.*--daemon-id / -> /; s/ --.*//' || true
