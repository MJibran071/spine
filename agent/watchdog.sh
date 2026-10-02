#!/usr/bin/env bash
# Fleet watchdog — runs forever (detached), every WATCHDOG_INTERVAL seconds:
#   1. relaunches any missing daemon via run-multi.sh (it skips live ones)
#   2. kills orphaned anvil forks (parent daemon no longer alive)
#   3. restarts the memory sidecar if it died
#   4. appends one status line to ../reports/watchdog.log
#
# Start:   ./watchdog.sh &   (or via the detached python launcher, below)
# Stop:    pkill -f watchdog.sh
set -u
cd "$(dirname "$0")"
INTERVAL="${WATCHDOG_INTERVAL:-300}"
EXPECTED="${LAB_FLEET_SIZE:-5}"
STALE_SEC="${WATCHDOG_STALE_SEC:-900}"   # beat older than this = daemon hung (cycle loop wedged)

stamp() { date "+%Y-%m-%d %H:%M:%S"; }

while true; do
  alive=$(pgrep -f 'index.ts daemon' 2>/dev/null | wc -l | tr -d ' ')

  # 1. Relaunch missing daemons (run-multi.sh skips ids already running).
  if [ "$alive" -lt "$EXPECTED" ]; then
    echo "$(stamp) watchdog: $alive/$EXPECTED daemons alive — relaunching missing" >> ../reports/watchdog.log
    ./run-multi.sh "$EXPECTED" >/dev/null 2>&1
    sleep 10
    alive=$(pgrep -f 'index.ts daemon' 2>/dev/null | wc -l | tr -d ' ')
  fi

  # 1b. HUNG daemons: process alive but heartbeat stale (cycle loop wedged on
  #     an await that never resolves). Kill the whole process group (daemon +
  #     its wedged forge/anvil children) and relaunch — run-multi.sh skips ids
  #     that are still live, so only the killed ones come back.
  hung=$(python3 - "$STALE_SEC" <<'PYEOF'
import json, sys, time
cutoff = time.time() - float(sys.argv[1])
try:
    s = json.load(open('../reports/state.json'))
    hung = [d for d, v in s.get('daemons', {}).items() if v.get('lastBeat', 0) < cutoff]
except Exception:
    hung = []
print(' '.join(hung))
PYEOF
)
  if [ -n "$hung" ]; then
    for id in $hung; do
      echo "$(stamp) watchdog: $id heartbeat stale — killing hung daemon (process group)" >> ../reports/watchdog.log
      for pid in $(pgrep -f "index.ts daemon.*--daemon-id ${id}([[:space:]]|$)" 2>/dev/null); do
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "$pgid" ] && kill -9 "-$pgid" 2>/dev/null || kill -9 "$pid" 2>/dev/null
      done
    done
    sleep 5
    ./run-multi.sh "$EXPECTED" >/dev/null 2>&1
  fi

  # 2. Orphaned anvils: fork processes whose parent is gone (ppid 1) — they
  #    hold fork RPC ports and memory. Never touch anvils with a live parent.
  for apid in $(pgrep anvil 2>/dev/null); do
    ppid=$(ps -o ppid= -p "$apid" 2>/dev/null | tr -d ' ')
    if [ "$ppid" = "1" ]; then
      kill "$apid" 2>/dev/null
      echo "$(stamp) watchdog: killed orphaned anvil $apid" >> ../reports/watchdog.log
    fi
  done

  # 2b. Ancient anvils: even with a live parent, a fork probe never runs an
  #     hour (rpc() now has a 10s timeout). Anything older is a leak — kill it;
  #     the parent daemon handles the dead child as a normal probe failure.
  old_anvils=$(python3 - <<'PYEOF'
import subprocess
try:
    pids = subprocess.run(['pgrep', 'anvil'], capture_output=True, text=True).stdout.split()
except Exception:
    pids = []
w = [1, 60, 3600, 86400]
for p in pids:
    try:
        et = subprocess.run(['ps', '-o', 'etime=', '-p', p], capture_output=True, text=True).stdout.strip()
        parts = [int(x) for x in et.replace('-', ':').split(':') if x != '']
        if sum(v * wi for v, wi in zip(reversed(parts), w)) > 3600:
            print(p)
    except Exception:
        pass
PYEOF
)
  for apid in $old_anvils; do
    kill -9 "$apid" 2>/dev/null
    echo "$(stamp) watchdog: killed leaked anvil $apid (>1h old)" >> ../reports/watchdog.log
  done

  # 3. Memory sidecar: restart if the port stopped answering.
  if ! curl -s -m 4 http://127.0.0.1:8765/health 2>/dev/null | grep -q '"ok"'; then
    echo "$(stamp) watchdog: sidecar down — restarting" >> ../reports/watchdog.log
    python3 - <<'PYEOF' >/dev/null 2>&1
import os
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        log = os.open("memory/sidecar.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(log, 1); os.dup2(log, 2)
        py = "memory/venv/bin/python"
        exe = py if os.path.exists(py) else "python3"
        os.execv(exe, [exe, "memory/sidecar.py"])
    os._exit(0)
os.waitpid(pid, 0)
PYEOF
  fi

  # 4. Status line: daemons + sidecar + enlisted targets + memories.
  sidecar=$(curl -s -m 4 http://127.0.0.1:8765/health 2>/dev/null | grep -o '"ok": *true' >/dev/null && echo up || echo DOWN)
  enlisted=$(python3 -c "
import json
try:
    s = json.load(open('../reports/state.json'))
    print(sum(1 for w in s.get('watchlist', {}).values() if w.get('enlisted')))
except Exception:
    print('?')
" 2>/dev/null)
  mem=$(wc -l < ../reports/memory/memories.jsonl 2>/dev/null | tr -d ' ' || echo '?')
  echo "$(stamp) ok daemons=$alive/$EXPECTED sidecar=$sidecar enlisted=$enlisted memories=$mem" >> ../reports/watchdog.log

  sleep "$INTERVAL"
done
