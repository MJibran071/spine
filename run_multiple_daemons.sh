#!/usr/bin/env bash
# Launch multiple daemon instances with custom options.
# Each entry in daemon_instances.json is a JSON object defining flags for one daemon.
# Example entry:
#   {"intervalSec":30,"workers":6,"probeWorkers":8,"watchlist":["0x...","0x..."],"scanEveryCycles":5}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG_FILE="$SCRIPT_DIR/daemon_instances.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Configuration file $CONFIG_FILE not found."
  exit 1
fi

IDX=0
jq -c '.[]' "$CONFIG_FILE" | while read -r INSTANCE; do
  IDX=$((IDX+1))
  LOG="daemon_$IDX.log"
  echo "Launching daemon #$IDX with config: $INSTANCE"
  ARGS=""
  for key in $(echo $INSTANCE | jq -r 'keys[]'); do
    value=$(echo $INSTANCE | jq -r ".[\"$key\"]")
    if [[ $value == "["*"]" ]]; then
      value=$(echo $value | jq -r 'join(",")')
    fi
    ARGS+=" --$key $value"
  done
  npm run daemon -- $ARGS > "$SCRIPT_DIR/$LOG" 2>&1 &
  echo "Daemon #$IDX started, logging to $SCRIPT_DIR/$LOG"
done

wait
