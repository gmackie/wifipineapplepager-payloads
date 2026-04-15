#!/bin/bash
# Title: EdgeOps Agent
# Description: EdgeOps gateway agent — streams ICS probe data to Controls Foundry
# Author: ICS Toolkit
# Version: 0.1
# Category: remote_access
# Net Mode: NAT
#
# LED States
# - Blue:  Menu / idle
# - Amber: Agent running
# - Green: Connected to cloud
# - Red:   Error

set -euo pipefail

PAYLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PKG="$PAYLOAD_DIR/edgeops_agent"
PID_FILE="/tmp/edgeops-agent.pid"
STATUS_FILE="/tmp/edgeops-status.json"
ENROLLMENT_FILE="/root/edgeops/enrollment.json"
CONFIG_FILE="/root/edgeops/agent-config.json"

# --- Helpers ---

agent_is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

show_status() {
  if [[ -f "$STATUS_FILE" ]]; then
    local state probe adapters pending
    state=$(python3 -c "import json; d=json.load(open('$STATUS_FILE')); print(d.get('state','unknown'))" 2>/dev/null || echo "unknown")
    probe=$(python3 -c "import json; d=json.load(open('$STATUS_FILE')); print('yes' if d.get('probe_connected') else 'no')" 2>/dev/null || echo "unknown")
    adapters=$(python3 -c "import json; d=json.load(open('$STATUS_FILE')); print(d.get('adapter_count',0))" 2>/dev/null || echo "0")
    pending=$(python3 -c "import json; d=json.load(open('$STATUS_FILE')); print(d.get('buffer_pending',0))" 2>/dev/null || echo "0")

    LOG blue "Agent state: $state"
    LOG blue "Probe connected: $probe"
    LOG blue "Adapters: $adapters"
    LOG blue "Buffered readings: $pending"
  else
    LOG blue "No status available"
  fi
}

start_agent() {
  if agent_is_running; then
    LOG blue "Agent is already running (PID $(cat "$PID_FILE"))"
    return
  fi

  if [[ ! -f "$CONFIG_FILE" ]]; then
    ERROR_DIALOG "No agent config found. Run enrollment first."
    return
  fi

  LOG blue "Starting EdgeOps agent..."
  local sid
  sid=$(START_SPINNER "Starting agent...")

  cd "$PAYLOAD_DIR"
  PYTHONPATH="$AGENT_PKG/vendor:$PYTHONPATH" \
    python3 -m edgeops_agent > /tmp/edgeops-agent.log 2>&1 &
  echo $! > "$PID_FILE"

  STOP_SPINNER "$sid"

  sleep 2
  if agent_is_running; then
    LOG green "Agent started (PID $(cat "$PID_FILE"))"
    ALERT "EdgeOps agent running"
  else
    LOG red "Agent failed to start. Check /tmp/edgeops-agent.log"
    ERROR_DIALOG "Agent failed to start"
    rm -f "$PID_FILE"
  fi
}

stop_agent() {
  if ! agent_is_running; then
    LOG blue "Agent is not running"
    return
  fi

  local pid
  pid=$(cat "$PID_FILE")
  LOG blue "Stopping agent (PID $pid)..."
  kill "$pid" 2>/dev/null || true
  sleep 2

  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$PID_FILE"
  LOG green "Agent stopped"
}

run_discovery() {
  if ! agent_is_running; then
    ERROR_DIALOG "Start the agent first"
    return
  fi

  LOG blue "Running device discovery..."
  local sid
  sid=$(START_SPINNER "Discovering devices...")

  # Send SIGUSR1 to trigger discovery (agent would need to handle this)
  # For now, just show current status
  sleep 3
  STOP_SPINNER "$sid"
  show_status
}

# --- Main menu ---

main() {
  LOG blue "=== EdgeOps Agent ==="
  LOG ""

  # Check enrollment
  if [[ ! -f "$ENROLLMENT_FILE" ]] && [[ ! -f "$CONFIG_FILE" ]]; then
    LOG red "Device not enrolled."
    local resp
    resp=$(CONFIRMATION_DIALOG "Run enrollment now?")
    case "$resp" in
      "$DUCKYSCRIPT_USER_CONFIRMED")
        source "$PAYLOAD_DIR/enrollment/enroll.sh"
        return
        ;;
      *) LOG "Skipping enrollment — agent will run in local-only mode" ;;
    esac
  fi

  while true; do
    local choice
    if agent_is_running; then
      LOG green "[Agent running — PID $(cat "$PID_FILE")]"
    else
      LOG blue "[Agent stopped]"
    fi
    LOG ""

    choice=$(WAIT_FOR_INPUT)
    case "$choice" in
      UP)
        start_agent
        ;;
      DOWN)
        stop_agent
        ;;
      SELECT)
        show_status
        ;;
      BACK)
        run_discovery
        ;;
      *)
        LOG blue "Controls: UP=Start  DOWN=Stop  SELECT=Status  BACK=Discover"
        LOG blue "Hold BACK to exit"
        ;;
    esac
  done
}

main "$@"
