#!/bin/bash
# Title: OPC UA Node Browser
# Description: Level C — browse the OPC UA node tree on a target server.
#              Requires explicit operator confirmation before sending read requests.
#              Calls opcua_browse_nodes from the ICS protocol library.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Browsing node tree
# - Green: Browse complete
# - Red:   Error / cancelled

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "OPC UA Node Browser (Level C)"
LOG red "WARNING: This payload sends active read requests to a live OPC UA server."
LOG "Browsing the node tree may generate log entries on the target system."
LOG "Use only with explicit authorisation from the asset owner."

confirm=$(CONFIRMATION_DIALOG "Proceed with OPC UA node browse? (Level C — active interaction)")
case "$confirm" in
  "$DUCKYSCRIPT_USER_CONFIRMED") ;;
  *)
    LOG "Aborted by operator."; exit 0 ;;
esac

ics_init_engagement

LOG blue "Enter the OPC UA server host to browse."
target_host=$(IP_PICKER "OPC UA server IP" "192.168.1.100")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

target_port=$(NUMBER_PICKER "OPC UA port" 4840)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    target_port=4840 ;;
esac

# Verify the server is reachable before browsing
spin_id=$(START_SPINNER "Connecting to OPC UA server at $target_host:$target_port...")
probe_result=$(opcua_discover "$target_host" "$target_port" 2>/dev/null) || true
STOP_SPINNER "$spin_id"

if ! echo "$probe_result" | grep -q "status=ok"; then
  ERROR_DIALOG "OPC UA server at $target_host:$target_port is not reachable or did not respond. Aborting browse."
  exit 1
fi

LOG green "Server confirmed reachable: $target_host:$target_port"

# opcua_browse_nodes issues its own CONFIRMATION_DIALOG per library contract.
# The outer confirmation above covers the overall Level C consent; the library
# guard below provides a final per-operation confirmation.
LOG "Starting node tree browse on $target_host:$target_port..."
spin_id=$(START_SPINNER "Browsing OPC UA node tree...")
opcua_browse_nodes "$target_host" "$target_port"
browse_rc=$?
STOP_SPINNER "$spin_id"

if [[ "$browse_rc" -ne 0 ]]; then
  ERROR_DIALOG "Node browse cancelled or failed for $target_host:$target_port"
  exit 1
fi

LOG green "Node browse complete for $target_host:$target_port"
ALERT "OPC UA node browse complete. Check log for results."
