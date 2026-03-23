#!/bin/bash
# Title: CAN Bus Node Enumeration
# Description: Enumerate active CAN nodes via ESP32 ICS Probe using passive arbitration
#              ID scanning. Identifies unique IDs present on the bus and estimates the
#              number of active nodes from ID distribution patterns.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Scanning bus
# - Green: Enumeration complete
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_pick_baud() {
  LOG blue "Select CAN baud rate:"
  LOG blue "  1) 125 kbps  — low-speed/fault-tolerant"
  LOG blue "  2) 250 kbps  — J1939 / industrial"
  LOG blue "  3) 500 kbps  — CANopen / automotive"
  LOG blue "  4) 1000 kbps — high-speed"
  LOG ""

  local choice
  choice=$(NUMBER_PICKER "Baud rate option (1-4)" 3)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      return 1 ;;
  esac

  case "$choice" in
    1) echo "125000" ;;
    2) echo "250000" ;;
    3) echo "500000" ;;
    4) echo "1000000" ;;
    *) echo "500000" ;;
  esac
}

# Parse unique arbitration IDs from can.scan_ids JSON response
_parse_arb_ids() {
  local response="$1"
  # Response format: {"status":"ok","ids":[{"id":"0x123","count":42}, ...]}
  echo "$response" | grep -oE '"id":"0x[0-9a-fA-F]+"' | grep -oE '0x[0-9a-fA-F]+' | sort -u
}

_count_arb_ids() {
  local response="$1"
  echo "$response" | grep -oE '"id":"0x[0-9a-fA-F]+"' | wc -l | tr -d ' '
}

# Heuristic node count: standard CAN assigns one base ID per node;
# clusters of sequential IDs typically map to a single ECU/controller.
_estimate_node_count() {
  local ids="$1"
  local id_list
  id_list=$(echo "$ids" | sort -t x -k2 -V)

  local node_count=0
  local prev_id="-1"

  while IFS= read -r raw_id; do
    [[ -z "$raw_id" ]] && continue
    local dec_id
    dec_id=$(printf '%d' "$raw_id" 2>/dev/null) || continue

    if [[ "$prev_id" == "-1" ]]; then
      node_count=1
    else
      # Gap > 8 IDs between messages likely indicates a new node
      local gap=$(( dec_id - prev_id ))
      if [[ "$gap" -gt 8 ]]; then
        node_count=$(( node_count + 1 ))
      fi
    fi
    prev_id="$dec_id"
  done <<< "$id_list"

  echo "$node_count"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== CAN Bus Node Enumeration ==="
  LOG ""

  ics_init_engagement
  esp32_require

  local baud
  baud=$(_pick_baud) || { LOG "Cancelled"; exit 1; }

  local scan_duration
  scan_duration=$(NUMBER_PICKER "Scan duration (seconds)" 10)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$scan_duration" -lt 1 || "$scan_duration" -gt 300 ]]; then
    ERROR_DIALOG "Duration must be between 1 and 300 seconds."
    exit 1
  fi

  LOG blue "Baud: $baud bps | Scan window: ${scan_duration}s"
  LOG ""

  local spinner_id
  spinner_id=$(START_SPINNER "Listening for CAN arbitration IDs ...")

  local scan_result
  scan_result=$(can_scan_ids "$baud" "$scan_duration" 2>/dev/null) || {
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "can_scan_ids failed. Check ESP32 probe and CAN bus connection."
    exit 1
  }

  STOP_SPINNER "$spinner_id"

  if ! echo "$scan_result" | grep -q '"status":"ok"'; then
    local err
    err=$(echo "$scan_result" | grep -oE '"error":"[^"]+"' | cut -d'"' -f4)
    ERROR_DIALOG "Scan error: ${err:-unknown}. Is the CAN bus active?"
    exit 1
  fi

  local arb_ids
  arb_ids=$(_parse_arb_ids "$scan_result")

  local unique_count
  unique_count=$(_count_arb_ids "$scan_result")

  if [[ "$unique_count" -eq 0 ]]; then
    LOG "No CAN arbitration IDs observed. Verify baud rate and bus activity."
    ALERT "CAN scan complete — no IDs detected. Try a different baud rate."
    exit 0
  fi

  local est_nodes
  est_nodes=$(_estimate_node_count "$arb_ids")

  LOG green "Unique arbitration IDs detected: $unique_count"
  LOG green "Estimated active nodes         : $est_nodes"
  LOG ""
  LOG blue "Arbitration ID list:"
  while IFS= read -r arb_id; do
    [[ -z "$arb_id" ]] && continue
    # Extract frame count for this ID if present
    local frame_count
    frame_count=$(echo "$scan_result" | grep -o "\"id\":\"$arb_id\",\"count\":[0-9]*" \
      | grep -oE '"count":[0-9]+' | cut -d: -f2)
    LOG "  $arb_id  (frames: ${frame_count:-?})"
  done <<< "$arb_ids"

  # Save artifact
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local artifact_content
  artifact_content=$(printf \
    '{"baud":%d,"scan_duration_s":%d,"unique_ids":%d,"estimated_nodes":%d,"raw_scan":%s}' \
    "$baud" "$scan_duration" "$unique_count" "$est_nodes" "$scan_result")
  local artifact_path
  artifact_path=$(ics_save_artifact "can-enum-${ts}" "$artifact_content")

  # Report each node cluster to inventory
  local node_idx=1
  while IFS= read -r arb_id; do
    [[ -z "$arb_id" ]] && continue
    local json
    json=$(printf \
      '{"id":"can_node_%s_%d","protocol":"can","bus":"can0","arb_id":"%s","baud":%d,"status":"detected"}' \
      "$ICS_ENGAGEMENT" "$node_idx" "$arb_id" "$baud")
    ics_report_device "$json"
    node_idx=$(( node_idx + 1 ))
  done <<< "$arb_ids"

  LOG ""
  LOG green "Artifact: $artifact_path"
  ALERT "CAN enum: $unique_count unique IDs, ~$est_nodes nodes at $baud bps"

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
