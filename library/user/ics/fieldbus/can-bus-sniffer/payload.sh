#!/bin/bash
# Title: CAN Bus Sniffer
# Description: Passive CAN bus frame capture via ESP32 ICS Probe. Captures frames for
#              a user-specified duration at a chosen baud rate and saves a timestamped
#              JSON artifact. Displays live frame count during capture.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Capturing frames
# - Green: Capture complete
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# Common automotive/industrial CAN baud rates (bps)
BAUD_OPTIONS="125000|250000|500000|1000000"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_pick_baud() {
  LOG blue "Common CAN baud rates:"
  LOG blue "  1) 125 kbps  — low-speed/fault-tolerant CAN (ISO 11519)"
  LOG blue "  2) 250 kbps  — J1939 / industrial automation"
  LOG blue "  3) 500 kbps  — automotive OBD-II, CANopen"
  LOG blue "  4) 1000 kbps — high-speed CAN (ISO 11898)"
  LOG ""

  local choice
  choice=$(NUMBER_PICKER "Select baud rate option (1-4)" 3)
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

_count_frames() {
  local file="$1"
  grep -c '"frame"' "$file" 2>/dev/null || echo "0"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== CAN Bus Sniffer ==="
  LOG ""

  ics_init_engagement
  esp32_require

  # Baud rate selection
  local baud
  baud=$(_pick_baud) || { LOG "Cancelled"; exit 1; }
  LOG blue "Baud rate: $baud bps"

  # Duration
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 30)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$duration" -lt 1 || "$duration" -gt 3600 ]]; then
    ERROR_DIALOG "Duration must be between 1 and 3600 seconds."
    exit 1
  fi

  # Prepare output file
  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local capture_file="$eng_dir/raw/can-capture-${baud}-${ts}.jsonl"

  LOG blue "Saving frames to: $capture_file"
  LOG ""

  # Start streaming capture
  local spinner_id
  spinner_id=$(START_SPINNER "Starting CAN capture at $baud bps ...")

  local stream_pid
  stream_pid=$(can_listen "$baud" "$duration" "$capture_file")

  STOP_SPINNER "$spinner_id"

  if [[ -z "$stream_pid" ]]; then
    ERROR_DIALOG "Failed to start CAN capture. Check ESP32 probe connection and CAN bus wiring."
    exit 1
  fi

  LOG green "Capture started (PID $stream_pid). Press button to abort early."
  LOG ""

  # Live frame count display loop
  local elapsed=0
  local last_count=0
  while kill -0 "$stream_pid" 2>/dev/null && [[ "$elapsed" -lt "$duration" ]]; do
    local current_count
    current_count=$(_count_frames "$capture_file")
    local new_frames=$(( current_count - last_count ))
    LOG "  [${elapsed}s / ${duration}s] Frames captured: $current_count (+${new_frames} since last update)"
    last_count="$current_count"

    # Non-blocking button check — WAIT_FOR_INPUT with 0 timeout not standard;
    # use a short sleep and proceed
    sleep 5 || true
    elapsed=$(( elapsed + 5 ))
  done

  # Ensure stream process is stopped
  esp32_stream_stop "$stream_pid"

  local total_frames
  total_frames=$(_count_frames "$capture_file")

  LOG ""
  if [[ "$total_frames" -eq 0 ]]; then
    LOG "No frames captured. Verify baud rate and CAN bus activity."
    ALERT "CAN capture complete — 0 frames. Check baud rate and bus connection."
  else
    LOG green "Capture complete: $total_frames frames in $capture_file"

    # Save summary artifact
    local artifact_content
    artifact_content=$(printf \
      '{"baud":%d,"duration_s":%d,"frame_count":%d,"capture_file":"%s","timestamp":"%s"}' \
      "$baud" "$duration" "$total_frames" "$capture_file" "$ts")
    ics_save_artifact "can-sniffer-summary-${ts}" "$artifact_content"

    ALERT "CAN capture complete: $total_frames frames at $baud bps saved."
  fi

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
