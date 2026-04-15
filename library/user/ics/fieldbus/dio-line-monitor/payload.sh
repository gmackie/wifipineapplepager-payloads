#!/bin/bash
# Title: DIO Line Monitor
# Description: Passively monitor up to 4 digital I/O lines (12V/24V) via the ESP32
#              ICS Probe's MAX14906 interface. Logs all state transitions with timestamps
#              to an engagement artifact.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
# Interaction Level: B (passive monitoring)
#
# LED States
# - Blue:  Configuring channels
# - Amber: Monitoring
# - Green: Stable
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== DIO Line Monitor ==="
  LOG ""

  ics_init_engagement
  esp32_require

  # Configure channels as inputs
  local num_channels
  num_channels=$(NUMBER_PICKER "Number of channels to monitor (1-4)" 4)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$num_channels" -lt 1 ]]; then num_channels=1; fi
  if [[ "$num_channels" -gt 4 ]]; then num_channels=4; fi

  local ch
  for ch in $(seq 0 $((num_channels - 1))); do
    LOG blue "Configuring channel $ch as input (Type 3 / 5V threshold)..."
    esp32_dio_configure "$ch" "input_t3" >/dev/null
  done

  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds, 0=until stopped)" 60)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$duration" -lt 1 ]]; then duration=3600; fi

  local interval_ms
  interval_ms=$(NUMBER_PICKER "Poll interval (milliseconds)" 100)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts_start
  ts_start=$(date +%Y%m%d_%H%M%S)
  local artifact_file="$eng_dir/raw/dio-monitor-${ts_start}.jsonl"

  LOG ""
  LOG blue "Monitoring $num_channels channel(s) for ${duration}s at ${interval_ms}ms intervals."
  LOG blue "Recording transitions to: $artifact_file"
  LOG blue "Sending stream command to probe..."
  LOG ""

  local output_file
  output_file=$(mktemp)
  local stream_pid
  stream_pid=$(esp32_stream_start "dio.monitor" \
    "$(printf '{"interval_ms":%d,"duration_s":%d}' "$interval_ms" "$duration")" \
    "$output_file")

  LOG blue "Streaming (PID: $stream_pid). Press any button to stop."
  WAIT_FOR_BUTTON_PRESS

  esp32_stream_stop "$stream_pid"

  # Copy captured lines to artifact
  if [[ -f "$output_file" ]]; then
    cp "$output_file" "$artifact_file"
    local line_count
    line_count=$(wc -l < "$output_file")
    LOG green "Captured $line_count event(s)."
  fi
  rm -f "$output_file"

  ALERT "DIO monitor: captured to $artifact_file"
  LOG blue "Done."
}

main "$@"
