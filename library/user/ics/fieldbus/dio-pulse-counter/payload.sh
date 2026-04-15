#!/bin/bash
# Title: DIO Pulse Counter
# Description: Count rising-edge pulses on a digital input channel via the ESP32 ICS
#              Probe's MAX14906 interface. Useful for flow meters, tachometers, and
#              totalizer verification.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
# Interaction Level: B (passive monitoring)
#
# LED States
# - Blue:  Configuring
# - Amber: Counting
# - Green: Complete
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== DIO Pulse Counter ==="
  LOG ""

  ics_init_engagement
  esp32_require

  local ch
  ch=$(NUMBER_PICKER "Channel to monitor (0-3)" 0)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$ch" -lt 0 || "$ch" -gt 3 ]]; then
    ERROR_DIALOG "Channel must be 0-3."
    exit 1
  fi

  LOG blue "Configuring channel $ch as digital input (Type 3)..."
  esp32_dio_configure "$ch" "input_t3" >/dev/null

  local duration
  duration=$(NUMBER_PICKER "Count duration (seconds)" 30)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$duration" -lt 1 ]]; then duration=1; fi

  LOG ""
  LOG blue "Counting pulses on channel $ch for ${duration}s..."
  LOG blue "Using 10ms poll interval for best resolution."
  local sid
  sid=$(START_SPINNER "Counting pulses...")

  # Stream DIO monitor at 10ms interval, capture output
  local output_file
  output_file=$(mktemp)
  local stream_pid
  stream_pid=$(esp32_stream_start "dio.monitor" \
    "$(printf '{"interval_ms":10,"duration_s":%d}' "$duration")" \
    "$output_file")

  sleep "$((duration + 2))"
  esp32_stream_stop "$stream_pid"
  STOP_SPINNER "$sid"

  # Count rising edges for our channel from the captured stream
  local pulse_count=0
  local prev_val=""
  while IFS= read -r line; do
    # Each line is JSON with channel data; grep for our channel's transitions
    local val
    val=$(echo "$line" | sed -n "s/.*\"ch\":${ch}[^}]*\"value\":\([01]\).*/\1/p")
    if [[ -n "$val" ]]; then
      if [[ "$prev_val" == "0" && "$val" == "1" ]]; then
        pulse_count=$((pulse_count + 1))
      fi
      prev_val="$val"
    fi
  done < "$output_file"
  rm -f "$output_file"

  LOG ""
  LOG green "Pulse count: $pulse_count rising edges in ${duration}s"
  if [[ "$duration" -gt 0 ]]; then
    local rate
    rate=$(awk -v count="$pulse_count" -v dur="$duration" 'BEGIN { printf "%.2f", count / dur }')
    LOG green "Rate: ${rate} Hz"
  fi

  ALERT "Pulse counter: $pulse_count pulses in ${duration}s on ch${ch}"
  LOG blue "Done."
}

main "$@"
