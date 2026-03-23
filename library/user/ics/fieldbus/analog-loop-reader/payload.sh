#!/bin/bash
# Title: 4-20mA Analog Loop Reader
# Description: Continuously read a 4-20mA process current loop via the ESP32 ICS Probe
#              ADC input. Applies user-defined linear scaling to display a calibrated
#              process value (e.g., pressure, temperature, flow). Saves all readings
#              to a timestamped artifact.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Reading loop
# - Green: Within normal range
# - Red:   Out-of-range or error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# 4-20mA range constants (milliamps)
LOOP_MIN_MA=4
LOOP_MAX_MA=20

# Default polling interval in seconds
DEFAULT_POLL_INTERVAL=2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Parse scaling string "4mA=<low>, 20mA=<high>" and extract low/high values and unit
_parse_scaling() {
  local spec="$1"
  # Expected format examples:
  #   "4mA=0%, 20mA=100%"
  #   "4mA=0.0bar, 20mA=10.0bar"
  #   "4mA=-40C, 20mA=150C"

  local low_val high_val unit

  low_val=$(echo "$spec"  | grep -oE '4mA=[-0-9.]+' | head -1 | cut -d= -f2)
  high_val=$(echo "$spec" | grep -oE '20mA=[-0-9.]+' | head -1 | cut -d= -f2)

  # Extract unit from the high value field (trailing non-numeric chars)
  unit=$(echo "$spec" | grep -oE '20mA=[-0-9.]+[^,]*' | head -1 | sed 's/20mA=[-0-9.]*//')
  unit=$(echo "$unit" | tr -d ' ')

  if [[ -z "$low_val" || -z "$high_val" ]]; then
    # Defaults
    low_val=0
    high_val=100
    unit="%"
  fi

  echo "${low_val} ${high_val} ${unit}"
}

# Linear interpolation: map milliamps to engineering units
# scale_value <milliamps> <low_val> <high_val>
_scale_value() {
  local ma="$1" low_val="$2" high_val="$3"

  # Use awk for floating-point arithmetic
  awk -v ma="$ma" -v lo="$low_val" -v hi="$high_val" \
    -v lo_ma="$LOOP_MIN_MA" -v hi_ma="$LOOP_MAX_MA" \
    'BEGIN {
      if (hi_ma == lo_ma) { print lo; exit }
      val = lo + (ma - lo_ma) * (hi - lo) / (hi_ma - lo_ma)
      printf "%.2f", val
    }'
}

# Check if value is within reasonable loop range (allow slight under/over-range)
_check_range() {
  local ma="$1"
  awk -v ma="$ma" \
    -v lo="$LOOP_MIN_MA" -v hi="$LOOP_MAX_MA" \
    'BEGIN { ok = (ma >= lo - 0.5) && (ma <= hi + 0.5); print ok ? "ok" : "out_of_range" }'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== 4-20mA Analog Loop Reader ==="
  LOG ""

  ics_init_engagement
  esp32_require

  # Scaling configuration
  LOG blue "Enter scaling. Examples:"
  LOG blue "  4mA=0%, 20mA=100%"
  LOG blue "  4mA=0.0bar, 20mA=10.0bar"
  LOG blue "  4mA=-40C, 20mA=150C"
  LOG ""

  local scaling_spec
  scaling_spec=$(TEXT_PICKER "Scaling (4mA=<low>, 20mA=<high>)" "4mA=0%, 20mA=100%")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local scale_params
  scale_params=$(_parse_scaling "$scaling_spec")
  local low_val high_val unit
  low_val=$(echo "$scale_params" | awk '{print $1}')
  high_val=$(echo "$scale_params" | awk '{print $2}')
  unit=$(echo "$scale_params"    | awk '{print $3}')

  LOG blue "Scaling: ${LOOP_MIN_MA}mA = ${low_val}${unit}  |  ${LOOP_MAX_MA}mA = ${high_val}${unit}"

  # Poll interval
  local poll_interval
  poll_interval=$(NUMBER_PICKER "Poll interval (seconds)" "$DEFAULT_POLL_INTERVAL")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$poll_interval" -lt 1 ]]; then
    poll_interval=1
  fi

  # Sample count
  local sample_count
  sample_count=$(NUMBER_PICKER "Number of samples (0 = run until button press)" 0)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  # Prepare artifact file
  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts_start
  ts_start=$(date +%Y%m%d_%H%M%S)
  local artifact_file="$eng_dir/raw/analog-loop-${ts_start}.jsonl"

  LOG ""
  LOG blue "Recording to: $artifact_file"
  LOG blue "Press Ctrl-C or the device button to stop."
  LOG ""
  LOG blue "Time                 | Current (mA) | Scaled Value    | Status"
  LOG blue "---------------------|--------------|-----------------|-------"

  local reading_idx=0
  local run=true

  while $run; do
    local ma_reading
    ma_reading=$(adc_read_ma 2>/dev/null) || {
      LOG red "  ADC read error — probe disconnected?"
      break
    }

    if [[ "$ma_reading" == "error" ]]; then
      LOG red "  ADC returned error — skipping sample"
      sleep "$poll_interval"
      continue
    fi

    local scaled_val
    scaled_val=$(_scale_value "$ma_reading" "$low_val" "$high_val")

    local range_status
    range_status=$(_check_range "$ma_reading")

    local ts_now
    ts_now=$(date '+%Y-%m-%dT%H:%M:%S')

    if [[ "$range_status" == "ok" ]]; then
      LOG green "  $ts_now | ${ma_reading} mA     | ${scaled_val} ${unit}   | OK"
    else
      LOG red   "  $ts_now | ${ma_reading} mA     | ${scaled_val} ${unit}   | OUT-OF-RANGE"
    fi

    # Append JSON line to artifact
    printf '{"ts":"%s","ma":%s,"scaled_value":%s,"unit":"%s","range_status":"%s"}\n' \
      "$ts_now" "$ma_reading" "$scaled_val" "$unit" "$range_status" >> "$artifact_file"

    reading_idx=$(( reading_idx + 1 ))

    # Check termination
    if [[ "$sample_count" -gt 0 && "$reading_idx" -ge "$sample_count" ]]; then
      run=false
    else
      sleep "$poll_interval"
    fi
  done

  LOG ""
  LOG green "Loop reading stopped after $reading_idx samples."
  LOG green "Artifact: $artifact_file"

  # Save summary artifact to inventory-linked location
  local summary_content
  summary_content=$(printf \
    '{"scaling":"%s","low_val":%s,"high_val":%s,"unit":"%s","poll_interval_s":%d,"sample_count":%d,"artifact_file":"%s","started":"%s"}' \
    "$scaling_spec" "$low_val" "$high_val" "$unit" \
    "$poll_interval" "$reading_idx" "$artifact_file" "$ts_start")
  ics_save_artifact "analog-loop-summary-${ts_start}" "$summary_content"

  local json
  json=$(printf \
    '{"id":"analog_loop_%s","protocol":"4-20mA","interface":"analog","scaling":"%s","unit":"%s","sample_count":%d,"status":"read"}' \
    "$ICS_ENGAGEMENT" "$scaling_spec" "$unit" "$reading_idx")
  ics_report_device "$json"

  ALERT "4-20mA loop: $reading_idx samples recorded. Artifact saved."

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
