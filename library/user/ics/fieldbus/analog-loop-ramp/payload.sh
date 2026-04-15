#!/bin/bash
# Title: 4-20mA Loop Ramp Generator
# Description: Generate a controlled 4-20mA ramp via the ESP32 ICS Probe's AD5420 DAC.
#              Ramps the loop current from a start value to an end value over a specified
#              duration. Useful for verifying PLC analog input scaling and alarm setpoints.
# Author: ICS Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
# Interaction Level: C (opt-in — drives physical output)
#
# LED States
# - Blue:  Awaiting input
# - Amber: Ramping
# - Green: Ramp complete
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== 4-20mA Loop Ramp Generator ==="
  LOG ""
  LOG blue "Generates a linear ramp on the probe's loop output."
  LOG ""

  esp32_require

  local from_ma
  from_ma=$(NUMBER_PICKER "Start current (mA)" 4)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local to_ma
  to_ma=$(NUMBER_PICKER "End current (mA)" 20)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local duration_s
  duration_s=$(NUMBER_PICKER "Ramp duration (seconds)" 10)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$duration_s" -lt 1 ]]; then duration_s=1; fi

  LOG ""
  LOG blue "Ramp: ${from_ma} mA -> ${to_ma} mA over ${duration_s}s"
  local sid
  sid=$(START_SPINNER "Ramping...")

  esp32_iout_ramp "$from_ma" "$to_ma" "$duration_s" >/dev/null
  # esp32_iout_ramp already prompts CONFIRMATION_DIALOG

  STOP_SPINNER "$sid"

  LOG green "Ramp complete. Output is now at ${to_ma} mA."
  LOG ""

  local resp
  resp=$(CONFIRMATION_DIALOG "Return output to 4mA (minimum)?")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED")
      esp32_iout_off >/dev/null
      LOG green "Output set to minimum (4mA)."
      ;;
    *)
      LOG blue "Output left at ${to_ma} mA."
      ;;
  esac

  ALERT "Ramp complete: ${from_ma} -> ${to_ma} mA over ${duration_s}s"
  LOG blue "Done."
}

main "$@"
