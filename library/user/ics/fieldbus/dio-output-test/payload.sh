#!/bin/bash
# Title: DIO Output Test
# Description: Drive 24V digital outputs via the ESP32 ICS Probe's MAX14906 interface.
#              Each output activation is individually confirmed. Useful for testing
#              relay wiring, valve position indicators, and stack lights.
# Author: ICS Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
# Interaction Level: C (opt-in — drives physical outputs)
#
# LED States
# - Blue:  Awaiting selection
# - Amber: Output active
# - Green: Test complete
# - Red:   Error or fault

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== DIO Output Test ==="
  LOG ""
  LOG red "WARNING: This payload drives 24V digital outputs."
  LOG red "Verify wiring before proceeding."
  LOG ""

  esp32_require

  local resp
  resp=$(CONFIRMATION_DIALOG "This will drive 24V outputs. Continue?")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") ;;
    *) LOG "Cancelled"; exit 0 ;;
  esac

  local ch
  ch=$(NUMBER_PICKER "Output channel (0-3)" 0)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  if [[ "$ch" -lt 0 || "$ch" -gt 3 ]]; then
    ERROR_DIALOG "Channel must be 0-3."
    exit 1
  fi

  LOG blue "Configuring channel $ch as output..."
  esp32_dio_configure "$ch" "output" >/dev/null

  # Drive high
  LOG blue "Driving channel $ch HIGH..."
  esp32_dio_write "$ch" 1 >/dev/null
  # esp32_dio_write already prompts CONFIRMATION_DIALOG internally

  LOG green "Channel $ch is HIGH. Verify output with meter/indicator."
  PROMPT "Press any button to drive LOW"

  # Drive low
  LOG blue "Driving channel $ch LOW..."
  esp32_dio_write "$ch" 0 >/dev/null

  LOG green "Channel $ch is LOW."

  # Check for faults
  local fault_resp
  fault_resp=$(esp32_dio_fault_status)
  if echo "$fault_resp" | grep -q '"channels_faulted":\[\]'; then
    LOG green "No faults detected."
  else
    LOG red "Faults detected:"
    LOG red "$fault_resp"
  fi

  LOG ""
  LOG green "Output test complete for channel $ch."
  ALERT "DIO output test complete (ch$ch)"
}

main "$@"
