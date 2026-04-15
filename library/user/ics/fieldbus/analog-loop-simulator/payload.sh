#!/bin/bash
# Title: 4-20mA Loop Simulator
# Description: Simulate a 4-20mA transmitter using the ESP32 ICS Probe's AD5420 DAC.
#              Enter an engineering unit range and a desired process value; the probe
#              outputs the corresponding milliamp current on the loop output terminal.
#              Useful for testing PLC/DCS analog input wiring and scaling.
# Author: ICS Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
# Interaction Level: C (opt-in — drives physical output)
#
# LED States
# - Blue:  Awaiting input
# - Amber: Setting output
# - Green: Output active
# - Red:   Error or fault

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== 4-20mA Loop Simulator ==="
  LOG ""
  LOG blue "This payload drives a 4-20mA current on the probe's loop output."
  LOG blue "Connect a loop circuit (24V supply → probe output → PLC input → GND)."
  LOG ""

  esp32_require

  # Engineering range
  local eng_low
  eng_low=$(NUMBER_PICKER "Engineering low (value at 4mA)" 0)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local eng_high
  eng_high=$(NUMBER_PICKER "Engineering high (value at 20mA)" 100)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local unit
  unit=$(TEXT_PICKER "Engineering unit" "PSI")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  LOG blue "Range: ${eng_low} ${unit} (4mA) to ${eng_high} ${unit} (20mA)"

  while true; do
    local desired
    desired=$(NUMBER_PICKER "Desired value (${unit}), or cancel to exit" "$eng_low")
    case $? in
      "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
        LOG blue "Exiting simulator."
        esp32_iout_off >/dev/null 2>&1
        break ;;
    esac

    # Map engineering value to mA
    local ma
    ma=$(awk -v val="$desired" -v lo="$eng_low" -v hi="$eng_high" \
      'BEGIN {
        if (hi == lo) { print 4.0; exit }
        ma = 4.0 + (val - lo) * 16.0 / (hi - lo)
        if (ma < 4.0) ma = 4.0
        if (ma > 20.0) ma = 20.0
        printf "%.2f", ma
      }')

    LOG blue "Setting output: ${desired} ${unit} = ${ma} mA"
    esp32_iout_set_ma "$ma" >/dev/null
    # esp32_iout_set_ma already prompts CONFIRMATION_DIALOG

    LOG green "Output active: ${ma} mA (${desired} ${unit})"
    LOG ""
  done

  LOG green "Simulator stopped. Loop output set to minimum (4mA)."
  ALERT "Loop simulator stopped."
}

main "$@"
