#!/bin/bash
# Title: Modbus RTU Register Dump
# Description: Level C payload — reads holding registers and input registers from a
#              specific Modbus RTU slave via ESP32 probe. Displays values in a
#              formatted table and saves the dump as a loot artifact.
#              Gated behind CONFIRMATION_DIALOG because this sends read requests
#              to a live device and may affect process observability.
# Author: ICS Toolkit
# Version: 1.0
# Category: ics
# Net Mode: OFF
#
# Requires: ESP32 ICS Probe connected via USB
#
# LED States
# - Blue:  Idle / prompting user
# - Amber: Reading registers
# - Green: Dump complete
# - Red:   Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"
source "$(dirname "$0")/../../lib/esp32.sh"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

esp32_require

ics_init_engagement

# ---------------------------------------------------------------------------
# User Input
# ---------------------------------------------------------------------------

LOG blue "Modbus RTU Register Dump  [Level C]"
PROMPT "This payload sends Modbus FC03 (Read Holding Registers) and FC04 (Read Input Registers) requests to a live slave. These are read-only operations but they DO generate bus traffic that may be logged by the target. Press OK to continue."

slave_addr=$(NUMBER_PICKER "Slave address (1-247)" 1)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

if [[ "$slave_addr" -lt 1 || "$slave_addr" -gt 247 ]]; then
  ERROR_DIALOG "Invalid slave address: $slave_addr. Must be 1-247."
  exit 1
fi

start_reg=$(NUMBER_PICKER "Start register address (0-based)" 0)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

reg_count=$(NUMBER_PICKER "Number of registers to read (1-125)" 10)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

if [[ "$reg_count" -lt 1 || "$reg_count" -gt 125 ]]; then
  ERROR_DIALOG "Invalid register count: $reg_count. Modbus FC03/FC04 supports 1-125 registers per request."
  exit 1
fi

# ---------------------------------------------------------------------------
# Level C Confirmation Gate
# ---------------------------------------------------------------------------

confirm=$(CONFIRMATION_DIALOG "Read $reg_count register(s) starting at $start_reg from slave $slave_addr? This sends live bus traffic to the device.")
case "$confirm" in
  "$DUCKYSCRIPT_USER_CONFIRMED") ;;
  *)
    LOG red "Operation cancelled by user."
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Read Holding Registers (FC03)
# ---------------------------------------------------------------------------

spinner_id=$(START_SPINNER "Reading FC03 holding registers from slave $slave_addr...")

holding_result=$(modbus_read_holding "$slave_addr" "$start_reg" "$reg_count" 2>/dev/null || true)

STOP_SPINNER "$spinner_id"

holding_ok=false
declare -a holding_values=()

if echo "$holding_result" | grep -q '"status":"ok"'; then
  holding_ok=true
  # Parse values array: {"status":"ok","values":[100,200,300,...]}
  values_raw=$(echo "$holding_result" | sed -n 's/.*"values":\[\([^]]*\)\].*/\1/p')
  IFS=',' read -ra holding_values <<< "$values_raw"
  LOG green "FC03 holding registers: $reg_count value(s) received"
else
  err=$(echo "$holding_result" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p')
  LOG red "FC03 failed: ${err:-no response from slave $slave_addr}"
fi

# ---------------------------------------------------------------------------
# Read Input Registers (FC04)
# ---------------------------------------------------------------------------

spinner_id=$(START_SPINNER "Reading FC04 input registers from slave $slave_addr...")

input_result=$(modbus_read_input "$slave_addr" "$start_reg" "$reg_count" 2>/dev/null || true)

STOP_SPINNER "$spinner_id"

input_ok=false
declare -a input_values=()

if echo "$input_result" | grep -q '"status":"ok"'; then
  input_ok=true
  values_raw=$(echo "$input_result" | sed -n 's/.*"values":\[\([^]]*\)\].*/\1/p')
  IFS=',' read -ra input_values <<< "$values_raw"
  LOG green "FC04 input registers: $reg_count value(s) received"
else
  err=$(echo "$input_result" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p')
  LOG red "FC04 failed: ${err:-no response from slave $slave_addr}"
fi

if [[ "$holding_ok" == false && "$input_ok" == false ]]; then
  ERROR_DIALOG "Both FC03 and FC04 reads failed for slave $slave_addr starting at register $start_reg. Verify slave address, register range, and bus connectivity."
  exit 1
fi

# ---------------------------------------------------------------------------
# Format Table
# ---------------------------------------------------------------------------

LOG green "--- Register Dump: Slave $slave_addr  Regs $start_reg - $((start_reg + reg_count - 1)) ---"
LOG "  Addr   Holding (FC03)   Input (FC04)"
LOG "  ----   --------------   -----------"

table_lines=""
for i in $(seq 0 $((reg_count - 1))); do
  reg_addr=$((start_reg + i))
  h_val="---"
  in_val="---"

  if [[ "$holding_ok" == true && $i -lt ${#holding_values[@]} ]]; then
    h_val=$(echo "${holding_values[$i]}" | tr -d ' ')
  fi

  if [[ "$input_ok" == true && $i -lt ${#input_values[@]} ]]; then
    in_val=$(echo "${input_values[$i]}" | tr -d ' ')
  fi

  row=$(printf "  %04d   %-16s %s" "$reg_addr" "$h_val" "$in_val")
  LOG "$row"
  table_lines="${table_lines}\n${row}"
done

# ---------------------------------------------------------------------------
# Save Artifact
# ---------------------------------------------------------------------------

ts=$(date '+%Y-%m-%dT%H:%M:%S')

artifact_json=$(printf '{
  "schema_version": 1,
  "type": "modbus_rtu_register_dump",
  "slave_addr": %d,
  "start_register": %d,
  "register_count": %d,
  "captured_at": "%s",
  "probe": "%s",
  "holding_registers": {
    "fc": 3,
    "ok": %s,
    "raw": "%s",
    "values": [%s]
  },
  "input_registers": {
    "fc": 4,
    "ok": %s,
    "raw": "%s",
    "values": [%s]
  }
}' \
  "$slave_addr" \
  "$start_reg" \
  "$reg_count" \
  "$ts" \
  "$ESP32_DEV" \
  "$holding_ok" \
  "${holding_result//\"/\\\"}" \
  "$(echo "${holding_values[*]:-}" | tr ' ' ',')" \
  "$input_ok" \
  "${input_result//\"/\\\"}" \
  "$(echo "${input_values[*]:-}" | tr ' ' ',')")

artifact_path=$(ics_save_artifact "modbus-rtu-slave${slave_addr}-reg${start_reg}" "$artifact_json")

LOG green "Artifact saved: $artifact_path"

ALERT "Register dump complete for slave $slave_addr. Registers $start_reg-$((start_reg + reg_count - 1)) captured. Artifact: $artifact_path"
