#!/bin/bash
# Title: Modbus RTU Live Register Monitor
# Description: Continuously poll a Modbus RTU slave register range via ESP32 probe
#              and display value changes in real time. Change events are logged to
#              a timestamped artifact. Press any button to stop monitoring.
# Author: ICS Toolkit
# Version: 1.0
# Category: ics
# Net Mode: OFF
#
# Requires: ESP32 ICS Probe connected via USB
#
# LED States
# - Blue:  Idle / prompting user
# - Amber: Polling loop active
# - Green: Clean exit / summary
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

LOG blue "Modbus RTU Live Register Monitor"
PROMPT "This payload continuously polls a slave's holding registers and highlights value changes. Polling sends repeated FC03 requests. Press any button to stop. Press OK to configure."

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

reg_count=$(NUMBER_PICKER "Number of registers to watch (1-125)" 10)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

if [[ "$reg_count" -lt 1 || "$reg_count" -gt 125 ]]; then
  ERROR_DIALOG "Invalid register count: $reg_count. Must be 1-125."
  exit 1
fi

poll_interval=$(NUMBER_PICKER "Poll interval (seconds, 1-60)" 2)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

if [[ "$poll_interval" -lt 1 || "$poll_interval" -gt 60 ]]; then
  ERROR_DIALOG "Invalid poll interval: $poll_interval. Must be 1-60 seconds."
  exit 1
fi

# ---------------------------------------------------------------------------
# Artifact Setup
# ---------------------------------------------------------------------------

ts_start=$(date '+%Y-%m-%dT%H:%M:%S')
ts_file=$(date +%Y%m%d_%H%M%S)

eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
artifact_path="${eng_dir}/raw/modbus-rtu-monitor-slave${slave_addr}-${ts_file}.jsonl"

# Write JSONL header record
printf '{"type":"monitor_start","slave_addr":%d,"start_reg":%d,"reg_count":%d,"poll_interval_s":%d,"started_at":"%s","probe":"%s"}\n' \
  "$slave_addr" "$start_reg" "$reg_count" "$poll_interval" "$ts_start" "$ESP32_DEV" \
  >> "$artifact_path"

LOG green "Change log: $artifact_path"
LOG "Monitoring slave $slave_addr  regs $start_reg-$((start_reg + reg_count - 1))  interval=${poll_interval}s"
LOG "Press any button to stop."

# ---------------------------------------------------------------------------
# Polling Loop
# ---------------------------------------------------------------------------

declare -a prev_values=()
poll_num=0
change_count=0
error_count=0

# Seed previous values with first successful read
spinner_id=$(START_SPINNER "Acquiring initial register snapshot...")

while true; do
  init_result=$(modbus_read_holding "$slave_addr" "$start_reg" "$reg_count" 2>/dev/null || true)
  if echo "$init_result" | grep -q '"status":"ok"'; then
    values_raw=$(echo "$init_result" | sed -n 's/.*"values":\[\([^]]*\)\].*/\1/p')
    IFS=',' read -ra prev_values <<< "$values_raw"
    break
  fi
  error_count=$((error_count + 1))
  if [[ $error_count -ge 5 ]]; then
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "Failed to read initial register snapshot from slave $slave_addr after 5 attempts. Verify slave address and RS-485 connection."
    exit 1
  fi
  sleep 1
done

STOP_SPINNER "$spinner_id"

LOG green "Initial snapshot acquired (${#prev_values[@]} register(s)). Monitoring..."

# Button-press watchdog — write PID file; main loop checks flag file
flag_file=$(mktemp)

(
  WAIT_FOR_BUTTON_PRESS
  echo "stop" > "$flag_file"
) &
btn_pid=$!

trap 'kill "$btn_pid" 2>/dev/null; rm -f "$flag_file"; true' EXIT INT TERM

while true; do
  # Check stop flag
  if [[ -f "$flag_file" ]] && [[ "$(cat "$flag_file" 2>/dev/null)" == "stop" ]]; then
    LOG blue "Button pressed — stopping monitor."
    break
  fi

  sleep "$poll_interval"

  poll_num=$((poll_num + 1))
  ts_now=$(date '+%Y-%m-%dT%H:%M:%S')

  read_result=$(modbus_read_holding "$slave_addr" "$start_reg" "$reg_count" 2>/dev/null || true)

  if ! echo "$read_result" | grep -q '"status":"ok"'; then
    error_count=$((error_count + 1))
    err=$(echo "$read_result" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p')
    LOG red "Poll #$poll_num error: ${err:-no response}"
    printf '{"type":"poll_error","poll":%d,"ts":"%s","error":"%s"}\n' \
      "$poll_num" "$ts_now" "${err:-no_response}" >> "$artifact_path"
    continue
  fi

  values_raw=$(echo "$read_result" | sed -n 's/.*"values":\[\([^]]*\)\].*/\1/p')
  IFS=',' read -ra curr_values <<< "$values_raw"

  # Diff against previous snapshot
  changed_regs=()
  for i in $(seq 0 $((reg_count - 1))); do
    reg_addr=$((start_reg + i))
    prev_v=$(echo "${prev_values[$i]:-0}" | tr -d ' ')
    curr_v=$(echo "${curr_values[$i]:-0}" | tr -d ' ')

    if [[ "$curr_v" != "$prev_v" ]]; then
      changed_regs+=("$reg_addr")
      change_count=$((change_count + 1))
      LOG green "CHANGE  reg=$reg_addr  ${prev_v} -> ${curr_v}  (poll #$poll_num  $ts_now)"

      printf '{"type":"register_change","poll":%d,"ts":"%s","slave_addr":%d,"register":%d,"prev":%s,"curr":%s}\n' \
        "$poll_num" "$ts_now" "$slave_addr" "$reg_addr" "$prev_v" "$curr_v" \
        >> "$artifact_path"
    fi
  done

  if [[ ${#changed_regs[@]} -eq 0 ]]; then
    LOG "Poll #$poll_num — no changes ($ts_now)"
  fi

  # Update baseline
  prev_values=("${curr_values[@]}")

  # Check stop flag again after processing
  if [[ -f "$flag_file" ]] && [[ "$(cat "$flag_file" 2>/dev/null)" == "stop" ]]; then
    LOG blue "Button pressed — stopping monitor."
    break
  fi
done

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

kill "$btn_pid" 2>/dev/null || true
rm -f "$flag_file"

ts_end=$(date '+%Y-%m-%dT%H:%M:%S')

printf '{"type":"monitor_stop","slave_addr":%d,"polls":%d,"changes":%d,"errors":%d,"stopped_at":"%s"}\n' \
  "$slave_addr" "$poll_num" "$change_count" "$error_count" "$ts_end" \
  >> "$artifact_path"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

LOG green "--- Live Monitor Summary ---"
LOG "Slave monitored : $slave_addr"
LOG "Registers       : $start_reg - $((start_reg + reg_count - 1))"
LOG "Poll interval   : ${poll_interval}s"
LOG "Polls completed : $poll_num"
LOG "Value changes   : $change_count"
LOG "Read errors     : $error_count"
LOG "Change log      : $artifact_path"

ALERT "Monitor stopped. $change_count change(s) across $poll_num poll(s) for slave $slave_addr. Log saved: $artifact_path"
