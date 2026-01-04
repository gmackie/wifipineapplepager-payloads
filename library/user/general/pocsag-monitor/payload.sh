#!/bin/bash
# Title: POCSAG Monitor
# Description: RTL-SDR pager/POCSAG decoding with activity logging
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow: Listening
# - Cyan flash: Message decoded
# - Green: Session complete
# - Red: Error/missing tools
#
# Requirements: rtl_fm, multimon-ng

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/pocsag-monitor}"
MONITOR_DURATION="${MONITOR_DURATION:-600}"
POCSAG_FREQ="${POCSAG_FREQ:-152.480M}"
SAMPLE_RATE="${SAMPLE_RATE:-22050}"
GAIN="${GAIN:-40}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${RTL_PID:-}" ]] && kill "$RTL_PID" 2>/dev/null || true
  [[ -n "${MULTIMON_PID:-}" ]] && kill "$MULTIMON_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

MESSAGE_COUNT=0
UNIQUE_ADDRESSES=0
declare -A PAGER_ADDRESSES

log_message() {
  local timestamp="$1"
  local address="$2"
  local func="$3"
  local message="$4"
  
  MESSAGE_COUNT=$((MESSAGE_COUNT + 1))
  
  if [[ -z "${PAGER_ADDRESSES[$address]:-}" ]]; then
    PAGER_ADDRESSES["$address"]=1
    UNIQUE_ADDRESSES=$((UNIQUE_ADDRESSES + 1))
  else
    PAGER_ADDRESSES["$address"]=$((${PAGER_ADDRESSES[$address]} + 1))
  fi
  
  LED C FAST
  VIBRATE 100
  
  {
    echo "========================================"
    echo "Time: $timestamp"
    echo "Address: $address"
    echo "Function: $func"
    echo "Message: $message"
    echo "========================================"
  } >> "$ARTIFACTS_DIR/messages.log"
  
  LOG cyan "MSG #$MESSAGE_COUNT | Addr: $address"
  LOG "  $message"
  
  sleep 0.3
  LED B SLOW
}

parse_multimon_output() {
  local line
  while IFS= read -r line; do
    if [[ "$line" =~ POCSAG([0-9]+):\ Address:\ ([0-9]+)\ Function:\ ([0-9])\ (Alpha|Numeric):\ (.*) ]]; then
      local baud="${BASH_REMATCH[1]}"
      local address="${BASH_REMATCH[2]}"
      local func="${BASH_REMATCH[3]}"
      local msg_type="${BASH_REMATCH[4]}"
      local message="${BASH_REMATCH[5]}"
      local timestamp
      timestamp=$(date '+%Y-%m-%d %H:%M:%S')
      
      log_message "$timestamp" "$address" "$func" "[$msg_type] $message"
    fi
  done
}

start_monitoring() {
  local freq="$1"
  local duration="$2"
  
  LOG "Starting POCSAG monitoring..."
  LOG "Frequency: $freq"
  LOG "Duration: ${duration}s"
  LOG ""
  
  LED B SLOW
  
  local fifo="$ARTIFACTS_DIR/rtl_fifo"
  mkfifo "$fifo" 2>/dev/null || true
  
  rtl_fm \
    -f "$freq" \
    -s "$SAMPLE_RATE" \
    -g "$GAIN" \
    -p 0 \
    - 2>/dev/null > "$fifo" &
  RTL_PID=$!
  
  timeout "$duration" multimon-ng \
    -t raw \
    -a POCSAG512 \
    -a POCSAG1200 \
    -a POCSAG2400 \
    -f alpha \
    "$fifo" 2>/dev/null | parse_multimon_output &
  MULTIMON_PID=$!
  
  local start_time
  start_time=$(date +%s)
  local end_time=$((start_time + duration))
  
  while [[ $(date +%s) -lt $end_time ]]; do
    if ! kill -0 "$RTL_PID" 2>/dev/null; then
      LOG red "RTL-SDR process died"
      break
    fi
    
    local elapsed=$(($(date +%s) - start_time))
    local remaining=$((duration - elapsed))
    
    if [[ $((elapsed % 30)) -eq 0 ]]; then
      LOG "Listening... | Messages: $MESSAGE_COUNT | Addresses: $UNIQUE_ADDRESSES | ${remaining}s left"
    fi
    
    sleep 5
  done
  
  kill "$RTL_PID" 2>/dev/null || true
  kill "$MULTIMON_PID" 2>/dev/null || true
  rm -f "$fifo"
  
  RTL_PID=""
  MULTIMON_PID=""
}

generate_report() {
  local report_file="$ARTIFACTS_DIR/pocsag_report_$(date +%Y%m%d_%H%M%S).txt"
  
  {
    echo "========================================"
    echo "       POCSAG MONITOR REPORT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Frequency: $POCSAG_FREQ"
    echo "Duration: ${MONITOR_DURATION}s"
    echo ""
    echo "SUMMARY"
    echo "--------"
    echo "Total Messages: $MESSAGE_COUNT"
    echo "Unique Addresses: $UNIQUE_ADDRESSES"
    echo ""
    if [[ $UNIQUE_ADDRESSES -gt 0 ]]; then
      echo "ADDRESS ACTIVITY"
      echo "-----------------"
      for addr in "${!PAGER_ADDRESSES[@]}"; do
        echo "  $addr: ${PAGER_ADDRESSES[$addr]} messages"
      done | sort -t: -k2 -rn
      echo ""
    fi
    echo "MESSAGES"
    echo "--------"
    if [[ -f "$ARTIFACTS_DIR/messages.log" ]]; then
      cat "$ARTIFACTS_DIR/messages.log"
    else
      echo "No messages captured"
    fi
    echo ""
    echo "========================================"
  } > "$report_file"
  
  echo "$report_file"
}

main() {
  LOG blue "=== POCSAG Monitor ==="
  LOG "Pager signal decoding"
  LOG ""
  
  if ! have rtl_fm; then
    ERROR_DIALOG "rtl_fm not found. Install rtl-sdr tools."
    exit 1
  fi
  
  if ! have multimon-ng; then
    ERROR_DIALOG "multimon-ng not found. Install multimon-ng."
    exit 1
  fi
  
  LOG "Common POCSAG frequencies:"
  LOG "  1: 152.480 MHz (US common)"
  LOG "  2: 152.840 MHz (US alternate)"
  LOG "  3: 157.450 MHz (US alternate)"
  LOG "  4: 153.350 MHz (Hospital pagers)"
  LOG "  5: Custom frequency"
  LOG ""
  
  local freq_choice
  freq_choice=$(NUMBER_PICKER "Frequency preset (1-5)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "${freq_choice:-1}" in
    1) POCSAG_FREQ="152.480M" ;;
    2) POCSAG_FREQ="152.840M" ;;
    3) POCSAG_FREQ="157.450M" ;;
    4) POCSAG_FREQ="153.350M" ;;
    5)
      local custom_freq
      custom_freq=$(TEXT_PICKER "Frequency (MHz)" "152.480") || true
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      POCSAG_FREQ="${custom_freq}M"
      ;;
    *) POCSAG_FREQ="152.480M" ;;
  esac
  
  LOG "Selected frequency: $POCSAG_FREQ"
  
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  MONITOR_DURATION="$duration"
  
  mkdir -p "$ARTIFACTS_DIR"
  : > "$ARTIFACTS_DIR/messages.log"
  
  start_monitoring "$POCSAG_FREQ" "$duration"
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  LOG ""
  LOG green "=== Monitoring Complete ==="
  LOG "Total messages: $MESSAGE_COUNT"
  LOG "Unique addresses: $UNIQUE_ADDRESSES"
  
  local report
  report=$(generate_report)
  LOG "Report: $report"
  
  if [[ $MESSAGE_COUNT -gt 0 ]]; then
    ALERT "Captured $MESSAGE_COUNT POCSAG messages"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
