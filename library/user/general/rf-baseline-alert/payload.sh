#!/bin/bash
# Title: RF Baseline Alert
# Description: RTL-SDR based RF monitoring - establish baseline, alert on new emitters
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Amber slow: Establishing baseline
# - Blue slow: Monitoring
# - Red fast: New emitter detected
# - Green: Session complete
#
# Requirements: rtl_power, rtl-sdr drivers

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/rf-baseline}"
BASELINE_DURATION="${BASELINE_DURATION:-60}"
MONITOR_DURATION="${MONITOR_DURATION:-300}"
FREQ_START="${FREQ_START:-400M}"
FREQ_END="${FREQ_END:-500M}"
BIN_SIZE="${BIN_SIZE:-10k}"
INTERVAL="${INTERVAL:-10}"
THRESHOLD_DB="${THRESHOLD_DB:-10}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${RTL_PID:-}" ]] && kill "$RTL_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

declare -A BASELINE_POWER
declare -A CURRENT_POWER
declare -A ALERTS

ALERT_COUNT=0
TOTAL_BINS=0

parse_rtl_power() {
  local csv_file="$1"
  local mode="$2"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  while IFS=',' read -r date time freq_low freq_high bin_hz samples db_values; do
    [[ "$date" =~ ^# || -z "$date" ]] && continue
    
    local freq="$freq_low"
    local step="${bin_hz:-$BIN_SIZE}"
    
    for db in $db_values; do
      [[ -z "$db" || "$db" == "-" ]] && continue
      
      local freq_key="${freq}"
      
      if [[ "$mode" == "baseline" ]]; then
        if [[ -z "${BASELINE_POWER[$freq_key]:-}" ]]; then
          BASELINE_POWER["$freq_key"]="$db"
          TOTAL_BINS=$((TOTAL_BINS + 1))
        else
          local old="${BASELINE_POWER[$freq_key]}"
          BASELINE_POWER["$freq_key"]=$(awk "BEGIN {printf \"%.1f\", ($old + $db) / 2}")
        fi
      else
        CURRENT_POWER["$freq_key"]="$db"
        
        if [[ -n "${BASELINE_POWER[$freq_key]:-}" ]]; then
          local baseline="${BASELINE_POWER[$freq_key]}"
          local diff
          diff=$(awk "BEGIN {printf \"%.1f\", $db - $baseline}")
          
          if awk "BEGIN {exit !($diff > $THRESHOLD_DB)}"; then
            if [[ -z "${ALERTS[$freq_key]:-}" ]]; then
              trigger_alert "$freq_key" "$baseline" "$db" "$diff"
            fi
          fi
        else
          if awk "BEGIN {exit !($db > -50)}"; then
            if [[ -z "${ALERTS[$freq_key]:-}" ]]; then
              trigger_alert "$freq_key" "N/A" "$db" "NEW"
            fi
          fi
        fi
      fi
      
      freq=$(awk "BEGIN {printf \"%.0f\", $freq + ${step%k}000}")
    done
  done < "$csv_file"
}

trigger_alert() {
  local freq="$1"
  local baseline="$2"
  local current="$3"
  local diff="$4"
  
  ALERTS["$freq"]="$current"
  ALERT_COUNT=$((ALERT_COUNT + 1))
  
  local freq_mhz
  freq_mhz=$(awk "BEGIN {printf \"%.3f\", $freq / 1000000}")
  
  LED R FAST
  VIBRATE 300
  
  LOG red "ALERT: New emitter at ${freq_mhz} MHz!"
  LOG "  Baseline: ${baseline} dB, Current: ${current} dB, Delta: ${diff}"
  
  echo "[$(date '+%H:%M:%S')] ALERT: ${freq_mhz} MHz | Baseline: ${baseline} | Current: ${current} | Delta: ${diff}" >> "$ARTIFACTS_DIR/alerts.log"
  
  sleep 1
  LED B SLOW
}

run_rtl_power() {
  local output_file="$1"
  local duration="$2"
  
  if ! have rtl_power; then
    LOG red "rtl_power not found"
    return 1
  fi
  
  rtl_power \
    -f "${FREQ_START}:${FREQ_END}:${BIN_SIZE}" \
    -i "$INTERVAL" \
    -e "$duration" \
    -g 40 \
    "$output_file" 2>/dev/null &
  RTL_PID=$!
  
  wait "$RTL_PID" 2>/dev/null || true
  RTL_PID=""
}

establish_baseline() {
  LOG "Establishing RF baseline..."
  LOG "Frequency range: $FREQ_START - $FREQ_END"
  LOG "Duration: ${BASELINE_DURATION}s"
  LOG ""
  
  LED Y SLOW
  
  local baseline_file="$ARTIFACTS_DIR/baseline.csv"
  
  run_rtl_power "$baseline_file" "$BASELINE_DURATION"
  
  if [[ -f "$baseline_file" ]]; then
    parse_rtl_power "$baseline_file" "baseline"
    LOG green "Baseline established: $TOTAL_BINS frequency bins"
  else
    LOG red "Failed to capture baseline"
    return 1
  fi
}

monitor_rf() {
  local duration="$1"
  local end_time=$(($(date +%s) + duration))
  local scan_num=0
  
  LOG ""
  LOG "Monitoring for anomalies..."
  LOG "Threshold: +${THRESHOLD_DB} dB above baseline"
  LOG ""
  
  LED B SLOW
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    local scan_file="$ARTIFACTS_DIR/scan_${scan_num}.csv"
    
    rtl_power \
      -f "${FREQ_START}:${FREQ_END}:${BIN_SIZE}" \
      -i "$INTERVAL" \
      -e "$INTERVAL" \
      -g 40 \
      -1 \
      "$scan_file" 2>/dev/null || true
    
    if [[ -f "$scan_file" ]]; then
      parse_rtl_power "$scan_file" "monitor"
      rm -f "$scan_file"
    fi
    
    local remaining=$((end_time - $(date +%s)))
    LOG "Scan #${scan_num} | Alerts: $ALERT_COUNT | ${remaining}s remaining"
    
    sleep 2
  done
}

generate_report() {
  local report_file="$ARTIFACTS_DIR/rf_report_$(date +%Y%m%d_%H%M%S).txt"
  
  {
    echo "========================================"
    echo "       RF BASELINE ALERT REPORT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Frequency Range: $FREQ_START - $FREQ_END"
    echo "Bin Size: $BIN_SIZE"
    echo "Threshold: +${THRESHOLD_DB} dB"
    echo ""
    echo "SUMMARY"
    echo "--------"
    echo "Baseline Bins: $TOTAL_BINS"
    echo "Alerts Triggered: $ALERT_COUNT"
    echo ""
    if [[ $ALERT_COUNT -gt 0 ]]; then
      echo "DETECTED ANOMALIES"
      echo "-------------------"
      for freq in "${!ALERTS[@]}"; do
        local freq_mhz
        freq_mhz=$(awk "BEGIN {printf \"%.3f\", $freq / 1000000}")
        echo "${freq_mhz} MHz: ${ALERTS[$freq]} dB"
      done | sort -t: -k1 -n
      echo ""
    fi
    echo "BASELINE DATA"
    echo "--------------"
    for freq in "${!BASELINE_POWER[@]}"; do
      local freq_mhz
      freq_mhz=$(awk "BEGIN {printf \"%.3f\", $freq / 1000000}")
      echo "${freq_mhz} MHz: ${BASELINE_POWER[$freq]} dB"
    done | sort -t: -k1 -n | head -50
    echo "[truncated at 50 entries]"
    echo ""
    echo "========================================"
  } > "$report_file"
  
  echo "$report_file"
}

main() {
  LOG blue "=== RF Baseline Alert ==="
  LOG "RTL-SDR RF anomaly detection"
  LOG ""
  
  if ! have rtl_power; then
    ERROR_DIALOG "rtl_power not found. Install rtl-sdr tools."
    exit 1
  fi
  
  local freq_choice
  freq_choice=$(NUMBER_PICKER "Frequency preset" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "${freq_choice:-1}" in
    1) FREQ_START="400M"; FREQ_END="500M"; LOG "Preset: UHF 400-500 MHz" ;;
    2) FREQ_START="800M"; FREQ_END="900M"; LOG "Preset: Cellular 800-900 MHz" ;;
    3) FREQ_START="100M"; FREQ_END="200M"; LOG "Preset: FM/VHF 100-200 MHz" ;;
    4) FREQ_START="1G"; FREQ_END="1.1G"; LOG "Preset: L-band 1-1.1 GHz" ;;
    *) FREQ_START="400M"; FREQ_END="500M"; LOG "Default: UHF 400-500 MHz" ;;
  esac
  
  local monitor_time
  monitor_time=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$monitor_time" ]] && monitor_time="$MONITOR_DURATION"
  
  mkdir -p "$ARTIFACTS_DIR"
  
  local spinner_id
  spinner_id=$(START_SPINNER "Establishing baseline...")
  establish_baseline
  STOP_SPINNER "$spinner_id"
  
  monitor_rf "$monitor_time"
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  LOG ""
  LOG green "=== Monitoring Complete ==="
  LOG "Total alerts: $ALERT_COUNT"
  
  local report
  report=$(generate_report)
  LOG "Report: $report"
  
  if [[ $ALERT_COUNT -gt 0 ]]; then
    ALERT "Detected $ALERT_COUNT RF anomalies!"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
