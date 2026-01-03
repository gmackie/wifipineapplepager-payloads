#!/bin/bash
# Title: Beacon Anomaly Watch
# Description: Detect RF anomalies - beacon floods, sudden SSID spikes, interference
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Amber slow blink: Monitoring baseline
# - Red fast blink: Anomaly detected!
# - Green: Monitoring complete

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/beacon-anomaly}"
BASELINE_WINDOW="${BASELINE_WINDOW:-30}"
SSID_SPIKE_THRESHOLD="${SSID_SPIKE_THRESHOLD:-10}"
BEACON_RATE_THRESHOLD="${BEACON_RATE_THRESHOLD:-500}"

have() { command -v "$1" >/dev/null 2>&1; }

ensure_monitor() {
  local mon_iface
  mon_iface=$(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
  if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  
  local base_iface
  base_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^wlan' | head -n1 || true)
  if have airmon-ng && [[ -n "$base_iface" ]]; then
    airmon-ng start "$base_iface" >/dev/null 2>&1 || true
    mon_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
    if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  fi
  echo ""
}

cleanup() {
  [[ -n "${SCAN_PID:-}" ]] && kill "$SCAN_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

BASELINE_SSID_COUNT=0
BASELINE_BSSID_COUNT=0
BASELINE_BEACON_RATE=0
ANOMALY_COUNT=0

alert_anomaly() {
  local anomaly_type="$1"
  local details="$2"
  
  ANOMALY_COUNT=$((ANOMALY_COUNT + 1))
  
  LED R FAST
  VIBRATE 500
  RINGTONE alarm 2>/dev/null || true
  
  LOG red "[!] ANOMALY: $anomaly_type"
  LOG "    $details"
  
  echo "[$(date '+%H:%M:%S')] $anomaly_type | $details" >> "$ARTIFACTS_DIR/anomalies.log"
  
  ALERT "RF Anomaly: $anomaly_type"
  
  sleep 2
  LED Y SLOW
}

count_from_csv() {
  local csv_file="$1"
  local ssid_count=0
  local bssid_count=0
  
  [[ ! -f "$csv_file" ]] && echo "0:0" && return
  
  while IFS=',' read -r bssid rest; do
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    bssid=$(echo "$bssid" | tr -d ' ')
    [[ -n "$bssid" ]] && bssid_count=$((bssid_count + 1))
  done < "$csv_file"
  
  ssid_count=$(awk -F',' 'NR>2 && $14!="" {print $14}' "$csv_file" 2>/dev/null | sort -u | wc -l || echo 0)
  
  echo "$ssid_count:$bssid_count"
}

check_anomalies() {
  local csv_file="$1"
  local counts
  counts=$(count_from_csv "$csv_file")
  local current_ssids current_bssids
  current_ssids=$(echo "$counts" | cut -d: -f1)
  current_bssids=$(echo "$counts" | cut -d: -f2)
  
  if [[ $BASELINE_SSID_COUNT -gt 0 ]]; then
    local ssid_increase=$((current_ssids - BASELINE_SSID_COUNT))
    if [[ $ssid_increase -gt $SSID_SPIKE_THRESHOLD ]]; then
      alert_anomaly "SSID Spike" "SSIDs jumped from $BASELINE_SSID_COUNT to $current_ssids (+$ssid_increase)"
    fi
    
    local bssid_increase=$((current_bssids - BASELINE_BSSID_COUNT))
    if [[ $bssid_increase -gt $SSID_SPIKE_THRESHOLD ]]; then
      alert_anomaly "BSSID Flood" "BSSIDs jumped from $BASELINE_BSSID_COUNT to $current_bssids (+$bssid_increase)"
    fi
  fi
  
  BASELINE_SSID_COUNT=$current_ssids
  BASELINE_BSSID_COUNT=$current_bssids
  
  LOG "Status: $current_ssids SSIDs, $current_bssids BSSIDs"
}

main() {
  LOG blue "=== Beacon Anomaly Watch ==="
  LOG "Detect RF environment anomalies"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  mkdir -p "$ARTIFACTS_DIR"
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG "SSID spike threshold: +$SSID_SPIKE_THRESHOLD"
  LOG ""
  
  LOG "Establishing baseline ($BASELINE_WINDOW seconds)..."
  LED Y FAST
  
  if have airodump-ng; then
    local csv_prefix="$ARTIFACTS_DIR/baseline"
    
    timeout "$BASELINE_WINDOW" airodump-ng \
      --write-interval 5 \
      --output-format csv \
      --write "$csv_prefix" \
      "$mon" 2>/dev/null || true
    
    local baseline_counts
    baseline_counts=$(count_from_csv "${csv_prefix}-01.csv")
    BASELINE_SSID_COUNT=$(echo "$baseline_counts" | cut -d: -f1)
    BASELINE_BSSID_COUNT=$(echo "$baseline_counts" | cut -d: -f2)
    
    LOG green "Baseline: $BASELINE_SSID_COUNT SSIDs, $BASELINE_BSSID_COUNT BSSIDs"
    LOG ""
    LOG "Monitoring for anomalies..."
    
    LED Y SLOW
    
    local end_time=$(($(date +%s) + duration - BASELINE_WINDOW))
    local scan_num=0
    
    while [[ $(date +%s) -lt $end_time ]]; do
      scan_num=$((scan_num + 1))
      local scan_prefix="$ARTIFACTS_DIR/scan_${scan_num}"
      
      timeout 15 airodump-ng \
        --write-interval 5 \
        --output-format csv \
        --write "$scan_prefix" \
        "$mon" 2>/dev/null &
      SCAN_PID=$!
      
      sleep 15
      kill "$SCAN_PID" 2>/dev/null || true
      
      check_anomalies "${scan_prefix}-01.csv"
      
      rm -f "${scan_prefix}"* 2>/dev/null || true
    done
  else
    ERROR_DIALOG "airodump-ng not available"
    exit 1
  fi
  
  LED G SOLID
  LOG ""
  LOG green "=== Monitoring Complete ==="
  LOG "Anomalies detected: $ANOMALY_COUNT"
  LOG "Final state: $BASELINE_SSID_COUNT SSIDs, $BASELINE_BSSID_COUNT BSSIDs"
  
  if [[ -f "$ARTIFACTS_DIR/anomalies.log" ]]; then
    LOG ""
    LOG "Anomaly log:"
    cat "$ARTIFACTS_DIR/anomalies.log"
  fi
  
  {
    echo "=== Beacon Anomaly Watch Results ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo "Anomalies: $ANOMALY_COUNT"
    echo "Final SSIDs: $BASELINE_SSID_COUNT"
    echo "Final BSSIDs: $BASELINE_BSSID_COUNT"
  } > "$ARTIFACTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
  
  PROMPT "Press button to exit"
}

main "$@"
