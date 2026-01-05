#!/bin/bash
# Title: LoRa Sniffer
# Description: RTL-SDR LoRa/ISM band monitoring with device detection
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow: Listening
# - Cyan flash: Transmission detected
# - Magenta flash: New device found
# - Green: Session complete
#
# Requirements: rtl_433 (preferred) or rtl_power + rtl_sdr

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/lora-sniffer}"
MONITOR_DURATION="${MONITOR_DURATION:-600}"
LORA_FREQ="${LORA_FREQ:-915M}"
GAIN="${GAIN:-40}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${RTL_PID:-}" ]] && kill "$RTL_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

PACKET_COUNT=0
DEVICE_COUNT=0
declare -A KNOWN_DEVICES
declare -A DEVICE_PACKETS

log_transmission() {
  local timestamp="$1"
  local device_id="$2"
  local protocol="$3"
  local data="$4"
  
  PACKET_COUNT=$((PACKET_COUNT + 1))
  
  if [[ -z "${KNOWN_DEVICES[$device_id]:-}" ]]; then
    KNOWN_DEVICES["$device_id"]="$protocol"
    DEVICE_PACKETS["$device_id"]=1
    DEVICE_COUNT=$((DEVICE_COUNT + 1))
    
    LED M FAST
    VIBRATE 200
    LOG magenta "NEW DEVICE: $device_id ($protocol)"
  else
    DEVICE_PACKETS["$device_id"]=$((${DEVICE_PACKETS[$device_id]} + 1))
    LED C FAST
  fi
  
  {
    echo "========================================"
    echo "Time: $timestamp"
    echo "Device: $device_id"
    echo "Protocol: $protocol"
    echo "Data: $data"
    echo "========================================"
  } >> "$ARTIFACTS_DIR/packets.log"
  
  LOG cyan "PKT #$PACKET_COUNT | $device_id | $protocol"
  
  sleep 0.2
  LED B SLOW
}

parse_rtl433_output() {
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$line" =~ model.*:.*([^,]+) ]]; then
      local model="${BASH_REMATCH[1]}"
      local device_id="unknown"
      local protocol="$model"
      
      if [[ "$line" =~ id.*:.*([0-9]+) ]]; then
        device_id="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ device.*:.*([0-9]+) ]]; then
        device_id="${BASH_REMATCH[1]}"
      fi
      
      log_transmission "$timestamp" "$device_id" "$protocol" "$line"
    elif [[ "$line" =~ time.*([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
      echo "$line" >> "$ARTIFACTS_DIR/raw.log"
    fi
  done
}

run_rtl433_monitor() {
  local freq="$1"
  local duration="$2"
  
  LOG "Starting rtl_433 monitoring..."
  LOG "Frequency: $freq"
  LOG ""
  
  LED B SLOW
  
  local freq_hz="${freq%M}000000"
  [[ "$freq" =~ G$ ]] && freq_hz="${freq%G}000000000"
  
  timeout "$duration" rtl_433 \
    -f "$freq_hz" \
    -g "$GAIN" \
    -F json \
    -M time:utc \
    -M protocol \
    -M level \
    2>/dev/null | while IFS= read -r json_line; do
      [[ -z "$json_line" ]] && continue
      
      local timestamp
      timestamp=$(date '+%Y-%m-%d %H:%M:%S')
      
      local model=""
      local device_id=""
      
      if [[ "$json_line" =~ \"model\":\"([^\"]+)\" ]]; then
        model="${BASH_REMATCH[1]}"
      fi
      
      if [[ "$json_line" =~ \"id\":([0-9]+) ]]; then
        device_id="${BASH_REMATCH[1]}"
      elif [[ "$json_line" =~ \"device\":([0-9]+) ]]; then
        device_id="${BASH_REMATCH[1]}"
      else
        device_id="dev_$RANDOM"
      fi
      
      [[ -n "$model" ]] && log_transmission "$timestamp" "$device_id" "$model" "$json_line"
    done || true
}

run_spectrum_monitor() {
  local freq="$1"
  local duration="$2"
  
  LOG "rtl_433 not available, using spectrum analysis..."
  LOG "Frequency: $freq (looking for chirp patterns)"
  LOG ""
  
  LED B SLOW
  
  if ! have rtl_power; then
    LOG red "rtl_power not available"
    return 1
  fi
  
  local center_mhz="${freq%M}"
  local start_freq="$((center_mhz - 1))M"
  local end_freq="$((center_mhz + 1))M"
  
  local scan_file="$ARTIFACTS_DIR/spectrum.csv"
  local end_time=$(($(date +%s) + duration))
  local scan_num=0
  local last_max_power=-100
  local threshold=-50
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    
    rtl_power \
      -f "${start_freq}:${end_freq}:10k" \
      -i 1 \
      -e 2 \
      -g "$GAIN" \
      -1 \
      "$scan_file" 2>/dev/null || true
    
    if [[ -f "$scan_file" ]]; then
      local max_power
      max_power=$(awk -F',' 'NR>1 {for(i=7;i<=NF;i++) if($i>max) max=$i} END {print max}' "$scan_file" 2>/dev/null || echo "-100")
      
      if awk "BEGIN {exit !($max_power > $threshold && $max_power > $last_max_power + 10)}"; then
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        PACKET_COUNT=$((PACKET_COUNT + 1))
        LED C FAST
        VIBRATE 100
        
        LOG cyan "BURST #$PACKET_COUNT | Power: ${max_power} dB @ $freq"
        echo "[$timestamp] Burst detected: ${max_power} dB" >> "$ARTIFACTS_DIR/bursts.log"
        
        sleep 0.3
        LED B SLOW
      fi
      
      last_max_power="$max_power"
      rm -f "$scan_file"
    fi
    
    local remaining=$((end_time - $(date +%s)))
    if [[ $((scan_num % 30)) -eq 0 ]]; then
      LOG "Scan #$scan_num | Bursts: $PACKET_COUNT | ${remaining}s left"
    fi
    
    sleep 1
  done
}

generate_report() {
  local report_file="$ARTIFACTS_DIR/lora_report_$(date +%Y%m%d_%H%M%S).txt"
  
  {
    echo "========================================"
    echo "       LORA SNIFFER REPORT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Frequency: $LORA_FREQ"
    echo "Duration: ${MONITOR_DURATION}s"
    echo ""
    echo "SUMMARY"
    echo "--------"
    echo "Total Packets: $PACKET_COUNT"
    echo "Unique Devices: $DEVICE_COUNT"
    echo ""
    if [[ $DEVICE_COUNT -gt 0 ]]; then
      echo "DEVICE INVENTORY"
      echo "-----------------"
      for dev in "${!KNOWN_DEVICES[@]}"; do
        echo "  $dev: ${KNOWN_DEVICES[$dev]} (${DEVICE_PACKETS[$dev]} packets)"
      done | sort -t: -k2 -rn
      echo ""
    fi
    echo "PACKET LOG"
    echo "----------"
    if [[ -f "$ARTIFACTS_DIR/packets.log" ]]; then
      cat "$ARTIFACTS_DIR/packets.log"
    elif [[ -f "$ARTIFACTS_DIR/bursts.log" ]]; then
      cat "$ARTIFACTS_DIR/bursts.log"
    else
      echo "No packets captured"
    fi
    echo ""
    echo "========================================"
  } > "$report_file"
  
  echo "$report_file"
}

main() {
  LOG blue "=== LoRa Sniffer ==="
  LOG "ISM band monitoring"
  LOG ""
  
  if ! have rtl_433 && ! have rtl_power; then
    ERROR_DIALOG "No RTL-SDR tools found. Install rtl_433 or rtl-sdr."
    exit 1
  fi
  
  LOG "LoRa/ISM Frequency Bands:"
  LOG "  1: 915 MHz (US ISM / LoRa)"
  LOG "  2: 868 MHz (EU ISM / LoRa)"
  LOG "  3: 433 MHz (Global ISM)"
  LOG "  4: 315 MHz (US remotes)"
  LOG "  5: Custom frequency"
  LOG ""
  
  local freq_choice
  freq_choice=$(NUMBER_PICKER "Frequency preset (1-5)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "${freq_choice:-1}" in
    1) LORA_FREQ="915M" ;;
    2) LORA_FREQ="868M" ;;
    3) LORA_FREQ="433.92M" ;;
    4) LORA_FREQ="315M" ;;
    5)
      local custom_freq
      custom_freq=$(TEXT_PICKER "Frequency (MHz)" "915") || true
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      LORA_FREQ="${custom_freq}M"
      ;;
    *) LORA_FREQ="915M" ;;
  esac
  
  LOG "Selected: $LORA_FREQ"
  
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  MONITOR_DURATION="$duration"
  
  mkdir -p "$ARTIFACTS_DIR"
  : > "$ARTIFACTS_DIR/packets.log"
  
  if have rtl_433; then
    LOG green "Using rtl_433 (protocol decoding enabled)"
    run_rtl433_monitor "$LORA_FREQ" "$duration"
  else
    LOG "Using spectrum analysis (burst detection only)"
    run_spectrum_monitor "$LORA_FREQ" "$duration"
  fi
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  LOG ""
  LOG green "=== Monitoring Complete ==="
  LOG "Packets: $PACKET_COUNT"
  LOG "Devices: $DEVICE_COUNT"
  
  local report
  report=$(generate_report)
  LOG "Report: $report"
  
  if [[ $DEVICE_COUNT -gt 0 ]]; then
    ALERT "Found $DEVICE_COUNT LoRa/ISM devices"
  elif [[ $PACKET_COUNT -gt 0 ]]; then
    ALERT "Detected $PACKET_COUNT RF bursts"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
