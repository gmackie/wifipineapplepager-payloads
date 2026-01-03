#!/bin/bash
# Title: Rogue Twin Radar
# Description: Passive evil twin detector - alerts on same SSID with new BSSID or security downgrade
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Cyan slow blink: Monitoring
# - Red double blink: Evil twin detected!
# - Green: Monitoring complete
#
# Alerts
# - RINGTONE + VIBRATE on detection

set -euo pipefail

# === CONFIGURATION ===
MONITOR_DURATION="${MONITOR_DURATION:-300}"  # 5 minutes default
SCAN_INTERVAL="${SCAN_INTERVAL:-5}"          # Seconds between scans
MIN_RSSI_DIFF="${MIN_RSSI_DIFF:-20}"         # dB diff to flag RSSI anomaly
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/rogue-twin}"

# === HELPERS ===
have() { command -v "$1" >/dev/null 2>&1; }

ensure_monitor() {
  local base_iface mon_iface
  mon_iface=$(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
  if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  
  base_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^wlan' | head -n1 || true)
  if have airmon-ng && [[ -n "$base_iface" ]]; then
    airmon-ng start "$base_iface" >/dev/null 2>&1 || true
    mon_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
    if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  fi
  echo ""
}

cleanup() {
  LOG "Cleaning up..."
  [[ -n "${SCAN_PID:-}" ]] && kill "$SCAN_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

# === DETECTION STATE ===
declare -A SSID_MAP      # SSID -> "BSSID:ENC:RSSI" (first seen)
declare -A ALERT_SENT    # Track which SSIDs we've alerted on

alert_evil_twin() {
  local ssid="$1"
  local reason="$2"
  local details="$3"
  
  # Prevent duplicate alerts for same SSID
  if [[ -n "${ALERT_SENT[$ssid]:-}" ]]; then
    return 0
  fi
  ALERT_SENT["$ssid"]=1
  
  # Visual alert
  LED R DOUBLE
  VIBRATE 500
  RINGTONE alarm 2>/dev/null || true
  
  # Log and alert
  LOG red "!!! EVIL TWIN DETECTED !!!"
  LOG red "SSID: $ssid"
  LOG red "Reason: $reason"
  LOG "$details"
  
  ALERT "Evil Twin: $ssid - $reason"
  
  # Log to file
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] EVIL TWIN: $ssid | $reason | $details" >> "$ARTIFACTS_DIR/detections.log"
  
  # Brief pause then resume monitoring
  sleep 2
  LED C SLOW
}

check_for_twins() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  # Parse airodump CSV format
  # Format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
  
  while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_len essid rest; do
    # Skip header and empty lines
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    
    # Clean up fields
    bssid=$(echo "$bssid" | tr -d ' ')
    essid=$(echo "$essid" | tr -d ' ')
    privacy=$(echo "$privacy" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    
    # Skip empty SSIDs (hidden networks)
    [[ -z "$essid" || "$essid" == "<length:" ]] && continue
    
    # Current signature
    local current_sig="$bssid:$privacy:$power"
    
    # Check if we've seen this SSID before
    if [[ -n "${SSID_MAP[$essid]:-}" ]]; then
      local stored="${SSID_MAP[$essid]}"
      local stored_bssid stored_enc stored_rssi
      stored_bssid=$(echo "$stored" | cut -d: -f1-6)
      stored_enc=$(echo "$stored" | cut -d: -f7)
      stored_rssi=$(echo "$stored" | cut -d: -f8)
      
      # Check 1: Different BSSID for same SSID
      if [[ "$bssid" != "$stored_bssid" ]]; then
        alert_evil_twin "$essid" "New BSSID appeared" "Original: $stored_bssid -> New: $bssid"
        continue
      fi
      
      # Check 2: Security downgrade (WPA2 -> WPA -> OPEN)
      if [[ "$stored_enc" =~ WPA2 && ! "$privacy" =~ WPA2 ]]; then
        alert_evil_twin "$essid" "Security downgrade" "Was: $stored_enc -> Now: $privacy"
        continue
      fi
      if [[ "$stored_enc" =~ WPA && "$privacy" == "OPN" ]]; then
        alert_evil_twin "$essid" "Security downgrade to OPEN" "Was: $stored_enc -> Now: OPEN"
        continue
      fi
      
      # Check 3: Massive RSSI jump (could indicate closer rogue AP)
      if [[ -n "$stored_rssi" && -n "$power" && "$power" =~ ^-?[0-9]+$ && "$stored_rssi" =~ ^-?[0-9]+$ ]]; then
        local rssi_diff=$(( power - stored_rssi ))
        if [[ $rssi_diff -gt $MIN_RSSI_DIFF ]]; then
          alert_evil_twin "$essid" "Sudden RSSI spike (+${rssi_diff}dB)" "Was: ${stored_rssi}dB -> Now: ${power}dB"
          continue
        fi
      fi
    else
      # First time seeing this SSID - store it
      SSID_MAP["$essid"]="$current_sig"
      LOG "Baseline: $essid ($bssid) [$privacy] ${power}dB"
    fi
  done < "$csv_file"
}

# === MAIN ===
main() {
  LOG blue "=== Rogue Twin Radar ==="
  LOG "Passive evil twin detection"
  LOG ""
  
  # Get duration
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") 
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  # Setup
  mkdir -p "$ARTIFACTS_DIR"
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG ""
  LOG "Monitoring for evil twins..."
  LOG "Alerts: New BSSID, security downgrade, RSSI anomaly"
  LOG ""
  
  LED C SLOW
  
  local end_time=$(($(date +%s) + duration))
  local csv_prefix="$ARTIFACTS_DIR/scan"
  local scan_num=0
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    local csv_file="${csv_prefix}-${scan_num}-01.csv"
    
    # Quick scan with airodump-ng
    if have airodump-ng; then
      timeout "$SCAN_INTERVAL" airodump-ng \
        --write-interval 1 \
        --output-format csv \
        --write "${csv_prefix}-${scan_num}" \
        "$mon" 2>/dev/null &
      SCAN_PID=$!
      wait "$SCAN_PID" 2>/dev/null || true
      
      # Check the CSV for twins
      check_for_twins "$csv_file"
      
      # Cleanup old scan files
      rm -f "${csv_prefix}-${scan_num}"* 2>/dev/null || true
    else
      LOG red "airodump-ng not available"
      sleep "$SCAN_INTERVAL"
    fi
    
    # Show progress
    local remaining=$((end_time - $(date +%s)))
    LOG "Monitoring... ${remaining}s remaining | ${#SSID_MAP[@]} SSIDs tracked"
  done
  
  # Done
  LED G SOLID
  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "SSIDs tracked: ${#SSID_MAP[@]}"
  LOG "Detections: $(wc -l < "$ARTIFACTS_DIR/detections.log" 2>/dev/null || echo 0)"
  
  if [[ -f "$ARTIFACTS_DIR/detections.log" ]]; then
    LOG ""
    LOG "Detection log:"
    cat "$ARTIFACTS_DIR/detections.log"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
