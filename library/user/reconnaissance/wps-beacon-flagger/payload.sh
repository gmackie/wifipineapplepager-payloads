#!/bin/bash
# Title: WPS Beacon Flagger
# Description: Detect WPS-enabled access points (potential attack vectors)
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Amber slow blink: Scanning
# - Yellow double blink: WPS AP found!
# - Green: Scan complete
#
# Use Case: Identify APs vulnerable to WPS attacks (Reaver, Bully)

set -euo pipefail

# === CONFIGURATION ===
SCAN_DURATION="${SCAN_DURATION:-120}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/wps-flagger}"

# === HELPERS ===
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

# === STATE ===
declare -A WPS_APS        # BSSID -> "SSID:WPS_VERSION:LOCKED"
WPS_COUNT=0

alert_wps_found() {
  local bssid="$1"
  local ssid="$2"
  local wps_info="$3"
  local rssi="$4"
  
  WPS_COUNT=$((WPS_COUNT + 1))
  
  LED Y DOUBLE
  VIBRATE 200
  VIBRATE 200
  
  LOG green "[!] WPS Enabled: $ssid"
  LOG "    BSSID: $bssid"
  LOG "    WPS: $wps_info"
  LOG "    Signal: ${rssi}dB"
  
  echo "[$(date '+%H:%M:%S')] $bssid | $ssid | WPS: $wps_info | ${rssi}dB" >> "$ARTIFACTS_DIR/wps_aps.log"
  
  sleep 1
  LED Y SLOW
}

parse_wash_output() {
  local line="$1"
  
  # wash output format: BSSID Ch dBm WPS Lck Vendor ESSID
  # Example: AA:BB:CC:DD:EE:FF  6  -65  2.0  No  RalinkTech  MyNetwork
  
  if [[ "$line" =~ ^([0-9A-Fa-f:]{17})[[:space:]]+([0-9]+)[[:space:]]+(-?[0-9]+)[[:space:]]+([0-9.]+)[[:space:]]+(Yes|No)[[:space:]]+([^[:space:]]+)[[:space:]]+(.+)$ ]]; then
    local bssid="${BASH_REMATCH[1]}"
    local channel="${BASH_REMATCH[2]}"
    local rssi="${BASH_REMATCH[3]}"
    local wps_ver="${BASH_REMATCH[4]}"
    local locked="${BASH_REMATCH[5]}"
    local vendor="${BASH_REMATCH[6]}"
    local ssid="${BASH_REMATCH[7]}"
    
    # Skip if already seen
    [[ -n "${WPS_APS[$bssid]:-}" ]] && return 0
    
    WPS_APS["$bssid"]="$ssid:$wps_ver:$locked"
    
    local lock_status="Unlocked"
    [[ "$locked" == "Yes" ]] && lock_status="LOCKED"
    
    alert_wps_found "$bssid" "$ssid" "v$wps_ver ($lock_status)" "$rssi"
  fi
}

parse_airodump_wps() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  while IFS=',' read -r bssid first last channel speed privacy cipher auth power beacons iv lan_ip id_len essid rest; do
    # Skip headers
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    
    bssid=$(echo "$bssid" | tr -d ' ')
    essid=$(echo "$essid" | tr -d ' ')
    
    # Skip if already seen
    [[ -n "${WPS_APS[$bssid]:-}" ]] && continue
    
    # airodump doesn't always show WPS, but we can check with additional tools
    # For now, flag any WPA/WPA2 networks for potential WPS check
    if have wash; then
      # wash will be more accurate
      continue
    fi
    
  done < "$csv_file"
}

# === MAIN ===
main() {
  LOG blue "=== WPS Beacon Flagger ==="
  LOG "Detect WPS-enabled access points"
  LOG ""
  
  # Get duration
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$SCAN_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$SCAN_DURATION"
  
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
  LOG "Scanning for WPS-enabled networks..."
  
  LED Y SLOW
  
  # Prefer wash (from reaver suite) for WPS detection
  if have wash; then
    LOG "Using wash for WPS detection..."
    
    local wash_out="$ARTIFACTS_DIR/wash_$(date +%Y%m%d_%H%M%S).txt"
    
    timeout "$duration" wash -i "$mon" -C 2>&1 | while read -r line; do
      echo "$line" >> "$wash_out"
      parse_wash_output "$line"
    done &
    SCAN_PID=$!
    
    wait "$SCAN_PID" 2>/dev/null || true
    
  elif have airodump-ng; then
    LOG "Using airodump-ng (less accurate for WPS)..."
    LOG "Tip: Install reaver/wash for better WPS detection"
    
    local csv_prefix="$ARTIFACTS_DIR/scan"
    
    timeout "$duration" airodump-ng \
      --write-interval 5 \
      --output-format csv \
      --write "$csv_prefix" \
      "$mon" 2>/dev/null &
    SCAN_PID=$!
    
    # Periodically check the CSV
    local end_time=$(($(date +%s) + duration))
    while [[ $(date +%s) -lt $end_time ]]; do
      sleep 10
      parse_airodump_wps "${csv_prefix}-01.csv"
      LOG "Scanning... ${#WPS_APS[@]} WPS APs found"
    done
    
    kill "$SCAN_PID" 2>/dev/null || true
  else
    ERROR_DIALOG "No scanning tool available (need wash or airodump-ng)"
    exit 1
  fi
  
  # Results
  LED G SOLID
  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "WPS-enabled APs found: ${#WPS_APS[@]}"
  LOG ""
  
  if [[ ${#WPS_APS[@]} -gt 0 ]]; then
    LOG blue "WPS Access Points:"
    for bssid in "${!WPS_APS[@]}"; do
      local info="${WPS_APS[$bssid]}"
      LOG "  $bssid -> $info"
    done
    
    # Save summary
    {
      echo "=== WPS Beacon Flagger Results ==="
      echo "Time: $(date)"
      echo "Duration: ${duration}s"
      echo "WPS APs Found: ${#WPS_APS[@]}"
      echo ""
      echo "=== Details ==="
      for bssid in "${!WPS_APS[@]}"; do
        echo "$bssid: ${WPS_APS[$bssid]}"
      done
    } > "$ARTIFACTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
  else
    LOG "No WPS-enabled networks found"
  fi
  
  LOG ""
  LOG "Results saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
