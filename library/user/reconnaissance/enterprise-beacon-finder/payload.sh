#!/bin/bash
# Title: Enterprise Beacon Finder
# Description: Detect WPA2/WPA3-Enterprise networks (802.1X/EAP)
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Scanning
# - Blue solid flash: Enterprise network found
# - Green: Scan complete

set -euo pipefail

SCAN_DURATION="${SCAN_DURATION:-120}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/enterprise-finder}"

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

declare -A ENTERPRISE_APS
ENTERPRISE_COUNT=0

is_enterprise() {
  local privacy="$1"
  local auth="$2"
  
  [[ "$privacy" =~ MGT || "$auth" =~ MGT || "$auth" =~ 802\.1X || "$auth" =~ EAP ]] && return 0
  [[ "$privacy" =~ WPA.*Enterprise || "$privacy" =~ WPA2.*Enterprise || "$privacy" =~ WPA3.*Enterprise ]] && return 0
  return 1
}

alert_enterprise_found() {
  local bssid="$1"
  local ssid="$2"
  local enc="$3"
  local rssi="$4"
  
  ENTERPRISE_COUNT=$((ENTERPRISE_COUNT + 1))
  
  LED B SOLID
  VIBRATE 150
  
  LOG green "[!] Enterprise Network: $ssid"
  LOG "    BSSID: $bssid"
  LOG "    Security: $enc"
  LOG "    Signal: ${rssi}dB"
  
  echo "[$(date '+%H:%M:%S')] $bssid | $ssid | $enc | ${rssi}dB" >> "$ARTIFACTS_DIR/enterprise_aps.log"
  
  sleep 1
  LED B SLOW
}

parse_airodump_csv() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  while IFS=',' read -r bssid first last channel speed privacy cipher auth power beacons iv lan_ip id_len essid rest; do
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    
    bssid=$(echo "$bssid" | tr -d ' ')
    essid=$(echo "$essid" | tr -d ' ')
    privacy=$(echo "$privacy" | tr -d ' ')
    auth=$(echo "$auth" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    
    [[ -z "$essid" ]] && continue
    [[ -n "${ENTERPRISE_APS[$bssid]:-}" ]] && continue
    
    if is_enterprise "$privacy" "$auth"; then
      ENTERPRISE_APS["$bssid"]="$essid:$privacy:$auth"
      alert_enterprise_found "$bssid" "$essid" "$privacy/$auth" "$power"
    fi
  done < "$csv_file"
}

main() {
  LOG blue "=== Enterprise Beacon Finder ==="
  LOG "Detect WPA2/WPA3-Enterprise networks"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$SCAN_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$SCAN_DURATION"
  
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
  LOG "Scanning for enterprise networks..."
  
  LED B SLOW
  
  if have airodump-ng; then
    local csv_prefix="$ARTIFACTS_DIR/scan"
    
    timeout "$duration" airodump-ng \
      --write-interval 5 \
      --output-format csv \
      --write "$csv_prefix" \
      "$mon" 2>/dev/null &
    SCAN_PID=$!
    
    local end_time=$(($(date +%s) + duration))
    while [[ $(date +%s) -lt $end_time ]]; do
      sleep 10
      parse_airodump_csv "${csv_prefix}-01.csv"
      LOG "Scanning... ${#ENTERPRISE_APS[@]} enterprise networks found"
    done
    
    kill "$SCAN_PID" 2>/dev/null || true
  else
    ERROR_DIALOG "airodump-ng not available"
    exit 1
  fi
  
  LED G SOLID
  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "Enterprise networks found: ${#ENTERPRISE_APS[@]}"
  LOG ""
  
  if [[ ${#ENTERPRISE_APS[@]} -gt 0 ]]; then
    LOG blue "Enterprise Networks:"
    for bssid in "${!ENTERPRISE_APS[@]}"; do
      LOG "  $bssid -> ${ENTERPRISE_APS[$bssid]}"
    done
    
    {
      echo "=== Enterprise Beacon Finder Results ==="
      echo "Time: $(date)"
      echo "Duration: ${duration}s"
      echo "Enterprise APs: ${#ENTERPRISE_APS[@]}"
      echo ""
      for bssid in "${!ENTERPRISE_APS[@]}"; do
        echo "$bssid: ${ENTERPRISE_APS[$bssid]}"
      done
    } > "$ARTIFACTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
