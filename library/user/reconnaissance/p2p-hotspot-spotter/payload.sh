#!/bin/bash
# Title: P2P Hotspot Spotter
# Description: Detect WiFi Direct, mobile hotspots, and P2P networks
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Scanning
# - Cyan flash: Mobile hotspot detected
# - Yellow flash: WiFi Direct / P2P device found
# - Green: Scan complete
#
# Use Case: Find mobile devices sharing networks, P2P attack surfaces

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
SCAN_INTERVAL="${SCAN_INTERVAL:-10}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/p2p-spotter}"

HOTSPOT_PATTERNS=(
  "AndroidAP"
  "android"
  "iPhone"
  "iPad"
  "Galaxy"
  "Pixel"
  "Hotspot"
  "Mobile"
  "Personal"
  "Mi Phone"
  "OnePlus"
  "Redmi"
  "HUAWEI"
  "Xperia"
  "LG"
  "MOTO"
  "Nokia"
  "OPPO"
  "vivo"
  "realme"
)

P2P_PATTERNS=(
  "DIRECT-"
  "p2p-"
  "Chromecast"
  "Fire TV"
  "Roku"
  "Miracast"
  "SmartShare"
  "AllShare"
  "Screen Mirror"
  "AirPlay"
)

MOBILE_OUI=(
  "00:1A:11"  # Google
  "40:4E:36"  # Google Pixel
  "94:65:2D"  # OnePlus
  "F8:A9:D0"  # Apple
  "AC:BC:32"  # Apple
  "3C:06:30"  # Apple
  "00:26:E8"  # Murata (used in phones)
  "28:6C:07"  # Xiaomi
  "64:CC:2E"  # Xiaomi
  "F8:4D:89"  # Samsung
  "CC:07:AB"  # Samsung
  "BC:14:85"  # Samsung
)

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

declare -A HOTSPOTS
declare -A P2P_DEVICES
declare -A ALERTED
HOTSPOT_COUNT=0
P2P_COUNT=0

is_hotspot() {
  local ssid="$1"
  local ssid_lower
  ssid_lower=$(echo "$ssid" | tr '[:upper:]' '[:lower:]')
  
  for pattern in "${HOTSPOT_PATTERNS[@]}"; do
    local pattern_lower
    pattern_lower=$(echo "$pattern" | tr '[:upper:]' '[:lower:]')
    if [[ "$ssid_lower" == *"$pattern_lower"* ]]; then
      return 0
    fi
  done
  return 1
}

is_p2p() {
  local ssid="$1"
  
  for pattern in "${P2P_PATTERNS[@]}"; do
    if [[ "$ssid" == *"$pattern"* ]]; then
      return 0
    fi
  done
  return 1
}

is_mobile_oui() {
  local bssid="$1"
  local oui
  oui=$(echo "$bssid" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
  
  for mobile_oui in "${MOBILE_OUI[@]}"; do
    if [[ "$oui" == "$mobile_oui" ]]; then
      return 0
    fi
  done
  return 1
}

alert_hotspot() {
  local bssid="$1"
  local ssid="$2"
  local channel="$3"
  local rssi="$4"
  
  [[ -n "${ALERTED[$bssid]:-}" ]] && return 0
  ALERTED["$bssid"]=1
  
  LED C FAST
  VIBRATE 200
  
  LOG green "[!] Mobile hotspot: $ssid"
  LOG "    BSSID: $bssid | Ch: $channel | RSSI: ${rssi}dB"
  
  echo "[$(date '+%H:%M:%S')] HOTSPOT: $ssid ($bssid) ch:$channel rssi:$rssi" >> "$ARTIFACTS_DIR/hotspots.log"
  
  sleep 1
  LED B SLOW
}

alert_p2p() {
  local bssid="$1"
  local ssid="$2"
  local channel="$3"
  local rssi="$4"
  
  [[ -n "${ALERTED[$bssid]:-}" ]] && return 0
  ALERTED["$bssid"]=1
  
  LED Y FAST
  VIBRATE 300
  
  LOG green "[!] P2P/Direct: $ssid"
  LOG "    BSSID: $bssid | Ch: $channel | RSSI: ${rssi}dB"
  
  ALERT "P2P Device: $ssid"
  
  echo "[$(date '+%H:%M:%S')] P2P: $ssid ($bssid) ch:$channel rssi:$rssi" >> "$ARTIFACTS_DIR/p2p.log"
  
  sleep 1
  LED B SLOW
}

parse_scan() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_len essid rest; do
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    
    bssid=$(echo "$bssid" | tr -d ' ')
    essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    channel=$(echo "$channel" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    privacy=$(echo "$privacy" | tr -d ' ')
    
    [[ -z "$essid" ]] && continue
    
    if is_p2p "$essid"; then
      if [[ -z "${P2P_DEVICES[$bssid]:-}" ]]; then
        P2P_DEVICES["$bssid"]="$essid:$channel:$power"
        P2P_COUNT=$((P2P_COUNT + 1))
        alert_p2p "$bssid" "$essid" "$channel" "$power"
      fi
    elif is_hotspot "$essid" || is_mobile_oui "$bssid"; then
      if [[ -z "${HOTSPOTS[$bssid]:-}" ]]; then
        HOTSPOTS["$bssid"]="$essid:$channel:$power:$privacy"
        HOTSPOT_COUNT=$((HOTSPOT_COUNT + 1))
        alert_hotspot "$bssid" "$essid" "$channel" "$power"
      fi
    fi
  done < "$csv_file"
}

main() {
  LOG blue "=== P2P Hotspot Spotter ==="
  LOG "Detect mobile hotspots and P2P networks"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$MONITOR_DURATION") || true
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
  LOG ""
  LOG "Looking for:"
  LOG "  - Mobile hotspots (Android/iOS/etc)"
  LOG "  - WiFi Direct devices"
  LOG "  - Casting devices (Chromecast, Fire TV, etc)"
  LOG ""
  
  LED B SLOW
  
  local end_time=$(($(date +%s) + duration))
  local csv_prefix="$ARTIFACTS_DIR/scan"
  local scan_num=0
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    
    if have airodump-ng; then
      local csv_file="${csv_prefix}-${scan_num}"
      
      timeout "$SCAN_INTERVAL" airodump-ng \
        --write-interval 2 \
        --output-format csv \
        --write "$csv_file" \
        "$mon" 2>/dev/null &
      SCAN_PID=$!
      wait "$SCAN_PID" 2>/dev/null || true
      
      parse_scan "${csv_file}-01.csv"
      
      rm -f "${csv_file}"* 2>/dev/null || true
    else
      LOG red "airodump-ng not available"
      sleep "$SCAN_INTERVAL"
    fi
    
    local remaining=$((end_time - $(date +%s)))
    LOG "Status: ${HOTSPOT_COUNT} hotspots | ${P2P_COUNT} P2P | ${remaining}s left"
  done
  
  LED G SOLID
  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "Mobile hotspots: $HOTSPOT_COUNT"
  LOG "P2P/Direct devices: $P2P_COUNT"
  LOG ""
  
  if [[ $HOTSPOT_COUNT -gt 0 ]]; then
    LOG blue "Mobile Hotspots:"
    for bssid in "${!HOTSPOTS[@]}"; do
      local info="${HOTSPOTS[$bssid]}"
      local ssid ch rssi enc
      ssid=$(echo "$info" | cut -d: -f1)
      ch=$(echo "$info" | cut -d: -f2)
      rssi=$(echo "$info" | cut -d: -f3)
      enc=$(echo "$info" | cut -d: -f4)
      LOG "  $ssid ($bssid) ch:$ch ${rssi}dB [$enc]"
    done
  fi
  
  if [[ $P2P_COUNT -gt 0 ]]; then
    LOG ""
    LOG blue "P2P/Direct Devices:"
    for bssid in "${!P2P_DEVICES[@]}"; do
      local info="${P2P_DEVICES[$bssid]}"
      local ssid ch rssi
      ssid=$(echo "$info" | cut -d: -f1)
      ch=$(echo "$info" | cut -d: -f2)
      rssi=$(echo "$info" | cut -d: -f3)
      LOG "  $ssid ($bssid) ch:$ch ${rssi}dB"
    done
  fi
  
  {
    echo "=== P2P Hotspot Spotter Results ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo ""
    echo "=== Mobile Hotspots ($HOTSPOT_COUNT) ==="
    for bssid in "${!HOTSPOTS[@]}"; do
      echo "$bssid | ${HOTSPOTS[$bssid]}"
    done
    echo ""
    echo "=== P2P/Direct Devices ($P2P_COUNT) ==="
    for bssid in "${!P2P_DEVICES[@]}"; do
      echo "$bssid | ${P2P_DEVICES[$bssid]}"
    done
  } > "$ARTIFACTS_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG ""
  LOG "Report saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
