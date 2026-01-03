#!/bin/bash
# Title: OT OUI Scout
# Description: Detect ICS/OT devices by MAC OUI prefix in wireless traffic
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Magenta slow blink: Monitoring
# - Magenta fast blink: OT device detected!
# - Green: Monitoring complete

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ot-oui-scout}"

ICS_OUI_FILE="${ICS_OUI_FILE:-}"

ICS_OUI_BUILTIN=(
  "00:00:BC:Rockwell"
  "00:0E:8C:Siemens"
  "00:1C:06:Siemens"
  "00:80:F4:Schneider"
  "00:0B:AB:ABB"
  "00:0C:C6:ABB"
  "00:20:4A:Honeywell"
  "00:50:C2:Honeywell"
  "00:A0:F8:Emerson"
  "00:D0:C9:Emerson"
  "00:1D:9C:GE"
  "08:00:86:GE"
  "00:00:54:Yokogawa"
  "00:0D:89:Yokogawa"
  "00:80:4F:Mitsubishi"
  "00:60:35:Omron"
  "00:00:65:Omron"
  "00:01:4A:Phoenix"
  "00:04:A5:Beckhoff"
  "00:0D:56:Moxa"
  "00:90:E8:Moxa"
  "00:0B:8E:WAGO"
  "00:30:DE:WAGO"
  "00:80:72:Pilz"
  "00:00:A7:Hirschmann"
  "00:10:2F:Cisco-IE"
  "00:0E:5C:Motorola-SCADA"
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
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

declare -A OT_DEVICES_FOUND
declare -A ALL_MACS_SEEN

load_oui_database() {
  if [[ -n "$ICS_OUI_FILE" && -f "$ICS_OUI_FILE" ]]; then
    while IFS=',' read -r oui vendor; do
      [[ "$oui" =~ ^# ]] && continue
      ICS_OUI_BUILTIN+=("$oui:$vendor")
    done < "$ICS_OUI_FILE"
  fi
}

lookup_oui() {
  local mac="$1"
  local oui
  oui=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | cut -d: -f1-3)
  
  for entry in "${ICS_OUI_BUILTIN[@]}"; do
    local entry_oui entry_vendor
    entry_oui=$(echo "$entry" | cut -d: -f1-3)
    entry_vendor=$(echo "$entry" | cut -d: -f4-)
    
    if [[ "$oui" == "$entry_oui" ]]; then
      echo "$entry_vendor"
      return 0
    fi
  done
  return 1
}

alert_ot_device() {
  local mac="$1"
  local vendor="$2"
  local context="$3"
  
  LED M FAST
  VIBRATE 300
  
  LOG red "[!] OT DEVICE DETECTED"
  LOG "    MAC: $mac"
  LOG "    Vendor: $vendor"
  LOG "    Context: $context"
  
  echo "[$(date '+%H:%M:%S')] $mac | $vendor | $context" >> "$ARTIFACTS_DIR/ot_devices.log"
  
  ALERT "OT Device: $vendor ($mac)"
  
  sleep 1
  LED M SLOW
}

check_mac() {
  local mac="$1"
  local context="$2"
  
  [[ -z "$mac" || ! "$mac" =~ ^[0-9a-fA-F:]{17}$ ]] && return 0
  [[ -n "${ALL_MACS_SEEN[$mac]:-}" ]] && return 0
  ALL_MACS_SEEN["$mac"]=1
  
  local vendor
  if vendor=$(lookup_oui "$mac"); then
    [[ -n "${OT_DEVICES_FOUND[$mac]:-}" ]] && return 0
    OT_DEVICES_FOUND["$mac"]="$vendor"
    alert_ot_device "$mac" "$vendor" "$context"
  fi
}

process_packet() {
  local line="$1"
  
  local mac
  if [[ "$line" =~ SA:([0-9a-fA-F:]{17}) ]]; then
    check_mac "${BASH_REMATCH[1]}" "Source"
  fi
  if [[ "$line" =~ DA:([0-9a-fA-F:]{17}) ]]; then
    check_mac "${BASH_REMATCH[1]}" "Destination"
  fi
  if [[ "$line" =~ BSSID:([0-9a-fA-F:]{17}) ]]; then
    check_mac "${BASH_REMATCH[1]}" "BSSID"
  fi
  if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
    check_mac "${BASH_REMATCH[1]}" "Frame"
  fi
}

main() {
  LOG blue "=== OT OUI Scout ==="
  LOG "Detect ICS/OT devices by MAC vendor"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  mkdir -p "$ARTIFACTS_DIR"
  load_oui_database
  
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG "OUI entries: ${#ICS_OUI_BUILTIN[@]}"
  LOG ""
  LOG "Monitoring for OT device MACs..."
  
  LED M SLOW
  
  local end_time=$(($(date +%s) + duration))
  
  if have tcpdump; then
    tcpdump -I -i "$mon" -l -e 2>/dev/null | \
    while read -r line && [[ $(date +%s) -lt $end_time ]]; do
      process_packet "$line"
    done &
    TCPDUMP_PID=$!
    
    while [[ $(date +%s) -lt $end_time ]]; do
      sleep 10
      LOG "Monitoring... ${#ALL_MACS_SEEN[@]} MACs seen, ${#OT_DEVICES_FOUND[@]} OT devices"
    done
    
    kill "$TCPDUMP_PID" 2>/dev/null || true
  else
    ERROR_DIALOG "tcpdump not available"
    exit 1
  fi
  
  LED G SOLID
  LOG ""
  LOG green "=== Monitoring Complete ==="
  LOG "Total MACs seen: ${#ALL_MACS_SEEN[@]}"
  LOG "OT devices found: ${#OT_DEVICES_FOUND[@]}"
  LOG ""
  
  if [[ ${#OT_DEVICES_FOUND[@]} -gt 0 ]]; then
    LOG red "OT Devices Detected:"
    for mac in "${!OT_DEVICES_FOUND[@]}"; do
      LOG "  $mac -> ${OT_DEVICES_FOUND[$mac]}"
    done
    
    {
      echo "=== OT OUI Scout Results ==="
      echo "Time: $(date)"
      echo "Duration: ${duration}s"
      echo "MACs Seen: ${#ALL_MACS_SEEN[@]}"
      echo "OT Devices: ${#OT_DEVICES_FOUND[@]}"
      echo ""
      for mac in "${!OT_DEVICES_FOUND[@]}"; do
        echo "$mac: ${OT_DEVICES_FOUND[$mac]}"
      done
    } > "$ARTIFACTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
