#!/bin/bash
# Title: Client Profiler
# Description: Log client connections with OUI lookup and device fingerprinting
# Author: Red Team Toolkit
# Version: 1.0
# Category: alerts
# Net Mode: OFF
#
# LED States
# - Cyan blink: New client connected
# - Green: Client logged

set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/client-profiles}"
OUI_FILE="${OUI_FILE:-/usr/share/ieee-data/oui.txt}"

mkdir -p "$LOG_DIR"

LED C FAST
VIBRATE 200

timestamp=$(date '+%Y-%m-%d %H:%M:%S')

ap_mac="${_ALERT_CLIENT_CONNECTED_AP_MAC_ADDRESS:-unknown}"
client_mac="${_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS:-unknown}"
ssid="${_ALERT_CLIENT_CONNECTED_SSID:-unknown}"

oui_prefix=$(echo "$client_mac" | tr -d ':' | cut -c1-6 | tr '[:lower:]' '[:upper:]')

vendor="Unknown"
if [[ -f "$OUI_FILE" ]]; then
  vendor=$(grep -i "^$oui_prefix" "$OUI_FILE" 2>/dev/null | head -1 | cut -f3 || echo "Unknown")
fi

if [[ "$vendor" == "Unknown" ]]; then
  case "$oui_prefix" in
    F8A9D0|ACBC32|3C0630|A4D1D2|28ED6A) vendor="Apple" ;;
    F84D89|CC07AB|BC1485|90B0ED|6C2F2C) vendor="Samsung" ;;
    001A11|404E36|94EB2C|E8B4C8|34363B) vendor="Google" ;;
    9465?2D|C0EEFD) vendor="OnePlus" ;;
    28:6C:07|64:CC:2E|78:11:DC) vendor="Xiaomi" ;;
    *) vendor="Unknown ($oui_prefix)" ;;
  esac
fi

device_type="Unknown"
case "$vendor" in
  Apple*)
    if [[ "$client_mac" =~ ^(28|3C|A4|F8) ]]; then
      device_type="iPhone/iPad"
    else
      device_type="MacBook/Apple Device"
    fi
    ;;
  Samsung*) device_type="Android (Samsung)" ;;
  Google*) device_type="Android (Pixel)" ;;
  OnePlus*) device_type="Android (OnePlus)" ;;
  Xiaomi*) device_type="Android (Xiaomi)" ;;
esac

client_file="$LOG_DIR/${client_mac//:/}.json"
log_file="$LOG_DIR/connections_$(date +%Y%m%d).log"
seen_before=0

if [[ -f "$client_file" ]]; then
  seen_before=1
fi

{
  echo "[$timestamp] CLIENT_CONNECTED"
  echo "  Client: $client_mac"
  echo "  Vendor: $vendor"
  echo "  Device: $device_type"
  echo "  AP: $ap_mac"
  echo "  SSID: $ssid"
  echo "  Repeat: $([ $seen_before -eq 1 ] && echo "Yes" || echo "No")"
  echo ""
} >> "$log_file"

{
  echo "{"
  echo "  \"mac\": \"$client_mac\","
  echo "  \"vendor\": \"$vendor\","
  echo "  \"device_type\": \"$device_type\","
  echo "  \"first_seen\": \"$([ $seen_before -eq 1 ] && cat "$client_file" 2>/dev/null | grep first_seen | cut -d'"' -f4 || echo "$timestamp")\","
  echo "  \"last_seen\": \"$timestamp\","
  echo "  \"ssids_connected\": ["
  if [[ $seen_before -eq 1 ]]; then
    prev_ssids=$(cat "$client_file" 2>/dev/null | grep -oP '(?<="ssids_connected": \[)[^\]]+' | tr -d '\n "' || echo "")
    if [[ -n "$prev_ssids" && ! "$prev_ssids" =~ $ssid ]]; then
      echo "    \"$prev_ssids\", \"$ssid\""
    else
      echo "    \"$ssid\""
    fi
  else
    echo "    \"$ssid\""
  fi
  echo "  ],"
  echo "  \"aps_seen\": ["
  if [[ $seen_before -eq 1 ]]; then
    prev_aps=$(cat "$client_file" 2>/dev/null | grep -oP '(?<="aps_seen": \[)[^\]]+' | tr -d '\n "' || echo "")
    if [[ -n "$prev_aps" && ! "$prev_aps" =~ $ap_mac ]]; then
      echo "    \"$prev_aps\", \"$ap_mac\""
    else
      echo "    \"$ap_mac\""
    fi
  else
    echo "    \"$ap_mac\""
  fi
  echo "  ]"
  echo "}"
} > "$client_file"

LED G SOLID

LOG blue "=== Client Connected ==="
LOG "${_ALERT_CLIENT_CONNECTED_SUMMARY:-New client connection}"
LOG ""
LOG "Client: $client_mac"
LOG "Vendor: $vendor"
LOG "Device: $device_type"
LOG "SSID: $ssid"

if [[ $seen_before -eq 1 ]]; then
  LOG ""
  LOG green "Returning client!"
  ALERT "Returning client: $vendor device on $ssid"
else
  LOG ""
  LOG "New client profiled"
  ALERT "New client: $vendor ($device_type)"
fi

unique_clients=$(ls -1 "$LOG_DIR"/*.json 2>/dev/null | wc -l || echo 0)
LOG ""
LOG "Total unique clients: $unique_clients"

LED OFF
