#!/bin/bash
# Title: Deauth Attack Logger
# Description: Log deauth attacks with timestamps and patterns for analysis
# Author: Red Team Toolkit
# Version: 1.0
# Category: alerts
# Net Mode: OFF
#
# LED States
# - Red fast blink: Attack detected
# - Yellow: Logging

set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/deauth-logs}"
ALERT_THRESHOLD="${ALERT_THRESHOLD:-5}"

mkdir -p "$LOG_DIR"

LED R FAST
VIBRATE 300

timestamp=$(date '+%Y-%m-%d %H:%M:%S')
log_file="$LOG_DIR/attacks_$(date +%Y%m%d).log"
summary_file="$LOG_DIR/attack_summary.json"

source_mac="${_ALERT_DENIAL_SOURCE_MAC_ADDRESS:-unknown}"
dest_mac="${_ALERT_DENIAL_DESTINATION_MAC_ADDRESS:-unknown}"
ap_mac="${_ALERT_DENIAL_AP_MAC_ADDRESS:-unknown}"
client_mac="${_ALERT_DENIAL_CLIENT_MAC_ADDRESS:-unknown}"

{
  echo "[$timestamp] DEAUTH_FLOOD"
  echo "  Source: $source_mac"
  echo "  Destination: $dest_mac"
  echo "  AP: $ap_mac"
  echo "  Client: $client_mac"
  echo "  Message: ${_ALERT_DENIAL_MESSAGE:-}"
  echo ""
} >> "$log_file"

attack_count=0
if [[ -f "$log_file" ]]; then
  attack_count=$(grep -c "DEAUTH_FLOOD" "$log_file" 2>/dev/null || echo 0)
fi

ap_attacks=0
if [[ -f "$log_file" ]]; then
  ap_attacks=$(grep -c "AP: $ap_mac" "$log_file" 2>/dev/null || echo 0)
fi

LED Y SOLID

LOG red "=== Deauth Flood Detected ==="
LOG "${_ALERT_DENIAL_MESSAGE:-Deauth attack in progress}"
LOG ""
LOG "Source: $source_mac"
LOG "Target AP: $ap_mac"
LOG "Target Client: $client_mac"
LOG ""
LOG "Stats: $attack_count attacks today, $ap_attacks against this AP"

if [[ $ap_attacks -ge $ALERT_THRESHOLD ]]; then
  LOG ""
  LOG red "!!! SUSTAINED ATTACK ON $ap_mac !!!"
  RINGTONE alarm 2>/dev/null || true
  ALERT "Sustained deauth attack: $ap_attacks hits on AP $ap_mac"
else
  ALERT "Deauth attack logged: $source_mac -> $ap_mac"
fi

{
  echo "{"
  echo "  \"last_updated\": \"$timestamp\","
  echo "  \"total_attacks_today\": $attack_count,"
  echo "  \"unique_sources\": $(grep "Source:" "$log_file" 2>/dev/null | sort -u | wc -l),"
  echo "  \"unique_targets\": $(grep "AP:" "$log_file" 2>/dev/null | sort -u | wc -l)"
  echo "}"
} > "$summary_file"

LED OFF
