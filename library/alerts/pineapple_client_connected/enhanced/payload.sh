#!/bin/bash
# Title: Enhanced Client Connected Alert
# Description: Notifies with LED/sound/vibrate based on severity; watchlist aware
# Author: anomaly
# Version: 1.0
# Category: alerts
# Net Mode: OFF

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="$DIR/../../_common/alert_common.sh"

if [[ -f "$COMMON_SH" ]]; then
  source "$COMMON_SH"
else
  ALERT "$_ALERT_CLIENT_CONNECTED_SUMMARY"
  exit 0
fi

severity="medium"
category="pineapple_client_connected"
message="${_ALERT_CLIENT_CONNECTED_SUMMARY:-Client connected}"

client_mac="${_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS:-}"
ssid="${_ALERT_CLIENT_CONNECTED_SSID:-}"

if [[ -n "$client_mac" ]]; then
  match_result="$(alert_common_watchlist_match "mac" "$client_mac" || true)"
  if [[ -n "$match_result" ]]; then
    IFS='|' read -r match_sev match_label <<< "$match_result"
    severity="$(alert_common_max_severity "$severity" "$match_sev")"
    category="watchlist"
    message="WATCHLIST: $match_label - $message"
  fi
fi

if [[ -n "$ssid" ]]; then
  match_result="$(alert_common_watchlist_match "ssid" "$ssid" || true)"
  if [[ -n "$match_result" ]]; then
    IFS='|' read -r match_sev match_label <<< "$match_result"
    severity="$(alert_common_max_severity "$severity" "$match_sev")"
    category="watchlist"
    message="WATCHLIST: $match_label - $message"
  fi
fi

alert_common_notify "$severity" "$category" "$message"
