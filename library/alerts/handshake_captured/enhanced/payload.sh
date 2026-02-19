#!/bin/bash
# Title: Enhanced Handshake Capture Alert
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
  ALERT "$_ALERT_HANDSHAKE_SUMMARY"
  exit 0
fi

severity="high"
category="handshake_captured"
message="$_ALERT_HANDSHAKE_SUMMARY"

ap_mac="${_ALERT_HANDSHAKE_AP_MAC_ADDRESS:-}"
client_mac="${_ALERT_HANDSHAKE_CLIENT_MAC_ADDRESS:-}"

if [[ -n "$ap_mac" ]]; then
  match_result="$(alert_common_watchlist_match "mac" "$ap_mac" || true)"
  if [[ -n "$match_result" ]]; then
    IFS='|' read -r match_sev match_label <<< "$match_result"
    severity="$(alert_common_max_severity "$severity" "$match_sev")"
    category="watchlist"
    message="WATCHLIST: $match_label - $message"
  fi
fi

if [[ -n "$client_mac" ]]; then
  match_result="$(alert_common_watchlist_match "mac" "$client_mac" || true)"
  if [[ -n "$match_result" ]]; then
    IFS='|' read -r match_sev match_label <<< "$match_result"
    severity="$(alert_common_max_severity "$severity" "$match_sev")"
    category="watchlist"
    message="WATCHLIST: $match_label - $message"
  fi
fi

if [[ "${_ALERT_HANDSHAKE_COMPLETE:-}" == "true" ]]; then
  severity="$(alert_common_max_severity "$severity" "high")"
  message="COMPLETE: $message"
fi

alert_common_notify "$severity" "$category" "$message"
