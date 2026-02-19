#!/bin/bash
# Title: Enhanced Auth Captured Alert
# Description: Notifies with LED/sound/vibrate based on severity
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
  ALERT "$_ALERT_AUTH_SUMMARY"
  exit 0
fi

severity="high"
category="pineapple_auth_captured"
message="${_ALERT_AUTH_SUMMARY:-Auth captured}"

username="${_ALERT_AUTH_USERNAME:-}"
if [[ -n "$username" ]]; then
  severity="critical"
  message="USER: $username - $message"
fi

alert_common_notify "$severity" "$category" "$message"
