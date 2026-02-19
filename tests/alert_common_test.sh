#!/bin/bash

set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

LED() { echo "LED $*"; }
RINGTONE() { echo "RINGTONE $*"; }
VIBRATE() { echo "VIBRATE $*"; }
ALERT() { echo "ALERT $*"; }
ALERT_RINGTONE() { echo "ALERT_RINGTONE $*"; }
LOG() { echo "LOG $*"; }

PAYLOAD_SET_CONFIG() {
  local payload="$1" key="$2" value="$3"
  mkdir -p "$tmp_dir/config/$payload"
  printf "%s" "$value" > "$tmp_dir/config/$payload/$key"
}

PAYLOAD_GET_CONFIG() {
  local payload="$1" key="$2"
  if [[ -f "$tmp_dir/config/$payload/$key" ]]; then
    cat "$tmp_dir/config/$payload/$key"
  fi
}

PAYLOAD_DEL_CONFIG() {
  local payload="$1" key="$2"
  rm -f "$tmp_dir/config/$payload/$key"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

source "$repo_root/library/alerts/_common/alert_common.sh" || fail "could not source alert_common.sh"

if ! type alert_common_set_config >/dev/null 2>&1; then
  fail "missing function: alert_common_set_config"
fi

alert_common_set_config watchlist_enabled 0 || fail "set config"
if alert_common_watchlist_enabled; then
  fail "watchlist should be disabled"
fi

alert_common_set_config watchlist_enabled 1 || fail "set config"
if ! alert_common_watchlist_enabled; then
  fail "watchlist should be enabled"
fi

[[ "$(alert_common_severity_to_pattern critical)" == "DOUBLE" ]] || fail "critical pattern"
[[ "$(alert_common_severity_to_pattern high)" == "FAST" ]] || fail "high pattern"
[[ "$(alert_common_category_to_color handshake_captured)" == "G" ]] || fail "handshake color"
[[ "$(alert_common_category_to_color unknown)" == "Y" ]] || fail "default color"

if ! type alert_common_watchlist_add >/dev/null 2>&1; then
  fail "missing function: alert_common_watchlist_add"
fi
if ! type alert_common_watchlist_remove >/dev/null 2>&1; then
  fail "missing function: alert_common_watchlist_remove"
fi

alert_common_watchlist_clear || fail "clear"
[[ "$(alert_common_watchlist_count)" == "0" ]] || fail "count after clear"

alert_common_watchlist_add mac "AA:BB:CC:DD:EE:FF" "testmac" critical || fail "add mac"
[[ "$(alert_common_watchlist_count)" == "1" ]] || fail "count after add"

match="$(alert_common_watchlist_match mac "aa:bb:cc:dd:ee:ff" || true)"
[[ "$match" == "critical|testmac" ]] || fail "match mac"

alert_common_watchlist_add ssid "CorpWiFi" "testssid" high || fail "add ssid"
[[ "$(alert_common_watchlist_count)" == "2" ]] || fail "count after add ssid"

match="$(alert_common_watchlist_match ssid "MyCorpWiFiGuest" || true)"
[[ "$match" == "high|testssid" ]] || fail "match ssid"

alert_common_watchlist_add mac "11:22:33:44:55:66" "ignored" ignore || fail "add ignore"
match="$(alert_common_watchlist_match mac "11:22:33:44:55:66" || true)"
[[ -z "$match" ]] || fail "ignore should not match"

alert_common_watchlist_remove 1 || fail "remove"
[[ "$(alert_common_watchlist_count)" == "2" ]] || fail "count after remove"

out="$(alert_common_notify critical watchlist "hello" 2>/dev/null || true)"
echo "$out" | grep -q '^LED ' || fail "notify LED"
echo "$out" | grep -q '^RINGTONE ' || fail "notify RINGTONE"

echo OK