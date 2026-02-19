#!/bin/bash
# Title: Alert Monitor
# Description: Continuous monitoring for new APs, evil twins, probes, high-value targets
# Author: anomaly
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${DIR}/../../../alerts/_common/alert_common.sh"
RECON_DB="/root/recon/recon.db"

if [[ ! -f "$COMMON_SH" ]]; then
  ERROR_DIALOG "Missing alert_common.sh"
  exit 1
fi

source "$COMMON_SH"

POLL_INTERVAL=5
PAYLOAD_NAME="alert_monitor"

config_get() {
  local key="$1"
  local default="${2:-}"
  if alert_common_have PAYLOAD_GET_CONFIG; then
    local v
    v="$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "$key" 2>/dev/null || true)"
    [[ -n "$v" ]] && { printf "%s" "$v"; return 0; }
  fi
  printf "%s" "$default"
}

config_set() {
  local key="$1"
  local value="$2"
  if alert_common_have PAYLOAD_SET_CONFIG; then
    PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "$key" "$value" 2>/dev/null || true
  fi
}

db_query() {
  local query="$1"
  if [[ -f "$RECON_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$RECON_DB" "$query" 2>/dev/null || true
  fi
}

check_new_aps() {
  local last_ts
  last_ts="$(config_get "last_ap_ts" "0")"

  local results
  results="$(db_query "SELECT bssid, ssid, encryption_type, channel FROM wifi_device WHERE type='ap' AND first_seen > $last_ts ORDER BY first_seen DESC LIMIT 10;")"

  [[ -z "$results" ]] && return

  local now
  now="$(date +%s)"
  config_set "last_ap_ts" "$now"

  while IFS='|' read -r bssid ssid enc channel; do
    [[ -z "$bssid" ]] && continue

    local severity="medium"
    local category="new_ap"
    local message="New AP: $ssid ($bssid) ch$channel $enc"

    local match_result
    match_result="$(alert_common_watchlist_match "mac" "$bssid" || true)"
    if [[ -n "$match_result" ]]; then
      IFS='|' read -r match_sev match_label <<< "$match_result"
      severity="$(alert_common_max_severity "$severity" "$match_sev")"
      category="watchlist"
      message="WATCHLIST: $match_label - $message"
    fi

    match_result="$(alert_common_watchlist_match "ssid" "$ssid" || true)"
    if [[ -n "$match_result" ]]; then
      IFS='|' read -r match_sev match_label <<< "$match_result"
      severity="$(alert_common_max_severity "$severity" "$match_sev")"
      category="watchlist"
      message="WATCHLIST: $match_label - $message"
    fi

    alert_common_notify "$severity" "$category" "$message"
  done <<< "$results"
}

check_evil_twins() {
  local results
  results="$(db_query "SELECT ssid, COUNT(DISTINCT bssid) as cnt FROM wifi_device WHERE type='ap' AND ssid != '' GROUP BY ssid HAVING cnt > 1;")"

  [[ -z "$results" ]] && return

  local alerted
  alerted="$(config_get "alerted_twins" "")"

  while IFS='|' read -r ssid cnt; do
    [[ -z "$ssid" ]] && continue

    if [[ "$alerted" == *"|$ssid|"* ]]; then
      continue
    fi

    local severity="critical"
    local category="evil_twin"
    local message="EVIL TWIN? $cnt APs share SSID: $ssid"

    alert_common_notify "$severity" "$category" "$message"
    alerted="${alerted}|${ssid}|"
  done <<< "$results"

  config_set "alerted_twins" "$alerted"
}

check_hidden_probes() {
  local last_ts
  last_ts="$(config_get "last_probe_ts" "0")"

  local results
  results="$(db_query "SELECT mac, ssid FROM probe WHERE timestamp > $last_ts AND ssid != '' ORDER BY timestamp DESC LIMIT 10;")"

  [[ -z "$results" ]] && return

  local now
  now="$(date +%s)"
  config_set "last_probe_ts" "$now"

  while IFS='|' read -r mac ssid; do
    [[ -z "$mac" ]] && continue

    local match_result
    match_result="$(alert_common_watchlist_match "mac" "$mac" || true)"
    if [[ -n "$match_result" ]]; then
      IFS='|' read -r match_sev match_label <<< "$match_result"
      local message="WATCHLIST PROBE: $match_label - $mac probing for $ssid"
      alert_common_notify "$match_sev" "watchlist" "$message"
    fi

    match_result="$(alert_common_watchlist_match "ssid" "$ssid" || true)"
    if [[ -n "$match_result" ]]; then
      IFS='|' read -r match_sev match_label <<< "$match_result"
      local message="WATCHLIST SSID PROBE: $match_label - $mac probing for $ssid"
      alert_common_notify "$match_sev" "watchlist" "$message"
    fi
  done <<< "$results"
}

check_high_value() {
  local last_ts
  last_ts="$(config_get "last_hv_ts" "0")"

  local results
  results="$(db_query "SELECT bssid, ssid, encryption_type FROM wifi_device WHERE type='ap' AND encryption_type LIKE '%enterprise%' AND first_seen > $last_ts ORDER BY first_seen DESC LIMIT 5;")"

  [[ -z "$results" ]] && return

  local now
  now="$(date +%s)"
  config_set "last_hv_ts" "$now"

  while IFS='|' read -r bssid ssid enc; do
    [[ -z "$bssid" ]] && continue
    local message="HIGH VALUE: Enterprise AP $ssid ($bssid) - $enc"
    alert_common_notify "medium" "high_value" "$message"
  done <<< "$results"
}

show_menu() {
  local options="Start Monitoring|Reset Timestamps|Exit"
  local choice
  choice=$(OPTION_PICKER "Alert Monitor" "$options")
  case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
      exit 0
      ;;
  esac
  printf "%s" "$choice"
}

run_monitor() {
  LOG blue "Monitoring started (Ctrl+C or button to stop)"
  LED B SLOW

  local spinner_id=""
  if alert_common_have START_SPINNER; then
    spinner_id=$(START_SPINNER "Monitoring...")
  fi

  trap 'cleanup' INT TERM

  while true; do
    check_new_aps
    check_evil_twins
    check_hidden_probes
    check_high_value
    sleep "$POLL_INTERVAL"
  done
}

cleanup() {
  if [[ -n "${spinner_id:-}" ]] && alert_common_have STOP_SPINNER; then
    STOP_SPINNER "$spinner_id"
  fi
  LED OFF
  LOG "Monitoring stopped"
  exit 0
}

reset_timestamps() {
  config_set "last_ap_ts" "0"
  config_set "last_probe_ts" "0"
  config_set "last_hv_ts" "0"
  config_set "alerted_twins" ""
  LED G SINGLE
  LOG green "Timestamps reset"
  ALERT "Alert history cleared"
}

main() {
  if [[ ! -f "$RECON_DB" ]]; then
    ERROR_DIALOG "Recon DB not found at $RECON_DB"
    exit 1
  fi

  local choice
  choice="$(show_menu)"

  case "$choice" in
    "Start Monitoring")
      run_monitor
      ;;
    "Reset Timestamps")
      reset_timestamps
      ;;
    "Exit"|*)
      exit 0
      ;;
  esac
}

main "$@"
