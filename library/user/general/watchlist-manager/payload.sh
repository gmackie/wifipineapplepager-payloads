#!/bin/bash
# Title: Watchlist Manager
# Description: Manage MAC/SSID watchlist for alert notifications
# Author: anomaly
# Version: 1.0
# Category: general
# Net Mode: OFF
#
# LED States
# - Blue: Menu/Idle
# - Green: Success
# - Red: Error/Cancelled

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="$DIR/../../alerts/_common/alert_common.sh"

if [[ ! -f "$COMMON_SH" ]]; then
  ERROR_DIALOG "Missing alert_common.sh"
  exit 1
fi

source "$COMMON_SH"

show_main_menu() {
  local count
  count="$(alert_common_watchlist_count)"

  local options="Add MAC|Add SSID|View List ($count)|Remove Entry|Clear All|Exit"
  local choice
  choice=$(OPTION_PICKER "Watchlist Manager" "$options")
  case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
      exit 0
      ;;
  esac

  printf "%s" "$choice"
}

add_mac_entry() {
  local mac label severity

  mac=$(MAC_PICKER "Target MAC" "AA:BB:CC:DD:EE:FF")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  label=$(TEXT_PICKER "Label (optional)" "")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  severity=$(OPTION_PICKER "Alert Severity" "critical|high|medium|low")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  if alert_common_watchlist_add "mac" "$mac" "$label" "$severity"; then
    LED G SINGLE
    LOG green "Added MAC: $mac"
    ALERT "Added MAC to watchlist"
  else
    LED R SINGLE
    LOG red "Failed to add MAC"
    ERROR_DIALOG "Failed to add MAC"
  fi
}

add_ssid_entry() {
  local ssid label severity

  ssid=$(TEXT_PICKER "Target SSID (partial match)" "")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  if [[ -z "$ssid" ]]; then
    LOG red "SSID cannot be empty"
    ERROR_DIALOG "SSID cannot be empty"
    return
  fi

  label=$(TEXT_PICKER "Label (optional)" "")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  severity=$(OPTION_PICKER "Alert Severity" "critical|high|medium|low")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  if alert_common_watchlist_add "ssid" "$ssid" "$label" "$severity"; then
    LED G SINGLE
    LOG green "Added SSID: $ssid"
    ALERT "Added SSID to watchlist"
  else
    LED R SINGLE
    LOG red "Failed to add SSID"
    ERROR_DIALOG "Failed to add SSID"
  fi
}

view_watchlist() {
  local count
  count="$(alert_common_watchlist_count)"

  if [[ "$count" -lt 1 ]]; then
    ALERT "Watchlist is empty"
    return
  fi

  local output=""
  local i
  for i in $(seq 1 "$count"); do
    local entry
    entry="$(alert_common_watchlist_get_entry "$i")"
    [[ -z "$entry" ]] && continue

    local entry_type entry_value entry_label entry_sev
    IFS='|' read -r entry_type entry_value entry_label entry_sev <<< "$entry"

    local line="$i. [$entry_type] $entry_value"
    if [[ -n "$entry_label" ]]; then
      line="$line ($entry_label)"
    fi
    line="$line [$entry_sev]"

    if [[ -n "$output" ]]; then
      output="$output\n$line"
    else
      output="$line"
    fi
  done

  LOG blue "Watchlist ($count entries):"
  LOG "$output"
  PROMPT "Press button to continue"
}

remove_entry() {
  local count
  count="$(alert_common_watchlist_count)"

  if [[ "$count" -lt 1 ]]; then
    ALERT "Watchlist is empty"
    return
  fi

  local options=""
  local i
  for i in $(seq 1 "$count"); do
    local entry
    entry="$(alert_common_watchlist_get_entry "$i")"
    [[ -z "$entry" ]] && continue

    local entry_type entry_value entry_label entry_sev
    IFS='|' read -r entry_type entry_value entry_label entry_sev <<< "$entry"

    local item="$i: [$entry_type] $entry_value"
    if [[ -n "$entry_label" ]]; then
      item="$item ($entry_label)"
    fi

    if [[ -n "$options" ]]; then
      options="$options|$item"
    else
      options="$item"
    fi
  done

  local choice
  choice=$(OPTION_PICKER "Remove Entry" "$options")
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; return ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; return ;;
    $DUCKYSCRIPT_ERROR)     LOG red "Error"; return ;;
  esac

  local idx
  idx="${choice%%:*}"

  if [[ ! "$idx" =~ ^[0-9]+$ ]]; then
    LOG red "Invalid selection"
    return
  fi

  local confirm
  confirm=$(CONFIRMATION_DIALOG "Remove entry $idx?")
  case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
      LOG "Cancelled"
      return
      ;;
  esac

  if [[ "$confirm" != "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
    LOG "User denied"
    return
  fi

  if alert_common_watchlist_remove "$idx"; then
    LED G SINGLE
    LOG green "Removed entry $idx"
    ALERT "Entry removed"
  else
    LED R SINGLE
    LOG red "Failed to remove entry"
    ERROR_DIALOG "Failed to remove entry"
  fi
}

clear_all() {
  local count
  count="$(alert_common_watchlist_count)"

  if [[ "$count" -lt 1 ]]; then
    ALERT "Watchlist is already empty"
    return
  fi

  local confirm
  confirm=$(CONFIRMATION_DIALOG "Clear all $count entries?")
  case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
      LOG "Cancelled"
      return
      ;;
  esac

  if [[ "$confirm" != "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
    LOG "User denied"
    return
  fi

  local i
  for i in $(seq "$count" -1 1); do
    alert_common_watchlist_remove "$i" || true
  done

  LED G SINGLE
  LOG green "Watchlist cleared"
  ALERT "Watchlist cleared"
}

main() {
  LED B SLOW

  while true; do
    local choice
    choice="$(show_main_menu)"

    case "$choice" in
      "Add MAC")
        add_mac_entry
        ;;
      "Add SSID")
        add_ssid_entry
        ;;
      "View List"*)
        view_watchlist
        ;;
      "Remove Entry")
        remove_entry
        ;;
      "Clear All")
        clear_all
        ;;
      "Exit"|*)
        LED OFF
        exit 0
        ;;
    esac
  done
}

main "$@"
