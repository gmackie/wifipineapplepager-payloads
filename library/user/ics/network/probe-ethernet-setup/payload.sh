#!/bin/bash
# Title: Probe Ethernet Setup
# Description: Configure the ESP32 ICS Probe's W5500 Ethernet interface via DHCP
#              or static IP. Required before running any probe-routed network payloads.
# Author: ICS Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
#
# LED States
# - Blue:  Awaiting configuration choice
# - Amber: Acquiring IP
# - Green: Ethernet ready
# - Red:   Configuration failed

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== Probe Ethernet Setup ==="
  LOG ""

  esp32_require

  local resp
  resp=$(CONFIRMATION_DIALOG "Use DHCP? (No = enter static IP)")

  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED")
      LOG blue "Acquiring IP via DHCP..."
      local sid
      sid=$(START_SPINNER "DHCP...")
      local result
      result=$(esp32_net_dhcp 15)
      STOP_SPINNER "$sid"

      if echo "$result" | grep -q '"status":"ok"'; then
        local ip
        ip=$(echo "$result" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
        LOG green "DHCP success: $ip"
        ALERT "Probe Ethernet ready: $ip"
      else
        LOG red "DHCP failed"
        ERROR_DIALOG "DHCP failed. Check cable and switch."
        exit 1
      fi
      ;;

    *)
      local ip mask gw
      ip=$(IP_PICKER "Probe IP address" "192.168.1.100")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac

      mask=$(IP_PICKER "Subnet mask" "255.255.255.0")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac

      gw=$(IP_PICKER "Default gateway" "192.168.1.1")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac

      LOG blue "Setting static IP: $ip/$mask gw $gw"
      local result
      result=$(esp32_net_static "$ip" "$mask" "$gw")

      if echo "$result" | grep -q '"status":"ok"'; then
        LOG green "Static IP configured: $ip"
        ALERT "Probe Ethernet ready: $ip"
      else
        LOG red "Static configuration failed"
        ERROR_DIALOG "Failed to set static IP."
        exit 1
      fi
      ;;
  esac

  LOG ""
  LOG blue "Probe Ethernet status:"
  esp32_net_status
}

main "$@"
