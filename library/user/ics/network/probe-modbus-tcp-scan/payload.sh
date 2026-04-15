#!/bin/bash
# Title: Probe Modbus TCP Scan
# Description: Scan a subnet for Modbus TCP devices via the ESP32 probe's Ethernet
#              interface. Sends FC17 (Report Slave ID) to port 502 on each host.
#              Results are saved to the engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue:  Awaiting input
# - Amber: Scanning
# - Green: Devices found
# - Red:   Scan error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# Modbus FC17 Report Slave ID request (unit ID 1, function code 0x11, no data)
# MBAP header: transaction=0001, protocol=0000, length=0002, unit=01
# PDU: FC=11
MODBUS_FC17_HEX="000100000002011100"

main() {
  LOG blue "=== Probe Modbus TCP Scan ==="
  LOG ""

  ics_init_engagement
  esp32_require

  # Verify probe Ethernet is up
  local net_status
  net_status=$(esp32_net_status)
  if ! echo "$net_status" | grep -q '"link":true'; then
    ERROR_DIALOG "Probe Ethernet not connected. Run 'Probe Ethernet Setup' first."
    exit 1
  fi

  local subnet
  subnet=$(TEXT_PICKER "Target subnet (e.g., 192.168.1)" "192.168.1")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local start_host end_host
  start_host=$(NUMBER_PICKER "Start host" 1)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  end_host=$(NUMBER_PICKER "End host" 254)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  LOG blue "Scanning ${subnet}.${start_host}-${end_host}:502 for Modbus TCP..."
  local sid
  sid=$(START_SPINNER "Modbus TCP scan...")

  local found=0
  local host_num
  for host_num in $(seq "$start_host" "$end_host"); do
    local target="${subnet}.${host_num}"

    local conn_resp
    conn_resp=$(esp32_net_tcp_connect "$target" 502)

    if echo "$conn_resp" | grep -q '"status":"ok"'; then
      local sock
      sock=$(echo "$conn_resp" | sed -n 's/.*"sock":\([0-9]*\).*/\1/p')

      esp32_net_tcp_send "$sock" "$MODBUS_FC17_HEX" >/dev/null 2>&1
      local recv_resp
      recv_resp=$(esp32_net_tcp_recv "$sock" 2000)
      esp32_net_tcp_close "$sock" >/dev/null 2>&1

      if echo "$recv_resp" | grep -q '"data"'; then
        LOG green "  [+] $target:502 — Modbus TCP device found"
        found=$((found + 1))

        local json
        json=$(printf '{"ip":"%s","port":502,"protocol":"modbus_tcp","bus":"ethernet","discovered_by":"probe-modbus-tcp-scan"}' "$target")
        ics_report_device "$json"
      fi
    fi
  done

  STOP_SPINNER "$sid"

  LOG ""
  if [[ "$found" -gt 0 ]]; then
    LOG green "Scan complete: $found Modbus TCP device(s) found."
  else
    LOG blue "Scan complete: no Modbus TCP devices found."
  fi

  ALERT "Modbus TCP scan: $found device(s) on ${subnet}.*"
}

main "$@"
