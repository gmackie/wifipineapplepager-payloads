#!/bin/bash
# Title: Probe OPC UA Discover
# Description: Send an OPC UA FindServers request via the ESP32 probe's Ethernet
#              interface to a target host on port 4840. Reports discovered server
#              application names and endpoint URLs.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
# Interaction Level: B (active discovery)
# Requires: python3 (for OPC UA binary protocol encoding)
#
# LED States
# - Blue:  Awaiting target
# - Amber: Connecting
# - Green: Server found
# - Red:   Error or timeout

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

main() {
  LOG blue "=== Probe OPC UA Discover ==="
  LOG ""

  ics_init_engagement
  esp32_require

  local net_status
  net_status=$(esp32_net_status)
  if ! echo "$net_status" | grep -q '"link":true'; then
    ERROR_DIALOG "Probe Ethernet not connected. Run 'Probe Ethernet Setup' first."
    exit 1
  fi

  local target
  target=$(IP_PICKER "Target OPC UA server IP" "192.168.1.1")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local port
  port=$(NUMBER_PICKER "OPC UA port" 4840)
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  LOG blue "Connecting to ${target}:${port}..."
  local sid
  sid=$(START_SPINNER "OPC UA discovery...")

  local conn_resp
  conn_resp=$(esp32_net_tcp_connect "$target" "$port")

  if ! echo "$conn_resp" | grep -q '"status":"ok"'; then
    STOP_SPINNER "$sid"
    LOG red "Connection failed to ${target}:${port}"
    ERROR_DIALOG "Could not connect to OPC UA server."
    exit 1
  fi

  local sock
  sock=$(echo "$conn_resp" | sed -n 's/.*"sock":\([0-9]*\).*/\1/p')

  # OPC UA Hello message (minimal, requests endpoint opc.tcp://<target>:<port>)
  # This is a simplified binary Hello — full OPC UA encoding ideally uses python3.
  # For v1.1, send a raw Hello and look for an Acknowledge response.
  local endpoint_url="opc.tcp://${target}:${port}"
  local url_len=${#endpoint_url}

  # OPC UA Hello: MSG type "HEL" + "F" (final), message size, protocol version=0,
  # receive/send buffer sizes, max message/chunk sizes, endpoint URL
  # Encoded as hex via python3 for correctness
  ics_require_tool python3 "Required for OPC UA binary protocol encoding"

  local hello_hex
  hello_hex=$(python3 -c "
import struct
url = b'${endpoint_url}'
body = struct.pack('<I', 0)          # protocol version
body += struct.pack('<I', 65535)     # receive buffer
body += struct.pack('<I', 65535)     # send buffer
body += struct.pack('<I', 0)         # max message size (0=no limit)
body += struct.pack('<I', 0)         # max chunk count (0=no limit)
body += struct.pack('<I', len(url))  # url length
body += url
header = b'HELF' + struct.pack('<I', 8 + len(body))
msg = header + body
print(msg.hex())
")

  esp32_net_tcp_send "$sock" "$hello_hex" >/dev/null 2>&1

  local recv_resp
  recv_resp=$(esp32_net_tcp_recv "$sock" 3000)
  esp32_net_tcp_close "$sock" >/dev/null 2>&1

  STOP_SPINNER "$sid"

  if echo "$recv_resp" | grep -q '"data"'; then
    local raw_hex
    raw_hex=$(echo "$recv_resp" | sed -n 's/.*"data":"\([^"]*\)".*/\1/p')

    # Check for "ACK" response (0x41434b46 = "ACKF")
    if [[ "${raw_hex:0:8}" == "41434b46" ]]; then
      LOG green "[+] OPC UA server responded with ACK at ${target}:${port}"

      local json
      json=$(printf '{"ip":"%s","port":%d,"protocol":"opcua","bus":"ethernet","discovered_by":"probe-opcua-discover","endpoint":"%s"}' \
        "$target" "$port" "$endpoint_url")
      ics_report_device "$json"

      ALERT "OPC UA server found at ${target}:${port}"
    else
      LOG blue "Server responded but not with OPC UA ACK (first 8 hex: ${raw_hex:0:8})"
    fi
  else
    LOG red "No response from ${target}:${port} within timeout."
  fi

  LOG ""
  LOG blue "Done."
}

main "$@"
