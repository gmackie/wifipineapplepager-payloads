#!/bin/bash
# Title: Probe BACnet Who-Is
# Description: Send a BACnet Who-Is broadcast via the ESP32 probe's Ethernet interface.
#              NOTE: v1.1 probe firmware does not support UDP listen sockets, so this
#              payload sends the Who-Is but cannot capture I-Am responses. Full listen
#              support is deferred to v1.2. Use the pager's native network for full
#              BACnet discovery (see bacnet-device-discovery payload).
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
# Interaction Level: B (active discovery)
#
# LED States
# - Blue:  Sending
# - Amber: Partial (no listen)
# - Red:   Error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# BACnet Who-Is broadcast frame (BVLC + NPDU + APDU)
# BVLC: type=0x81, function=0x0b (distribute), length=0x000c
# NPDU: version=0x01, control=0x20 (no reply expected), DNET=0xffff, DLEN=0x00, hop=0xff
# APDU: type=0x10 (unconfirmed), service=0x08 (Who-Is)
BACNET_WHOIS_HEX="810b000c0120ffff00ff1008"

main() {
  LOG blue "=== Probe BACnet Who-Is ==="
  LOG ""

  esp32_require

  local net_status
  net_status=$(esp32_net_status)
  if ! echo "$net_status" | grep -q '"link":true'; then
    ERROR_DIALOG "Probe Ethernet not connected. Run 'Probe Ethernet Setup' first."
    exit 1
  fi

  LOG blue "Sending BACnet Who-Is broadcast to 255.255.255.255:47808..."
  local result
  result=$(esp32_net_udp_send "255.255.255.255" 47808 "$BACNET_WHOIS_HEX")

  if echo "$result" | grep -q '"status":"ok"'; then
    LOG green "Who-Is broadcast sent successfully."
  else
    LOG red "Failed to send Who-Is broadcast."
    ERROR_DIALOG "UDP send failed."
    exit 1
  fi

  LOG ""
  LOG blue "NOTE: v1.1 probe firmware does not support UDP listen."
  LOG blue "I-Am responses cannot be captured via the probe interface."
  LOG blue "For full BACnet discovery, use the pager's native network:"
  LOG blue "  -> Run 'BACnet Device Discovery' payload instead."
  LOG ""

  PROMPT "Who-Is sent. Press any button to exit."
}

main "$@"
