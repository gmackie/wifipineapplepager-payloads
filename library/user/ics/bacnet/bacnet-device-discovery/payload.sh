#!/bin/bash
# Title: BACnet Device Discovery
# Description: Send a Who-Is broadcast on UDP port 47808 and collect I-Am
#              responses. Parses device instance number and vendor ID from
#              each response, then reports discovered devices to the
#              engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Broadcasting / collecting responses
# - Green: Discovery complete
# - Red:   Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# BACnet vendor ID table (partial — ASHRAE 135 Annex H)
# ---------------------------------------------------------------------------

_bacnet_vendor_name() {
  local vid="$1"
  case "$vid" in
    0)   echo "ASHRAE" ;;
    1)   echo "NovaTech LLC" ;;
    4)   echo "Automated Logic" ;;
    5)   echo "American Auto-Matrix" ;;
    10)  echo "Alerton" ;;
    11)  echo "Andover Controls" ;;
    16)  echo "Desigo (Siemens)" ;;
    22)  echo "Johnson Controls" ;;
    24)  echo "Honeywell" ;;
    30)  echo "Delta Controls" ;;
    36)  echo "Trend Control Systems" ;;
    76)  echo "Trane" ;;
    86)  echo "Carrier" ;;
    95)  echo "Schneider Electric" ;;
    190) echo "TAC / Schneider" ;;
    260) echo "Distech Controls" ;;
    *)   echo "Vendor#$vid" ;;
  esac
}

# Parse a hex-encoded BACnet I-Am APDU and return key=value lines.
# I-Am structure (after BVLC and NPDU):
#   APDU type=0x10 (unconfirmed), service=0x00 (I-Am)
#   Object ID tag (context 0, 4-byte value):  device instance in lower 22 bits
#   Max APDU tag (context 1, variable)
#   Segmentation tag (context 2, 1 byte)
#   Vendor ID tag (context 3, 2 bytes)
_parse_iam() {
  local hexdata="$1"

  # Minimum: BVLC(4) + NPDU(2) + APDU(2 type/svc) + data
  [[ "${#hexdata}" -lt 20 ]] && return 1

  # BVLC: byte 0=0x81, byte 1=function, bytes 2-3=length (4 bytes total = 8 nibbles)
  # NPDU: variable length; function=0x0a (original-unicast-NPDU) = 2 bytes
  # Offset depends on routing — assume no routing (NPDU control=0x00 = 2 bytes)
  # APDU starts at byte 6 (nibble 12) for simple case
  local apdu_offset=12

  local apdu_type="${hexdata:${apdu_offset}:2}"
  local apdu_svc="${hexdata:$((apdu_offset+2)):2}"

  # 0x10 = unconfirmed, 0x00 = I-Am
  if [[ "$apdu_type" != "10" || "$apdu_svc" != "00" ]]; then
    # Try longer NPDU (with destination specifier etc)
    apdu_offset=20
    apdu_type="${hexdata:${apdu_offset}:2}"
    apdu_svc="${hexdata:$((apdu_offset+2)):2}"
    if [[ "$apdu_type" != "10" || "$apdu_svc" != "00" ]]; then
      return 1
    fi
  fi

  # After type + service (4 nibbles), read Object-Identifier tag
  local data_start=$(( apdu_offset + 4 ))
  # Object identifier: tag=0xC4 (context 0, application 4, length 4)
  local oid_tag="${hexdata:${data_start}:2}"
  local instance=0
  local device_type=0

  if [[ "$oid_tag" == "c4" ]]; then
    # 4 bytes = 8 nibbles of object ID
    local oid_b0="${hexdata:$((data_start+2)):2}"
    local oid_b1="${hexdata:$((data_start+4)):2}"
    local oid_b2="${hexdata:$((data_start+6)):2}"
    local oid_b3="${hexdata:$((data_start+8)):2}"
    local oid=$(( (0x${oid_b0} << 24) | (0x${oid_b1} << 16) | (0x${oid_b2} << 8) | 0x${oid_b3} ))
    device_type=$(( (oid >> 22) & 0x3ff ))
    instance=$(( oid & 0x3fffff ))
    data_start=$(( data_start + 10 ))
  fi

  # Skip max-APDU-length (tag varies) and segmentation; find vendor ID tag
  # Vendor ID tag = 0x21 or 0x22 (application unsigned, length 1 or 2)
  local vendor_id=0
  local scan=$data_start
  while [[ $scan -lt ${#hexdata} ]]; do
    local t="${hexdata:${scan}:2}"
    case "$t" in
      21) # 1-byte unsigned
        vendor_id=$(( 0x${hexdata:$((scan+2)):2} ))
        break ;;
      22) # 2-byte unsigned
        local v_hi="${hexdata:$((scan+2)):2}"
        local v_lo="${hexdata:$((scan+4)):2}"
        vendor_id=$(( (0x${v_hi} << 8) | 0x${v_lo} ))
        break ;;
    esac
    scan=$(( scan + 2 ))
  done

  echo "device_type=$device_type"
  echo "instance=$instance"
  echo "vendor_id=$vendor_id"
  echo "vendor_name=$(_bacnet_vendor_name "$vendor_id")"
}

_broadcast_whois() {
  local bcast="$1" port="${2:-47808}"
  local timeout_sec="${ICS_TIMEOUT:-5}"

  # BACnet Who-Is packet (BVLC original broadcast + NPDU + APDU Who-Is with no range)
  local packet
  packet=$(printf '\x81\x0b\x00\x08\x01\x20\x10\x08')

  # Send UDP broadcast and collect all responses within timeout window
  printf '%s' "$packet" | timeout "$timeout_sec" nc -u -w "$timeout_sec" -l 47808 &
  local listener_pid=$!

  printf '%s' "$packet" | timeout 1 nc -u -w 1 "$bcast" "$port" >/dev/null 2>&1 || true

  wait "$listener_pid" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "BACnet Device Discovery"
LOG "Sends Who-Is broadcast on UDP/47808 and collects I-Am responses."

ics_init_engagement

LOG blue "Enter the broadcast address for the BACnet network."
bcast=$(IP_PICKER "Broadcast address" "192.168.1.255")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

port=$(NUMBER_PICKER "BACnet UDP port" 47808)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    port=47808 ;;
esac

found=0

spin_id=$(START_SPINNER "Sending Who-Is to $bcast:$port and listening for I-Am responses...")

# Capture responses — bacnet_whois returns hex-encoded data for each response
# Multiple I-Am responses may be concatenated or arrive on separate attempts
raw_hex=$(bacnet_whois "$bcast" "$port" 2>/dev/null) || raw_hex=""

STOP_SPINNER "$spin_id"

if [[ -z "$raw_hex" ]]; then
  LOG "No I-Am responses received from $bcast:$port"
  ALERT "BACnet discovery complete — no devices responded to Who-Is on $bcast"
  exit 0
fi

LOG "Received I-Am response data — parsing..."

# The raw_hex may contain one or more BACnet frames concatenated.
# Process the first response; for sweeps with multiple devices, operators
# should use a dedicated BACnet scanner (e.g. bacnet-scan).
parsed=$(_parse_iam "$raw_hex") || parsed=""

if [[ -n "$parsed" ]]; then
  instance=$(echo "$parsed" | grep "^instance=" | cut -d= -f2)
  vendor_id=$(echo "$parsed" | grep "^vendor_id=" | cut -d= -f2)
  vendor_name=$(echo "$parsed" | grep "^vendor_name=" | cut -d= -f2-)

  LOG green "Found BACnet device: instance=$instance  vendor=\"$vendor_name\" (id=$vendor_id)"

  json=$(printf '{"id":"bacnet_%s","protocol":"bacnet","broadcast":"%s","port":%d,"device_instance":%s,"vendor_id":%s,"vendor_name":"%s"}' \
    "${instance:-0}" "$bcast" "$port" "${instance:-0}" "${vendor_id:-0}" "$vendor_name")
  ics_report_device "$json"
  found=$((found + 1))
else
  # Partial response — log raw hex for manual analysis
  LOG "I-Am response received but could not be fully parsed."
  LOG "Raw hex: $raw_hex"

  json=$(printf '{"id":"bacnet_raw_%s","protocol":"bacnet","broadcast":"%s","port":%d,"raw_hex":"%s","parse_status":"failed"}' \
    "$(date +%s)" "$bcast" "$port" "$raw_hex")
  ics_report_device "$json"
  found=1
fi

LOG "Discovery complete: $found BACnet device(s) found"
ALERT "BACnet discovery complete. $found device(s) found. Results in $ICS_INVENTORY"
