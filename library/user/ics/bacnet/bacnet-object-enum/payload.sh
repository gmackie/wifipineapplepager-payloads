#!/bin/bash
# Title: BACnet Object Enumeration
# Description: Level C — read the BACnet Object_List property from a target
#              device. Requires explicit operator confirmation before sending
#              ReadProperty requests to the live device. Asks for the target
#              device instance number and reports enumerated objects to the
#              engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Reading object list
# - Green: Enumeration complete
# - Red:   Error / cancelled

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# BACnet object type name map (ASHRAE 135 Table 23-2, partial)
# ---------------------------------------------------------------------------

_bacnet_object_type() {
  local ot="$1"
  case "$ot" in
    0)  echo "analog-input" ;;
    1)  echo "analog-output" ;;
    2)  echo "analog-value" ;;
    3)  echo "binary-input" ;;
    4)  echo "binary-output" ;;
    5)  echo "binary-value" ;;
    8)  echo "device" ;;
    13) echo "multi-state-input" ;;
    14) echo "multi-state-output" ;;
    15) echo "notification-class" ;;
    17) echo "program" ;;
    19) echo "schedule" ;;
    20) echo "averaging" ;;
    21) echo "multi-state-value" ;;
    29) echo "network-port" ;;
    *)  echo "type#$ot" ;;
  esac
}

# Build a BACnet ReadProperty request for Object_List (property 76)
# targeting device object type=8, instance=$device_instance
_build_readproperty_object_list() {
  local instance="$1"  # device instance (integer)
  local invoke_id="${2:-1}"

  # Object identifier for Device object: type=8 (bits 31-22), instance=lower 22 bits
  local oid=$(( (8 << 22) | (instance & 0x3fffff) ))
  local oid_b0=$(( (oid >> 24) & 0xff ))
  local oid_b1=$(( (oid >> 16) & 0xff ))
  local oid_b2=$(( (oid >> 8) & 0xff ))
  local oid_b3=$(( oid & 0xff ))

  # APDU: confirmed-request (0x00), no-segmentation, max-resp=480 (0x05)
  # service=0x0c (readProperty), invoke-id
  # Context tag 0 (object-identifier, 4 bytes): 0x0c + OID bytes
  # Context tag 1 (property-identifier, enum): 0x19 0x4c (76 = Object_List)
  printf '\x00\x05\x%02x\x0c\x0c\x%02x\x%02x\x%02x\x%02x\x19\x4c' \
    "$invoke_id" "$oid_b0" "$oid_b1" "$oid_b2" "$oid_b3"
}

# Wrap a BACnet APDU in BVLC original-unicast-NPDU
_wrap_bvlc_npdu() {
  local apdu_bytes="$1"
  # BVLC: 0x81 0x0a (original-unicast), 2-byte length = 4 + 2 + len(apdu)
  local apdu_len
  apdu_len=$(printf '%s' "$apdu_bytes" | wc -c)
  local total=$(( 4 + 2 + apdu_len ))
  local len_hi=$(( (total >> 8) & 0xff ))
  local len_lo=$(( total & 0xff ))
  # NPDU: version=0x01, control=0x04 (expecting reply)
  printf '\x81\x0a\x%02x\x%02x\x01\x04%s' "$len_hi" "$len_lo" "$apdu_bytes"
}

# Parse an Object_List response — returns one "type:instance" per line
_parse_object_list_response() {
  local hexdata="$1"
  # Skip BVLC(8 nib) + NPDU(4 nib) + APDU confirmed-ack header (8 nib)
  # = offset 20 nibbles (10 bytes)
  local offset=20

  # Expect: 0x4c (application tag 4, type ObjectIdentifier, opening)
  # Each object identifier: tag 0xC4 + 4 bytes
  local count=0
  while [[ $offset -lt ${#hexdata} ]]; do
    local tag="${hexdata:${offset}:2}"
    if [[ "$tag" == "c4" ]]; then
      local b0="${hexdata:$((offset+2)):2}"
      local b1="${hexdata:$((offset+4)):2}"
      local b2="${hexdata:$((offset+6)):2}"
      local b3="${hexdata:$((offset+8)):2}"
      local oid=$(( (0x${b0} << 24) | (0x${b1} << 16) | (0x${b2} << 8) | 0x${b3} ))
      local obj_type=$(( (oid >> 22) & 0x3ff ))
      local obj_instance=$(( oid & 0x3fffff ))
      echo "$(_bacnet_object_type "$obj_type"):$obj_instance"
      count=$((count + 1))
      offset=$(( offset + 10 ))
    else
      offset=$(( offset + 2 ))
    fi
  done
  return 0
}

# Send ReadProperty(Object_List) to device and return hex response
_read_object_list() {
  local host="$1" port="${2:-47808}" instance="$3"

  local apdu
  apdu=$(_build_readproperty_object_list "$instance")

  local packet
  packet=$(_wrap_bvlc_npdu "$apdu")

  local resp
  resp=$(printf '%s' "$packet" | timeout "${ICS_TIMEOUT:-5}" nc -u -w "${ICS_TIMEOUT:-5}" "$host" "$port" 2>/dev/null | xxd -p)
  echo "$resp"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "BACnet Object Enumeration (Level C)"
LOG red "WARNING: This payload sends active BACnet ReadProperty requests to a live device."
LOG "Reading the Object_List may appear in device audit logs."
LOG "Use only with explicit authorisation from the asset owner."

confirm=$(CONFIRMATION_DIALOG "Proceed with BACnet Object_List read? (Level C — active interaction)")
case "$confirm" in
  "$DUCKYSCRIPT_USER_CONFIRMED") ;;
  *)
    LOG "Aborted by operator."; exit 0 ;;
esac

ics_init_engagement

LOG blue "Enter the IP address of the BACnet device."
target_host=$(IP_PICKER "BACnet device IP" "192.168.1.100")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

target_port=$(NUMBER_PICKER "BACnet UDP port" 47808)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    target_port=47808 ;;
esac

device_instance=$(NUMBER_PICKER "Device instance number" 1)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

LOG "Reading Object_List from device instance $device_instance at $target_host:$target_port..."
spin_id=$(START_SPINNER "Sending BACnet ReadProperty(Object_List) to $target_host...")

raw_hex=$(_read_object_list "$target_host" "$target_port" "$device_instance") || raw_hex=""

STOP_SPINNER "$spin_id"

if [[ -z "$raw_hex" ]]; then
  ERROR_DIALOG "No response from BACnet device $device_instance at $target_host:$target_port"
  exit 1
fi

LOG green "Response received — parsing object list..."

objects=()
while IFS= read -r obj; do
  [[ -z "$obj" ]] && continue
  objects+=("$obj")
  LOG "  Object: $obj"
done < <(_parse_object_list_response "$raw_hex")

object_count="${#objects[@]}"

if [[ "$object_count" -eq 0 ]]; then
  LOG "Response received but no object identifiers could be parsed."
  LOG "Raw hex: $raw_hex"
  LOG "A full BACnet stack (e.g. bacpypes3) is required for complex response formats."
fi

# Encode object list as JSON array string
obj_list_json=""
for obj in "${objects[@]}"; do
  obj_list_json="${obj_list_json}\"${obj}\","
done
obj_list_json="[${obj_list_json%,}]"

json=$(printf '{"id":"bacnet_%d_objects","protocol":"bacnet","ip":"%s","port":%d,"device_instance":%d,"object_count":%d,"objects":%s,"action":"object_list_read","level":"C"}' \
  "$device_instance" "$target_host" "$target_port" "$device_instance" "$object_count" "$obj_list_json")
ics_report_device "$json"

LOG green "BACnet object enumeration complete: $object_count object(s) found"
ALERT "BACnet Object Enumeration complete. $object_count object(s) for device $device_instance. See $ICS_INVENTORY"
