#!/bin/bash
# Title: EtherNet/IP CIP Attribute Enumeration
# Description: Level C — read CIP object attributes from a target EtherNet/IP
#              device. Requires explicit operator confirmation before sending
#              attribute read requests to the live device.
#              Calls enip_get_attributes from the ICS protocol library.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Reading CIP attributes
# - Green: Enumeration complete
# - Red:   Error / cancelled

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "EtherNet/IP CIP Attribute Enumeration (Level C)"
LOG red "WARNING: This payload sends active CIP read requests to a live device."
LOG "Attribute reads may appear in device diagnostic logs and could interact"
LOG "with device state. Use only with explicit authorisation from the asset owner."

confirm=$(CONFIRMATION_DIALOG "Proceed with CIP attribute enumeration? (Level C — active interaction)")
case "$confirm" in
  "$DUCKYSCRIPT_USER_CONFIRMED") ;;
  *)
    LOG "Aborted by operator."; exit 0 ;;
esac

ics_init_engagement

LOG blue "Enter the target EtherNet/IP device IP address."
target_host=$(IP_PICKER "EtherNet/IP device IP" "192.168.1.100")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

target_port=$(NUMBER_PICKER "EtherNet/IP port" 44818)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    target_port=44818 ;;
esac

# Verify the device is reachable with a ListIdentity probe before enumerating
spin_id=$(START_SPINNER "Verifying EtherNet/IP device at $target_host:$target_port...")
probe_result=$(enip_list_identity "$target_host" "$target_port" 2>/dev/null) || probe_result=""
STOP_SPINNER "$spin_id"

if [[ -z "$probe_result" ]]; then
  ERROR_DIALOG "No EtherNet/IP response from $target_host:$target_port — device unreachable or not an EtherNet/IP node."
  exit 1
fi

LOG green "Device confirmed reachable: $target_host:$target_port"

# enip_get_attributes issues its own CONFIRMATION_DIALOG per library contract.
# The outer confirmation above covers the overall Level C consent.
spin_id=$(START_SPINNER "Reading CIP attributes from $target_host:$target_port...")
enip_get_attributes "$target_host" "$target_port"
enum_rc=$?
STOP_SPINNER "$spin_id"

if [[ "$enum_rc" -ne 0 ]]; then
  ERROR_DIALOG "CIP attribute enumeration cancelled or failed for $target_host:$target_port"
  exit 1
fi

# Record the enumeration attempt in inventory
json=$(printf '{"id":"%s_%d_cip_enum","protocol":"ethernet_ip","ip":"%s","port":%d,"action":"cip_attribute_read","level":"C"}' \
  "$target_host" "$target_port" "$target_host" "$target_port")
ics_report_device "$json"

LOG green "CIP attribute enumeration complete for $target_host:$target_port"
ALERT "EtherNet/IP CIP enumeration complete. Results recorded in $ICS_INVENTORY"
