#!/bin/bash
# Title: S7comm CPU Identify
# Description: Identify Siemens S7 CPUs via S7comm protocol on port 102. Reads the
#              System Status List (SZL) module identification block and reports CPU type,
#              firmware version, and serial number to the engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Probing target
# - Green: CPU identified
# - Red:   Error or no response

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== S7comm CPU Identify ==="
  LOG ""

  ics_init_engagement

  # Collect target
  local host
  host=$(IP_PICKER "Target S7 CPU IP address" "192.168.1.10")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local port=102
  LOG blue "Target: $host:$port"

  # Probe
  local spinner_id
  spinner_id=$(START_SPINNER "Connecting to S7 CPU at $host:$port ...")

  local result
  result=$(s7comm_identify "$host" "$port" 2>/dev/null) || {
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "Failed to connect to $host:$port. Check IP and ensure port 102 is reachable."
    exit 1
  }

  STOP_SPINNER "$spinner_id"

  if echo "$result" | grep -q "status=ok"; then
    local module_type serial_number firmware module_name
    module_type=$(echo "$result"  | grep "^module_type="  | cut -d= -f2-)
    serial_number=$(echo "$result" | grep "^serial_number=" | cut -d= -f2-)
    firmware=$(echo "$result"     | grep "^firmware="      | cut -d= -f2-)
    module_name=$(echo "$result"  | grep "^module_name="   | cut -d= -f2-)

    LOG green "S7 CPU identified at $host:$port"
    LOG green "  Module type  : ${module_type:-unknown}"
    LOG green "  Module name  : ${module_name:-unknown}"
    LOG green "  Serial number: ${serial_number:-unknown}"
    LOG green "  Firmware     : ${firmware:-unknown}"

    # Save raw result as artifact
    local artifact_content
    artifact_content=$(printf \
      '{"host":"%s","port":%d,"module_type":"%s","module_name":"%s","serial_number":"%s","firmware":"%s"}' \
      "$host" "$port" \
      "${module_type:-unknown}" "${module_name:-unknown}" \
      "${serial_number:-unknown}" "${firmware:-unknown}")
    ics_save_artifact "s7comm-identify-${host}" "$artifact_content"

    # Report to inventory
    local json
    json=$(printf \
      '{"id":"%s_%d","protocol":"s7comm","ip":"%s","port":%d,"vendor":"Siemens","model":"%s","serial":"%s","firmware":"%s","module_name":"%s","status":"identified"}' \
      "$host" "$port" "$host" "$port" \
      "${module_type:-unknown}" "${serial_number:-unknown}" \
      "${firmware:-unknown}" "${module_name:-unknown}")
    ics_report_device "$json"

    ALERT "S7 CPU identified: ${module_type:-unknown} (FW: ${firmware:-unknown})"

  elif echo "$result" | grep -q "status=no_data"; then
    LOG "S7comm connection succeeded but no module identification data returned."
    LOG "The CPU may require authentication to read SZL data."

    local json
    json=$(printf \
      '{"id":"%s_%d","protocol":"s7comm","ip":"%s","port":%d,"vendor":"Siemens","status":"connected_no_data"}' \
      "$host" "$port" "$host" "$port")
    ics_report_device "$json"

  elif echo "$result" | grep -q "cotp_rejected"; then
    ERROR_DIALOG "COTP connection rejected by $host:$port. Device may not be an S7 CPU or TSAP mismatch."
    exit 1
  else
    ERROR_DIALOG "Unexpected response from $host:$port."
    exit 1
  fi

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
