#!/bin/bash
# Title: Modbus RTU Bus Scanner
# Description: Scan an RS-485 bus via ESP32 probe for responding Modbus RTU slave
#              addresses. For each responding slave, request Device Identification
#              (FC43) and report all discovered devices to the ICS inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: ics
# Net Mode: OFF
#
# Requires: ESP32 ICS Probe connected via USB
#
# LED States
# - Blue:  Idle / prompting user
# - Amber: Bus scan in progress
# - Green: Scan complete
# - Red:   Error or no slaves found

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"
source "$(dirname "$0")/../../lib/esp32.sh"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

esp32_require

ics_init_engagement

# ---------------------------------------------------------------------------
# User Input
# ---------------------------------------------------------------------------

LOG blue "Modbus RTU Bus Scanner"
PROMPT "This payload scans the RS-485 bus for live Modbus RTU slave addresses. The ESP32 probe will broadcast a read request to each address in the specified range. Press OK to continue."

addr_start=$(NUMBER_PICKER "Start slave address" 1)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

addr_end=$(NUMBER_PICKER "End slave address" 247)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Input cancelled — aborting."
    exit 1
    ;;
esac

if [[ "$addr_start" -lt 1 || "$addr_end" -gt 247 || "$addr_start" -gt "$addr_end" ]]; then
  ERROR_DIALOG "Invalid address range: $addr_start-$addr_end. Valid Modbus RTU slave addresses are 1-247."
  exit 1
fi

LOG "Scanning slave addresses $addr_start to $addr_end on $ESP32_DEV..."

# ---------------------------------------------------------------------------
# Bus Scan
# ---------------------------------------------------------------------------

spinner_id=$(START_SPINNER "Scanning RS-485 bus (addresses $addr_start-$addr_end)...")

scan_result=$(modbus_scan_bus "$addr_start" "$addr_end" 2>/dev/null || true)

STOP_SPINNER "$spinner_id"

if [[ -z "$scan_result" ]]; then
  ERROR_DIALOG "No response from ESP32 probe during bus scan. Check cable and probe firmware."
  exit 1
fi

# Parse responding addresses from JSON array: {"status":"ok","slaves":[1,3,7,...]}
if ! echo "$scan_result" | grep -q '"status":"ok"'; then
  error_msg=$(echo "$scan_result" | sed -n 's/.*"error":"\([^"]*\)".*/\1/p')
  ERROR_DIALOG "Bus scan failed: ${error_msg:-unknown error}"
  exit 1
fi

slaves_raw=$(echo "$scan_result" | sed -n 's/.*"slaves":\[\([^]]*\)\].*/\1/p')

if [[ -z "$slaves_raw" ]]; then
  LOG red "No Modbus RTU slaves found in address range $addr_start-$addr_end."
  ALERT "Bus scan complete. No slaves responded in range $addr_start-$addr_end."
  exit 0
fi

# Build array from comma-separated slave list
IFS=',' read -ra slave_addrs <<< "$slaves_raw"

LOG green "Found ${#slave_addrs[@]} responding slave(s): $slaves_raw"

# ---------------------------------------------------------------------------
# Device Identification per Slave
# ---------------------------------------------------------------------------

spinner_id=$(START_SPINNER "Retrieving Device Identification from ${#slave_addrs[@]} slave(s)...")

discovered=0
device_list=""

for addr in "${slave_addrs[@]}"; do
  addr=$(echo "$addr" | tr -d ' ')
  LOG "Requesting FC43 Device ID from slave $addr..."

  id_result=$(modbus_device_id "$addr" 2>/dev/null || true)

  vendor="unknown"
  product="unknown"
  version="unknown"

  if echo "$id_result" | grep -q '"status":"ok"'; then
    vendor=$(echo "$id_result" | sed -n 's/.*"vendor_name":"\([^"]*\)".*/\1/p')
    product=$(echo "$id_result" | sed -n 's/.*"product_code":"\([^"]*\)".*/\1/p')
    version=$(echo "$id_result" | sed -n 's/.*"major_minor_revision":"\([^"]*\)".*/\1/p')
    vendor="${vendor:-unknown}"
    product="${product:-unknown}"
    version="${version:-unknown}"
    LOG green "Slave $addr: vendor=$vendor  product=$product  firmware=$version"
  else
    LOG "Slave $addr: FC43 not supported or no response (slave still recorded)"
  fi

  ts=$(date '+%Y-%m-%dT%H:%M:%S')
  device_json=$(printf '{"id":"modbus-rtu-%d","protocol":"modbus_rtu","bus":"%s","slave_addr":%d,"vendor":"%s","product":"%s","version":"%s","discovered_at":"%s"}' \
    "$addr" "$ESP32_DEV" "$addr" "$vendor" "$product" "$version" "$ts")

  ics_report_device "$device_json"
  discovered=$((discovered + 1))
  device_list="${device_list}\n  Slave $addr  vendor=${vendor}  product=${product}  firmware=${version}"
done

STOP_SPINNER "$spinner_id"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

LOG green "--- Modbus RTU Bus Scan Summary ---"
LOG "Address range scanned : $addr_start - $addr_end"
LOG "Slaves found          : ${#slave_addrs[@]}"
LOG "Devices recorded      : $discovered"
LOG green "Discovered devices:${device_list}"

ALERT "Bus scan complete. $discovered Modbus RTU slave(s) found and reported to inventory: $ICS_INVENTORY"
