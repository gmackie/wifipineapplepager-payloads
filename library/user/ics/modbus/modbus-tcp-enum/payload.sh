#!/bin/bash
# Title: Modbus TCP Subnet Enumerator
# Description: Scan a subnet for Modbus TCP devices on port 502, enumerate each
#              with modbus_tcp_scan (FC43 Device Identification), and report
#              discovered devices to the ICS inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: ics
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / prompting user
# - Amber: Scanning in progress
# - Green: Scan complete
# - Red:   Error / no devices found

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_pick_required() {
  local prompt="$1" default="$2"
  local val rc
  val=$(IP_PICKER "$prompt" "$default")
  rc=$?
  case $rc in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG red "Input cancelled — aborting."
      exit 1
      ;;
  esac
  echo "$val"
}

# Expand a CIDR /24 subnet (e.g. 192.168.1.0/24 or 192.168.1) to host list
_expand_subnet() {
  local subnet="$1"
  # Strip trailing /24 or /xx if present; derive base from first 3 octets
  local base
  base=$(echo "$subnet" | sed 's|/.*||' | sed 's|\.[0-9]*$||')
  local i
  for i in $(seq 1 254); do
    echo "${base}.${i}"
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ics_init_engagement

LOG blue "Modbus TCP Subnet Enumerator"
PROMPT "This payload scans port 502 across a /24 subnet and interrogates responding hosts with Modbus FC43 Device Identification. Press OK to continue."

subnet=$(_pick_required "Target subnet (e.g. 192.168.1.0)" "192.168.1.0")

LOG "Target subnet: $subnet"

# Derive printable base for display
subnet_base=$(echo "$subnet" | sed 's/\.[0-9]*$//')

spinner_id=$(START_SPINNER "Scanning ${subnet_base}.1-254 on port 502...")

hosts_502=()
scanned=0

while IFS= read -r host; do
  scanned=$((scanned + 1))
  if timeout 1 bash -c "echo >/dev/tcp/${host}/502" 2>/dev/null; then
    hosts_502+=("$host")
    LOG blue "Port 502 open: $host"
  fi
done < <(_expand_subnet "$subnet")

STOP_SPINNER "$spinner_id"

if [[ ${#hosts_502[@]} -eq 0 ]]; then
  LOG red "No hosts with port 502 open found on ${subnet_base}.x"
  ERROR_DIALOG "No Modbus TCP devices found. Verify subnet and connectivity."
  exit 1
fi

LOG green "Found ${#hosts_502[@]} host(s) with port 502 open. Probing with Modbus FC43..."

spinner_id=$(START_SPINNER "Enumerating Modbus devices...")

discovered=0
device_list=""

for host in "${hosts_502[@]}"; do
  LOG "Probing $host..."

  resp=$(modbus_tcp_scan "$host" 502 2>/dev/null || true)

  if [[ -n "$resp" ]]; then
    discovered=$((discovered + 1))
    LOG green "Modbus TCP device confirmed: $host"

    # Parse minimal device identification from raw hex response
    # Bytes 8-9 = unit id + function code; bytes 12+ = object data
    vendor=""
    product=""
    version=""

    # Best-effort ASCII extraction from hex response
    if command -v xxd >/dev/null 2>&1 && [[ -n "$resp" ]]; then
      ascii_resp=$(echo "$resp" | xxd -r -p 2>/dev/null | strings 2>/dev/null | tr '\n' ' ' || true)
      vendor=$(echo "$ascii_resp" | awk '{print $1}')
      product=$(echo "$ascii_resp" | awk '{print $2}')
      version=$(echo "$ascii_resp" | awk '{print $3}')
    fi

    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    device_json=$(printf '{"id":"modbus-tcp-%s","protocol":"modbus_tcp","ip":"%s","port":502,"vendor":"%s","product":"%s","version":"%s","raw_fc43":"%s","discovered_at":"%s"}' \
      "$host" "$host" "${vendor:-unknown}" "${product:-unknown}" "${version:-unknown}" \
      "${resp:0:64}" "$ts")

    ics_report_device "$device_json"
    device_list="${device_list}\n  $host  vendor=${vendor:-unknown}  product=${product:-unknown}"
  else
    LOG "No Modbus response from $host (port open, no FC43 reply)"
  fi
done

STOP_SPINNER "$spinner_id"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

LOG green "--- Modbus TCP Enumeration Summary ---"
LOG "Subnet scanned : ${subnet_base}.1-254"
LOG "Hosts with 502 : ${#hosts_502[@]}"
LOG "Modbus devices : $discovered"

if [[ $discovered -gt 0 ]]; then
  LOG green "Discovered devices:${device_list}"
  ALERT "Found $discovered Modbus TCP device(s) on ${subnet_base}.x. Results saved to inventory: $ICS_INVENTORY"
else
  LOG red "Port 502 was open on ${#hosts_502[@]} host(s) but none responded to Modbus FC43."
  ERROR_DIALOG "Hosts have port 502 open but did not respond to Modbus FC43 Device Identification. They may require authentication or use a non-standard implementation."
fi
