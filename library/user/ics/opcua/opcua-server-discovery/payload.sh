#!/bin/bash
# Title: OPC UA Server Discovery
# Description: Discover OPC UA servers on port 4840 within a target subnet or host,
#              enumerate available endpoints, and report findings to the engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Scanning
# - Green: Discovery complete
# - Red:   Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_expand_targets() {
  local target="$1"
  # Accepts a CIDR (192.168.1.0/24), range stub (192.168.1.1-254), or single IP
  if echo "$target" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    # CIDR — require nmap or generate host list with awk
    if command -v nmap >/dev/null 2>&1; then
      nmap -sL -n "$target" 2>/dev/null | awk '/Nmap scan report/{print $NF}'
    else
      ics_log "warn" "opcua" "nmap not found; treating $target as single host"
      echo "$target"
    fi
  elif echo "$target" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$'; then
    # e.g. 192.168.1.1-254
    local base end_oct
    base=$(echo "$target" | cut -d'-' -f1 | sed 's/\.[0-9]*$//')
    local start_oct
    start_oct=$(echo "$target" | cut -d'-' -f1 | awk -F. '{print $4}')
    end_oct=$(echo "$target" | cut -d'-' -f2)
    seq "$start_oct" "$end_oct" | while read -r oct; do
      echo "${base}.${oct}"
    done
  else
    echo "$target"
  fi
}

_probe_server() {
  local host="$1"
  local port=4840
  local result

  result=$(opcua_discover "$host" "$port" 2>/dev/null) || return 1

  if echo "$result" | grep -q "status=ok"; then
    local proto_ver
    proto_ver=$(echo "$result" | grep "protocol_version=" | cut -d= -f2)

    LOG green "Found OPC UA server: $host:$port (proto_ver=$proto_ver)"

    local json
    json=$(printf '{"id":"%s_%s","protocol":"opcua","ip":"%s","port":%d,"protocol_version":%s,"status":"open"}' \
      "$host" "$port" "$host" "$port" "${proto_ver:-0}")
    ics_report_device "$json"
    return 0
  elif echo "$result" | grep -q "status=error"; then
    local err_code
    err_code=$(echo "$result" | grep "opcua_error=" | cut -d= -f2)
    LOG "OPC UA error on $host:$port (code=$err_code) — server present but rejected"
    local json
    json=$(printf '{"id":"%s_%s","protocol":"opcua","ip":"%s","port":%d,"status":"error","error_code":"%s"}' \
      "$host" "$port" "$host" "$port" "${err_code:-unknown}")
    ics_report_device "$json"
    return 0
  fi

  return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "OPC UA Server Discovery"
LOG "Scans port 4840 for OPC UA servers and reports endpoints to inventory."

ics_init_engagement

LOG blue "Enter the target — single IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-50)."
target=$(IP_PICKER "Target subnet / host" "192.168.1.0/24")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

found=0
total=0

spin_id=$(START_SPINNER "Scanning for OPC UA servers on port 4840...")

while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  total=$((total + 1))
  if _probe_server "$host"; then
    found=$((found + 1))
  fi
done < <(_expand_targets "$target")

STOP_SPINNER "$spin_id"

if [[ "$found" -eq 0 ]]; then
  LOG "No OPC UA servers found in $target (scanned $total hosts)"
  ALERT "Discovery complete — no OPC UA servers found in $target"
else
  LOG green "Discovery complete: $found OPC UA server(s) found out of $total hosts"
  ALERT "Found $found OPC UA server(s). Results saved to $ICS_INVENTORY"
fi
