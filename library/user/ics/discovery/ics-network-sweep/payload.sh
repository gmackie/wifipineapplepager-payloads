#!/bin/bash
# Title: ICS Network Sweep
# Description: Full subnet ICS protocol discovery sweep with device inventory
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber slow blink: Scanning
# - Cyan flash: Host discovered
# - Magenta flash: ICS device confirmed
# - Green: Sweep complete
# - Red: Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ics-network-sweep}"
ICS_PORTS="102,502,4840,20000,44818,47808,9600,1962,2404,4000,18245,18246"

have() { command -v "$1" >/dev/null 2>&1; }

DISCOVERED_HOSTS=()
CONFIRMED_ICS=()

cleanup() {
  [[ -n "${SCAN_PID:-}" ]] && kill "$SCAN_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

nmap_sweep() {
  local subnet="$1"
  local out_xml="$ARTIFACTS_DIR/nmap_sweep.xml"

  LOG "Running nmap ICS port scan on $subnet..."
  nmap -Pn -sS -p "$ICS_PORTS" --open -oX "$out_xml" "$subnet" 2>/dev/null &
  SCAN_PID=$!

  local start_time
  start_time=$(date +%s)
  while kill -0 "$SCAN_PID" 2>/dev/null; do
    local elapsed=$(( $(date +%s) - start_time ))
    LOG "Scanning... ${elapsed}s elapsed"
    sleep 10
  done
  wait "$SCAN_PID" 2>/dev/null || true
  SCAN_PID=""

  if [[ -f "$out_xml" ]]; then
    grep -oP '(?<=addr=")[^"]+' "$out_xml" 2>/dev/null || true
  fi
}

nc_sweep() {
  local subnet="$1"

  LOG "nmap not available — falling back to nc port check..."
  local base="${subnet%.*}"
  local found_hosts=()

  for octet in $(seq 1 254); do
    local host="${base}.${octet}"
    for port in 502 4840 44818 47808 20000 102 9600; do
      if nc -z -w 1 "$host" "$port" 2>/dev/null; then
        LOG cyan "  Open: $host:$port"
        found_hosts+=("$host")
        break
      fi
    done
  done

  printf '%s\n' "${found_hosts[@]}" | sort -u
}

discover_hosts() {
  local subnet="$1"

  if have nmap; then
    mapfile -t DISCOVERED_HOSTS < <(nmap_sweep "$subnet")
  else
    mapfile -t DISCOVERED_HOSTS < <(nc_sweep "$subnet")
  fi
}

# ---------------------------------------------------------------------------
# Per-host protocol probing
# ---------------------------------------------------------------------------

probe_host() {
  local host="$1"
  local detected_protocols=()

  LOG blue "--- Probing $host ---"
  LED C FAST

  # Each function is expected to be provided by ics_protocols.sh.
  # They return 0 on success and print a result line; non-zero means no response.

  if ics_probe_modbus "$host" 2>/dev/null; then
    detected_protocols+=("Modbus/TCP:502")
  fi

  if ics_probe_enip "$host" 2>/dev/null; then
    detected_protocols+=("EtherNet/IP:44818")
  fi

  if ics_probe_opcua "$host" 2>/dev/null; then
    detected_protocols+=("OPC-UA:4840")
  fi

  if ics_probe_dnp3 "$host" 2>/dev/null; then
    detected_protocols+=("DNP3:20000")
  fi

  if ics_probe_bacnet "$host" 2>/dev/null; then
    detected_protocols+=("BACnet/IP:47808")
  fi

  if ics_probe_s7 "$host" 2>/dev/null; then
    detected_protocols+=("S7comm:102")
  fi

  if [[ ${#detected_protocols[@]} -eq 0 ]]; then
    LOG "  No ICS protocols detected on $host"
    return
  fi

  CONFIRMED_ICS+=("$host")
  LED M FAST
  VIBRATE 300

  local proto_list
  proto_list=$(printf ', %s' "${detected_protocols[@]}")
  proto_list="${proto_list:2}"
  LOG magenta "  ICS device confirmed: $host — $proto_list"

  # Report to engagement inventory
  ics_report_device \
    --host "$host" \
    --protocols "$proto_list" \
    --inventory "$ARTIFACTS_DIR/inventory.json" \
    2>/dev/null || true

  sleep 0.2
  LED Y SLOW
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  local total_hosts=${#DISCOVERED_HOSTS[@]}
  local total_ics=${#CONFIRMED_ICS[@]}
  local report_file="$ARTIFACTS_DIR/sweep_report_$(date +%Y%m%d_%H%M%S).txt"

  {
    echo "========================================"
    echo "       ICS NETWORK SWEEP REPORT"
    echo "========================================"
    echo "Date:            $(date)"
    echo "Engagement:      ${ENGAGEMENT_NAME:-unknown}"
    echo "Subnet:          ${TARGET_SUBNET:-unknown}"
    echo ""
    echo "SUMMARY"
    echo "-------"
    echo "Hosts with ICS ports open: $total_hosts"
    echo "Confirmed ICS devices:     $total_ics"
    echo ""
    if [[ $total_ics -gt 0 ]]; then
      echo "CONFIRMED ICS HOSTS"
      echo "-------------------"
      printf '  %s\n' "${CONFIRMED_ICS[@]}"
      echo ""
    fi
    echo "FULL HOST LIST"
    echo "--------------"
    if [[ $total_hosts -gt 0 ]]; then
      printf '  %s\n' "${DISCOVERED_HOSTS[@]}"
    else
      echo "  (none)"
    fi
    echo ""
    echo "Inventory: $ARTIFACTS_DIR/inventory.json"
    echo "========================================"
  } > "$report_file"

  LOG ""
  LOG green "=== Sweep Complete ==="
  LOG "Hosts with ICS ports: $total_hosts"
  LOG "Confirmed ICS devices: $total_ics"
  LOG "Report: $report_file"
  LOG "Inventory: $ARTIFACTS_DIR/inventory.json"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== ICS Network Sweep ==="
  LOG "Full subnet ICS protocol discovery"
  LOG ""

  mkdir -p "$ARTIFACTS_DIR"

  LED B SLOW

  # Engagement name
  local engagement
  engagement=$(TEXT_PICKER "Engagement name" "ICS-Assessment-001") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$engagement" ]] && engagement="ICS-Assessment-001"
  ENGAGEMENT_NAME="$engagement"

  ics_init_engagement \
    --name "$ENGAGEMENT_NAME" \
    --dir "$ARTIFACTS_DIR" \
    2>/dev/null || true

  # Target subnet
  local subnet
  subnet=$(IP_PICKER "Target subnet (CIDR)" "192.168.1.0") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$subnet" ]] && { ERROR_DIALOG "No subnet specified"; exit 1; }

  # Append /24 if no prefix was given
  [[ "$subnet" != */* ]] && subnet="${subnet}/24"
  TARGET_SUBNET="$subnet"

  LOG "Engagement: $ENGAGEMENT_NAME"
  LOG "Target:     $TARGET_SUBNET"
  LOG ""

  # Confirm before sweeping
  local confirm
  confirm=$(CONFIRMATION_DIALOG "Start ICS sweep on $TARGET_SUBNET?")
  case "$confirm" in
    "$DUCKYSCRIPT_USER_DENIED"|"")
      LOG "Aborted by user"; exit 0 ;;
  esac

  LED Y SLOW

  local spinner_id
  spinner_id=$(START_SPINNER "Discovering hosts on $TARGET_SUBNET...")

  discover_hosts "$TARGET_SUBNET"

  STOP_SPINNER "$spinner_id"

  local total_hosts=${#DISCOVERED_HOSTS[@]}
  LOG ""
  LOG "Found $total_hosts hosts with open ICS ports"
  LOG ""

  if [[ $total_hosts -eq 0 ]]; then
    LOG "No hosts with ICS ports found."
    LED G SOLID
    print_summary
    PROMPT "Press button to exit"
    exit 0
  fi

  # Protocol probe each host
  LOG blue "=== Protocol Identification ==="
  LED Y SLOW

  for host in "${DISCOVERED_HOSTS[@]}"; do
    probe_host "$host"
  done

  LED G SOLID
  RINGTONE success 2>/dev/null || true

  print_summary

  local total_ics=${#CONFIRMED_ICS[@]}
  if [[ $total_ics -gt 0 ]]; then
    ALERT "Found $total_ics ICS device(s) on $TARGET_SUBNET"
  else
    ALERT "Sweep complete — no ICS devices confirmed on $TARGET_SUBNET"
  fi

  PROMPT "Press button to exit"
}

main "$@"
