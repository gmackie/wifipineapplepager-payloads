#!/bin/bash
# Title: ICS Port Scanner
# Description: Fast nmap scan for known ICS/OT ports with protocol classification
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber slow blink: Scanning
# - Cyan flash: Hit found
# - Green: Scan complete
# - Red: Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ics-port-scanner}"

# Well-known ICS/OT port list
# 502   Modbus/TCP
# 4840  OPC-UA
# 44818 EtherNet/IP (EtherNet/IP CIP TCP)
# 47808 BACnet/IP (UDP — included for completeness)
# 20000 DNP3
# 102   S7comm (ISO-TSAP)
# 9600  OMRON FINS
# 1962  PCWorx (Phoenix Contact)
# 2404  IEC 60870-5-104
# 4000  Emerson ROC
# 18245 GE SRTP
# 18246 GE SRTP (alt)
ICS_PORT_LIST="102,502,1962,2404,4000,4840,9600,18245,18246,20000,44818,47808"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${SCAN_PID:-}" ]] && kill "$SCAN_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Protocol classification
# ---------------------------------------------------------------------------

classify_port() {
  local port="$1"

  # Delegate to library function first; fall back to local table
  if have ics_port_fingerprint; then
    ics_port_fingerprint "$port" 2>/dev/null && return
  fi

  case "$port" in
    102)   echo "S7comm / ISO-TSAP (Siemens S7 PLC)" ;;
    502)   echo "Modbus/TCP (IEC 61158)" ;;
    1962)  echo "PCWorx (Phoenix Contact PLC)" ;;
    2404)  echo "IEC 60870-5-104 (telecontrol)" ;;
    4000)  echo "Emerson ROC / iRPC" ;;
    4840)  echo "OPC-UA (OPC Unified Architecture)" ;;
    9600)  echo "OMRON FINS (factory automation)" ;;
    18245) echo "GE SRTP (GE PLCs)" ;;
    18246) echo "GE SRTP alternate" ;;
    20000) echo "DNP3 (SCADA/Distributed Network Protocol)" ;;
    44818) echo "EtherNet/IP CIP (Allen-Bradley / Rockwell)" ;;
    47808) echo "BACnet/IP (building automation)" ;;
    *)     echo "Unknown ICS port" ;;
  esac
}

# ---------------------------------------------------------------------------
# Scanning functions
# ---------------------------------------------------------------------------

run_nmap_scan() {
  local subnet="$1"
  local out_xml
  out_xml="$ARTIFACTS_DIR/scan_$(date +%Y%m%d_%H%M%S).xml"

  LOG "Launching nmap scan..."
  LOG "Ports: $ICS_PORT_LIST"
  LOG ""

  nmap -Pn -sS \
    -p "$ICS_PORT_LIST" \
    --open \
    -T4 \
    --version-intensity 2 \
    -oX "$out_xml" \
    "$subnet" 2>&1 &
  SCAN_PID=$!

  local start_time
  start_time=$(date +%s)
  while kill -0 "$SCAN_PID" 2>/dev/null; do
    local elapsed=$(( $(date +%s) - start_time ))
    LOG "Scanning... ${elapsed}s elapsed"
    sleep 8
  done
  wait "$SCAN_PID" 2>/dev/null || true
  SCAN_PID=""

  echo "$out_xml"
}

parse_nmap_xml() {
  local xml_file="$1"
  local results_file
  results_file="$ARTIFACTS_DIR/ics_hits_$(date +%Y%m%d_%H%M%S).txt"
  local hit_count=0

  {
    echo "========================================"
    echo "       ICS PORT SCANNER RESULTS"
    echo "========================================"
    echo "Date:   $(date)"
    echo "Source: $xml_file"
    echo ""
    echo "OPEN ICS PORTS"
    echo "--------------"
  } > "$results_file"

  # Extract host/port pairs from nmap XML using basic grep+awk
  local current_ip=""
  while IFS= read -r line; do
    if [[ "$line" =~ addr=\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
      current_ip="${BASH_REMATCH[1]}"
    fi
    if [[ -n "$current_ip" && "$line" =~ portid=\"([0-9]+)\".*state=\"open\" ]]; then
      local port="${BASH_REMATCH[1]}"
      local label
      label=$(classify_port "$port")

      hit_count=$((hit_count + 1))
      LED C FAST
      VIBRATE 150

      LOG cyan "  $current_ip:$port — $label"
      echo "  $current_ip : $port  — $label" >> "$results_file"

      sleep 0.1
      LED Y SLOW
    fi
  done < "$xml_file"

  {
    echo ""
    echo "TOTAL HITS: $hit_count"
    echo "========================================"
  } >> "$results_file"

  LOG ""
  LOG "Total ICS port hits: $hit_count"
  LOG "Artifact: $results_file"

  echo "$results_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== ICS Port Scanner ==="
  LOG "Known ICS/OT port fingerprinting"
  LOG ""

  mkdir -p "$ARTIFACTS_DIR"

  LED B SLOW

  if ! have nmap; then
    ERROR_DIALOG "nmap is required but not installed."
    exit 1
  fi

  # Target subnet
  local subnet
  subnet=$(IP_PICKER "Target subnet (CIDR)" "192.168.1.0") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$subnet" ]] && { ERROR_DIALOG "No subnet specified"; exit 1; }
  [[ "$subnet" != */* ]] && subnet="${subnet}/24"

  LOG "Target: $subnet"
  LOG ""

  # Optional: let operator override the port list
  LOG "Default ICS ports: $ICS_PORT_LIST"
  local use_default
  use_default=$(CONFIRMATION_DIALOG "Use default ICS port list?")
  if [[ "$use_default" == "$DUCKYSCRIPT_USER_DENIED" ]]; then
    local custom_ports
    custom_ports=$(TEXT_PICKER "Custom port list (comma-separated)" "$ICS_PORT_LIST") || true
    case $? in
      "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") ;;
      *) [[ -n "$custom_ports" ]] && ICS_PORT_LIST="$custom_ports" ;;
    esac
  fi

  LOG ""

  local confirm
  confirm=$(CONFIRMATION_DIALOG "Start ICS port scan on $subnet?")
  case "$confirm" in
    "$DUCKYSCRIPT_USER_DENIED"|"")
      LOG "Aborted by user"; exit 0 ;;
  esac

  LED Y SLOW

  local spinner_id
  spinner_id=$(START_SPINNER "Scanning $subnet for ICS ports...")

  local xml_file
  xml_file=$(run_nmap_scan "$subnet")

  STOP_SPINNER "$spinner_id"

  if [[ ! -f "$xml_file" ]]; then
    ERROR_DIALOG "nmap scan produced no output file."
    exit 1
  fi

  LOG ""
  LOG blue "=== Classifying Results ==="

  local results_file
  results_file=$(parse_nmap_xml "$xml_file")

  LED G SOLID
  RINGTONE success 2>/dev/null || true

  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "XML:     $xml_file"
  LOG "Results: $results_file"

  ALERT "ICS port scan finished — see artifacts"
  PROMPT "Press button to exit"
}

main "$@"
