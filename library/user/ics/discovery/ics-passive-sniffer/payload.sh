#!/bin/bash
# Title: ICS Passive Sniffer
# Description: Passive ICS traffic identification — no packets sent, listen only
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Cyan slow blink: Listening (passive)
# - Cyan flash: Packet burst on ICS port
# - Magenta flash: New protocol seen for first time
# - Green: Session complete
# - Red: Error
#
# Requirements: tcpdump

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ics-passive-sniffer}"
CAPTURE_PID=""

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${CAPTURE_PID:-}" ]] && kill "$CAPTURE_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Protocol-to-port mapping
# ---------------------------------------------------------------------------

# Maps a port number to a human-readable protocol name.
port_to_protocol() {
  local port="$1"
  case "$port" in
    102)   echo "S7comm" ;;
    502)   echo "Modbus/TCP" ;;
    1962)  echo "PCWorx" ;;
    2404)  echo "IEC-104" ;;
    4000)  echo "Emerson-ROC" ;;
    4840)  echo "OPC-UA" ;;
    9600)  echo "OMRON-FINS" ;;
    18245|18246) echo "GE-SRTP" ;;
    20000) echo "DNP3" ;;
    44818) echo "EtherNet/IP" ;;
    47808) echo "BACnet" ;;
    *)     echo "ICS:$port" ;;
  esac
}

# BPF filter covering all known ICS ports (TCP and UDP)
ICS_BPF_FILTER="port 102 or port 502 or port 1962 or port 2404 or port 4000 or port 4840 or port 9600 or port 18245 or port 18246 or port 20000 or port 44818 or port 47808"

# ---------------------------------------------------------------------------
# Live protocol counter (associative arrays)
# ---------------------------------------------------------------------------

declare -A PROTO_COUNT
declare -A PROTO_SEEN
declare -A HOST_SEEN
TOTAL_PACKETS=0
NEW_PROTO_COUNT=0

process_packet_line() {
  local line="$1"

  # tcpdump default one-line format:
  #   HH:MM:SS.usec IP src.port > dst.port: flags ...
  # We extract the port numbers from src.port and dst.port fields.

  local port=""
  # Match source port: "IP.PORT >" or destination port: "> IP.PORT:"
  if [[ "$line" =~ \.(502|4840|44818|47808|20000|102|9600|1962|2404|4000|18245|18246)[[:space:]] ]]; then
    port="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ \.(502|4840|44818|47808|20000|102|9600|1962|2404|4000|18245|18246): ]]; then
    port="${BASH_REMATCH[1]}"
  fi

  [[ -z "$port" ]] && return

  local proto
  proto=$(port_to_protocol "$port")

  TOTAL_PACKETS=$(( TOTAL_PACKETS + 1 ))
  PROTO_COUNT["$proto"]=$(( ${PROTO_COUNT["$proto"]:-0} + 1 ))

  # Track source host
  local src_host=""
  if [[ "$line" =~ IP[[:space:]]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\. ]]; then
    src_host="${BASH_REMATCH[1]}"
    HOST_SEEN["$src_host"]=1
  fi

  # Alert on first time we see a protocol
  if [[ -z "${PROTO_SEEN[$proto]:-}" ]]; then
    PROTO_SEEN["$proto"]=1
    NEW_PROTO_COUNT=$(( NEW_PROTO_COUNT + 1 ))
    LED M FAST
    VIBRATE 250
    LOG magenta "NEW PROTOCOL: $proto (port $port) from ${src_host:-unknown}"
    sleep 0.2
    LED C SLOW
  else
    # Brief flash on subsequent packets (rate-limited: every 10 packets per proto)
    local count="${PROTO_COUNT[$proto]}"
    if (( count % 10 == 0 )); then
      LED C FAST
      LOG "  $proto — ${count} packets total (last from ${src_host:-?})"
      sleep 0.1
      LED C SLOW
    fi
  fi
}

# ---------------------------------------------------------------------------
# Capture loop
# ---------------------------------------------------------------------------

run_passive_capture() {
  local iface="$1"
  local duration="$2"
  local pcap_file="$ARTIFACTS_DIR/ics_passive_$(date +%Y%m%d_%H%M%S).pcap"

  LOG "Interface: $iface"
  LOG "Duration:  ${duration}s"
  LOG "Filter:    ICS ports only (no injected traffic)"
  LOG ""
  LOG "Listening..."
  LOG ""

  LED C SLOW

  # Write pcap in background while we process the text output in real time.
  tcpdump -i "$iface" -w "$pcap_file" \
    -n -q \
    "$ICS_BPF_FILTER" \
    2>/dev/null &
  CAPTURE_PID=$!

  local end_time=$(( $(date +%s) + duration ))

  # Parallel text-mode stream for live display
  timeout "$duration" \
    tcpdump -i "$iface" -l -n -q \
    "$ICS_BPF_FILTER" \
    2>/dev/null | \
  while IFS= read -r pkt_line; do
    [[ -z "$pkt_line" ]] && continue
    process_packet_line "$pkt_line"

    local remaining=$(( end_time - $(date +%s) ))
    if (( TOTAL_PACKETS % 50 == 0 && TOTAL_PACKETS > 0 )); then
      LOG ""
      LOG blue "--- Live Summary (${remaining}s left) ---"
      for proto in "${!PROTO_COUNT[@]}"; do
        LOG "  $proto: ${PROTO_COUNT[$proto]} packets"
      done
      LOG "  Unique hosts: ${#HOST_SEEN[@]}"
      LOG ""
    fi
  done || true

  # Stop background pcap writer
  kill "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""

  echo "$pcap_file"
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

generate_report() {
  local pcap_file="$1"
  local report_file="$ARTIFACTS_DIR/passive_report_$(date +%Y%m%d_%H%M%S).txt"

  {
    echo "========================================"
    echo "     ICS PASSIVE SNIFFER REPORT"
    echo "========================================"
    echo "Date:        $(date)"
    echo "Interface:   ${CAPTURE_IFACE:-unknown}"
    echo "Duration:    ${CAPTURE_DURATION_USED:-unknown}s"
    echo "PCAP:        $pcap_file"
    echo ""
    echo "PROTOCOL SUMMARY"
    echo "----------------"
    if [[ ${#PROTO_COUNT[@]} -gt 0 ]]; then
      for proto in "${!PROTO_COUNT[@]}"; do
        printf "  %-20s %d packets\n" "$proto" "${PROTO_COUNT[$proto]}"
      done | sort -k2 -rn
    else
      echo "  No ICS traffic observed"
    fi
    echo ""
    echo "UNIQUE HOSTS OBSERVED"
    echo "---------------------"
    if [[ ${#HOST_SEEN[@]} -gt 0 ]]; then
      printf '  %s\n' "${!HOST_SEEN[@]}" | sort
    else
      echo "  None"
    fi
    echo ""
    echo "TOTALS"
    echo "------"
    echo "  Total ICS packets:    $TOTAL_PACKETS"
    echo "  Distinct protocols:   ${#PROTO_SEEN[@]}"
    echo "  Distinct source IPs:  ${#HOST_SEEN[@]}"
    echo "========================================"
  } > "$report_file"

  echo "$report_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== ICS Passive Sniffer ==="
  LOG "Passive traffic identification — no packets injected"
  LOG ""

  mkdir -p "$ARTIFACTS_DIR"

  LED B SLOW

  if ! have tcpdump; then
    ERROR_DIALOG "tcpdump is required but not installed."
    exit 1
  fi

  # Interface selection
  LOG "Available interfaces:"
  ip -o link show 2>/dev/null | awk -F': ' '{print "  " $2}' | grep -v '^  lo$' || \
    ifconfig -a 2>/dev/null | grep -E '^[a-z]' | awk -F':' '{print "  " $1}'
  LOG ""

  local iface
  iface=$(TEXT_PICKER "Capture interface" "eth0") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$iface" ]] && { ERROR_DIALOG "No interface specified"; exit 1; }
  CAPTURE_IFACE="$iface"

  # Duration
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" || "$duration" -lt 1 ]] && duration=120
  CAPTURE_DURATION_USED="$duration"

  LOG ""
  LOG "Interface: $iface"
  LOG "Duration:  ${duration}s"
  LOG "Mode:      passive (read-only)"
  LOG ""

  local confirm
  confirm=$(CONFIRMATION_DIALOG "Begin passive ICS capture on $iface?")
  case "$confirm" in
    "$DUCKYSCRIPT_USER_DENIED"|"")
      LOG "Aborted by user"; exit 0 ;;
  esac

  local pcap_file
  pcap_file=$(run_passive_capture "$iface" "$duration")

  LED G SOLID
  RINGTONE success 2>/dev/null || true

  LOG ""
  LOG green "=== Capture Complete ==="
  LOG "Total ICS packets: $TOTAL_PACKETS"
  LOG "Protocols detected: ${#PROTO_SEEN[@]}"
  LOG "Unique source IPs: ${#HOST_SEEN[@]}"
  LOG ""

  local report_file
  report_file=$(generate_report "$pcap_file")

  LOG "PCAP:   $pcap_file"
  LOG "Report: $report_file"

  if [[ ${#PROTO_SEEN[@]} -gt 0 ]]; then
    ALERT "Detected ICS traffic: $(printf '%s ' "${!PROTO_SEEN[@]}")"
  else
    ALERT "Capture complete — no ICS traffic observed on $iface"
  fi

  PROMPT "Press button to exit"
}

main "$@"
