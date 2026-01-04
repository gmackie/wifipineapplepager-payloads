#!/bin/bash
# Title: Packet Sniffer
# Description: Capture and analyze network traffic with filtering
# Author: Red Team Toolkit
# Version: 1.0
# Category: interception
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Cyan slow blink: Capturing
# - Amber: Processing
# - Green: Capture complete
# - Red: Error

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/packet-sniffer}"
CAPTURE_DURATION="${CAPTURE_DURATION:-60}"
MAX_PACKETS="${MAX_PACKETS:-10000}"
SNAP_LEN="${SNAP_LEN:-65535}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${CAPTURE_PID:-}" ]] && kill "$CAPTURE_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

get_interfaces() {
  if have ip; then
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo$'
  else
    ifconfig -a 2>/dev/null | grep -E '^[a-z]' | awk -F':' '{print $1}'
  fi
}

capture_tcpdump() {
  local iface="$1"
  local filter="$2"
  local output="$3"
  local duration="$4"
  
  LOG "Starting tcpdump capture..."
  LOG "Interface: $iface"
  LOG "Filter: ${filter:-none}"
  LOG "Duration: ${duration}s"
  LOG ""
  
  local cmd="tcpdump -i $iface -s $SNAP_LEN -c $MAX_PACKETS -w $output"
  [[ -n "$filter" ]] && cmd="$cmd $filter"
  
  timeout "$duration" $cmd 2>&1 &
  CAPTURE_PID=$!
  
  local end_time=$(($(date +%s) + duration))
  while kill -0 "$CAPTURE_PID" 2>/dev/null; do
    local remaining=$((end_time - $(date +%s)))
    [[ $remaining -le 0 ]] && break
    LOG "Capturing... ${remaining}s remaining"
    sleep 5
  done
  
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""
  
  if [[ -f "$output" ]]; then
    local size
    size=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output")
    LOG green "Capture saved: $output ($size bytes)"
    return 0
  else
    LOG red "Capture failed"
    return 1
  fi
}

capture_tshark() {
  local iface="$1"
  local filter="$2"
  local output="$3"
  local duration="$4"
  
  LOG "Starting tshark capture..."
  
  local cmd="tshark -i $iface -a duration:$duration -w $output"
  [[ -n "$filter" ]] && cmd="$cmd -f '$filter'"
  
  eval "$cmd" 2>&1 &
  CAPTURE_PID=$!
  
  local end_time=$(($(date +%s) + duration))
  while kill -0 "$CAPTURE_PID" 2>/dev/null; do
    local remaining=$((end_time - $(date +%s)))
    [[ $remaining -le 0 ]] && break
    LOG "Capturing... ${remaining}s remaining"
    sleep 5
  done
  
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""
  
  LOG green "Capture complete"
}

analyze_pcap() {
  local pcap="$1"
  local report="$ARTIFACTS_DIR/analysis_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG blue "=== Analyzing Capture ==="
  LOG ""
  
  {
    echo "=== Packet Analysis Report ==="
    echo "File: $pcap"
    echo "Time: $(date)"
    echo ""
  } > "$report"
  
  if have tshark; then
    {
      echo "=== Protocol Hierarchy ==="
      tshark -r "$pcap" -q -z io,phs 2>/dev/null || echo "Unable to analyze"
      echo ""
      
      echo "=== Conversations ==="
      tshark -r "$pcap" -q -z conv,ip 2>/dev/null | head -30 || echo "No conversations"
      echo ""
      
      echo "=== HTTP Hosts ==="
      tshark -r "$pcap" -Y http -T fields -e http.host 2>/dev/null | sort -u | head -20 || echo "No HTTP"
      echo ""
      
      echo "=== DNS Queries ==="
      tshark -r "$pcap" -Y dns.qry.name -T fields -e dns.qry.name 2>/dev/null | sort -u | head -20 || echo "No DNS"
      echo ""
      
    } >> "$report"
    
    LOG "Protocol hierarchy:"
    tshark -r "$pcap" -q -z io,phs 2>/dev/null | head -20
    
  elif have tcpdump; then
    {
      echo "=== Packet Summary ==="
      tcpdump -r "$pcap" -n 2>/dev/null | head -100
      echo ""
    } >> "$report"
    
    LOG "First 20 packets:"
    tcpdump -r "$pcap" -n 2>/dev/null | head -20
  fi
  
  LOG ""
  LOG green "Report: $report"
}

extract_credentials() {
  local pcap="$1"
  local output="$ARTIFACTS_DIR/credentials_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG blue "=== Extracting Credentials ==="
  LOG ""
  
  {
    echo "=== Credential Extraction ==="
    echo "File: $pcap"
    echo "Time: $(date)"
    echo ""
  } > "$output"
  
  if have tshark; then
    {
      echo "=== HTTP Basic Auth ==="
      tshark -r "$pcap" -Y 'http.authorization' -T fields -e http.authorization 2>/dev/null || echo "None found"
      echo ""
      
      echo "=== HTTP Form Data ==="
      tshark -r "$pcap" -Y 'http.request.method == "POST"' -T fields \
        -e http.host -e http.request.uri -e http.file_data 2>/dev/null | head -50 || echo "None found"
      echo ""
      
      echo "=== FTP Credentials ==="
      tshark -r "$pcap" -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
        -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null || echo "None found"
      echo ""
      
      echo "=== SMTP Auth ==="
      tshark -r "$pcap" -Y 'smtp.auth.password' -T fields -e smtp.auth.password 2>/dev/null || echo "None found"
      echo ""
      
      echo "=== Telnet Data ==="
      tshark -r "$pcap" -Y 'telnet.data' -T fields -e telnet.data 2>/dev/null | head -20 || echo "None found"
      echo ""
      
    } >> "$output"
    
    local cred_count
    cred_count=$(grep -c -v "^$\|None found\|===" "$output" 2>/dev/null || echo "0")
    
    if [[ "$cred_count" -gt 0 ]]; then
      LOG green "Found potential credentials"
      ALERT "Credentials extracted!"
      VIBRATE
    else
      LOG "No plaintext credentials found"
    fi
    
  else
    LOG red "tshark required for credential extraction"
  fi
  
  LOG "Output: $output"
}

live_stats() {
  local iface="$1"
  local duration="$2"
  
  LOG blue "=== Live Traffic Stats ==="
  LOG "Interface: $iface"
  LOG "Duration: ${duration}s"
  LOG ""
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" -q -z io,stat,5 2>/dev/null &
    CAPTURE_PID=$!
    
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
  elif have tcpdump; then
    LOG "Packet count per 5 seconds:"
    local count=0
    local end_time=$(($(date +%s) + duration))
    
    while [[ $(date +%s) -lt $end_time ]]; do
      local pkts
      pkts=$(timeout 5 tcpdump -i "$iface" -c 10000 2>/dev/null | wc -l)
      count=$((count + pkts))
      LOG "  $pkts packets (total: $count)"
    done
  else
    LOG red "No capture tool available"
  fi
}

main() {
  LOG blue "=== Packet Sniffer ==="
  LOG "Capture and analyze network traffic"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  if ! have tcpdump && ! have tshark; then
    ERROR_DIALOG "No capture tools available (tcpdump/tshark)"
    exit 1
  fi
  
  have tcpdump && LOG "tcpdump: available" || LOG "tcpdump: not found"
  have tshark && LOG "tshark: available" || LOG "tshark: not found"
  LOG ""
  
  LOG "Interfaces:"
  get_interfaces | head -5
  LOG ""
  
  LOG "Mode:"
  LOG "1. Capture all traffic"
  LOG "2. Capture with filter"
  LOG "3. HTTP only capture"
  LOG "4. DNS only capture"
  LOG "5. Credentials capture (auth traffic)"
  LOG "6. Analyze existing pcap"
  LOG "7. Live traffic stats"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-7)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  local filter=""
  local output="$ARTIFACTS_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap"
  
  case "$mode" in
    1) filter="" ;;
    2)
      filter=$(TEXT_PICKER "BPF filter" "tcp port 80") || true
      ;;
    3) filter="tcp port 80 or tcp port 443 or tcp port 8080" ;;
    4) filter="udp port 53" ;;
    5) filter="tcp port 21 or tcp port 23 or tcp port 25 or tcp port 110 or tcp port 143 or tcp port 80" ;;
    6)
      local pcap_path
      pcap_path=$(TEXT_PICKER "PCAP file path" "$ARTIFACTS_DIR/") || true
      [[ -z "$pcap_path" || ! -f "$pcap_path" ]] && { ERROR_DIALOG "File not found"; exit 1; }
      
      LED Y SOLID
      analyze_pcap "$pcap_path"
      extract_credentials "$pcap_path"
      
      LED G SOLID
      PROMPT "Press button to exit"
      exit 0
      ;;
    7)
      local iface duration
      iface=$(TEXT_PICKER "Interface" "wlan0") || true
      duration=$(NUMBER_PICKER "Duration (seconds)" 30) || true
      
      LED C SLOW
      live_stats "$iface" "$duration"
      
      LED G SOLID
      PROMPT "Press button to exit"
      exit 0
      ;;
  esac
  
  local iface duration
  iface=$(TEXT_PICKER "Interface" "wlan0") || true
  [[ -z "$iface" ]] && { LOG "Cancelled"; exit 1; }
  
  duration=$(NUMBER_PICKER "Duration (seconds)" "$CAPTURE_DURATION") || true
  [[ -z "$duration" ]] && duration="$CAPTURE_DURATION"
  
  LED C SLOW
  
  if have tcpdump; then
    capture_tcpdump "$iface" "$filter" "$output" "$duration"
  else
    capture_tshark "$iface" "$filter" "$output" "$duration"
  fi
  
  LED Y SOLID
  
  local analyze
  analyze=$(CONFIRMATION_DIALOG "Analyze capture now?")
  if [[ "$analyze" == "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
    analyze_pcap "$output"
    
    if [[ "$mode" == "5" ]]; then
      extract_credentials "$output"
    fi
  fi
  
  LED G SOLID
  VIBRATE
  
  LOG ""
  LOG green "=== Capture Complete ==="
  LOG "File: $output"
  
  PROMPT "Press button to exit"
}

main "$@"
