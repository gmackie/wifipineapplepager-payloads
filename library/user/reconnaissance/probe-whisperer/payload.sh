#!/bin/bash
# Title: Probe Whisperer
# Description: Monitor probe requests to discover what SSIDs devices are looking for
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Monitoring probes
# - Cyan flash: Interesting SSID detected
# - Green: Monitoring complete
#
# Use Case: Identify corporate SSIDs, find targets for evil twin attacks

set -euo pipefail

# === CONFIGURATION ===
MONITOR_DURATION="${MONITOR_DURATION:-300}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/probe-whisperer}"

# Interesting SSIDs to watch for (corporate patterns)
INTERESTING_PATTERNS=(
  "corp"
  "internal"
  "secure"
  "employee"
  "private"
  "office"
  "HQ"
  "vpn"
  "wifi"
  "guest"
  "iot"
  "scada"
  "plc"
)

# === HELPERS ===
have() { command -v "$1" >/dev/null 2>&1; }

ensure_monitor() {
  local mon_iface
  mon_iface=$(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
  if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  
  local base_iface
  base_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^wlan' | head -n1 || true)
  if have airmon-ng && [[ -n "$base_iface" ]]; then
    airmon-ng start "$base_iface" >/dev/null 2>&1 || true
    mon_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true)
    if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  fi
  echo ""
}

cleanup() {
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

# === STATE ===
declare -A PROBED_SSIDS      # SSID -> count
declare -A CLIENT_PROBES     # MAC -> "SSID1,SSID2,..."
declare -A INTERESTING_FOUND # Interesting SSIDs found

is_interesting() {
  local ssid="$1"
  local ssid_lower
  ssid_lower=$(echo "$ssid" | tr '[:upper:]' '[:lower:]')
  
  for pattern in "${INTERESTING_PATTERNS[@]}"; do
    if [[ "$ssid_lower" == *"$pattern"* ]]; then
      return 0
    fi
  done
  return 1
}

alert_interesting() {
  local ssid="$1"
  local client="$2"
  
  # Skip if already alerted
  [[ -n "${INTERESTING_FOUND[$ssid]:-}" ]] && return 0
  INTERESTING_FOUND["$ssid"]=1
  
  LED C FAST
  VIBRATE 200
  
  LOG green "[!] Interesting probe: $ssid"
  LOG "    From client: $client"
  
  echo "[$(date '+%H:%M:%S')] INTERESTING: $ssid (from $client)" >> "$ARTIFACTS_DIR/interesting.log"
  
  sleep 1
  LED B SLOW
}

process_probe() {
  local line="$1"
  
  # Parse tcpdump output for probe requests
  # Looking for: SA:xx:xx:xx:xx:xx ... Probe Request (SSID)
  
  local client_mac ssid
  
  # Extract source MAC
  if [[ "$line" =~ SA:([0-9a-fA-F:]+) ]]; then
    client_mac="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
    client_mac="${BASH_REMATCH[1]}"
  else
    return 0
  fi
  
  # Extract SSID from Probe Request
  if [[ "$line" =~ Probe\ Request\ \(([^\)]+)\) ]]; then
    ssid="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ SSID=([^,\ ]+) ]]; then
    ssid="${BASH_REMATCH[1]}"
  else
    return 0
  fi
  
  # Skip broadcast probes (empty SSID)
  [[ -z "$ssid" || "$ssid" == "Broadcast" ]] && return 0
  
  # Track the probe
  PROBED_SSIDS["$ssid"]=$((${PROBED_SSIDS[$ssid]:-0} + 1))
  
  # Track client -> SSID mapping
  local existing="${CLIENT_PROBES[$client_mac]:-}"
  if [[ ! "$existing" =~ $ssid ]]; then
    CLIENT_PROBES["$client_mac"]="${existing:+$existing,}$ssid"
  fi
  
  # Check if interesting
  if is_interesting "$ssid"; then
    alert_interesting "$ssid" "$client_mac"
  fi
  
  # Log first occurrence
  if [[ "${PROBED_SSIDS[$ssid]}" -eq 1 ]]; then
    LOG "New probe: $ssid (from $client_mac)"
  fi
}

# === MAIN ===
main() {
  LOG blue "=== Probe Whisperer ==="
  LOG "Passive probe request monitor"
  LOG ""
  
  # Get duration
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  # Optional: Add custom interesting SSIDs
  local custom_ssid
  custom_ssid=$(TEXT_PICKER "Watch for SSID (optional)" "") || true
  if [[ -n "$custom_ssid" ]]; then
    INTERESTING_PATTERNS+=("$custom_ssid")
    LOG "Added watch pattern: $custom_ssid"
  fi
  
  # Setup
  mkdir -p "$ARTIFACTS_DIR"
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG "Watching for: ${INTERESTING_PATTERNS[*]}"
  LOG ""
  LOG "Listening for probe requests..."
  
  LED B SLOW
  
  local end_time=$(($(date +%s) + duration))
  local probe_log="$ARTIFACTS_DIR/probes_$(date +%Y%m%d_%H%M%S).log"
  
  # Start tcpdump for probe requests
  if have tcpdump; then
    tcpdump -I -i "$mon" -l -e type mgt subtype probe-req 2>/dev/null | \
    while read -r line && [[ $(date +%s) -lt $end_time ]]; do
      process_probe "$line"
      echo "$line" >> "$probe_log"
    done &
    TCPDUMP_PID=$!
    
    # Wait for duration
    sleep "$duration"
    kill "$TCPDUMP_PID" 2>/dev/null || true
  else
    ERROR_DIALOG "tcpdump not available"
    exit 1
  fi
  
  # Results
  LED G SOLID
  LOG ""
  LOG green "=== Results ==="
  LOG "Unique SSIDs probed: ${#PROBED_SSIDS[@]}"
  LOG "Unique clients: ${#CLIENT_PROBES[@]}"
  LOG "Interesting SSIDs: ${#INTERESTING_FOUND[@]}"
  LOG ""
  
  # Top probed SSIDs
  LOG blue "Top Probed SSIDs:"
  for ssid in "${!PROBED_SSIDS[@]}"; do
    local count="${PROBED_SSIDS[$ssid]}"
    local marker=""
    is_interesting "$ssid" && marker=" [!]"
    echo "  $count x $ssid$marker"
  done | sort -rn | head -20
  
  # Save summary
  {
    echo "=== Probe Whisperer Results ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo ""
    echo "=== All Probed SSIDs ==="
    for ssid in "${!PROBED_SSIDS[@]}"; do
      echo "${PROBED_SSIDS[$ssid]} x $ssid"
    done | sort -rn
    echo ""
    echo "=== Client -> SSID Mappings ==="
    for client in "${!CLIENT_PROBES[@]}"; do
      echo "$client: ${CLIENT_PROBES[$client]}"
    done
  } > "$ARTIFACTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG ""
  LOG "Results saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
