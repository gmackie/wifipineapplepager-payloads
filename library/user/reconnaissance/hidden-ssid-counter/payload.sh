#!/bin/bash
# Title: Hidden SSID Counter
# Description: Count and track hidden networks, attempt to reveal via client probes
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Scanning for hidden networks
# - Magenta flash: New hidden network found
# - Yellow flash: Hidden SSID revealed via probe
# - Green: Scan complete
#
# Use Case: Identify hidden networks as potential targets, reveal names via client probes

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
SCAN_INTERVAL="${SCAN_INTERVAL:-10}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/hidden-ssid}"

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
  [[ -n "${SCAN_PID:-}" ]] && kill "$SCAN_PID" 2>/dev/null || true
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

declare -A HIDDEN_NETWORKS
declare -A REVEALED_SSIDS
HIDDEN_COUNT=0
REVEALED_COUNT=0

alert_hidden_found() {
  local bssid="$1"
  local channel="$2"
  local rssi="$3"
  
  LED M FAST
  VIBRATE 150
  
  LOG green "[+] Hidden network: $bssid"
  LOG "    Channel: $channel | RSSI: ${rssi}dB"
  
  echo "[$(date '+%H:%M:%S')] HIDDEN: $bssid ch:$channel rssi:$rssi" >> "$ARTIFACTS_DIR/hidden.log"
  
  sleep 1
  LED B SLOW
}

alert_ssid_revealed() {
  local bssid="$1"
  local ssid="$2"
  
  LED Y FAST
  VIBRATE 300
  RINGTONE notify 2>/dev/null || true
  
  LOG green "[!] REVEALED: $bssid -> $ssid"
  
  ALERT "Hidden SSID revealed: $ssid"
  
  echo "[$(date '+%H:%M:%S')] REVEALED: $bssid = $ssid" >> "$ARTIFACTS_DIR/revealed.log"
  
  sleep 2
  LED B SLOW
}

parse_airodump_csv() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_len essid rest; do
    [[ "$bssid" =~ ^BSSID || -z "$bssid" || "$bssid" =~ ^Station ]] && continue
    
    bssid=$(echo "$bssid" | tr -d ' ')
    essid=$(echo "$essid" | tr -d ' ')
    channel=$(echo "$channel" | tr -d ' ')
    power=$(echo "$power" | tr -d ' ')
    privacy=$(echo "$privacy" | tr -d ' ')
    id_len=$(echo "$id_len" | tr -d ' ')
    
    local is_hidden=0
    if [[ -z "$essid" || "$essid" == "<length:"* ]]; then
      is_hidden=1
    fi
    
    if [[ $is_hidden -eq 1 && -z "${HIDDEN_NETWORKS[$bssid]:-}" ]]; then
      HIDDEN_NETWORKS["$bssid"]="$channel:$power:$privacy"
      HIDDEN_COUNT=$((HIDDEN_COUNT + 1))
      alert_hidden_found "$bssid" "$channel" "$power"
    fi
  done < "$csv_file"
}

monitor_probes_for_reveals() {
  local mon="$1"
  local probe_log="$ARTIFACTS_DIR/probe_capture.log"
  
  if have tcpdump; then
    tcpdump -I -i "$mon" -l -e 'type mgt subtype probe-resp' 2>/dev/null >> "$probe_log" &
    TCPDUMP_PID=$!
  fi
}

check_probe_reveals() {
  local probe_log="$ARTIFACTS_DIR/probe_capture.log"
  
  [[ ! -f "$probe_log" ]] && return 0
  
  while read -r line; do
    for bssid in "${!HIDDEN_NETWORKS[@]}"; do
      if [[ "$line" == *"$bssid"* ]]; then
        local ssid
        if [[ "$line" =~ SSID=([^,\ ]+) ]]; then
          ssid="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ \(([A-Za-z0-9_-]+)\) ]]; then
          ssid="${BASH_REMATCH[1]}"
        fi
        
        if [[ -n "$ssid" && -z "${REVEALED_SSIDS[$bssid]:-}" ]]; then
          REVEALED_SSIDS["$bssid"]="$ssid"
          REVEALED_COUNT=$((REVEALED_COUNT + 1))
          alert_ssid_revealed "$bssid" "$ssid"
        fi
      fi
    done
  done < "$probe_log"
  
  : > "$probe_log"
}

main() {
  LOG blue "=== Hidden SSID Counter ==="
  LOG "Find and reveal hidden networks"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$MONITOR_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$MONITOR_DURATION"
  
  mkdir -p "$ARTIFACTS_DIR"
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG ""
  LOG "Scanning for hidden networks..."
  LOG "Tip: Hidden SSIDs may be revealed when clients connect"
  LOG ""
  
  LED B SLOW
  
  local end_time=$(($(date +%s) + duration))
  local csv_prefix="$ARTIFACTS_DIR/scan"
  local scan_num=0
  
  monitor_probes_for_reveals "$mon"
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    
    if have airodump-ng; then
      local csv_file="${csv_prefix}-${scan_num}"
      
      timeout "$SCAN_INTERVAL" airodump-ng \
        --write-interval 2 \
        --output-format csv \
        --write "$csv_file" \
        "$mon" 2>/dev/null &
      SCAN_PID=$!
      wait "$SCAN_PID" 2>/dev/null || true
      
      parse_airodump_csv "${csv_file}-01.csv"
      check_probe_reveals
      
      rm -f "${csv_file}"* 2>/dev/null || true
    else
      LOG red "airodump-ng not available"
      sleep "$SCAN_INTERVAL"
    fi
    
    local remaining=$((end_time - $(date +%s)))
    LOG "Status: ${HIDDEN_COUNT} hidden | ${REVEALED_COUNT} revealed | ${remaining}s left"
  done
  
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  
  LED G SOLID
  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "Hidden networks found: $HIDDEN_COUNT"
  LOG "SSIDs revealed: $REVEALED_COUNT"
  LOG ""
  
  if [[ $HIDDEN_COUNT -gt 0 ]]; then
    LOG blue "Hidden Networks:"
    for bssid in "${!HIDDEN_NETWORKS[@]}"; do
      local info="${HIDDEN_NETWORKS[$bssid]}"
      local ch rssi enc
      ch=$(echo "$info" | cut -d: -f1)
      rssi=$(echo "$info" | cut -d: -f2)
      enc=$(echo "$info" | cut -d: -f3)
      
      local revealed=""
      if [[ -n "${REVEALED_SSIDS[$bssid]:-}" ]]; then
        revealed=" -> ${REVEALED_SSIDS[$bssid]}"
      fi
      
      LOG "  $bssid (ch:$ch ${rssi}dB $enc)$revealed"
    done
  fi
  
  {
    echo "=== Hidden SSID Counter Results ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo "Hidden networks: $HIDDEN_COUNT"
    echo "Revealed: $REVEALED_COUNT"
    echo ""
    echo "=== Hidden Networks ==="
    for bssid in "${!HIDDEN_NETWORKS[@]}"; do
      local info="${HIDDEN_NETWORKS[$bssid]}"
      local revealed="${REVEALED_SSIDS[$bssid]:-[unknown]}"
      echo "$bssid | $info | SSID: $revealed"
    done
  } > "$ARTIFACTS_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG ""
  LOG "Report saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
