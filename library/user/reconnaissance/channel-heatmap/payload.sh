#!/bin/bash
# Title: Channel Heatmap
# Description: Visualize WiFi channel usage and congestion with ASCII heatmap
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Scanning channels
# - Amber: Processing data
# - Green: Heatmap complete
#
# Use Case: Find optimal attack channels, identify crowded vs clear frequencies

set -euo pipefail

SCAN_DURATION="${SCAN_DURATION:-60}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/channel-heatmap}"

CHANNELS_24=(1 2 3 4 5 6 7 8 9 10 11 12 13)
CHANNELS_5=(36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165)

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
  LED OFF
}
trap cleanup EXIT

declare -A CHANNEL_AP_COUNT
declare -A CHANNEL_RSSI_SUM
declare -A CHANNEL_SSIDS
TOTAL_APS=0
TOTAL_CLIENTS=0

HEAT_CHARS=(" " "░" "▒" "▓" "█")

get_heat_char() {
  local count="$1"
  local max="$2"
  
  [[ $max -eq 0 ]] && echo " " && return
  
  local ratio=$((count * 4 / max))
  [[ $ratio -gt 4 ]] && ratio=4
  
  echo "${HEAT_CHARS[$ratio]}"
}

get_congestion_level() {
  local count="$1"
  
  if [[ $count -eq 0 ]]; then
    echo "CLEAR"
  elif [[ $count -le 3 ]]; then
    echo "LOW"
  elif [[ $count -le 7 ]]; then
    echo "MEDIUM"
  elif [[ $count -le 15 ]]; then
    echo "HIGH"
  else
    echo "SEVERE"
  fi
}

parse_scan() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  local in_client_section=0
  
  while IFS=',' read -r col1 col2 col3 col4 col5 col6 col7 col8 col9 col10 col11 col12 col13 col14 rest; do
    if [[ "$col1" =~ ^Station ]]; then
      in_client_section=1
      continue
    fi
    
    [[ "$col1" =~ ^BSSID ]] && continue
    [[ -z "$col1" ]] && continue
    
    col1=$(echo "$col1" | tr -d ' ')
    
    if [[ $in_client_section -eq 0 ]]; then
      local bssid="$col1"
      local channel="$col4"
      local power="$col9"
      local essid="$col14"
      
      channel=$(echo "$channel" | tr -d ' ')
      power=$(echo "$power" | tr -d ' ')
      essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      
      [[ -z "$channel" || ! "$channel" =~ ^[0-9]+$ ]] && continue
      
      CHANNEL_AP_COUNT["$channel"]=$((${CHANNEL_AP_COUNT[$channel]:-0} + 1))
      TOTAL_APS=$((TOTAL_APS + 1))
      
      if [[ -n "$power" && "$power" =~ ^-?[0-9]+$ ]]; then
        CHANNEL_RSSI_SUM["$channel"]=$((${CHANNEL_RSSI_SUM[$channel]:-0} + power))
      fi
      
      if [[ -n "$essid" ]]; then
        local existing="${CHANNEL_SSIDS[$channel]:-}"
        if [[ ! "$existing" =~ $essid ]]; then
          CHANNEL_SSIDS["$channel"]="${existing:+$existing,}$essid"
        fi
      fi
    else
      local station="$col1"
      local assoc_bssid="$col6"
      
      assoc_bssid=$(echo "$assoc_bssid" | tr -d ' ')
      
      if [[ -n "$assoc_bssid" && "$assoc_bssid" != "(not" ]]; then
        TOTAL_CLIENTS=$((TOTAL_CLIENTS + 1))
      fi
    fi
  done < "$csv_file"
}

render_heatmap_24() {
  local max_count=0
  
  for ch in "${CHANNELS_24[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    [[ $count -gt $max_count ]] && max_count=$count
  done
  
  LOG blue "=== 2.4 GHz Channel Heatmap ==="
  LOG ""
  LOG "Ch  APs  Heat Bar         Congestion   Top SSIDs"
  LOG "--- ---- ---------------- ------------ -------------------------"
  
  for ch in "${CHANNELS_24[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    local level
    level=$(get_congestion_level "$count")
    
    local bar=""
    local bar_len=$((count * 16 / (max_count + 1)))
    [[ $max_count -eq 0 ]] && bar_len=0
    [[ $bar_len -gt 16 ]] && bar_len=16
    
    for ((i=0; i<bar_len; i++)); do
      bar+="█"
    done
    for ((i=bar_len; i<16; i++)); do
      bar+="░"
    done
    
    local ssids="${CHANNEL_SSIDS[$ch]:-}"
    local top_ssids
    top_ssids=$(echo "$ssids" | tr ',' '\n' | head -3 | tr '\n' ',' | sed 's/,$//')
    [[ ${#top_ssids} -gt 25 ]] && top_ssids="${top_ssids:0:22}..."
    
    printf "%2d  %3d  [%s] %-12s %s\n" "$ch" "$count" "$bar" "$level" "$top_ssids"
  done
}

render_heatmap_5() {
  local max_count=0
  local has_5ghz=0
  
  for ch in "${CHANNELS_5[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    [[ $count -gt 0 ]] && has_5ghz=1
    [[ $count -gt $max_count ]] && max_count=$count
  done
  
  [[ $has_5ghz -eq 0 ]] && return 0
  
  LOG ""
  LOG blue "=== 5 GHz Channel Heatmap ==="
  LOG ""
  LOG "Ch   APs  Heat Bar         Congestion   Top SSIDs"
  LOG "---- ---- ---------------- ------------ -------------------------"
  
  for ch in "${CHANNELS_5[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    [[ $count -eq 0 ]] && continue
    
    local level
    level=$(get_congestion_level "$count")
    
    local bar=""
    local bar_len=$((count * 16 / (max_count + 1)))
    [[ $max_count -eq 0 ]] && bar_len=0
    [[ $bar_len -gt 16 ]] && bar_len=16
    
    for ((i=0; i<bar_len; i++)); do
      bar+="█"
    done
    for ((i=bar_len; i<16; i++)); do
      bar+="░"
    done
    
    local ssids="${CHANNEL_SSIDS[$ch]:-}"
    local top_ssids
    top_ssids=$(echo "$ssids" | tr ',' '\n' | head -3 | tr '\n' ',' | sed 's/,$//')
    [[ ${#top_ssids} -gt 25 ]] && top_ssids="${top_ssids:0:22}..."
    
    printf "%3d  %3d  [%s] %-12s %s\n" "$ch" "$count" "$bar" "$level" "$top_ssids"
  done
}

find_best_channels() {
  LOG ""
  LOG blue "=== Recommendations ==="
  LOG ""
  
  local best_24=""
  local best_24_count=999
  for ch in 1 6 11; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    if [[ $count -lt $best_24_count ]]; then
      best_24_count=$count
      best_24=$ch
    fi
  done
  
  LOG green "Best 2.4 GHz channel: $best_24 ($best_24_count APs)"
  
  local best_5=""
  local best_5_count=999
  for ch in "${CHANNELS_5[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]:-0}"
    if [[ $count -lt $best_5_count ]]; then
      best_5_count=$count
      best_5=$ch
    fi
  done
  
  if [[ -n "$best_5" ]]; then
    LOG green "Best 5 GHz channel: $best_5 ($best_5_count APs)"
  fi
  
  local worst=""
  local worst_count=0
  for ch in "${!CHANNEL_AP_COUNT[@]}"; do
    local count="${CHANNEL_AP_COUNT[$ch]}"
    if [[ $count -gt $worst_count ]]; then
      worst_count=$count
      worst=$ch
    fi
  done
  
  if [[ -n "$worst" ]]; then
    LOG ""
    LOG red "Most congested: Channel $worst ($worst_count APs)"
  fi
}

main() {
  LOG blue "=== Channel Heatmap ==="
  LOG "Visualize WiFi channel congestion"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$SCAN_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" ]] && duration="$SCAN_DURATION"
  
  mkdir -p "$ARTIFACTS_DIR"
  local mon
  mon=$(ensure_monitor)
  
  if [[ -z "$mon" ]]; then
    ERROR_DIALOG "No monitor interface available"
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Scan duration: ${duration}s"
  LOG ""
  LOG "Scanning all channels..."
  
  LED B SLOW
  
  if have airodump-ng; then
    local csv_prefix="$ARTIFACTS_DIR/fullscan"
    
    timeout "$duration" airodump-ng \
      --band abg \
      --write-interval 5 \
      --output-format csv \
      --write "$csv_prefix" \
      "$mon" 2>/dev/null &
    SCAN_PID=$!
    
    local end_time=$(($(date +%s) + duration))
    while [[ $(date +%s) -lt $end_time ]]; do
      local remaining=$((end_time - $(date +%s)))
      LOG "Scanning... ${remaining}s remaining"
      sleep 10
    done
    
    wait "$SCAN_PID" 2>/dev/null || true
    
    LED Y SOLID
    LOG ""
    LOG "Processing data..."
    
    parse_scan "${csv_prefix}-01.csv"
    
  else
    ERROR_DIALOG "airodump-ng not available"
    exit 1
  fi
  
  LED G SOLID
  LOG ""
  LOG green "=== Channel Analysis Complete ==="
  LOG "Total APs: $TOTAL_APS"
  LOG "Total Clients: $TOTAL_CLIENTS"
  LOG ""
  
  render_heatmap_24
  render_heatmap_5
  find_best_channels
  
  {
    echo "=== Channel Heatmap Report ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo "Total APs: $TOTAL_APS"
    echo "Total Clients: $TOTAL_CLIENTS"
    echo ""
    echo "=== Channel Data ==="
    echo "Channel,AP_Count,SSIDs"
    for ch in $(echo "${!CHANNEL_AP_COUNT[@]}" | tr ' ' '\n' | sort -n); do
      echo "$ch,${CHANNEL_AP_COUNT[$ch]},\"${CHANNEL_SSIDS[$ch]:-}\""
    done
  } > "$ARTIFACTS_DIR/report_$(date +%Y%m%d_%H%M%S).csv"
  
  LOG ""
  LOG "Report saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
