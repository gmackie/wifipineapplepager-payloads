#!/bin/bash
# Title: Recon Dashboard
# Description: Unified passive recon combining multiple monitors with live status
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue pulse: Dashboard active
# - Cyan: Detection event
# - Green: Session complete

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/recon-dashboard}"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-10}"

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
  [[ -n "${AIRODUMP_PID:-}" ]] && kill "$AIRODUMP_PID" 2>/dev/null || true
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  LED OFF
}
trap cleanup EXIT

declare -A SSID_MAP
declare -A HIDDEN_APS
declare -A PROBE_SSIDS
declare -A HOTSPOTS
declare -A P2P_DEVICES
declare -A EVIL_TWINS
declare -A CHANNEL_COUNTS

STATS_TOTAL_APS=0
STATS_TOTAL_CLIENTS=0
STATS_HIDDEN=0
STATS_PROBES=0
STATS_HOTSPOTS=0
STATS_P2P=0
STATS_TWINS=0
STATS_ALERTS=0

HOTSPOT_PATTERNS="AndroidAP|android|iPhone|iPad|Galaxy|Pixel|Hotspot|Mobile|Personal"
P2P_PATTERNS="DIRECT-|p2p-|Chromecast|Fire TV|Roku|Miracast"
CORP_PATTERNS="corp|internal|secure|employee|private|office|HQ|vpn"

is_hotspot() { [[ "$1" =~ $HOTSPOT_PATTERNS ]]; }
is_p2p() { [[ "$1" =~ $P2P_PATTERNS ]]; }
is_interesting() { [[ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" =~ $CORP_PATTERNS ]]; }

trigger_alert() {
  local type="$1"
  local msg="$2"
  
  STATS_ALERTS=$((STATS_ALERTS + 1))
  
  LED C FAST
  VIBRATE 200
  
  echo "[$(date '+%H:%M:%S')] $type: $msg" >> "$ARTIFACTS_DIR/alerts.log"
  
  sleep 1
  LED B SLOW
}

parse_airodump() {
  local csv_file="$1"
  
  [[ ! -f "$csv_file" ]] && return 0
  
  local in_client=0
  
  while IFS=',' read -r col1 col2 col3 col4 col5 col6 col7 col8 col9 col10 col11 col12 col13 col14 rest; do
    if [[ "$col1" =~ ^Station ]]; then
      in_client=1
      continue
    fi
    [[ "$col1" =~ ^BSSID || -z "$col1" ]] && continue
    
    col1=$(echo "$col1" | tr -d ' ')
    
    if [[ $in_client -eq 0 ]]; then
      local bssid="$col1"
      local channel="$col4"
      local privacy="$col6"
      local essid="$col14"
      
      channel=$(echo "$channel" | tr -d ' ')
      privacy=$(echo "$privacy" | tr -d ' ')
      essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      
      STATS_TOTAL_APS=$((STATS_TOTAL_APS + 1))
      CHANNEL_COUNTS["$channel"]=$((${CHANNEL_COUNTS[$channel]:-0} + 1))
      
      if [[ -z "$essid" || "$essid" == "<length:"* ]]; then
        if [[ -z "${HIDDEN_APS[$bssid]:-}" ]]; then
          HIDDEN_APS["$bssid"]="$channel:$privacy"
          STATS_HIDDEN=$((STATS_HIDDEN + 1))
          trigger_alert "HIDDEN" "New hidden AP: $bssid (ch$channel)"
        fi
      else
        if [[ -n "${SSID_MAP[$essid]:-}" ]]; then
          local stored_bssid="${SSID_MAP[$essid]%%:*}"
          if [[ "$bssid" != "$stored_bssid" && -z "${EVIL_TWINS[$essid]:-}" ]]; then
            EVIL_TWINS["$essid"]="$stored_bssid->$bssid"
            STATS_TWINS=$((STATS_TWINS + 1))
            trigger_alert "EVIL_TWIN" "$essid has multiple BSSIDs!"
          fi
        else
          SSID_MAP["$essid"]="$bssid:$channel:$privacy"
        fi
        
        if is_p2p "$essid" && [[ -z "${P2P_DEVICES[$bssid]:-}" ]]; then
          P2P_DEVICES["$bssid"]="$essid"
          STATS_P2P=$((STATS_P2P + 1))
          trigger_alert "P2P" "$essid"
        elif is_hotspot "$essid" && [[ -z "${HOTSPOTS[$bssid]:-}" ]]; then
          HOTSPOTS["$bssid"]="$essid"
          STATS_HOTSPOTS=$((STATS_HOTSPOTS + 1))
          trigger_alert "HOTSPOT" "$essid"
        fi
      fi
    else
      STATS_TOTAL_CLIENTS=$((STATS_TOTAL_CLIENTS + 1))
    fi
  done < "$csv_file"
}

parse_probes() {
  local probe_log="$ARTIFACTS_DIR/probes.log"
  
  [[ ! -f "$probe_log" ]] && return 0
  
  while read -r line; do
    if [[ "$line" =~ Probe\ Request\ \(([^\)]+)\) ]]; then
      local ssid="${BASH_REMATCH[1]}"
      [[ -z "$ssid" || "$ssid" == "Broadcast" ]] && continue
      
      if [[ -z "${PROBE_SSIDS[$ssid]:-}" ]]; then
        PROBE_SSIDS["$ssid"]=1
        STATS_PROBES=$((STATS_PROBES + 1))
        
        if is_interesting "$ssid"; then
          trigger_alert "CORP_PROBE" "$ssid"
        fi
      else
        PROBE_SSIDS["$ssid"]=$((${PROBE_SSIDS[$ssid]} + 1))
      fi
    fi
  done < "$probe_log"
  
  : > "$probe_log"
}

render_dashboard() {
  LOG ""
  LOG blue "╔══════════════════════════════════════════╗"
  LOG blue "║        RECON DASHBOARD - LIVE            ║"
  LOG blue "╠══════════════════════════════════════════╣"
  LOG "║ APs: ${STATS_TOTAL_APS}  Clients: ${STATS_TOTAL_CLIENTS}  Alerts: ${STATS_ALERTS}"
  LOG blue "╠══════════════════════════════════════════╣"
  LOG "║ Hidden APs:     ${STATS_HIDDEN}"
  LOG "║ Evil Twins:     ${STATS_TWINS}"
  LOG "║ Mobile Hotspots:${STATS_HOTSPOTS}"
  LOG "║ P2P/Direct:     ${STATS_P2P}"
  LOG "║ Probe SSIDs:    ${STATS_PROBES}"
  LOG blue "╠══════════════════════════════════════════╣"
  
  local busiest_ch=""
  local busiest_count=0
  for ch in "${!CHANNEL_COUNTS[@]}"; do
    if [[ ${CHANNEL_COUNTS[$ch]} -gt $busiest_count ]]; then
      busiest_count=${CHANNEL_COUNTS[$ch]}
      busiest_ch=$ch
    fi
  done
  LOG "║ Busiest Channel: $busiest_ch ($busiest_count APs)"
  
  LOG blue "╚══════════════════════════════════════════╝"
}

main() {
  LOG blue "=== Recon Dashboard ==="
  LOG "Unified passive reconnaissance"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Monitor duration (seconds)" "$MONITOR_DURATION") || true
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
  LOG "Monitoring: APs, clients, probes, twins, hotspots, P2P"
  LOG ""
  
  LED B SLOW
  
  local end_time=$(($(date +%s) + duration))
  local csv_prefix="$ARTIFACTS_DIR/scan"
  local scan_num=0
  
  if have tcpdump; then
    tcpdump -I -i "$mon" -l -e type mgt subtype probe-req 2>/dev/null >> "$ARTIFACTS_DIR/probes.log" &
    TCPDUMP_PID=$!
  fi
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    
    if have airodump-ng; then
      local csv_file="${csv_prefix}-${scan_num}"
      
      timeout "$REFRESH_INTERVAL" airodump-ng \
        --band abg \
        --write-interval 2 \
        --output-format csv \
        --write "$csv_file" \
        "$mon" 2>/dev/null &
      AIRODUMP_PID=$!
      wait "$AIRODUMP_PID" 2>/dev/null || true
      
      parse_airodump "${csv_file}-01.csv"
      parse_probes
      
      rm -f "${csv_file}"* 2>/dev/null || true
    else
      sleep "$REFRESH_INTERVAL"
    fi
    
    render_dashboard
    
    local remaining=$((end_time - $(date +%s)))
    LOG ""
    LOG "Time remaining: ${remaining}s"
  done
  
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  LOG ""
  LOG green "╔══════════════════════════════════════════╗"
  LOG green "║           SESSION COMPLETE               ║"
  LOG green "╚══════════════════════════════════════════╝"
  render_dashboard
  
  if [[ $STATS_TWINS -gt 0 ]]; then
    LOG ""
    LOG red "!!! EVIL TWINS DETECTED !!!"
    for ssid in "${!EVIL_TWINS[@]}"; do
      LOG "  $ssid: ${EVIL_TWINS[$ssid]}"
    done
  fi
  
  if [[ $STATS_HIDDEN -gt 0 ]]; then
    LOG ""
    LOG "Hidden APs:"
    for bssid in "${!HIDDEN_APS[@]}"; do
      LOG "  $bssid (${HIDDEN_APS[$bssid]})"
    done | head -10
  fi
  
  {
    echo "=== Recon Dashboard Report ==="
    echo "Time: $(date)"
    echo "Duration: ${duration}s"
    echo ""
    echo "Stats:"
    echo "  Total APs: $STATS_TOTAL_APS"
    echo "  Total Clients: $STATS_TOTAL_CLIENTS"
    echo "  Hidden APs: $STATS_HIDDEN"
    echo "  Evil Twins: $STATS_TWINS"
    echo "  Mobile Hotspots: $STATS_HOTSPOTS"
    echo "  P2P Devices: $STATS_P2P"
    echo "  Unique Probes: $STATS_PROBES"
    echo "  Total Alerts: $STATS_ALERTS"
    echo ""
    echo "=== Detected SSIDs ==="
    for ssid in "${!SSID_MAP[@]}"; do
      echo "$ssid: ${SSID_MAP[$ssid]}"
    done | sort
    echo ""
    echo "=== Channel Distribution ==="
    for ch in $(echo "${!CHANNEL_COUNTS[@]}" | tr ' ' '\n' | sort -n); do
      echo "Ch$ch: ${CHANNEL_COUNTS[$ch]} APs"
    done
    echo ""
    echo "=== Alerts ==="
    cat "$ARTIFACTS_DIR/alerts.log" 2>/dev/null || echo "None"
  } > "$ARTIFACTS_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
  
  LOG ""
  LOG "Report saved to $ARTIFACTS_DIR"
  
  PROMPT "Press button to exit"
}

main "$@"
