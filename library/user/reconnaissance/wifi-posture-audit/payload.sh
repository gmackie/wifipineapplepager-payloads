#!/bin/bash
# Title: WiFi Posture Audit
# Description: Passive WiFi security assessment - WPA2/WPA3, PMF, WPS, weak encryption
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow: Scanning
# - Yellow flash: Security issue found
# - Green: Audit complete
# - Red: Error/no interface

set -euo pipefail

MONITOR_DURATION="${MONITOR_DURATION:-300}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/wifi-posture-audit}"
SCAN_INTERVAL="${SCAN_INTERVAL:-15}"

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
  LED OFF
}
trap cleanup EXIT

declare -A SEC_LEVELS=(
  ["OPEN"]="CRITICAL"
  ["WEP"]="CRITICAL"
  ["WPA"]="HIGH"
  ["WPA2"]="OK"
  ["WPA3"]="GOOD"
)

TOTAL_APS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

declare -A AP_DATA
declare -A ISSUES

flag_issue() {
  local bssid="$1"
  local severity="$2"
  local issue="$3"
  
  ISSUES["${bssid}:${issue}"]="$severity"
  
  case "$severity" in
    CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)); LED R FAST ;;
    HIGH)     HIGH_COUNT=$((HIGH_COUNT + 1)); LED Y DOUBLE ;;
    MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1)); LED Y FAST ;;
    LOW)      LOW_COUNT=$((LOW_COUNT + 1)) ;;
  esac
  
  VIBRATE 100
  echo "[$(date '+%H:%M:%S')] [$severity] $bssid: $issue" >> "$ARTIFACTS_DIR/issues.log"
  
  sleep 0.5
  LED B SLOW
}

analyze_encryption() {
  local bssid="$1"
  local privacy="$2"
  local cipher="$3"
  local auth="$4"
  local essid="$5"
  
  if [[ "$privacy" == "OPN" || -z "$privacy" ]]; then
    flag_issue "$bssid" "CRITICAL" "Open network: $essid"
    return
  fi
  
  if [[ "$privacy" =~ WEP ]]; then
    flag_issue "$bssid" "CRITICAL" "WEP encryption (deprecated): $essid"
    return
  fi
  
  if [[ "$privacy" == "WPA" && ! "$privacy" =~ WPA2 ]]; then
    flag_issue "$bssid" "HIGH" "WPA1 only (no WPA2): $essid"
  fi
  
  if [[ "$cipher" =~ TKIP && ! "$cipher" =~ CCMP ]]; then
    flag_issue "$bssid" "HIGH" "TKIP only (no CCMP/AES): $essid"
  fi
  
  if [[ "$privacy" =~ WPA3 || "$auth" =~ SAE ]]; then
    if [[ "$privacy" =~ WPA2 ]]; then
      echo "[INFO] $bssid: WPA3 transition mode (WPA2+WPA3): $essid" >> "$ARTIFACTS_DIR/audit.log"
    fi
  elif [[ "$privacy" =~ WPA2 ]]; then
    flag_issue "$bssid" "LOW" "No WPA3 support: $essid"
  fi
  
  if [[ "$auth" =~ PSK && ! "$auth" =~ MGT && ! "$auth" =~ 802\.1X ]]; then
    echo "[INFO] $bssid: PSK authentication (not 802.1X): $essid" >> "$ARTIFACTS_DIR/audit.log"
  fi
}

check_wps() {
  local bssid="$1"
  local essid="$2"
  local line="$3"
  
  if [[ "$line" =~ WPS ]]; then
    if [[ "$line" =~ "WPS 1.0" ]]; then
      flag_issue "$bssid" "HIGH" "WPS 1.0 enabled (vulnerable to Reaver): $essid"
    elif [[ "$line" =~ "WPS 2.0" ]]; then
      flag_issue "$bssid" "MEDIUM" "WPS 2.0 enabled: $essid"
    else
      flag_issue "$bssid" "MEDIUM" "WPS enabled: $essid"
    fi
  fi
}

check_pmf() {
  local bssid="$1"
  local essid="$2"
  local rsn_caps="$3"
  
  if [[ -z "$rsn_caps" || ! "$rsn_caps" =~ MFPC ]]; then
    flag_issue "$bssid" "LOW" "PMF not detected (deauth vulnerable): $essid"
  fi
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
      local cipher="$col7"
      local auth="$col8"
      local power="$col9"
      local essid="$col14"
      
      privacy=$(echo "$privacy" | tr -d ' ')
      cipher=$(echo "$cipher" | tr -d ' ')
      auth=$(echo "$auth" | tr -d ' ')
      essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      
      [[ -n "${AP_DATA[$bssid]:-}" ]] && continue
      
      AP_DATA["$bssid"]="$essid|$privacy|$cipher|$auth"
      TOTAL_APS=$((TOTAL_APS + 1))
      
      analyze_encryption "$bssid" "$privacy" "$cipher" "$auth" "$essid"
      
      LOG "Audited: $essid ($privacy)"
    fi
  done < "$csv_file"
}

render_summary() {
  LOG ""
  LOG blue "============================================"
  LOG blue "        WIFI POSTURE AUDIT SUMMARY          "
  LOG blue "============================================"
  LOG "Total APs Scanned: $TOTAL_APS"
  LOG ""
  
  if [[ $CRITICAL_COUNT -gt 0 ]]; then
    LOG red "CRITICAL Issues: $CRITICAL_COUNT"
  else
    LOG green "CRITICAL Issues: 0"
  fi
  
  if [[ $HIGH_COUNT -gt 0 ]]; then
    LOG red "HIGH Issues: $HIGH_COUNT"
  else
    LOG green "HIGH Issues: 0"
  fi
  
  if [[ $MEDIUM_COUNT -gt 0 ]]; then
    LOG "MEDIUM Issues: $MEDIUM_COUNT"
  else
    LOG green "MEDIUM Issues: 0"
  fi
  
  LOG "LOW Issues: $LOW_COUNT"
  LOG blue "============================================"
}

generate_report() {
  local report_file="$ARTIFACTS_DIR/posture_report_$(date +%Y%m%d_%H%M%S).txt"
  
  {
    echo "========================================"
    echo "     WIFI SECURITY POSTURE AUDIT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Duration: ${MONITOR_DURATION}s"
    echo ""
    echo "SUMMARY"
    echo "--------"
    echo "Total APs: $TOTAL_APS"
    echo "Critical: $CRITICAL_COUNT"
    echo "High: $HIGH_COUNT"
    echo "Medium: $MEDIUM_COUNT"
    echo "Low: $LOW_COUNT"
    echo ""
    echo "SECURITY GUIDELINES"
    echo "--------------------"
    echo "- CRITICAL: Open or WEP networks - immediate action required"
    echo "- HIGH: WPA1/TKIP only, WPS 1.0 - should remediate"
    echo "- MEDIUM: WPS 2.0 enabled - consider disabling"
    echo "- LOW: No WPA3/PMF - upgrade when possible"
    echo ""
    echo "AP INVENTORY"
    echo "-------------"
    for bssid in "${!AP_DATA[@]}"; do
      echo "$bssid: ${AP_DATA[$bssid]}"
    done | sort
    echo ""
    echo "ISSUES DETECTED"
    echo "----------------"
    for key in "${!ISSUES[@]}"; do
      echo "[${ISSUES[$key]}] $key"
    done | sort -t'[' -k2
    echo ""
    echo "========================================"
    echo "        END OF AUDIT REPORT"
    echo "========================================"
  } > "$report_file"
  
  echo "$report_file"
}

main() {
  LOG blue "=== WiFi Posture Audit ==="
  LOG "Passive security assessment"
  LOG ""
  
  local duration
  duration=$(NUMBER_PICKER "Audit duration (seconds)" "$MONITOR_DURATION") || true
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
    LED R SOLID
    exit 1
  fi
  
  LOG "Interface: $mon"
  LOG "Duration: ${duration}s"
  LOG ""
  LOG "Checking: Encryption, WPS, PMF, cipher strength"
  LOG ""
  
  LED B SLOW
  
  local end_time=$(($(date +%s) + duration))
  local csv_prefix="$ARTIFACTS_DIR/scan"
  local scan_num=0
  
  while [[ $(date +%s) -lt $end_time ]]; do
    scan_num=$((scan_num + 1))
    
    if have airodump-ng; then
      local csv_file="${csv_prefix}-${scan_num}"
      
      timeout "$SCAN_INTERVAL" airodump-ng \
        --band abg \
        --write-interval 2 \
        --output-format csv \
        --write "$csv_file" \
        "$mon" 2>/dev/null &
      AIRODUMP_PID=$!
      wait "$AIRODUMP_PID" 2>/dev/null || true
      
      parse_airodump "${csv_file}-01.csv"
      
      rm -f "${csv_file}"* 2>/dev/null || true
    else
      LOG red "airodump-ng not available"
      sleep "$SCAN_INTERVAL"
    fi
    
    local remaining=$((end_time - $(date +%s)))
    LOG "Scanned $TOTAL_APS APs | Issues: C:$CRITICAL_COUNT H:$HIGH_COUNT M:$MEDIUM_COUNT | ${remaining}s left"
  done
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  render_summary
  
  local report
  report=$(generate_report)
  
  LOG ""
  LOG green "Audit complete!"
  LOG "Report: $report"
  
  if [[ $CRITICAL_COUNT -gt 0 ]]; then
    ALERT "CRITICAL: Found $CRITICAL_COUNT critical security issues!"
  elif [[ $HIGH_COUNT -gt 0 ]]; then
    ALERT "Found $HIGH_COUNT high severity issues"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
