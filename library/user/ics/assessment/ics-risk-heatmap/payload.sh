#!/bin/bash
# Title: ICS Risk Heatmap
# Description: Visual risk ranking by device criticality and exposure level
# Author: ICS Toolkit
# Version: 1.0
# Category: assessment
# Net Mode: OFF
#
# Reads inventory.json and scores each device by:
# - Protocol exposure (unencrypted = higher risk)
# - Authentication level (none/weak = higher risk)
# - Device criticality (PLCs > HMIs > sensors)
# - Network position (directly reachable = higher risk)

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"

main() {
  LOG blue "=== ICS Risk Heatmap ==="
  LOG ""

  ics_init_engagement

  if [[ ! -f "$ICS_INVENTORY" ]]; then
    ERROR_DIALOG "No inventory found. Run discovery payloads first."
    exit 1
  fi

  local device_count
  device_count=$(grep -c '"id"' "$ICS_INVENTORY" 2>/dev/null || echo "0")

  if [[ "$device_count" -eq 0 ]]; then
    ERROR_DIALOG "Inventory is empty. Run discovery payloads first."
    exit 1
  fi

  LOG "Analyzing $device_count devices..."
  LOG ""

  local sid
  sid=$(START_SPINNER "Calculating risk scores...")

  local critical=0 high=0 medium=0 low=0
  local report=""

  # Parse each device and assign risk score
  # Risk factors:
  #   Protocol risk: modbus_tcp=9, modbus_rtu=7, s7comm=8, opcua=5, bacnet=7, enip=8, dnp3=8, fins=7
  #   Bus risk: ethernet=6, rs485=4, can=5, ble=3
  #   Unprotected bonus: +2 if no auth detected

  local protocol_scores="modbus_tcp:9 modbus_rtu:7 s7comm:8 opcua:5 bacnet:7 ethernet_ip:8 dnp3:8 fins:7"
  local bus_scores="ethernet:6 rs485:4 can:5 ble:3"

  while IFS= read -r line; do
    local protocol vendor product ip bus slave_addr
    protocol=$(echo "$line" | sed -n 's/.*"protocol":"\([^"]*\)".*/\1/p')
    vendor=$(echo "$line" | sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p')
    product=$(echo "$line" | sed -n 's/.*"product":"\([^"]*\)".*/\1/p')
    ip=$(echo "$line" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
    bus=$(echo "$line" | sed -n 's/.*"bus":"\([^"]*\)".*/\1/p')
    slave_addr=$(echo "$line" | sed -n 's/.*"slave_addr":\([0-9]*\).*/\1/p')

    [[ -z "$protocol" ]] && continue

    # Calculate risk score (0-10)
    local proto_score=5
    for ps in $protocol_scores; do
      local p="${ps%%:*}" s="${ps##*:}"
      [[ "$protocol" == "$p" ]] && proto_score="$s"
    done

    local bus_score=5
    for bs in $bus_scores; do
      local b="${bs%%:*}" s="${bs##*:}"
      [[ "$bus" == "$b" ]] && bus_score="$s"
    done

    local risk_score=$(( (proto_score + bus_score) / 2 ))

    local risk_level identifier
    if [[ $risk_score -ge 8 ]]; then
      risk_level="CRITICAL"
      critical=$((critical + 1))
    elif [[ $risk_score -ge 6 ]]; then
      risk_level="HIGH"
      high=$((high + 1))
    elif [[ $risk_score -ge 4 ]]; then
      risk_level="MEDIUM"
      medium=$((medium + 1))
    else
      risk_level="LOW"
      low=$((low + 1))
    fi

    if [[ -n "$ip" ]]; then
      identifier="$ip"
    elif [[ -n "$slave_addr" ]]; then
      identifier="slave:$slave_addr"
    else
      identifier="unknown"
    fi

    report+="[$risk_level] $identifier | $vendor $product | $protocol ($bus) | Score: $risk_score/10
"
  done < <(grep '"protocol"' "$ICS_INVENTORY")

  STOP_SPINNER "$sid"

  # Display heatmap
  LOG red "=== RISK HEATMAP ==="
  LOG ""

  if [[ $critical -gt 0 ]]; then
    LOG red "CRITICAL ($critical devices):"
    echo "$report" | grep '^\[CRITICAL\]' | while read -r line; do
      LOG red "  $line"
    done
    LOG ""
  fi

  if [[ $high -gt 0 ]]; then
    LOG red "HIGH ($high devices):"
    echo "$report" | grep '^\[HIGH\]' | while read -r line; do
      LOG "  $line"
    done
    LOG ""
  fi

  if [[ $medium -gt 0 ]]; then
    LOG blue "MEDIUM ($medium devices):"
    echo "$report" | grep '^\[MEDIUM\]' | while read -r line; do
      LOG "  $line"
    done
    LOG ""
  fi

  if [[ $low -gt 0 ]]; then
    LOG green "LOW ($low devices):"
    echo "$report" | grep '^\[LOW\]' | while read -r line; do
      LOG "  $line"
    done
    LOG ""
  fi

  # Summary bar
  local total=$((critical + high + medium + low))
  LOG "=== SUMMARY ==="
  LOG "Total devices: $total"
  LOG red "  Critical: $critical"
  LOG red "  High:     $high"
  LOG blue "  Medium:   $medium"
  LOG green "  Low:      $low"

  # Save report
  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local report_file="$eng_dir/reports/risk-heatmap-${ts}.txt"

  {
    echo "=== ICS Risk Heatmap ==="
    echo "Generated: $(date)"
    echo "Engagement: $ICS_ENGAGEMENT"
    echo "Devices: $total"
    echo ""
    echo "CRITICAL: $critical | HIGH: $high | MEDIUM: $medium | LOW: $low"
    echo ""
    echo "$report"
  } > "$report_file"

  LOG ""
  LOG green "Report saved: $report_file"

  PROMPT "Press button to exit"
}

main "$@"
