#!/bin/bash
# Title: ICS Posture Scorecard
# Description: Rate ICS network security posture across segmentation, auth, encryption, and exposure
# Author: ICS Toolkit
# Version: 1.0
# Category: assessment
# Net Mode: OFF
#
# Reads inventory.json and scores the overall ICS security posture.
# Categories: Segmentation, Authentication, Encryption, Exposure

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"

score_segmentation() {
  local inventory="$1"
  local score=10
  local findings=""

  # Count unique protocols exposed over ethernet
  local eth_protocols
  eth_protocols=$(grep '"bus":"ethernet"' "$inventory" | \
    sed -n 's/.*"protocol":"\([^"]*\)".*/\1/p' | sort -u | wc -l)

  if [[ $eth_protocols -ge 5 ]]; then
    score=2
    findings="$findings\n  - CRITICAL: $eth_protocols ICS protocols reachable on same network segment"
  elif [[ $eth_protocols -ge 3 ]]; then
    score=5
    findings="$findings\n  - HIGH: $eth_protocols ICS protocols on network — suggests flat network"
  elif [[ $eth_protocols -ge 1 ]]; then
    score=7
    findings="$findings\n  - MEDIUM: $eth_protocols ICS protocol(s) reachable"
  fi

  # Check for mixed IT/OT protocols
  if grep -q '"port":22\|"port":80\|"port":443' "$inventory" 2>/dev/null; then
    score=$((score - 2))
    findings="$findings\n  - IT services (SSH/HTTP) on same segment as ICS devices"
  fi

  [[ $score -lt 0 ]] && score=0
  echo "$score"
  echo -e "$findings"
}

score_authentication() {
  local inventory="$1"
  local score=10
  local findings=""

  # Modbus TCP has no authentication by design
  local modbus_count
  modbus_count=$(grep -c '"protocol":"modbus_tcp"' "$inventory" 2>/dev/null || echo "0")
  if [[ $modbus_count -gt 0 ]]; then
    score=$((score - 3))
    findings="$findings\n  - $modbus_count Modbus TCP devices (no authentication by protocol design)"
  fi

  # OPC UA with no security policy
  if grep -q '"security_policy":"None"\|"anonymous_auth":"true"' "$inventory" 2>/dev/null; then
    score=$((score - 3))
    findings="$findings\n  - CRITICAL: OPC UA server(s) with SecurityPolicy#None or anonymous auth"
  fi

  # S7comm without password protection
  if grep -q '"protection_level":"1"\|"protection":"none"' "$inventory" 2>/dev/null; then
    score=$((score - 2))
    findings="$findings\n  - S7comm CPU(s) without password protection"
  fi

  # EtherNet/IP has no auth
  local enip_count
  enip_count=$(grep -c '"protocol":"ethernet_ip"' "$inventory" 2>/dev/null || echo "0")
  if [[ $enip_count -gt 0 ]]; then
    score=$((score - 2))
    findings="$findings\n  - $enip_count EtherNet/IP devices (no authentication by protocol design)"
  fi

  [[ $score -lt 0 ]] && score=0
  echo "$score"
  echo -e "$findings"
}

score_encryption() {
  local inventory="$1"
  local score=10
  local findings=""

  local total
  total=$(grep -c '"protocol"' "$inventory" 2>/dev/null || echo "0")

  # Most ICS protocols are unencrypted by design
  local unencrypted=0
  for proto in modbus_tcp modbus_rtu ethernet_ip bacnet dnp3 fins s7comm; do
    local c
    c=$(grep -c "\"protocol\":\"$proto\"" "$inventory" 2>/dev/null || echo "0")
    unencrypted=$((unencrypted + c))
  done

  if [[ $total -gt 0 ]]; then
    local pct=$((unencrypted * 100 / total))
    if [[ $pct -ge 80 ]]; then
      score=2
      findings="$findings\n  - CRITICAL: ${pct}% of devices use unencrypted protocols"
    elif [[ $pct -ge 50 ]]; then
      score=5
      findings="$findings\n  - HIGH: ${pct}% of devices use unencrypted protocols"
    elif [[ $pct -ge 20 ]]; then
      score=7
      findings="$findings\n  - MEDIUM: ${pct}% of devices use unencrypted protocols"
    fi
  fi

  # Check for OPC UA with encryption
  if grep -q '"security_policy":"Basic256Sha256"' "$inventory" 2>/dev/null; then
    findings="$findings\n  + OPC UA server(s) with strong encryption detected"
  fi

  [[ $score -lt 0 ]] && score=0
  echo "$score"
  echo -e "$findings"
}

score_exposure() {
  local inventory="$1"
  local score=10
  local findings=""

  local total
  total=$(grep -c '"protocol"' "$inventory" 2>/dev/null || echo "0")

  # Directly reachable from assessment network = exposed
  local ethernet_count
  ethernet_count=$(grep -c '"bus":"ethernet"' "$inventory" 2>/dev/null || echo "0")

  if [[ $total -gt 0 && $ethernet_count -gt 0 ]]; then
    local pct=$((ethernet_count * 100 / total))
    if [[ $pct -ge 80 ]]; then
      score=3
      findings="$findings\n  - HIGH: ${pct}% of ICS devices directly reachable over Ethernet"
    elif [[ $pct -ge 50 ]]; then
      score=5
      findings="$findings\n  - MEDIUM: ${pct}% of ICS devices on reachable Ethernet"
    fi
  fi

  # Count unique vendors — more diversity = harder to manage security
  local vendor_count
  vendor_count=$(sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p' "$inventory" | sort -u | wc -l)
  if [[ $vendor_count -ge 5 ]]; then
    score=$((score - 1))
    findings="$findings\n  - $vendor_count different vendors — complex patch management"
  fi

  [[ $score -lt 0 ]] && score=0
  echo "$score"
  echo -e "$findings"
}

main() {
  LOG blue "=== ICS Posture Scorecard ==="
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

  LOG "Scoring posture for $device_count devices..."
  LOG ""

  local sid
  sid=$(START_SPINNER "Analyzing security posture...")

  # Score each category
  local seg_output auth_output enc_output exp_output
  seg_output=$(score_segmentation "$ICS_INVENTORY")
  auth_output=$(score_authentication "$ICS_INVENTORY")
  enc_output=$(score_encryption "$ICS_INVENTORY")
  exp_output=$(score_exposure "$ICS_INVENTORY")

  # Extract scores (first line of each output)
  local seg_score auth_score enc_score exp_score
  seg_score=$(echo "$seg_output" | head -1)
  auth_score=$(echo "$auth_output" | head -1)
  enc_score=$(echo "$enc_output" | head -1)
  exp_score=$(echo "$exp_output" | head -1)

  local overall=$(( (seg_score + auth_score + enc_score + exp_score) / 4 ))

  STOP_SPINNER "$sid"

  # Display scorecard
  LOG "=== SCORECARD ==="
  LOG ""

  local grade
  if [[ $overall -ge 8 ]]; then grade="A"; elif [[ $overall -ge 6 ]]; then grade="B"
  elif [[ $overall -ge 4 ]]; then grade="C"; elif [[ $overall -ge 2 ]]; then grade="D"
  else grade="F"; fi

  LOG "Overall Grade: $grade ($overall/10)"
  LOG ""
  LOG "Segmentation:    $seg_score/10"
  echo "$seg_output" | tail -n +2 | while IFS= read -r line; do
    [[ -n "$line" ]] && LOG "$line"
  done
  LOG ""
  LOG "Authentication:  $auth_score/10"
  echo "$auth_output" | tail -n +2 | while IFS= read -r line; do
    [[ -n "$line" ]] && LOG "$line"
  done
  LOG ""
  LOG "Encryption:      $enc_score/10"
  echo "$enc_output" | tail -n +2 | while IFS= read -r line; do
    [[ -n "$line" ]] && LOG "$line"
  done
  LOG ""
  LOG "Exposure:        $exp_score/10"
  echo "$exp_output" | tail -n +2 | while IFS= read -r line; do
    [[ -n "$line" ]] && LOG "$line"
  done

  # Recommendations
  LOG ""
  LOG blue "=== RECOMMENDATIONS ==="
  if [[ $seg_score -le 5 ]]; then
    LOG "1. Implement network segmentation between IT and OT zones (IEC 62443 zones/conduits)"
  fi
  if [[ $auth_score -le 5 ]]; then
    LOG "2. Enable authentication where supported (OPC UA, S7comm access protection)"
  fi
  if [[ $enc_score -le 5 ]]; then
    LOG "3. Deploy encrypted protocols where available (OPC UA with Basic256Sha256)"
  fi
  if [[ $exp_score -le 5 ]]; then
    LOG "4. Reduce attack surface — limit direct Ethernet access to critical ICS devices"
  fi

  # Save report
  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local report_file="$eng_dir/reports/posture-scorecard-${ts}.txt"

  {
    echo "=== ICS Posture Scorecard ==="
    echo "Generated: $(date)"
    echo "Engagement: $ICS_ENGAGEMENT"
    echo "Devices: $device_count"
    echo ""
    echo "Overall Grade: $grade ($overall/10)"
    echo ""
    echo "Segmentation:   $seg_score/10"
    echo "$seg_output" | tail -n +2
    echo ""
    echo "Authentication: $auth_score/10"
    echo "$auth_output" | tail -n +2
    echo ""
    echo "Encryption:     $enc_score/10"
    echo "$enc_output" | tail -n +2
    echo ""
    echo "Exposure:       $exp_score/10"
    echo "$exp_output" | tail -n +2
  } > "$report_file"

  LOG ""
  LOG green "Report saved: $report_file"

  PROMPT "Press button to exit"
}

main "$@"
