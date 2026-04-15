#!/bin/bash
# Title: ICS Asset Report
# Description: Compile the engagement inventory.json into a structured plain-text report.
#              Groups devices by protocol and vendor, summarises total device count,
#              protocol breakdown, and risk distribution. Saves the report to the
#              engagement reports/ directory.
# Author: ICS Toolkit
# Version: 1.0
# Category: assessment
# Net Mode: OFF
#
# LED States
# - Blue:  Generating report
# - Green: Report complete
# - Red:   No inventory found or error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Extract a JSON array field from inventory using only POSIX tools
_extract_field() {
  local json="$1" field="$2"
  echo "$json" | grep -oE "\"${field}\":\"[^\"]*\"" | cut -d'"' -f4
}

_extract_num_field() {
  local json="$1" field="$2"
  echo "$json" | grep -oE "\"${field}\":[0-9]+" | cut -d: -f2
}

# Print a horizontal rule
_rule() {
  printf '%0.s-' {1..72}
  echo
}

# Count occurrences of a value in a multiline list
_count_value() {
  local list="$1" value="$2"
  echo "$list" | grep -cxF "$value" 2>/dev/null || echo "0"
}

# Unique sorted values from a newline-separated list
_unique() {
  echo "$1" | sort -u | grep -v '^$' || true
}

# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

_generate_report() {
  local inventory_file="$1" report_file="$2" engagement="$3"

  local inventory
  inventory=$(cat "$inventory_file")

  # Parse all device records — each "id" field marks a device entry
  local device_count
  device_count=$(echo "$inventory" | grep -o '"id"' | wc -l | tr -d ' ')

  # Extract per-device fields
  local protocols vendors risks
  protocols=$(_extract_field "$inventory" "protocol")
  vendors=$(_extract_field "$inventory" "vendor")
  risks=$(_extract_field "$inventory" "risk")

  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  {
    echo "================================================================"
    echo "  ICS ASSET REPORT"
    echo "================================================================"
    echo "  Engagement : $engagement"
    echo "  Generated  : $ts"
    echo "  Inventory  : $inventory_file"
    _rule

    echo ""
    echo "SUMMARY"
    echo "-------"
    echo "  Total devices identified : $device_count"

    local unique_protocols
    unique_protocols=$(_unique "$protocols")
    local proto_count
    proto_count=$(echo "$unique_protocols" | grep -c . 2>/dev/null || echo "0")
    echo "  Unique protocols         : $proto_count"

    local unique_vendors
    unique_vendors=$(_unique "$vendors")
    local vendor_count
    vendor_count=$(echo "$unique_vendors" | grep -c . 2>/dev/null || echo "0")
    echo "  Unique vendors           : $vendor_count"

    echo ""
    echo "PROTOCOL BREAKDOWN"
    echo "------------------"
    while IFS= read -r proto; do
      [[ -z "$proto" ]] && continue
      local cnt
      cnt=$(_count_value "$protocols" "$proto")
      printf "  %-20s %3s device(s)\n" "$proto" "$cnt"
    done <<< "$unique_protocols"

    echo ""
    echo "VENDOR BREAKDOWN"
    echo "----------------"
    if [[ -z "$(echo "$unique_vendors" | tr -d ' \n')" ]]; then
      echo "  No vendor information available."
    else
      while IFS= read -r vendor; do
        [[ -z "$vendor" ]] && continue
        local cnt
        cnt=$(_count_value "$vendors" "$vendor")
        printf "  %-30s %3s device(s)\n" "$vendor" "$cnt"
      done <<< "$unique_vendors"
    fi

    echo ""
    echo "RISK DISTRIBUTION"
    echo "-----------------"
    local risk_critical risk_high risk_medium risk_low
    risk_critical=$(_count_value "$risks" "critical")
    risk_high=$(_count_value "$risks" "high")
    risk_medium=$(_count_value "$risks" "medium")
    risk_low=$(_count_value "$risks" "low")
    local risk_unrated=$(( device_count - risk_critical - risk_high - risk_medium - risk_low ))
    [[ "$risk_unrated" -lt 0 ]] && risk_unrated=0

    printf "  %-12s %3s\n" "Critical:"  "$risk_critical"
    printf "  %-12s %3s\n" "High:"      "$risk_high"
    printf "  %-12s %3s\n" "Medium:"    "$risk_medium"
    printf "  %-12s %3s\n" "Low:"       "$risk_low"
    printf "  %-12s %3s\n" "Unrated:"   "$risk_unrated"

    echo ""
    echo "DEVICE INVENTORY"
    echo "----------------"

    # Re-parse per protocol group using simple sed-based extraction
    while IFS= read -r proto; do
      [[ -z "$proto" ]] && continue
      echo ""
      echo "  Protocol: $proto"
      _rule | sed 's/^/  /'

      # Walk the raw JSON for matching entries
      # Each device is a JSON object inside the "devices" array
      local in_device=false dev_buf=""
      while IFS= read -r line; do
        if echo "$line" | grep -q '"id"'; then
          in_device=true
          dev_buf="$line"
        elif $in_device; then
          dev_buf="$dev_buf $line"
          if echo "$line" | grep -q '}'; then
            local dev_proto
            dev_proto=$(echo "$dev_buf" | grep -oE '"protocol":"[^"]*"' | cut -d'"' -f4)
            if [[ "$dev_proto" == "$proto" ]]; then
              local dev_id dev_ip dev_vendor dev_model dev_fw dev_risk dev_status
              dev_id=$(echo "$dev_buf"     | grep -oE '"id":"[^"]*"'      | head -1 | cut -d'"' -f4)
              dev_ip=$(echo "$dev_buf"     | grep -oE '"ip":"[^"]*"'      | head -1 | cut -d'"' -f4)
              dev_vendor=$(echo "$dev_buf" | grep -oE '"vendor":"[^"]*"'  | head -1 | cut -d'"' -f4)
              dev_model=$(echo "$dev_buf"  | grep -oE '"model":"[^"]*"'   | head -1 | cut -d'"' -f4)
              dev_fw=$(echo "$dev_buf"     | grep -oE '"firmware":"[^"]*"'| head -1 | cut -d'"' -f4)
              dev_risk=$(echo "$dev_buf"   | grep -oE '"risk":"[^"]*"'    | head -1 | cut -d'"' -f4)
              dev_status=$(echo "$dev_buf" | grep -oE '"status":"[^"]*"'  | head -1 | cut -d'"' -f4)
              printf "  ID     : %s\n"     "${dev_id:-?}"
              printf "  IP     : %s\n"     "${dev_ip:--}"
              printf "  Vendor : %s\n"     "${dev_vendor:--}"
              printf "  Model  : %s\n"     "${dev_model:--}"
              printf "  FW     : %s\n"     "${dev_fw:--}"
              printf "  Risk   : %s\n"     "${dev_risk:-unrated}"
              printf "  Status : %s\n"     "${dev_status:--}"
              echo ""
            fi
            in_device=false
            dev_buf=""
          fi
        fi
      done < <(echo "$inventory" | tr ',' '\n' | tr '{' '\n' | tr '}' '\n')

    done <<< "$unique_protocols"

    _rule
    echo "  END OF REPORT"
    _rule

  } > "$report_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== ICS Asset Report ==="
  LOG ""

  ics_init_engagement

  if [[ ! -f "$ICS_INVENTORY" ]]; then
    ERROR_DIALOG "No inventory found at $ICS_INVENTORY. Run discovery payloads first."
    exit 1
  fi

  local device_count
  device_count=$(grep -o '"id"' "$ICS_INVENTORY" | wc -l | tr -d ' ')

  if [[ "$device_count" -eq 0 ]]; then
    ERROR_DIALOG "Inventory exists but contains no devices. Run discovery payloads first."
    exit 1
  fi

  LOG blue "Inventory: $ICS_INVENTORY"
  LOG blue "Devices found: $device_count"
  LOG ""

  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local report_file="$eng_dir/reports/asset-report-${ts}.txt"

  mkdir -p "$eng_dir/reports"

  local spinner_id
  spinner_id=$(START_SPINNER "Compiling asset report ...")

  _generate_report "$ICS_INVENTORY" "$report_file" "$ICS_ENGAGEMENT"

  STOP_SPINNER "$spinner_id"

  if [[ ! -f "$report_file" ]]; then
    ERROR_DIALOG "Report generation failed — output file not created."
    exit 1
  fi

  local line_count
  line_count=$(wc -l < "$report_file" | tr -d ' ')

  LOG green "Report saved: $report_file ($line_count lines)"
  LOG ""
  LOG blue "--- Report Preview (first 30 lines) ---"
  head -30 "$report_file" | while IFS= read -r line; do LOG "$line"; done
  LOG blue "--- (see full report at $report_file) ---"

  ALERT "Asset report generated: $device_count devices. Saved to reports/."

  LOG ""
  LOG blue "Done. Report saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
