#!/bin/bash
# Title: Serial Console Probe
# Description: Detect active RS-232 serial consoles via ESP32 ICS Probe. Tries common
#              baud rates (9600, 19200, 38400, 57600, 115200), sends CR/LF at each,
#              and looks for printable ASCII responses. Reports detected baud rate and
#              banner text.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue:  Idle / attempting baud rates
# - Amber: Receiving response
# - Green: Console detected
# - Red:   No console found

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"
source "$SCRIPT_DIR/../../lib/esp32.sh"

# Ordered from most common first
BAUD_RATES=(9600 19200 38400 57600 115200)

# Minimum ratio of printable characters in a response to call it valid ASCII
PRINTABLE_THRESHOLD=60

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Check if a string is mostly printable ASCII (percentage >= threshold)
_is_printable_ascii() {
  local text="$1"
  local len="${#text}"
  [[ "$len" -eq 0 ]] && return 1

  local printable=0
  local i=0
  while [[ "$i" -lt "$len" ]]; do
    local char="${text:$i:1}"
    local ord
    ord=$(printf '%d' "'$char" 2>/dev/null) || { i=$(( i + 1 )); continue; }
    if [[ "$ord" -ge 32 && "$ord" -le 126 ]] || [[ "$ord" -eq 9 ]] || \
       [[ "$ord" -eq 10 ]] || [[ "$ord" -eq 13 ]]; then
      printable=$(( printable + 1 ))
    fi
    i=$(( i + 1 ))
  done

  local pct=$(( (printable * 100) / len ))
  [[ "$pct" -ge "$PRINTABLE_THRESHOLD" ]]
}

# Send CR+LF via ESP32 serial probe and read response
_probe_baud() {
  local baud="$1"

  # Ask ESP32 to set baud, send CR/LF, return any received bytes within timeout
  local resp
  resp=$(esp32_send "serial.probe" \
    "$(printf '{"baud":%d,"send_crlf":true,"timeout_ms":2000}' "$baud")" \
    "" "10") || return 1

  if ! echo "$resp" | grep -q '"status":"ok"'; then
    return 1
  fi

  # Extract the "data" field (hex-encoded received bytes)
  local hex_data
  hex_data=$(echo "$resp" | grep -oE '"data":"[0-9a-fA-F]*"' | cut -d'"' -f4)

  if [[ -z "$hex_data" || ${#hex_data} -lt 4 ]]; then
    return 1
  fi

  # Decode hex to text
  local decoded
  decoded=$(echo "$hex_data" | xxd -r -p 2>/dev/null) || return 1

  echo "$decoded"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== Serial Console Probe ==="
  LOG ""

  ics_init_engagement
  esp32_require

  LOG blue "Probing RS-232 at baud rates: ${BAUD_RATES[*]}"
  LOG blue "Sending CR/LF at each rate and listening for ASCII response."
  LOG ""

  local detected_baud=""
  local detected_banner=""

  for baud in "${BAUD_RATES[@]}"; do
    LOG "  Testing $baud bps ..."
    local spinner_id
    spinner_id=$(START_SPINNER "Probing at $baud bps ...")

    local response
    response=$(_probe_baud "$baud") || {
      STOP_SPINNER "$spinner_id"
      LOG "    No response at $baud"
      continue
    }

    STOP_SPINNER "$spinner_id"

    if _is_printable_ascii "$response"; then
      # Sanitize for display — collapse whitespace
      local banner_clean
      banner_clean=$(echo "$response" | tr -dc '[:print:]\n' | head -c 256)

      LOG green "  RESPONSE at $baud bps:"
      LOG green "    ${banner_clean}"

      detected_baud="$baud"
      detected_banner="$banner_clean"
      break
    else
      LOG "    Response at $baud not printable ASCII (binary/noise)"
    fi
  done

  LOG ""

  if [[ -z "$detected_baud" ]]; then
    LOG "No serial console detected at any tested baud rate."
    LOG "Possible reasons: device is off, RS-232 not connected, non-standard baud rate."
    ALERT "Serial probe: no console detected across ${#BAUD_RATES[@]} baud rates."
    exit 0
  fi

  LOG green "Serial console detected at $detected_baud bps"
  LOG green "Banner text: ${detected_banner:0:120}"

  # Save artifact
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local artifact_content
  # Escape banner for JSON
  local banner_json
  banner_json=$(echo "$detected_banner" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n')
  artifact_content=$(printf \
    '{"baud":%d,"banner":"%s","tested_rates":[%s],"timestamp":"%s"}' \
    "$detected_baud" "$banner_json" \
    "$(IFS=,; echo "${BAUD_RATES[*]}")" "$ts")
  local artifact_path
  artifact_path=$(ics_save_artifact "serial-probe-${ts}" "$artifact_content")

  # Report to inventory
  local json
  json=$(printf \
    '{"id":"serial_console_%s","protocol":"rs232","interface":"serial","baud":%d,"banner":"%s","status":"console_detected"}' \
    "$ICS_ENGAGEMENT" "$detected_baud" "$banner_json")
  ics_report_device "$json"

  LOG ""
  LOG blue "Artifact: $artifact_path"
  ALERT "Serial console found at $detected_baud bps. Banner: ${detected_banner:0:60}"

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
