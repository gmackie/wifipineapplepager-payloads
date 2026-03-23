#!/bin/bash
# Title: BLE Sensor Scout
# Description: ESP32-based BLE scan for ICS wireless sensors and field devices
# Author: Red Team Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: OFF
#
# LED States
# - Blue slow blink: Configuring / waiting for ESP32
# - Cyan slow blink: BLE scan in progress
# - Cyan flash: BLE advertisement received
# - Magenta flash: ICS-related device detected
# - Green: Scan complete
# - Red: ESP32 error
#
# Requirements: ESP32 probe attached (esp32_require)

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"
source "$(dirname "$0")/../../lib/esp32.sh"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ble-sensor-scout}"
DEFAULT_SCAN_DURATION=60

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  LED OFF
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# ICS BLE heuristics
# ICS sensor manufacturers often advertise recognisable name prefixes or
# well-known Service UUIDs. This function returns non-zero for non-ICS devices.
# ---------------------------------------------------------------------------

ICS_NAME_PATTERNS=(
  "ABB"
  "Emerson"
  "Endress"
  "Hauser"
  "Honeywell"
  "HART"
  "ISA100"
  "Pepperl"
  "Rosemount"
  "Siemens"
  "Vega"
  "WirelessHART"
  "Yokogawa"
  "ifm"
  "KROHNE"
  "ProfiHub"
  "IO-Link"
  "FieldEdge"
  "InFusion"
  "iWireless"
)

# Known ICS BLE service UUID fragments (partial match is acceptable)
ICS_UUID_PATTERNS=(
  "0000FFF0"   # Common sensor profile
  "0000FFE0"   # HART-IP proxy
  "1BA90001"   # WirelessHART characteristic
  "569A0001"   # Emerson Pervasive sensing
  "00001523"   # Smart home (used by some field gateways)
)

is_ics_device() {
  local name="$1"
  local uuids="$2"

  local name_upper
  name_upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')

  for pattern in "${ICS_NAME_PATTERNS[@]}"; do
    local pat_upper
    pat_upper=$(printf '%s' "$pattern" | tr '[:lower:]' '[:upper:]')
    if [[ "$name_upper" == *"$pat_upper"* ]]; then
      return 0
    fi
  done

  for uuid_pat in "${ICS_UUID_PATTERNS[@]}"; do
    local uuid_upper
    uuid_upper=$(printf '%s' "$uuids" | tr '[:lower:]' '[:upper:]')
    if [[ "$uuid_upper" == *"${uuid_pat}"* ]]; then
      return 0
    fi
  done

  return 1
}

# ---------------------------------------------------------------------------
# Result storage
# ---------------------------------------------------------------------------

declare -A BLE_DEVICES        # addr -> "name|rssi|uuids"
TOTAL_DEVICES=0
ICS_DEVICE_COUNT=0
ICS_DEVICES=()

record_device() {
  local addr="$1"
  local name="$2"
  local rssi="$3"
  local uuids="${4:-}"

  # Deduplicate by address
  if [[ -n "${BLE_DEVICES[$addr]:-}" ]]; then
    return
  fi

  BLE_DEVICES["$addr"]="${name}|${rssi}|${uuids}"
  TOTAL_DEVICES=$(( TOTAL_DEVICES + 1 ))

  LED C FAST

  if is_ics_device "$name" "$uuids"; then
    ICS_DEVICE_COUNT=$(( ICS_DEVICE_COUNT + 1 ))
    ICS_DEVICES+=("$addr")
    LED M FAST
    VIBRATE 300
    LOG magenta "ICS DEVICE: $addr  name='$name'  rssi=$rssi"
  else
    LOG cyan "  Device: $addr  name='${name:-<unnamed>}'  rssi=$rssi"
  fi

  sleep 0.1
  LED C SLOW
}

# ---------------------------------------------------------------------------
# Parse BLE scan results from esp32 library output
#
# The ble_scan_ics function (provided by esp32.sh) is expected to emit
# newline-delimited records in one of these formats:
#
#   DEVICE <addr> NAME <name> RSSI <rssi> UUIDS <uuid1,uuid2,...>
#   DEVICE <addr> NAME <name> RSSI <rssi>
#
# Lines that do not match are logged verbatim for debugging.
# ---------------------------------------------------------------------------

parse_ble_output() {
  local raw_file="$1"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^DEVICE[[:space:]]+([0-9A-Fa-f:]+)[[:space:]]+NAME[[:space:]]+(.*)[[:space:]]+RSSI[[:space:]]+(-?[0-9]+) ]]; then
      local addr="${BASH_REMATCH[1]}"
      local name="${BASH_REMATCH[2]}"
      local rssi="${BASH_REMATCH[3]}"
      local uuids=""

      # Optional UUIDS field
      if [[ "$line" =~ UUIDS[[:space:]]+([^[:space:]]+) ]]; then
        uuids="${BASH_REMATCH[1]}"
        # Strip trailing UUIDS token from name if it leaked in
        name="${name%%UUIDS*}"
        name="${name%%RSSI*}"
      fi
      name="${name%"${name##*[![:space:]]}"}"  # rtrim

      record_device "$addr" "$name" "$rssi" "$uuids"
    else
      # Passthrough unrecognised lines as debug
      LOG "  [esp32] $line"
    fi
  done < "$raw_file"
}

# ---------------------------------------------------------------------------
# Artifact generation
# ---------------------------------------------------------------------------

save_artifact() {
  local artifact_file="$ARTIFACTS_DIR/ble_ics_scan_$(date +%Y%m%d_%H%M%S).json"

  {
    echo "{"
    echo "  \"scan_time\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"duration_seconds\": ${SCAN_DURATION_USED:-0},"
    echo "  \"total_devices\": $TOTAL_DEVICES,"
    echo "  \"ics_devices\": $ICS_DEVICE_COUNT,"
    echo "  \"devices\": ["

    local first=1
    for addr in "${!BLE_DEVICES[@]}"; do
      local entry="${BLE_DEVICES[$addr]}"
      local name rssi uuids
      IFS='|' read -r name rssi uuids <<< "$entry"

      local is_ics="false"
      for ics_addr in "${ICS_DEVICES[@]}"; do
        [[ "$ics_addr" == "$addr" ]] && is_ics="true" && break
      done

      [[ $first -eq 0 ]] && echo "    ,"
      first=0

      echo "    {"
      echo "      \"address\": \"$addr\","
      echo "      \"name\": \"$name\","
      echo "      \"rssi\": $rssi,"
      echo "      \"uuids\": \"$uuids\","
      echo "      \"ics_heuristic\": $is_ics"
      echo "    }"
    done

    echo "  ]"
    echo "}"
  } > "$artifact_file"

  echo "$artifact_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== BLE Sensor Scout ==="
  LOG "ESP32 BLE scan for ICS wireless sensors"
  LOG ""

  mkdir -p "$ARTIFACTS_DIR"

  LED B SLOW

  # Verify ESP32 probe is connected and responsive
  LOG "Checking ESP32 probe..."
  esp32_require || {
    ERROR_DIALOG "ESP32 probe not found or not responding. Attach the probe and retry."
    exit 1
  }
  LOG green "ESP32 probe ready"
  LOG ""

  # Scan duration
  local duration
  duration=$(NUMBER_PICKER "Scan duration (seconds)" "$DEFAULT_SCAN_DURATION") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$duration" || "$duration" -lt 5 ]] && duration="$DEFAULT_SCAN_DURATION"
  SCAN_DURATION_USED="$duration"

  LOG "Scan duration: ${duration}s"
  LOG ""

  local confirm
  confirm=$(CONFIRMATION_DIALOG "Start BLE scan for ${duration}s?")
  case "$confirm" in
    "$DUCKYSCRIPT_USER_DENIED"|"")
      LOG "Aborted by user"; exit 0 ;;
  esac

  LED C SLOW

  local raw_output="$ARTIFACTS_DIR/ble_raw_$(date +%Y%m%d_%H%M%S).txt"
  local spinner_id
  spinner_id=$(START_SPINNER "Scanning BLE (${duration}s)...")

  # ble_scan_ics is provided by esp32.sh; it writes DEVICE lines to stdout.
  # Pass duration in seconds and redirect output to raw file.
  ble_scan_ics "$duration" 2>/dev/null > "$raw_output" || {
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "BLE scan failed — check ESP32 connection."
    exit 1
  }

  STOP_SPINNER "$spinner_id"

  LOG ""
  LOG blue "=== Parsing Results ==="

  parse_ble_output "$raw_output"

  LOG ""
  LOG green "=== Scan Complete ==="
  LOG "Total BLE devices seen: $TOTAL_DEVICES"
  LOG "ICS-related devices:    $ICS_DEVICE_COUNT"
  LOG ""

  # Save JSON artifact
  local artifact_file
  artifact_file=$(save_artifact)
  LOG "Artifact: $artifact_file"
  LOG "Raw log:  $raw_output"

  LED G SOLID
  RINGTONE success 2>/dev/null || true

  if [[ $ICS_DEVICE_COUNT -gt 0 ]]; then
    ALERT "Found $ICS_DEVICE_COUNT ICS BLE device(s) — see artifact"
  elif [[ $TOTAL_DEVICES -gt 0 ]]; then
    ALERT "$TOTAL_DEVICES BLE device(s) found, none matched ICS heuristics"
  else
    ALERT "No BLE devices detected in ${duration}s"
  fi

  PROMPT "Press button to exit"
}

main "$@"
