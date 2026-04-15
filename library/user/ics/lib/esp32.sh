#!/bin/bash
# Title: ESP32 ICS Probe Communication Library
# Description: Serial JSON protocol interface for the ESP32 ICS Probe peripheral
# Author: ICS Toolkit
# Version: 1.0
#
# Source this file in payloads that need the ESP32 probe:
#   source "$(dirname "$0")/../lib/esp32.sh"

# --- Configuration ---
ESP32_BAUD="${ESP32_BAUD:-115200}"
ESP32_TIMEOUT="${ESP32_TIMEOUT:-5}"
ESP32_DEV=""
ESP32_FW_VERSION=""

# --- Detection & Setup ---

esp32_detect() {
  local dev
  for dev in /dev/ttyACM*; do
    [[ -e "$dev" ]] || continue
    # Try to get probe info
    local resp
    resp=$(echo '{"cmd":"probe.info","params":{}}' > "$dev" && \
           timeout "$ESP32_TIMEOUT" head -n1 "$dev" 2>/dev/null) || continue

    if echo "$resp" | grep -q '"status":"ok"'; then
      ESP32_DEV="$dev"
      ESP32_FW_VERSION=$(echo "$resp" | sed -n 's/.*"fw_version":"\([^"]*\)".*/\1/p')
      return 0
    fi
  done
  return 1
}

esp32_require() {
  if ! esp32_detect; then
    ERROR_DIALOG "ICS Probe not detected. Plug in the ESP32 USB peripheral and try again."
    exit 1
  fi
  LOG blue "ICS Probe detected: $ESP32_DEV (firmware $ESP32_FW_VERSION)"
}

esp32_send() {
  local cmd="$1"
  local params="${2:-{}}"
  local id="${3:-$(date +%s%N)}"
  local timeout="${4:-$ESP32_TIMEOUT}"

  [[ -z "$ESP32_DEV" ]] && { echo '{"status":"error","error":"no_device"}'; return 1; }

  local request
  request=$(printf '{"cmd":"%s","params":%s,"id":"%s"}' "$cmd" "$params" "$id")

  echo "$request" > "$ESP32_DEV"
  local resp
  resp=$(timeout "$timeout" head -n1 "$ESP32_DEV" 2>/dev/null)

  if [[ -z "$resp" ]]; then
    echo '{"status":"error","error":"timeout"}'
    return 1
  fi

  echo "$resp"
}

esp32_stream_start() {
  local cmd="$1"
  local params="${2:-{}}"
  local output_file="$3"

  [[ -z "$ESP32_DEV" ]] && return 1

  local request
  request=$(printf '{"cmd":"%s","params":%s}' "$cmd" "$params")
  echo "$request" > "$ESP32_DEV"

  cat "$ESP32_DEV" >> "$output_file" &
  echo $!
}

esp32_stream_stop() {
  local pid="$1"
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  echo '{"cmd":"stop"}' > "$ESP32_DEV" 2>/dev/null || true
}

# --- Modbus RTU Wrappers ---

modbus_read_holding() {
  local addr="$1" reg="$2" count="${3:-1}"

  [[ -z "$addr" || -z "$reg" ]] && { LOG red "Usage: modbus_read_holding <addr> <reg> [count]"; return 1; }
  [[ ! "$addr" =~ ^[0-9]+$ ]] && { LOG red "Invalid slave address: $addr"; return 1; }
  [[ ! "$reg" =~ ^[0-9]+$ ]] && { LOG red "Invalid register: $reg"; return 1; }

  esp32_send "modbus.read_holding" \
    "$(printf '{"addr":%d,"reg":%d,"count":%d}' "$addr" "$reg" "$count")"
}

modbus_read_input() {
  local addr="$1" reg="$2" count="${3:-1}"

  [[ -z "$addr" || -z "$reg" ]] && { LOG red "Usage: modbus_read_input <addr> <reg> [count]"; return 1; }
  [[ ! "$addr" =~ ^[0-9]+$ ]] && { LOG red "Invalid slave address: $addr"; return 1; }

  esp32_send "modbus.read_input" \
    "$(printf '{"addr":%d,"reg":%d,"count":%d}' "$addr" "$reg" "$count")"
}

modbus_scan_bus() {
  local start="${1:-1}" end="${2:-247}"

  esp32_send "modbus.scan_bus" \
    "$(printf '{"range":[%d,%d]}' "$start" "$end")" "" "60"
}

modbus_device_id() {
  local addr="$1"

  [[ -z "$addr" ]] && { LOG red "Usage: modbus_device_id <addr>"; return 1; }
  [[ ! "$addr" =~ ^[0-9]+$ ]] && { LOG red "Invalid slave address: $addr"; return 1; }

  esp32_send "modbus.device_id" "$(printf '{"addr":%d}' "$addr")"
}

modbus_write_register() {
  local addr="$1" reg="$2" value="$3"

  [[ -z "$addr" || -z "$reg" || -z "$value" ]] && {
    LOG red "Usage: modbus_write_register <addr> <reg> <value>"
    return 1
  }

  local resp
  resp=$(CONFIRMATION_DIALOG "Write value $value to register $reg on slave $addr?")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") ;;
    *) LOG "Write cancelled"; return 1 ;;
  esac

  esp32_send "modbus.write_register" \
    "$(printf '{"addr":%d,"reg":%d,"value":%d,"confirm":true}' "$addr" "$reg" "$value")"
}

# --- CAN Bus Wrappers ---

can_listen() {
  local baud="${1:-500000}" duration="${2:-30}" output_file="$3"

  if [[ -n "$output_file" ]]; then
    esp32_stream_start "can.listen" \
      "$(printf '{"baud":%d,"duration_s":%d}' "$baud" "$duration")" "$output_file"
  else
    esp32_send "can.listen" \
      "$(printf '{"baud":%d,"duration_s":%d}' "$baud" "$duration")" "" "$((duration + 5))"
  fi
}

can_scan_ids() {
  local baud="${1:-500000}" duration="${2:-10}"

  esp32_send "can.scan_ids" \
    "$(printf '{"baud":%d,"duration_s":%d}' "$baud" "$duration")" "" "$((duration + 5))"
}

# --- ADC Wrappers ---

adc_read_ma() {
  local resp
  resp=$(esp32_send "adc.read" "{}")
  if echo "$resp" | grep -q '"status":"ok"'; then
    echo "$resp" | sed -n 's/.*"milliamps":\([0-9.]*\).*/\1/p'
  else
    echo "error"
    return 1
  fi
}

# --- BLE Wrappers ---

ble_scan_ics() {
  local duration="${1:-15}"

  esp32_send "ble.scan" \
    "$(printf '{"duration_s":%d,"filter":"ics"}' "$duration")" "" "$((duration + 5))"
}

# --- Probe Management ---

probe_selftest() {
  esp32_send "probe.selftest" "{}" "" "30"
}

probe_log() {
  esp32_send "probe.log" "{}"
}

# --- v1.1: Ethernet via W5500 ---

esp32_net_dhcp() {
  local timeout="${1:-10}"
  esp32_send "net.dhcp" "$(printf '{"timeout_s":%d}' "$timeout")"
}

esp32_net_static() {
  local ip="$1" mask="$2" gw="$3"
  esp32_send "net.static" "$(printf '{"ip":"%s","mask":"%s","gw":"%s"}' "$ip" "$mask" "$gw")"
}

esp32_net_status() {
  esp32_send "net.status" "{}"
}

esp32_net_tcp_connect() {
  local host="$1" port="$2"
  esp32_send "net.tcp_connect" "$(printf '{"host":"%s","port":%d}' "$host" "$port")"
}

esp32_net_tcp_send() {
  local sock="$1" hex="$2"
  esp32_send "net.tcp_send" "$(printf '{"sock":%d,"data":"%s"}' "$sock" "$hex")"
}

esp32_net_tcp_recv() {
  local sock="$1" timeout_ms="${2:-2000}"
  esp32_send "net.tcp_recv" "$(printf '{"sock":%d,"timeout_ms":%d}' "$sock" "$timeout_ms")"
}

esp32_net_tcp_close() {
  local sock="$1"
  esp32_send "net.tcp_close" "$(printf '{"sock":%d}' "$sock")"
}

esp32_net_udp_send() {
  local host="$1" port="$2" hex="$3"
  esp32_send "net.udp_send" "$(printf '{"host":"%s","port":%d,"data":"%s"}' "$host" "$port" "$hex")"
}
