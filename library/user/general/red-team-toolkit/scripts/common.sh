#!/bin/bash
set -euo pipefail

ensure_dir() {
  for d in "$@"; do
    mkdir -p "$d"
  done
}

have() { command -v "$1" >/dev/null 2>&1; }

safe_confirm() {
  local msg="$1"; local safe_mode="${2:-1}"
  if [[ "$safe_mode" -eq 0 ]]; then
    return 0
  fi
  local resp
  resp=$(CONFIRMATION_DIALOG "$msg") || true
  case $? in
    $DUCKYSCRIPT_REJECTED) LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)    LOG "Dialog error"; return 1 ;;
  esac
  case "$resp" in
    $DUCKYSCRIPT_USER_CONFIRMED) return 0 ;;
    $DUCKYSCRIPT_USER_DENIED)    return 1 ;;
    *) LOG "Unknown response: $resp"; return 1 ;;
  esac
}

start_task() {
  local label="$1"
  START_SPINNER "$label"
}

end_task() {
  local id="$1"
  STOP_SPINNER "$id"
}

with_spinner() {
  local label="$1"; shift
  local id
  id=$(start_task "$label")
  "$@" || {
    end_task "$id" || true
    return 1
  }
  end_task "$id" || true
}

run_timeboxed() {
  local seconds="$1"; shift
  if have timeout; then
    timeout -s INT "$seconds" "$@"
  else
    # Poor-man's timeout
    ( "$@" & pid=$!; ( sleep "$seconds"; kill -INT "$pid" 2>/dev/null || true ) & waiter=$!; wait "$pid" 2>/dev/null; kill -TERM "$waiter" 2>/dev/null || true )
  fi
}

pick_wlan_iface() {
  # Prefer monitor interface if present
  ip -o link 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wlan.*mon$' | head -n1 || true
}

ensure_monitor() {
  local base_iface
  base_iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^wlan' | head -n1 || true)
  local mon_iface
  mon_iface=$(pick_wlan_iface)
  if [[ -n "$mon_iface" ]]; then
    echo "$mon_iface"
    return 0
  fi
  if have airmon-ng && [[ -n "$base_iface" ]]; then
    airmon-ng start "$base_iface" >/dev/null 2>&1 || true
    mon_iface=$(pick_wlan_iface)
    if [[ -n "$mon_iface" ]]; then echo "$mon_iface"; return 0; fi
  fi
  # Fallback: try iw
  if have iw && [[ -n "$base_iface" ]]; then
    local new="${base_iface}mon"
    iw dev "$base_iface" interface add "$new" type monitor 2>/dev/null || true
    ip link set "$new" up 2>/dev/null || true
    echo "$new"
    return 0
  fi
  echo ""
}

# === ADDITIONAL HELPERS FOR V2 ===

# Timestamp for filenames
ts() {
  date +%Y%m%d_%H%M%S
}

# Log to file and screen
log_both() {
  local msg="$1"
  local logfile="${2:-$LOG_DIR/toolkit.log}"
  echo "[$(date '+%H:%M:%S')] $msg" | tee -a "$logfile"
}

# Check if IP is valid format
is_valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# Check if port is open (quick check)
port_open() {
  local host="$1"
  local port="$2"
  local timeout="${3:-2}"
  
  if have nc; then
    nc -z -w "$timeout" "$host" "$port" 2>/dev/null
  elif have bash; then
    timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
  else
    return 1
  fi
}

# Get local IP address
get_local_ip() {
  ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}'
}

# Parse CIDR to get network range (basic)
cidr_to_range() {
  local cidr="$1"
  echo "${cidr%/*}"  # Just return base for now
}

# Kill background process by name pattern
kill_bg() {
  local pattern="$1"
  pkill -f "$pattern" 2>/dev/null || true
}
