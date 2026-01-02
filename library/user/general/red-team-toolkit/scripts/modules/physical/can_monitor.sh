#!/bin/bash
set -euo pipefail

# CAN monitor using SocketCAN (candump) or slcand for USB adapters

rt_can_monitor() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"

  local iface
  iface=$(TEXT_PICKER "SocketCAN iface (e.g., can0)" "can0") || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Text picker error"; return 1 ;;
  esac

  local bitrate
  bitrate=$(NUMBER_PICKER "Bitrate" 500000) || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Number picker error"; return 1 ;;
  esac

  local ts="$(date +%Y%m%d_%H%M%S)"
  local out="$base_dir/$artifacts/can_${iface}_${ts}.log"

  LOG blue "Bringing up $iface @ ${bitrate}"
  if have ip; then
    ip link set "$iface" down 2>/dev/null || true
    ip link set "$iface" type can bitrate "$bitrate" 2>/dev/null || true
    ip link set "$iface" up 2>/dev/null || true
  fi

  if have candump; then
    with_spinner "candump $iface" bash -c "candump -tz '$iface' | tee '$out' >/dev/null"
    LOG green "CAN log -> $out"
    return 0
  fi

  LOG red "candump not found. Install can-utils and ensure SocketCAN is available"
  return 1
}

