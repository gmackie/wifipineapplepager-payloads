#!/bin/bash
set -euo pipefail

# RS485 serial helper using common tools (stty/socat)
# Expects a USB RS485 adapter at /dev/ttyUSB0 (adjust as needed)

rt_rs485_serial() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"
  local dev
  dev=$(TEXT_PICKER "Serial device path" "/dev/ttyUSB0") || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Text picker error"; return 1 ;;
  esac

  local baud
  baud=$(NUMBER_PICKER "Baud rate" 115200) || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Number picker error"; return 1 ;;
  esac

  local ts="$(date +%Y%m%d_%H%M%S)"
  local out="$base_dir/$artifacts/rs485_${ts}.log"

  LOG blue "RS485 monitor $dev @ ${baud}"
  if have stty && have socat; then
    with_spinner "serial monitor" bash -c "stty -F '$dev' ${baud} cs8 -cstopb -parenb -ixon -ixoff -crtscts; socat -d -d '$dev,raw,echo=0,crnl,cs8,clocal,ixon=0,ixoff=0,${baud}' - | tee '$out' >/dev/null"
    LOG green "Serial log -> $out"
    return 0
  fi
  LOG red "Need stty and socat for RS485 module"
  return 1
}

