#!/bin/bash
set -euo pipefail

# RTL-SDR helpers using rtl_433 or rtl_power/rtl_sdr if present

rt_rtl_sdr() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"

  local mode
  mode=$(TEXT_PICKER "Mode: rtl_433 | rtl_power | raw" "rtl_433") || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Text picker error"; return 1 ;;
  esac

  local ts="$(date +%Y%m%d_%H%M%S)"
  local out_prefix="$base_dir/$artifacts/rtl_${ts}"

  if [[ "$mode" == "rtl_433" ]] && have rtl_433; then
    LOG blue "Running rtl_433 JSON stream"
    with_spinner "rtl_433" bash -c "rtl_433 -M utc -F json | tee '${out_prefix}.jsonl' >/dev/null"
    LOG green "RTL433 log -> ${out_prefix}.jsonl"
    return 0
  fi

  if [[ "$mode" == "rtl_power" ]] && have rtl_power; then
    local range
    range=$(TEXT_PICKER "Freq range (e.g., 70M:1G:1M)" "70M:1G:1M") || true
    LOG blue "rtl_power sweep $range"
    with_spinner "rtl_power" bash -c "rtl_power -f '$range' -g 20 -e 30s '${out_prefix}.csv'"
    LOG green "RTL power CSV -> ${out_prefix}.csv"
    return 0
  fi

  if [[ "$mode" == "raw" ]] && have rtl_sdr; then
    local freq
    freq=$(TEXT_PICKER "Center freq (Hz)" "433920000") || true
    LOG blue "rtl_sdr IQ capture @ $freq"
    with_spinner "rtl_sdr" bash -c "rtl_sdr -f '$freq' -s 2048000 -g 20 '${out_prefix}.iq'"
    LOG green "RTL raw IQ -> ${out_prefix}.iq"
    return 0
  fi

  LOG red "Requested SDR mode not available (missing tools)"
  return 1
}

