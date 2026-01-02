#!/bin/bash
set -euo pipefail

rt_passive_recon() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"; local channels="$4"; local maxdur="$5"; local scope_bssids="$6"

  LOG blue "Passive Recon: channels=[$channels] scope=[${scope_bssids:-any}] max=${maxdur}s"

  local dur
  dur=$(NUMBER_PICKER "Duration seconds (<= $maxdur)" "$maxdur") || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Number picker error"; return 1 ;;
  esac
  if [[ "${dur:-0}" -gt "$maxdur" ]]; then dur="$maxdur"; fi
  if [[ -z "${dur:-}" ]]; then dur="$maxdur"; fi

  local ts="$(date +%Y%m%d_%H%M%S)"
  local out_prefix="$base_dir/$artifacts/recon_${ts}"
  local out_log="${out_prefix}.log"

  # Try preferred backends in order: airodump-ng, tcpdump (monitor), iw scan
  local mon
  mon=$(ensure_monitor)

  if have airodump-ng && [[ -n "$mon" ]]; then
    LOG "Using airodump-ng on $mon"
    with_spinner "airodump $dur s" run_timeboxed "$dur" airodump-ng --write-interval 1 --output-format csv,pcap --channel "${channels// /,}" --write "$out_prefix" "$mon" || true
    LOG green "Recon complete -> ${out_prefix}-01.csv / .pcap"
    return 0
  fi

  if have tcpdump && [[ -n "$mon" ]]; then
    LOG "Using tcpdump on $mon"
    with_spinner "tcpdump $dur s" run_timeboxed "$dur" tcpdump -I -i "$mon" -s 0 -w "${out_prefix}.pcap" type mgt || true
    LOG green "Recon pcap -> ${out_prefix}.pcap"
    return 0
  fi

  if have iw; then
    LOG "Falling back to iw scan (active)"
    {
      for ch in $channels; do
        LOG "Scanning channel $ch"
        iw dev "$mon" set channel "$ch" 2>/dev/null || true
        iw dev "$mon" scan 2>/dev/null || true
      done
    } | tee "$out_log" >/dev/null || true
    LOG green "Recon log -> $out_log"
    return 0
  fi

  LOG red "No suitable recon backend found (need airodump-ng or tcpdump or iw)"
  return 1
}
