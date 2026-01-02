#!/bin/bash
set -euo pipefail

rt_handshake_capture() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"; local channels="$4"; local maxdur="$5"; local scope_bssids="$6"

  LOG blue "Handshake Capture: channels=[$channels] scope=[${scope_bssids:-any}] max=${maxdur}s"

  local target_bssid
  target_bssid=$(TEXT_PICKER "Target BSSID (optional)" "") || true
  case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "User cancelled"; return 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Dialog rejected"; return 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Text picker error"; return 1 ;;
  esac

  local ts="$(date +%Y%m%d_%H%M%S)"
  local out_prefix="$base_dir/$artifacts/hs_${ts}"
  local pcap="${out_prefix}.pcap"

  local mon
  mon=$(ensure_monitor)

  # Prefer hcxdumptool if available
  if have hcxdumptool; then
    LOG "Using hcxdumptool (timeboxed ${maxdur}s)"
    local args=("-o" "$pcap" "--enable_status=1")
    [[ -n "$mon" ]] && args+=("-i" "$mon")
    [[ -n "$target_bssid" ]] && args+=("--filterlist_ap=$target_bssid" "--filtermode=2")
    with_spinner "hcxdumptool" run_timeboxed "$maxdur" hcxdumptool "${args[@]}" || true
    LOG green "Capture complete -> $pcap"
    ALERT "Handshake capture attempted. Artifact: $(basename "$pcap")"
    return 0
  fi

  # Fall back to airodump-ng
  if have airodump-ng && [[ -n "$mon" ]]; then
    LOG "Using airodump-ng (timeboxed ${maxdur}s)"
    local chan_opt=("--channel" "${channels// /,}")
    local filt=( )
    [[ -n "$target_bssid" ]] && filt=("--bssid" "$target_bssid")
    with_spinner "airodump" run_timeboxed "$maxdur" airodump-ng "${chan_opt[@]}" --write "$out_prefix" --write-interval 1 --output-format pcap "$mon" "${filt[@]}" || true
    LOG green "Capture complete -> ${out_prefix}-01.cap"
    ALERT "Handshake capture attempted. Artifact: $(basename "${out_prefix}-01.cap")"
    return 0
  fi

  # Last resort: tcpdump EAPOL only
  if have tcpdump && [[ -n "$mon" ]]; then
    LOG "Using tcpdump EAPOL filter (timeboxed ${maxdur}s)"
    with_spinner "tcpdump eapol" run_timeboxed "$maxdur" tcpdump -I -i "$mon" -s 0 -w "$pcap" "ether proto 0x888e" || true
    LOG green "EAPOL pcap -> $pcap"
    ALERT "Handshake/EAPOL capture attempted. Artifact: $(basename "$pcap")"
    return 0
  fi

  LOG red "No capture backend found (need hcxdumptool or airodump-ng or tcpdump)"
  return 1
}
