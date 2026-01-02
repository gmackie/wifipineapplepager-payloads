#!/bin/bash
set -euo pipefail

rt_deauth_watch() {
  local base_dir="$1"; local artifacts="$2"; local _logs="$3"; local channels="$4"; local maxdur="$5"; local scope_bssids="$6"

  LOG blue "Deauth Watch: channels=[$channels] scope=[${scope_bssids:-any}] window=${maxdur}s"

  local out="$base_dir/$artifacts/deauth_watch_$(date +%Y%m%d_%H%M%S).log"
  local mon
  mon=$(ensure_monitor)

  if have tcpdump && [[ -n "$mon" ]]; then
    LOG "Using tcpdump on $mon"
    with_spinner "deauth monitor" run_timeboxed "$maxdur" tcpdump -I -i "$mon" -l -tt "type mgmt subtype deauth" 2>/dev/null | tee "$out" >/dev/null || true
    LOG green "Deauth events log -> $out"
    return 0
  fi

  LOG red "tcpdump not available or no monitor interface"
  return 1
}
