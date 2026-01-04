#!/bin/bash

RECON_DIR="${RECON_DIR:-/root/payloads/library/user/reconnaissance}"

rt_recon_menu() {
  while true; do
    local choice
    choice=$(menu_pick "Passive Recon Monitors" \
      "Rogue Twin Radar (evil twin detection)" \
      "Probe Whisperer (probe request monitor)" \
      "WPS Beacon Flagger (WPS-enabled APs)" \
      "Enterprise Finder (WPA-Enterprise)" \
      "OT OUI Scout (ICS device detection)" \
      "Beacon Anomaly Watch (RF anomalies)" \
      "Hidden SSID Counter" \
      "P2P Hotspot Spotter" \
      "Channel Heatmap")
    
    case "$choice" in
      1) launch_recon_payload "rogue-twin-radar" ;;
      2) launch_recon_payload "probe-whisperer" ;;
      3) launch_recon_payload "wps-beacon-flagger" ;;
      4) launch_recon_payload "enterprise-beacon-finder" ;;
      5) launch_recon_payload "ot-oui-scout" ;;
      6) launch_recon_payload "beacon-anomaly-watch" ;;
      7) launch_recon_payload "hidden-ssid-counter" ;;
      8) launch_recon_payload "p2p-hotspot-spotter" ;;
      9) launch_recon_payload "channel-heatmap" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

launch_recon_payload() {
  local payload_name="$1"
  local payload_path="$RECON_DIR/$payload_name/payload.sh"
  
  if [[ ! -f "$payload_path" ]]; then
    local alt_paths=(
      "/usr/share/payloads/library/user/reconnaissance/$payload_name/payload.sh"
      "$DIR/../../../reconnaissance/$payload_name/payload.sh"
    )
    
    for alt in "${alt_paths[@]}"; do
      if [[ -f "$alt" ]]; then
        payload_path="$alt"
        break
      fi
    done
  fi
  
  if [[ ! -f "$payload_path" ]]; then
    LOG red "Payload not found: $payload_name"
    LOG "Expected: $RECON_DIR/$payload_name/payload.sh"
    LOG ""
    LOG "Install recon payloads from:"
    LOG "  library/user/reconnaissance/"
    return 1
  fi
  
  LOG blue "Launching: $payload_name"
  LOG ""
  
  export ARTIFACTS_DIR="$ARTIFACT_DIR/recon"
  ensure_dir "$ARTIFACTS_DIR"
  
  bash "$payload_path"
  local exit_code=$?
  
  if [[ $exit_code -eq 0 ]]; then
    LOG green "$payload_name completed"
    log_timeline "Executed passive recon: $payload_name"
  else
    LOG red "$payload_name exited with code $exit_code"
  fi
  
  return $exit_code
}

rt_recon_all() {
  LOG blue "=== Multi-Monitor Recon ==="
  LOG "Runs all passive monitors in sequence"
  LOG ""
  
  local monitors=(
    "rogue-twin-radar:60"
    "probe-whisperer:60"
    "hidden-ssid-counter:60"
    "channel-heatmap:30"
  )
  
  local duration_per
  duration_per=$(NUMBER_PICKER "Seconds per monitor" 60) || return
  
  for entry in "${monitors[@]}"; do
    local name="${entry%%:*}"
    
    LOG ""
    LOG blue ">>> $name (${duration_per}s)"
    
    export MONITOR_DURATION="$duration_per"
    export SCAN_DURATION="$duration_per"
    
    launch_recon_payload "$name" || true
    
    sleep 2
  done
  
  LOG ""
  LOG green "=== Multi-Monitor Complete ==="
  LOG "Results in: $ARTIFACT_DIR/recon/"
  
  log_timeline "Completed multi-monitor recon sweep"
}
