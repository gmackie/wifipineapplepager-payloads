#!/bin/bash
# Network scanning module - ARP scan, ping sweep, port scan

rt_net_scan() {
  local choice
  choice=$(menu_pick "Network Scan" \
    "ARP Scan (local subnet)" \
    "Ping Sweep" \
    "Quick Port Scan (top 100)" \
    "Full Port Scan (1-65535)")
  
  local target
  case "$choice" in
    1) rt_arp_scan ;;
    2|3|4)
      target=$(TEXT_PICKER "Target (IP or CIDR)" "$TARGET_NETWORK")
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      
      if ! in_scope "${target%%/*}"; then
        LOG red "Target $target not in scope"
        return 1
      fi
      
      case "$choice" in
        2) rt_ping_sweep "$target" ;;
        3) rt_port_scan "$target" "quick" ;;
        4) rt_port_scan "$target" "full" ;;
      esac
      ;;
    0|"") return ;;
  esac
}

rt_arp_scan() {
  local outfile="$ARTIFACT_DIR/arp_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Running ARP scan on local subnet..."
  
  if have arp-scan; then
    with_spinner "ARP scan" bash -c "arp-scan -l 2>/dev/null | tee '$outfile'"
  elif have nmap && [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    local subnet
    subnet=$(get_local_ip | sed 's/\.[0-9]*$/.0\/24/')
    run_with_fallback "" "nmap -sn -PR $subnet -oG -" | tee "$outfile"
  elif have ip; then
    LOG "Using ip neigh (cached only)"
    ip neigh show | tee "$outfile"
  else
    LOG red "No ARP scan tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_ping_sweep() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/ping_sweep_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Ping sweep: $target"
  
  if have nmap; then
    with_spinner "Ping sweep" bash -c "nmap -sn '$target' -oG - | grep 'Up' | tee '$outfile'"
  elif have fping; then
    with_spinner "Ping sweep" bash -c "fping -a -g '$target' 2>/dev/null | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -sn $target -oG $LAPTOP_RESULTS_DIR/ping.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/ping.txt" "$outfile"
  else
    LOG red "No ping sweep tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_port_scan() {
  local target="$1"
  local mode="${2:-quick}"
  local outfile="$ARTIFACT_DIR/port_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  local ports
  if [[ "$mode" == "quick" ]]; then
    # Top OT/IT ports
    ports="21,22,23,25,80,102,443,445,502,993,995,1433,1521,1883,3306,3389,4840,5432,5900,8080,20000,44818,47808"
  else
    ports="1-65535"
  fi
  
  LOG blue "Port scan ($mode): $target"
  
  if have nmap; then
    with_spinner "Port scan" bash -c "nmap -Pn -p '$ports' '$target' -oG - | tee '$outfile'"
  elif have nc; then
    LOG "Using netcat (slow)"
    {
      for p in ${ports//,/ }; do
        if [[ "$p" =~ - ]]; then
          # Range - skip for nc
          continue
        fi
        if port_open "$target" "$p" 1; then
          echo "$target:$p open"
        fi
      done
    } | tee "$outfile"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -Pn -p $ports $target -oG $LAPTOP_RESULTS_DIR/ports.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/ports.txt" "$outfile"
  else
    LOG red "No port scan tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}
