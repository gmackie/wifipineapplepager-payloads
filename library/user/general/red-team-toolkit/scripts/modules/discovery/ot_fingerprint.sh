#!/bin/bash
# OT Device Fingerprinting - MAC OUI lookup, port-based classification

rt_ot_fingerprint() {
  local choice
  choice=$(menu_pick "OT Fingerprint" \
    "Fingerprint Single IP" \
    "Scan Subnet for OT Devices" \
    "Passive Broadcast Listen")
  
  case "$choice" in
    1) rt_fingerprint_single ;;
    2) rt_fingerprint_subnet ;;
    3) rt_fingerprint_passive ;;
    0|"") return ;;
  esac
}

rt_fingerprint_single() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/fingerprint_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Fingerprinting $target..."
  
  {
    echo "=== OT Fingerprint: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Get MAC via ARP
    local mac=""
    if have arp; then
      mac=$(arp -n "$target" 2>/dev/null | awk '/ether/{print $3}')
    elif have ip; then
      mac=$(ip neigh show "$target" 2>/dev/null | awk '{print $5}')
    fi
    
    if [[ -n "$mac" ]]; then
      echo "MAC Address: $mac"
      local oui="${mac:0:8}"
      oui="${oui^^}"  # uppercase
      oui="${oui//:/-}"
      
      # Lookup OUI
      local vendor=""
      if [[ -f "$TOOLKIT_DIR/wordlists/ics-oui.txt" ]]; then
        vendor=$(grep -i "^${oui:0:8}" "$TOOLKIT_DIR/wordlists/ics-oui.txt" 2>/dev/null | cut -d',' -f2)
      fi
      echo "Vendor (OUI): ${vendor:-Unknown}"
    else
      echo "MAC Address: (not in ARP cache - try ping first)"
    fi
    
    echo ""
    echo "=== Open OT Ports ==="
    
    # Check OT ports and classify
    local device_type="Unknown"
    local protocols=""
    
    if port_open "$target" 502 2; then
      echo "[OPEN] 502/tcp - Modbus/TCP"
      protocols="$protocols Modbus"
    fi
    if port_open "$target" 44818 2; then
      echo "[OPEN] 44818/tcp - EtherNet/IP"
      protocols="$protocols EtherNet/IP"
    fi
    if port_open "$target" 102 2; then
      echo "[OPEN] 102/tcp - S7comm (Siemens)"
      protocols="$protocols S7comm"
      device_type="Siemens PLC"
    fi
    if port_open "$target" 4840 2; then
      echo "[OPEN] 4840/tcp - OPC UA"
      protocols="$protocols OPC-UA"
    fi
    if port_open "$target" 47808 2; then
      echo "[OPEN] 47808/udp - BACnet"
      protocols="$protocols BACnet"
      device_type="BACnet Device"
    fi
    if port_open "$target" 20000 2; then
      echo "[OPEN] 20000/tcp - DNP3"
      protocols="$protocols DNP3"
    fi
    if port_open "$target" 80 2 || port_open "$target" 443 2; then
      echo "[OPEN] HTTP/HTTPS - Web Interface"
      protocols="$protocols Web"
    fi
    if port_open "$target" 22 2; then
      echo "[OPEN] 22/tcp - SSH"
    fi
    if port_open "$target" 3389 2; then
      echo "[OPEN] 3389/tcp - RDP"
      device_type="Windows (HMI/Historian?)"
    fi
    
    echo ""
    echo "=== Classification ==="
    echo "Device Type: $device_type"
    echo "Protocols: ${protocols:-None detected}"
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

rt_fingerprint_subnet() {
  local target
  target=$(TEXT_PICKER "Subnet (CIDR)" "$TARGET_NETWORK")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/ot_subnet_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Scanning $target for OT devices..."
  LOG "This may take a while..."
  
  # First, get live hosts
  local live_hosts="$ARTIFACT_DIR/.live_hosts_tmp"
  
  if have nmap; then
    nmap -sn "$target" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' > "$live_hosts"
  elif have fping; then
    fping -a -g "$target" 2>/dev/null > "$live_hosts"
  else
    LOG red "Need nmap or fping for subnet scan"
    return 1
  fi
  
  local count
  count=$(wc -l < "$live_hosts")
  LOG "Found $count live hosts, checking for OT ports..."
  
  {
    echo "=== OT Subnet Scan: $target ==="
    echo "Timestamp: $(date)"
    echo "Live hosts: $count"
    echo ""
    
    while read -r ip; do
      local ot_found=0
      local ot_info=""
      
      for port in 502 44818 102 4840 20000 47808; do
        if port_open "$ip" "$port" 1; then
          ot_found=1
          case $port in
            502) ot_info="$ot_info Modbus" ;;
            44818) ot_info="$ot_info EtherNet/IP" ;;
            102) ot_info="$ot_info S7comm" ;;
            4840) ot_info="$ot_info OPC-UA" ;;
            20000) ot_info="$ot_info DNP3" ;;
            47808) ot_info="$ot_info BACnet" ;;
          esac
        fi
      done
      
      if [[ $ot_found -eq 1 ]]; then
        echo "[OT] $ip -$ot_info"
      fi
    done < "$live_hosts"
    
  } | tee "$outfile"
  
  rm -f "$live_hosts"
  LOG green "Results: $outfile"
}

rt_fingerprint_passive() {
  local duration
  duration=$(NUMBER_PICKER "Listen duration (seconds)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/passive_ot_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Passive listening for $duration seconds..."
  LOG "Capturing: ARP, mDNS, LLDP, Profinet DCP, BACnet broadcasts"
  
  if have tcpdump; then
    # Capture broadcast/multicast traffic common in OT environments
    with_spinner "Listening" run_timeboxed "$duration" \
      tcpdump -i any -w "$outfile" \
      'arp or port 5353 or ether proto 0x88cc or udp port 34964 or udp port 47808' \
      2>/dev/null
    
    LOG green "Capture saved: $outfile"
    LOG "Analyze with: tcpdump -r $outfile"
  else
    LOG red "tcpdump required for passive capture"
    return 1
  fi
}
