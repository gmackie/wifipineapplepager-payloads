#!/bin/bash
# OT/ICS protocol authentication sniffing

rt_protocol_auth() {
  local choice
  choice=$(menu_pick "Protocol Auth Sniff" \
    "Modbus Device IDs" \
    "EtherNet/IP Sessions" \
    "OPC UA Security Audit" \
    "S7comm Authentication" \
    "BACnet Device Passwords" \
    "Generic OT Port Capture")
  
  case "$choice" in
    1) proto_modbus_ids ;;
    2) proto_enip_sessions ;;
    3) proto_opcua_security ;;
    4) proto_s7_auth ;;
    5) proto_bacnet_auth ;;
    6) proto_ot_generic ;;
    0|"") return ;;
  esac
}

proto_modbus_ids() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/modbus_ids_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing Modbus traffic for device identification..."
  LOG "Looking for: Unit IDs, Function codes, Read/Write patterns"
  
  {
    echo "=== Modbus Device ID Capture ==="
    echo "Start: $(date)"
    echo "Interface: $iface"
    echo ""
    
    if have tcpdump; then
      # Capture Modbus TCP (port 502)
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -nn -X port 502 2>/dev/null | \
        awk '
          /IP.*\.502:/ { src=$3; dst=$5 }
          /0x0010:/ { 
            # Parse Modbus header - byte 7 is unit ID, byte 8 is function code
            print "Transaction from " src " to " dst
            print "  Raw: " $0
          }
        '
    else
      LOG red "tcpdump required"
    fi
    
    echo ""
    echo "End: $(date)"
  } | tee "$outfile"
  
  LOG green "Saved: $outfile"
  LOG ""
  LOG "Analysis tips:"
  LOG "  - Unit ID 0 = broadcast"
  LOG "  - Function 1-4 = reads (safe)"
  LOG "  - Function 5,6,15,16 = writes (dangerous)"
}

proto_enip_sessions() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/enip_sessions_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing EtherNet/IP sessions..."
  LOG "Port 44818 (explicit), 2222 (implicit)"
  
  if have tcpdump; then
    with_spinner "Capturing" run_timeboxed "$duration" \
      tcpdump -i "$iface" -w "$outfile" \
      'port 44818 or port 2222' 2>/dev/null
    
    LOG green "Saved: $outfile"
    LOG ""
    LOG "Analyze with Wireshark: Filter 'enip'"
    LOG "Look for RegisterSession and ForwardOpen commands"
  else
    LOG red "tcpdump required"
  fi
}

proto_opcua_security() {
  local target
  target=$(IP_PICKER "OPC UA Server" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 4840)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/opcua_security_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Auditing OPC UA security configuration..."
  
  {
    echo "=== OPC UA Security Audit ==="
    echo "Target: $target:$port"
    echo "Date: $(date)"
    echo ""
    
    # Check endpoint security policies
    if have python3; then
      python3 << PYEOF 2>/dev/null || echo "Python OPC UA library not available"
try:
    from opcua import Client
    
    client = Client("opc.tcp://${target}:${port}")
    
    print("Endpoints:")
    endpoints = client.connect_and_get_server_endpoints()
    
    for ep in endpoints:
        print(f"  URL: {ep.EndpointUrl}")
        print(f"  Security Mode: {ep.SecurityMode}")
        print(f"  Security Policy: {ep.SecurityPolicyUri}")
        print(f"  User Tokens: {[t.TokenType for t in ep.UserIdentityTokens]}")
        print("")
        
        if "None" in str(ep.SecurityPolicyUri):
            print("  [!] WARNING: No security policy - plaintext auth!")
        if "Anonymous" in str([t.TokenType for t in ep.UserIdentityTokens]):
            print("  [!] WARNING: Anonymous access allowed!")
            
except Exception as e:
    print(f"Error: {e}")
PYEOF
    else
      LOG "Python3 not available, trying nmap..."
      run_with_fallback \
        "nmap -p $port --script opcua-info $target" \
        "nmap -p $port --script opcua-info $target"
    fi
    
    echo ""
    echo "=== Recommendations ==="
    echo "- Disable Anonymous authentication"
    echo "- Use SignAndEncrypt security mode"
    echo "- Require certificates for all clients"
    
  } | tee "$outfile"
  
  LOG green "Saved: $outfile"
}

proto_s7_auth() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/s7comm_auth_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing S7comm authentication..."
  LOG "Looking for: Connection setup, password challenges"
  
  if have tcpdump; then
    with_spinner "Capturing" run_timeboxed "$duration" \
      tcpdump -i "$iface" -w "$outfile" 'port 102' 2>/dev/null
    
    LOG green "Saved: $outfile"
    LOG ""
    LOG "Analyze with Wireshark:"
    LOG "  Filter: s7comm"
    LOG "  Look for: COTP CR/CC, S7 Setup Communication"
    LOG ""
    LOG "S7 password protection levels:"
    LOG "  1 = Read protection"
    LOG "  2 = Read/Write protection"
    LOG "  3 = Full protection"
  else
    LOG red "tcpdump required"
  fi
}

proto_bacnet_auth() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/bacnet_auth_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing BACnet authentication..."
  LOG "Note: BACnet rarely uses auth - looking for passwords in properties"
  
  {
    echo "=== BACnet Auth Capture ==="
    echo "Start: $(date)"
    echo ""
    
    if have tcpdump; then
      # BACnet IP uses UDP 47808
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -nn -A 'udp port 47808' 2>/dev/null | \
        grep -iE '(password|pass|key|secret|auth|login|credential)' || \
        echo "(No obvious credentials in traffic)"
    else
      LOG red "tcpdump required"
    fi
    
    echo ""
    echo "BACnet Security Notes:"
    echo "  - Most BACnet devices have NO authentication"
    echo "  - BACnet/SC adds TLS but is rarely deployed"
    echo "  - Check WriteProperty commands for abuse"
    
  } | tee "$outfile"
  
  LOG green "Saved: $outfile"
}

proto_ot_generic() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/ot_protocols_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing ALL OT protocol traffic..."
  
  # All common OT ports
  local ports="port 102 or port 502 or port 20000 or port 44818 or port 2222 or port 4840 or port 47808 or port 1911 or port 789 or port 34962 or port 34963 or port 34964"
  
  if have tcpdump; then
    LOG "Ports: Modbus(502), S7(102), DNP3(20000), EtherNet/IP(44818,2222),"
    LOG "       OPC-UA(4840), BACnet(47808), Niagara(1911), Crimson(789),"
    LOG "       PROFINET(34962-34964)"
    
    with_spinner "Capturing" run_timeboxed "$duration" \
      tcpdump -i "$iface" -w "$outfile" "$ports" 2>/dev/null
    
    LOG green "Saved: $outfile"
    LOG ""
    LOG "Open in Wireshark for protocol-specific analysis"
  else
    LOG red "tcpdump required"
  fi
}
