#!/bin/bash
# PROFINET module - DCP discovery and device info

rt_profinet() {
  local choice
  choice=$(menu_pick "PROFINET" \
    "DCP Discovery (broadcast)" \
    "Get Device Info" \
    "Passive Sniff")
  
  case "$choice" in
    1) profinet_dcp_discover ;;
    2) profinet_device_info ;;
    3) profinet_passive ;;
    0|"") return ;;
  esac
}

profinet_dcp_discover() {
  local outfile
  outfile="$ARTIFACT_DIR/profinet_discovery_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "PROFINET DCP Discovery (broadcast)..."
  
  local iface
  iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^eth|^enp|^ens' | head -n1)
  if [[ -z "$iface" ]]; then
    iface=$(ip -o link | awk -F': ' '{print $2}' | grep -v lo | head -n1)
  fi
  
  if [[ -z "$iface" ]]; then
    LOG red "No suitable network interface found"
    return 1
  fi
  
  LOG "Using interface: $iface"
  
  {
    echo "=== PROFINET DCP Discovery ==="
    echo "Timestamp: $(date)"
    echo "Interface: $iface"
    echo ""
    
    if have nmap; then
      # Scan for PROFINET ports
      LOG "Scanning PROFINET ports (34962-34964)..."
      local net
      net="${TARGET_NETWORK:-$(ip -4 route show dev "$iface" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | head -n1)}"
      if [[ -n "$net" ]]; then
        nmap -sU -p 34962-34964 --open "$net" 2>&1 | grep -E '(Nmap scan|Host|PORT|profinet|open)'
      fi
    fi
    
    echo ""
    echo "=== DCP Identify All (passive capture) ==="
    
    # Capture PROFINET DCP traffic (ethertype 0x8892)
    # DCP uses multicast 01:0e:cf:00:00:00
    if have tcpdump; then
      LOG "Capturing DCP responses for 10 seconds..."
      with_spinner "DCP capture" run_timeboxed 10 \
        tcpdump -i "$iface" -nn -c 50 \
        '(ether proto 0x8892) or (udp port 34964)' 2>&1 || true
    else
      LOG red "tcpdump required for DCP capture"
    fi
    
    echo ""
    echo "=== Detected Devices ==="
    
    # Try to send DCP Identify All if pndcp tool available
    if have pndcp; then
      LOG "Sending DCP Identify All..."
      pndcp -i "$iface" identify-all 2>&1 || true
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      # Use laptop for DCP enumeration
      laptop_exec "python3 -c \"
import socket
import struct

# PROFINET DCP Identify All
# Destination: 01:0e:cf:00:00:00 (DCP multicast)
# Ethertype: 0x8892

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892))
sock.bind(('$iface', 0))
sock.settimeout(5)

# DCP Identify All frame
dst_mac = bytes([0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00])
src_mac = sock.getsockname()[4][:6] if len(sock.getsockname()) > 4 else bytes(6)
ethertype = struct.pack('>H', 0x8892)

# DCP header: ServiceID=5 (Identify), ServiceType=0 (Request)
dcp_header = bytes([0xfe, 0xfe, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04])
# Identify All block
dcp_block = bytes([0xff, 0xff, 0x00, 0x00])

frame = dst_mac + src_mac + ethertype + dcp_header + dcp_block
sock.send(frame)

print('DCP Identify All sent, waiting for responses...')
try:
    while True:
        data, addr = sock.recvfrom(1500)
        src = ':'.join(f'{b:02x}' for b in data[6:12])
        print(f'Response from {src}')
        # Parse DCP response (simplified)
        if len(data) > 26:
            print(f'  Raw: {data[14:50].hex()}')
except socket.timeout:
    pass
sock.close()
\" 2>&1" || LOG "DCP enumeration requires laptop with raw socket support"
    else
      LOG "For active DCP discovery, enable laptop mode or install pndcp"
      LOG "Falling back to passive capture only"
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

profinet_device_info() {
  local target
  target=$(IP_PICKER "PROFINET device IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local outfile
  outfile="$ARTIFACT_DIR/profinet_info_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Getting PROFINET device info: $target"
  
  {
    echo "=== PROFINET Device Info: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Check PROFINET-related ports
    echo "=== Port Scan ==="
    if have nmap; then
      nmap -sU -sT -p 34962-34964,102,135,445 --open "$target" 2>&1 | \
        grep -E '(PORT|open|Nmap)' || true
    elif have nc; then
      for port in 34962 34963 34964; do
        if nc -zu -w 2 "$target" "$port" 2>/dev/null; then
          echo "$port/udp open (PROFINET)"
        fi
      done
    fi
    
    echo ""
    echo "=== Device Identification ==="
    
    # Try SNMP for device info (many PROFINET devices support SNMP)
    if have snmpwalk; then
      LOG "Querying SNMP for device info..."
      snmpwalk -v2c -c public "$target" sysDescr 2>/dev/null || true
      snmpwalk -v2c -c public "$target" sysName 2>/dev/null || true
    fi
    
    # Try HTTP for web interface (common on PROFINET devices)
    if have curl; then
      LOG "Checking web interface..."
      local http_resp
      http_resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://$target/" 2>/dev/null || true)
      if [[ "$http_resp" == "200" ]] || [[ "$http_resp" == "401" ]]; then
        echo "HTTP interface available (status: $http_resp)"
        curl -s --connect-timeout 3 "http://$target/" 2>/dev/null | \
          grep -iE '(siemens|profinet|plc|s7|title)' | head -5 || true
      fi
    fi
    
    echo ""
    echo "=== DCP Get Request ==="
    
    # Send DCP Get request for specific device info
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "python3 -c \"
import socket
import struct

# PROFINET DCP Get request to specific IP
# This gets: NameOfStation, DeviceVendor, DeviceRole, IP settings

target_ip = '$target'
port = 34964

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)

# DCP Get request for all parameters
# ServiceID=3 (Get), ServiceType=0 (Request)
dcp_get = bytes([
    0xfe, 0xfd,  # Frame ID
    0x03, 0x00,  # ServiceID=Get, ServiceType=Request
    0x00, 0x00, 0x00, 0x0c,  # Xid, ResponseDelay
    0x00, 0x08,  # DataLength
    # Option: All Selector
    0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

try:
    sock.sendto(dcp_get, (target_ip, port))
    data, addr = sock.recvfrom(1500)
    print(f'Response from {addr}: {len(data)} bytes')
    print(f'Raw: {data.hex()}')
    # Parse would go here
except socket.timeout:
    print('No response (timeout)')
except Exception as e:
    print(f'Error: {e}')
sock.close()
\" 2>&1" || LOG "DCP Get request failed"
    else
      LOG "DCP Get requires laptop mode for raw packet construction"
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

profinet_passive() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  # Cap duration
  if [[ "$duration" -gt "$MAX_DURATION_SEC" ]]; then
    duration="$MAX_DURATION_SEC"
    LOG "Duration capped to $MAX_DURATION_SEC seconds"
  fi
  
  local iface
  iface=$(ip -o link | awk -F': ' '{print $2}' | grep -E '^eth|^enp|^ens' | head -n1)
  if [[ -z "$iface" ]]; then
    iface=$(ip -o link | awk -F': ' '{print $2}' | grep -v lo | head -n1)
  fi
  
  if [[ -z "$iface" ]]; then
    LOG red "No suitable network interface found"
    return 1
  fi
  
  local pcap_file
  pcap_file="$ARTIFACT_DIR/profinet_capture_$(ts).pcap"
  local log_file
  log_file="$ARTIFACT_DIR/profinet_capture_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Passive PROFINET capture on $iface for ${duration}s"
  
  if ! have tcpdump; then
    LOG red "tcpdump required for passive capture"
    return 1
  fi
  
  {
    echo "=== PROFINET Passive Capture ==="
    echo "Interface: $iface"
    echo "Duration: ${duration}s"
    echo "Timestamp: $(date)"
    echo ""
    echo "Filter: PROFINET RT (0x8892), PROFINET DCP (UDP 34962-34964)"
    echo ""
    
    # Capture PROFINET traffic:
    # - Ethertype 0x8892 = PROFINET RT/IRT (real-time)
    # - UDP ports 34962-34964 = PROFINET DCP
    # - Ethertype 0x8893 = PROFINET PTCP (precision time)
    LOG "Starting capture..."
    with_spinner "PROFINET capture" run_timeboxed "$duration" \
      tcpdump -i "$iface" -nn -w "$pcap_file" \
      '(ether proto 0x8892) or (ether proto 0x8893) or (udp portrange 34962-34964)' 2>&1
    
    echo ""
    echo "=== Capture Summary ==="
    
    if [[ -f "$pcap_file" ]]; then
      local pkt_count
      pkt_count=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | wc -l)
      echo "Packets captured: $pkt_count"
      echo "PCAP file: $pcap_file"
      
      echo ""
      echo "=== Sample Packets ==="
      tcpdump -r "$pcap_file" -nn -c 20 2>/dev/null || true
      
      echo ""
      echo "=== Unique Sources ==="
      tcpdump -r "$pcap_file" -nn -e 2>/dev/null | \
        awk '{print $2}' | sort -u | head -20 || true
    else
      echo "No packets captured or capture failed"
    fi
    
  } | tee "$log_file"
  
  LOG green "PCAP: $pcap_file"
  LOG green "Log: $log_file"
}
