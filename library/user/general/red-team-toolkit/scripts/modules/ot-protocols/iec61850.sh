#!/bin/bash
# IEC 61850 module - MMS browse, GOOSE sniff
# Used in substation automation systems
# MMS uses port 102/tcp, GOOSE uses Ethertype 0x88B8

rt_iec61850() {
  local choice
  choice=$(menu_pick "IEC 61850 Protocol" \
    "MMS Server Directory" \
    "Read Data Object" \
    "GOOSE Passive Capture" \
    "Scan for MMS Servers")
  
  case "$choice" in
    1) iec61850_directory ;;
    2) iec61850_read ;;
    3) iec61850_goose_sniff ;;
    4) iec61850_scan ;;
    0|"") return ;;
  esac
}

iec61850_directory() {
  local target
  target=$(IP_PICKER "MMS server IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 102)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/iec61850_directory_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Getting MMS server directory: $target:$port"
  
  {
    echo "=== IEC 61850 MMS Server Directory ==="
    echo "Target: $target:$port"
    echo "Timestamp: $(date)"
    echo ""
    
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      # Use libiec61850 client tools via laptop
      laptop_exec "
if command -v iec61850_client >/dev/null 2>&1; then
  iec61850_client -h $target -p $port -d 2>&1
elif command -v mms_client >/dev/null 2>&1; then
  mms_client -h $target -p $port directory 2>&1
elif python3 -c 'import iec61850' 2>/dev/null; then
  python3 -c \"
import iec61850
con = iec61850.IedConnection_create()
err = iec61850.IedConnection_connect(con, '$target', $port)
if err == iec61850.IED_ERROR_OK:
    devices = iec61850.IedConnection_getLogicalDeviceList(con)
    device = iec61850.LinkedList_getNext(devices)
    while device:
        ld_name = iec61850.LinkedList_getData(device)
        print(f'Logical Device: {ld_name}')
        nodes = iec61850.IedConnection_getLogicalDeviceDirectory(con, ld_name)
        node = iec61850.LinkedList_getNext(nodes)
        while node:
            ln_name = iec61850.LinkedList_getData(node)
            print(f'  Logical Node: {ln_name}')
            node = iec61850.LinkedList_getNext(node)
        iec61850.LinkedList_destroy(nodes)
        device = iec61850.LinkedList_getNext(device)
    iec61850.LinkedList_destroy(devices)
    iec61850.IedConnection_close(con)
else:
    print(f'Connection failed: error code {err}')
iec61850.IedConnection_destroy(con)
\" 2>&1
else
  echo 'No IEC 61850 tools available on laptop'
  echo 'Install: libiec61850 or python iec61850 library'
  echo ''
  echo 'Fallback: checking port connectivity...'
  nc -zv $target $port 2>&1 || echo 'Port $port not reachable'
fi
" || echo "Connection failed"
    elif have python3 && python3 -c 'import iec61850' 2>/dev/null; then
      # Local python with iec61850 library
      python3 -c "
import iec61850
con = iec61850.IedConnection_create()
err = iec61850.IedConnection_connect(con, '$target', $port)
if err == iec61850.IED_ERROR_OK:
    devices = iec61850.IedConnection_getLogicalDeviceList(con)
    device = iec61850.LinkedList_getNext(devices)
    while device:
        ld_name = iec61850.LinkedList_getData(device)
        print(f'Logical Device: {ld_name}')
        nodes = iec61850.IedConnection_getLogicalDeviceDirectory(con, ld_name)
        node = iec61850.LinkedList_getNext(nodes)
        while node:
            ln_name = iec61850.LinkedList_getData(node)
            print(f'  Logical Node: {ln_name}')
            node = iec61850.LinkedList_getNext(node)
        iec61850.LinkedList_destroy(nodes)
        device = iec61850.LinkedList_getNext(device)
    iec61850.LinkedList_destroy(devices)
    iec61850.IedConnection_close(con)
else:
    print(f'Connection failed: error code {err}')
iec61850.IedConnection_destroy(con)
" 2>&1
    else
      # Fallback: basic connectivity check and port probe
      LOG "No IEC 61850 library available, performing basic probe..."
      echo ""
      echo "Port connectivity check:"
      if port_open "$target" "$port" 3; then
        echo "[+] Port $port is open (MMS/TPKT likely)"
        echo ""
        echo "Sending TPKT/COTP connection request..."
        # TPKT header + COTP CR (Connection Request)
        # This is a minimal probe to check for MMS service
        printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02' | \
          nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C | head -20
      else
        echo "[-] Port $port is closed or filtered"
      fi
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

iec61850_read() {
  local target
  target=$(IP_PICKER "MMS server IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 102)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local ld_name
  ld_name=$(TEXT_PICKER "Logical Device" "LD0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local data_path
  data_path=$(TEXT_PICKER "Data Object Path" "LLN0\$ST\$Mod\$stVal")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  # Construct full reference: LD/LN$FC$DO$DA
  local full_ref="${ld_name}/${data_path}"
  
  local outfile
  outfile="$ARTIFACT_DIR/iec61850_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Reading IEC 61850 data object: $full_ref"
  
  {
    echo "=== IEC 61850 Read Data Object ==="
    echo "Target: $target:$port"
    echo "Reference: $full_ref"
    echo "Timestamp: $(date)"
    echo ""
    
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "
if command -v iec61850_client >/dev/null 2>&1; then
  iec61850_client -h $target -p $port -r '$full_ref' 2>&1
elif command -v mms_client >/dev/null 2>&1; then
  mms_client -h $target -p $port read '$full_ref' 2>&1
elif python3 -c 'import iec61850' 2>/dev/null; then
  python3 -c \"
import iec61850
con = iec61850.IedConnection_create()
err = iec61850.IedConnection_connect(con, '$target', $port)
if err == iec61850.IED_ERROR_OK:
    fc_str = '$data_path'.split('\\\$')[1] if '\\\$' in '$data_path' else 'ST'
    fc_map = {'ST': iec61850.IEC61850_FC_ST, 'MX': iec61850.IEC61850_FC_MX,
              'CO': iec61850.IEC61850_FC_CO, 'CF': iec61850.IEC61850_FC_CF}
    fc = fc_map.get(fc_str, iec61850.IEC61850_FC_ST)
    value = iec61850.IedConnection_readObject(con, '$full_ref', fc)
    if value:
        print(f'Value: {iec61850.MmsValue_toString(value)}')
        print(f'Type: {iec61850.MmsValue_getTypeString(value)}')
    else:
        print('Read failed or object not found')
    iec61850.IedConnection_close(con)
else:
    print(f'Connection failed: error code {err}')
iec61850.IedConnection_destroy(con)
\" 2>&1
else
  echo 'No IEC 61850 tools available on laptop'
  echo 'Install: libiec61850 or python iec61850 library'
fi
" || echo "Read operation failed"
    elif have python3 && python3 -c 'import iec61850' 2>/dev/null; then
      python3 -c "
import iec61850
con = iec61850.IedConnection_create()
err = iec61850.IedConnection_connect(con, '$target', $port)
if err == iec61850.IED_ERROR_OK:
    fc_str = '$data_path'.split('\$')[1] if '\$' in '$data_path' else 'ST'
    fc_map = {'ST': iec61850.IEC61850_FC_ST, 'MX': iec61850.IEC61850_FC_MX,
              'CO': iec61850.IEC61850_FC_CO, 'CF': iec61850.IEC61850_FC_CF}
    fc = fc_map.get(fc_str, iec61850.IEC61850_FC_ST)
    value = iec61850.IedConnection_readObject(con, '$full_ref', fc)
    if value:
        print(f'Value: {iec61850.MmsValue_toString(value)}')
        print(f'Type: {iec61850.MmsValue_getTypeString(value)}')
    else:
        print('Read failed or object not found')
    iec61850.IedConnection_close(con)
else:
    print(f'Connection failed: error code {err}')
iec61850.IedConnection_destroy(con)
" 2>&1
    else
      LOG red "IEC 61850 read requires libiec61850 or python iec61850 library"
      echo "Required: libiec61850 client tools or python iec61850 module"
      echo "Consider enabling laptop mode for this operation"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

iec61850_goose_sniff() {
  local iface
  iface=$(TEXT_PICKER "Network interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local duration
  duration=$(NUMBER_PICKER "Capture duration (sec)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  # Cap at MAX_DURATION_SEC for safety
  if [[ "$duration" -gt "${MAX_DURATION_SEC:-300}" ]]; then
    duration="${MAX_DURATION_SEC:-300}"
    LOG "Duration capped at $duration seconds"
  fi
  
  local ts_now
  ts_now=$(ts)
  local pcap_file="$ARTIFACT_DIR/goose_capture_${ts_now}.pcap"
  local txt_file="$ARTIFACT_DIR/goose_capture_${ts_now}.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Starting GOOSE capture on $iface for ${duration}s"
  LOG "GOOSE uses Ethertype 0x88B8 (IEC 61850 layer 2)"
  
  {
    echo "=== IEC 61850 GOOSE Capture ==="
    echo "Interface: $iface"
    echo "Duration: ${duration}s"
    echo "Timestamp: $(date)"
    echo "PCAP: $pcap_file"
    echo ""
    
    if have tcpdump; then
      LOG "Capturing GOOSE frames (Ethertype 0x88b8)..."
      
      # Capture GOOSE traffic - Ethertype 0x88b8
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -w "$pcap_file" 'ether proto 0x88b8' 2>&1 &
      local tcpdump_pid=$!
      
      # Show live summary while capturing
      sleep 2
      if [[ -f "$pcap_file" ]]; then
        LOG "Capture in progress..."
      fi
      
      # Wait for tcpdump to finish
      wait $tcpdump_pid 2>/dev/null || true
      
      echo ""
      echo "=== Capture Summary ==="
      
      if [[ -s "$pcap_file" ]]; then
        local pkt_count
        pkt_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l || echo "0")
        echo "Packets captured: $pkt_count"
        echo ""
        
        if [[ "$pkt_count" -gt 0 ]]; then
          echo "=== GOOSE Frame Details ==="
          # Parse GOOSE headers if tshark available
          if have tshark; then
            tshark -r "$pcap_file" -T fields \
              -e eth.src -e eth.dst \
              -e goose.gocbRef -e goose.datSet \
              -e goose.goID -e goose.stNum -e goose.sqNum \
              2>/dev/null | head -20 || \
            tcpdump -r "$pcap_file" -nn -v 2>/dev/null | head -30
          else
            # Fallback to basic tcpdump output
            tcpdump -r "$pcap_file" -nn -e 2>/dev/null | head -20
          fi
          
          echo ""
          echo "=== Unique GOOSE Publishers ==="
          tcpdump -r "$pcap_file" -nn -e 2>/dev/null | \
            awk '{print $2}' | sort -u | head -10
        fi
      else
        echo "No GOOSE frames captured"
        echo "Verify: interface correct, GOOSE traffic present on segment"
      fi
    else
      LOG red "tcpdump required for GOOSE capture"
      echo "Install tcpdump or use laptop mode"
    fi
  } | tee "$txt_file"
  
  if [[ -s "$pcap_file" ]]; then
    LOG green "PCAP saved: $pcap_file"
  fi
  LOG green "Summary: $txt_file"
}

iec61850_scan() {
  local subnet
  subnet=$(TEXT_PICKER "Subnet to scan" "${TARGET_NETWORK:-192.168.1.0/24}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/iec61850_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Scanning for IEC 61850 MMS servers (port 102) in $subnet"
  
  with_spinner "Scanning MMS..." _iec61850_scan_impl "$subnet" "$outfile"
  
  LOG green "Results: $outfile"
}

_iec61850_scan_impl() {
  local subnet="$1"
  local outfile="$2"
  
  {
    echo "=== IEC 61850 MMS Server Scan ==="
    echo "Subnet: $subnet"
    echo "Port: 102 (ISO-TSAP / MMS)"
    echo "Timestamp: $(date)"
    echo ""
    
    if have nmap; then
      # Port 102 is used by ISO-TSAP (TPKT/COTP/MMS stack)
      nmap -p 102 --open -sV "$subnet" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "nmap -p 102 --open -sV $subnet 2>&1"
    else
      # Fallback: manual port scan
      LOG "Using netcat fallback (slower)..."
      local base_ip
      base_ip="${subnet%/*}"
      base_ip="${base_ip%.*}"
      
      for i in $(seq 1 254); do
        local ip="${base_ip}.$i"
        if port_open "$ip" 102 1; then
          echo "[+] MMS port open: $ip:102"
        fi
      done
    fi
    
    echo ""
    echo "Note: Port 102 hosts indicate potential IEC 61850 MMS servers"
    echo "Use 'MMS Server Directory' to enumerate logical devices"
  } | tee "$outfile"
}
