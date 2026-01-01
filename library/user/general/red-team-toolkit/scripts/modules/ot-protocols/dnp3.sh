#!/bin/bash
# DNP3 protocol module - enumeration, point read
# Used in power/water utilities, SCADA systems
# Default port: 20000/tcp

rt_dnp3() {
  local target
  target=$(IP_PICKER "DNP3 target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 20000)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "DNP3: $target:$port" \
    "Device Identification" \
    "Read Data Points" \
    "Scan for DNP3 Devices")
  
  case "$choice" in
    1) dnp3_identify "$target" "$port" ;;
    2) dnp3_read_points "$target" "$port" ;;
    3) dnp3_scan ;;
    0|"") return ;;
  esac
}

dnp3_identify() {
  local target="$1" port="$2"
  local outfile
  outfile="$ARTIFACT_DIR/dnp3_id_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "DNP3 device identification: $target:$port"
  
  {
    echo "=== DNP3 Device ID: $target:$port ==="
    echo "Timestamp: $(date)"
    echo ""
    
    if have nmap; then
      # Use nmap dnp3-info script if available
      nmap -p "$port" --script dnp3-info "$target" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "nmap -p $port --script dnp3-info $target 2>&1"
    else
      # Raw: Send DNP3 Request Link Status frame
      # Data Link Layer: 0x0564 (start bytes), length, ctrl, dest, src
      LOG "Sending raw Request Link Status..."
      # Request Link Status (control byte 0xC9)
      # Frame: 05 64 05 C9 01 00 00 00 (with CRC)
      printf '\x05\x64\x05\xc9\x01\x00\x00\x00\xff\xff' | \
        nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C || echo "No response or connection failed"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

dnp3_read_points() {
  local target="$1" port="$2"
  
  local src_addr
  src_addr=$(NUMBER_PICKER "Source address" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local dst_addr
  dst_addr=$(NUMBER_PICKER "Destination address" 10)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local point_type
  point_type=$(menu_pick "Point type" \
    "Binary Inputs (Class 1)" \
    "Analog Inputs (Class 30)" \
    "Binary Outputs (Class 10)" \
    "Analog Outputs (Class 40)" \
    "Counters (Class 20)")
  
  case "$point_type" in
    0|"") return ;;
  esac
  
  local outfile
  outfile="$ARTIFACT_DIR/dnp3_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Reading DNP3 points from $target (src:$src_addr dst:$dst_addr)"
  
  {
    echo "=== DNP3 Read Points: $target:$port ==="
    echo "Source: $src_addr, Destination: $dst_addr"
    echo "Point type: $point_type"
    echo ""
    
    if have nmap; then
      # Use nmap dnp3-read if available
      local nmap_args=""
      case "$point_type" in
        1) nmap_args="--script-args dnp3-read.object=1" ;;  # Binary Input
        2) nmap_args="--script-args dnp3-read.object=30" ;; # Analog Input
        3) nmap_args="--script-args dnp3-read.object=10" ;; # Binary Output
        4) nmap_args="--script-args dnp3-read.object=40" ;; # Analog Output
        5) nmap_args="--script-args dnp3-read.object=20" ;; # Counter
      esac
      # shellcheck disable=SC2086
      nmap -p "$port" --script dnp3-read $nmap_args "$target" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      # Use python dnp3 library on laptop
      local obj_group
      case "$point_type" in
        1) obj_group=1 ;;
        2) obj_group=30 ;;
        3) obj_group=10 ;;
        4) obj_group=40 ;;
        5) obj_group=20 ;;
      esac
      laptop_exec "python3 -c \"
from pydnp3 import opendnp3, asiodnp3
import time

# Simple DNP3 read - requires pydnp3 library
print('DNP3 point read requires pydnp3 library')
print('Object group: $obj_group')
print('Install: pip3 install pydnp3')
print('')
print('Alternative: use dnp3-master tool if available')
\" 2>&1" || echo "DNP3 read requires laptop with pydnp3 library"
    else
      LOG red "DNP3 read requires nmap with dnp3-read script or laptop mode"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

dnp3_scan() {
  local subnet
  subnet=$(TEXT_PICKER "Subnet to scan" "${TARGET_NETWORK:-192.168.1.0/24}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/dnp3_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Scanning for DNP3 devices (port 20000) in $subnet"
  
  with_spinner "Scanning DNP3..." _dnp3_scan_impl "$subnet" "$outfile"
  
  LOG green "Results: $outfile"
}

_dnp3_scan_impl() {
  local subnet="$1"
  local outfile="$2"
  
  {
    echo "=== DNP3 Device Scan ==="
    echo "Subnet: $subnet"
    echo "Timestamp: $(date)"
    echo ""
    
    if have nmap; then
      nmap -p 20000 --open -sV "$subnet" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "nmap -p 20000 --open -sV $subnet 2>&1"
    else
      # Fallback: Use netcat for port checking
      LOG "Using netcat fallback (slower)..."
      local base_ip
      base_ip="${subnet%/*}"
      base_ip="${base_ip%.*}"
      
      for i in $(seq 1 254); do
        local ip="${base_ip}.$i"
        if port_open "$ip" 20000 1; then
          echo "[+] DNP3 open: $ip:20000"
        fi
      done
    fi
  } | tee "$outfile"
}
