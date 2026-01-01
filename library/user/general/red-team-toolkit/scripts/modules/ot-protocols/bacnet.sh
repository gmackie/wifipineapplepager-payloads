#!/bin/bash
# BACnet module - device discovery, property read/write
# Port 47808/udp - Building Automation and Control Networks

rt_bacnet() {
  local choice
  choice=$(menu_pick "BACnet Operations" \
    "Who-Is Discovery (broadcast)" \
    "Read Property" \
    "Write Property" \
    "Enumerate Objects")
  
  case "$choice" in
    1) bacnet_whois ;;
    2) bacnet_read_property ;;
    3) bacnet_write_property ;;
    4) bacnet_enumerate ;;
    0|"") return ;;
  esac
}

bacnet_whois() {
  local outfile
  outfile="$ARTIFACT_DIR/bacnet_discovery_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "BACnet Who-Is Discovery (broadcast on port 47808/udp)"
  
  {
    echo "=== BACnet Who-Is Discovery ==="
    echo "Timestamp: $(date)"
    echo "Network: ${TARGET_NETWORK:-broadcast}"
    echo ""
    
    if have bacwi; then
      # bacnet-stack Who-Is tool
      LOG "Using bacwi (bacnet-stack)..."
      run_timeboxed 30 bacwi 2>&1 | while read -r line; do
        echo "$line"
        # Parse I-Am responses: Device ID, IP, vendor
        if [[ "$line" =~ Device\ ID:\ ([0-9]+) ]]; then
          echo "  -> Device found: ${BASH_REMATCH[1]}"
        fi
      done
    elif have nmap; then
      # Nmap BACnet info script
      LOG "Using nmap bacnet-info script..."
      local target_range="${TARGET_NETWORK:-192.168.1.0/24}"
      nmap -sU -p 47808 --script bacnet-info "$target_range" 2>&1
    else
      # Raw Who-Is broadcast via netcat
      LOG "Sending raw Who-Is broadcast..."
      # BACnet/IP header: BVLC type=0x81, function=0x0b (broadcast), length=12
      # APDU: Who-Is (unconfirmed, service=0x08)
      local bacnet_whois_pdu
      bacnet_whois_pdu=$(printf '\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08')
      echo "$bacnet_whois_pdu" | nc -u -w 5 -b 255.255.255.255 47808 2>/dev/null | hexdump -C || true
      
      # Also try specific broadcast if TARGET_NETWORK defined
      if [[ -n "$TARGET_NETWORK" ]]; then
        local broadcast_ip
        broadcast_ip=$(echo "$TARGET_NETWORK" | sed 's/\.[0-9]*\/.*/.255/')
        LOG "Trying broadcast to $broadcast_ip..."
        echo "$bacnet_whois_pdu" | nc -u -w 5 "$broadcast_ip" 47808 2>/dev/null | hexdump -C || true
      fi
    fi
    
    echo ""
    echo "=== Discovery Complete ==="
  } | tee "$outfile"
  
  LOG green "Results saved: $outfile"
}

bacnet_read_property() {
  local target
  target=$(IP_PICKER "BACnet device IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local device_instance
  device_instance=$(NUMBER_PICKER "Device instance" 1234)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local object_type
  object_type=$(menu_pick "Object Type" \
    "Analog Input (0)" \
    "Analog Output (1)" \
    "Analog Value (2)" \
    "Binary Input (3)" \
    "Binary Output (4)" \
    "Binary Value (5)" \
    "Device (8)" \
    "Custom...")
  
  local obj_type_num
  case "$object_type" in
    1) obj_type_num=0 ;;
    2) obj_type_num=1 ;;
    3) obj_type_num=2 ;;
    4) obj_type_num=3 ;;
    5) obj_type_num=4 ;;
    6) obj_type_num=5 ;;
    7) obj_type_num=8 ;;
    8)
      obj_type_num=$(NUMBER_PICKER "Object type number" 0)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    0|"") return ;;
  esac
  
  local object_instance
  object_instance=$(NUMBER_PICKER "Object instance" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local property_id
  property_id=$(menu_pick "Property" \
    "Present Value (85)" \
    "Object Name (77)" \
    "Description (28)" \
    "Object List (76)" \
    "Custom...")
  
  local prop_id_num
  case "$property_id" in
    1) prop_id_num=85 ;;
    2) prop_id_num=77 ;;
    3) prop_id_num=28 ;;
    4) prop_id_num=76 ;;
    5)
      prop_id_num=$(NUMBER_PICKER "Property ID" 85)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    0|"") return ;;
  esac
  
  local outfile
  outfile="$ARTIFACT_DIR/bacnet_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Reading BACnet property from $target"
  LOG "Device: $device_instance, Object: $obj_type_num:$object_instance, Property: $prop_id_num"
  
  {
    echo "=== BACnet Read Property ==="
    echo "Target: $target"
    echo "Device Instance: $device_instance"
    echo "Object: Type=$obj_type_num, Instance=$object_instance"
    echo "Property ID: $prop_id_num"
    echo "Timestamp: $(date)"
    echo ""
    
    if have bacrp; then
      # bacnet-stack Read Property tool
      bacrp "$device_instance" "$obj_type_num" "$object_instance" "$prop_id_num" 2>&1
    elif have nmap; then
      LOG "Using nmap for basic device info..."
      nmap -sU -p 47808 --script bacnet-info "$target" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "bacrp $device_instance $obj_type_num $object_instance $prop_id_num 2>&1" || \
      laptop_exec "python3 -c \"
import BAC0
bacnet = BAC0.lite(ip='$target')
try:
    result = bacnet.read('$target $obj_type_num:$object_instance $prop_id_num')
    print(f'Value: {result}')
except Exception as e:
    print(f'Error: {e}')
\" 2>&1"
    else
      LOG red "bacrp (bacnet-stack) or laptop mode required for property read"
    fi
  } | tee "$outfile"
  
  LOG green "Results saved: $outfile"
}

bacnet_write_property() {
  if ! check_passive; then return 1; fi
  
  local target
  target=$(IP_PICKER "BACnet device IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  if ! confirm_danger "WRITE to BACnet device $target. This may affect building systems (HVAC, lighting, access control)!"; then
    return 1
  fi
  
  local device_instance
  device_instance=$(NUMBER_PICKER "Device instance" 1234)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local object_type
  object_type=$(menu_pick "Object Type" \
    "Analog Output (1)" \
    "Analog Value (2)" \
    "Binary Output (4)" \
    "Binary Value (5)" \
    "Custom...")
  
  local obj_type_num
  case "$object_type" in
    1) obj_type_num=1 ;;
    2) obj_type_num=2 ;;
    3) obj_type_num=4 ;;
    4) obj_type_num=5 ;;
    5)
      obj_type_num=$(NUMBER_PICKER "Object type number" 2)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    0|"") return ;;
  esac
  
  local object_instance
  object_instance=$(NUMBER_PICKER "Object instance" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(TEXT_PICKER "Value to write" "0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local priority
  priority=$(NUMBER_PICKER "Priority (1-16, 8=manual)" 8)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WARNING: Writing to BACnet device!"
  LOG red "Target: $target, Device: $device_instance"
  LOG red "Object: $obj_type_num:$object_instance, Value: $value, Priority: $priority"
  
  if have bacwp; then
    # bacnet-stack Write Property tool
    # bacwp device-instance object-type object-instance property-id priority index tag value
    bacwp "$device_instance" "$obj_type_num" "$object_instance" 85 "$priority" -1 4 "$value" 2>&1
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "bacwp $device_instance $obj_type_num $object_instance 85 $priority -1 4 $value 2>&1" || \
    laptop_exec "python3 -c \"
import BAC0
bacnet = BAC0.lite(ip='$target')
try:
    bacnet.write('$target $obj_type_num:$object_instance presentValue $value - $priority')
    print('Write completed')
except Exception as e:
    print(f'Error: {e}')
\" 2>&1"
  else
    LOG red "bacwp (bacnet-stack) or laptop mode required for write operations"
    return 1
  fi
}

bacnet_enumerate() {
  local target
  target=$(IP_PICKER "BACnet device IP" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local device_instance
  device_instance=$(NUMBER_PICKER "Device instance" 1234)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/bacnet_objects_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Enumerating objects on BACnet device $target (instance $device_instance)"
  
  {
    echo "=== BACnet Object Enumeration ==="
    echo "Target: $target"
    echo "Device Instance: $device_instance"
    echo "Timestamp: $(date)"
    echo ""
    
    if have bacepics; then
      # bacnet-stack EPICS tool - enumerate all objects
      LOG "Using bacepics for full enumeration..."
      run_timeboxed 60 bacepics "$device_instance" 2>&1
    elif have bacrp; then
      # Read object-list property (76) from device object (type 8)
      LOG "Reading object-list from device..."
      bacrp "$device_instance" 8 "$device_instance" 76 2>&1 | while read -r line; do
        echo "$line"
        # Try to get object names for discovered objects
        if [[ "$line" =~ \(([0-9]+),\ *([0-9]+)\) ]]; then
          local otype="${BASH_REMATCH[1]}"
          local oinst="${BASH_REMATCH[2]}"
          local oname
          oname=$(bacrp "$device_instance" "$otype" "$oinst" 77 2>/dev/null || echo "")
          [[ -n "$oname" ]] && echo "  -> Name: $oname"
        fi
      done
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "python3 -c \"
import BAC0
bacnet = BAC0.lite()
try:
    device = BAC0.device('$target', $device_instance, bacnet)
    print('Objects found:')
    for point in device.points:
        print(f'  {point.properties.name}: {point.properties.type} ({point.properties.address})')
except Exception as e:
    print(f'Error: {e}')
\" 2>&1"
    else
      # Fallback: use nmap for basic info
      LOG "Using nmap for basic device info..."
      if have nmap; then
        nmap -sU -p 47808 --script bacnet-info "$target" 2>&1
      else
        LOG red "bacrp/bacepics (bacnet-stack) or laptop mode required for enumeration"
      fi
    fi
    
    echo ""
    echo "=== Enumeration Complete ==="
  } | tee "$outfile"
  
  LOG green "Results saved: $outfile"
}
