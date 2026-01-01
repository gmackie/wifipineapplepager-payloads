#!/bin/bash
# S7comm module - CPU info, memory read/write for Siemens S7 PLCs

# S7comm main menu
rt_s7comm() {
  local target
  target=$(IP_PICKER "S7comm target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local rack slot
  rack=$(NUMBER_PICKER "Rack (usually 0)" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  slot=$(NUMBER_PICKER "Slot (usually 2)" 2)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "S7comm: $target (R${rack}/S${slot})" \
    "Get CPU Info" \
    "Read Memory" \
    "Write Memory" \
    "List Program Blocks")
  
  case "$choice" in
    1) s7_cpu_info "$target" "$rack" "$slot" ;;
    2) s7_read_memory "$target" "$rack" "$slot" ;;
    3) s7_write_memory "$target" "$rack" "$slot" ;;
    4) s7_list_blocks "$target" "$rack" "$slot" ;;
    0|"") return ;;
  esac
}

# Get CPU identification
s7_cpu_info() {
  local target="$1" rack="$2" slot="$3"
  local port=102
  local outfile
  outfile="$ARTIFACT_DIR/s7_info_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "S7comm CPU Info: $target (rack $rack, slot $slot)"
  
  {
    echo "=== S7comm CPU Info: $target ==="
    echo "Timestamp: $(date)"
    echo "Rack: $rack, Slot: $slot"
    echo ""
    
    if have nmap; then
      # nmap s7-info script extracts module type, serial, firmware, PLC name
      nmap -p "$port" --script s7-info "$target" 2>&1
    elif have plcscan; then
      # plcscan can identify S7 PLCs
      plcscan -i "$target" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      # Use snap7 client via laptop
      laptop_exec "python3 -c \"
import snap7
client = snap7.client.Client()
try:
    client.connect('$target', $rack, $slot)
    info = client.get_cpu_info()
    print('Module Type:', info.ModuleTypeName.decode())
    print('Serial Number:', info.SerialNumber.decode())
    print('AS Name:', info.ASName.decode())
    print('Copyright:', info.Copyright.decode())
    print('Module Name:', info.ModuleName.decode())
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
\" 2>&1" || echo "snap7 not available or connection failed"
    else
      # Raw COTP connection test
      LOG "Testing S7comm connectivity (port $port)..."
      if port_open "$target" "$port" 3; then
        echo "Port $port OPEN - S7comm likely available"
        echo ""
        echo "For full identification, enable laptop mode with snap7 or use nmap"
      else
        echo "Port $port CLOSED or filtered"
      fi
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

# Read data block or memory area
s7_read_memory() {
  local target="$1" rack="$2" slot="$3"
  
  # Select memory area type
  local area_choice
  area_choice=$(menu_pick "Memory Area Type" \
    "DB (Data Block)" \
    "M (Markers/Flags)" \
    "I (Inputs)" \
    "Q (Outputs)")
  
  local area_type
  case "$area_choice" in
    1) area_type="DB" ;;
    2) area_type="M" ;;
    3) area_type="I" ;;
    4) area_type="Q" ;;
    0|"") return ;;
  esac
  
  local db_num=1
  if [[ "$area_type" == "DB" ]]; then
    db_num=$(NUMBER_PICKER "DB Number" 1)
    case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  fi
  
  local start_addr
  start_addr=$(NUMBER_PICKER "Start Address (byte)" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local length
  length=$(NUMBER_PICKER "Length (bytes)" 10)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/s7_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Reading ${area_type} from $target (addr $start_addr, len $length)"
  
  {
    echo "=== S7comm Read: $target ==="
    echo "Timestamp: $(date)"
    echo "Area: $area_type, DB: $db_num, Start: $start_addr, Length: $length"
    echo "Rack: $rack, Slot: $slot"
    echo ""
    
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      # Map area type to snap7 constants
      # S7AreaDB=0x84, S7AreaMK=0x83, S7AreaPE=0x81 (inputs), S7AreaPA=0x82 (outputs)
      local area_code
      case "$area_type" in
        DB) area_code="0x84" ;;
        M)  area_code="0x83" ;;
        I)  area_code="0x81" ;;
        Q)  area_code="0x82" ;;
      esac
      
      laptop_exec "python3 -c \"
import snap7
import binascii

client = snap7.client.Client()
try:
    client.connect('$target', $rack, $slot)
    
    # Read area
    data = client.read_area($area_code, $db_num, $start_addr, $length)
    
    # Hex dump
    print('Hex dump:')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{i:04X}: {hex_str:<48} {ascii_str}')
    
    print()
    print('Raw bytes:', binascii.hexlify(bytes(data)).decode())
    
    # Interpret common types
    if len(data) >= 2:
        import struct
        print()
        print('Interpreted values (if applicable):')
        print(f'  BYTE[0]: {data[0]}')
        if len(data) >= 2:
            print(f'  INT (bytes 0-1): {struct.unpack(\">h\", bytes(data[0:2]))[0]}')
            print(f'  WORD (bytes 0-1): {struct.unpack(\">H\", bytes(data[0:2]))[0]}')
        if len(data) >= 4:
            print(f'  DINT (bytes 0-3): {struct.unpack(\">i\", bytes(data[0:4]))[0]}')
            print(f'  REAL (bytes 0-3): {struct.unpack(\">f\", bytes(data[0:4]))[0]:.6f}')
    
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
\" 2>&1" || echo "snap7 read failed"
    else
      LOG red "Memory read requires laptop mode with python-snap7"
      echo "Install: pip3 install python-snap7"
      echo "Also requires libsnap7 library"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

# Write to memory area (SAFE_MODE gated)
s7_write_memory() {
  local target="$1" rack="$2" slot="$3"
  
  if ! check_passive; then return 1; fi
  
  LOG red "WARNING: Writing to PLC memory can cause:"
  LOG red "  - Process disruption"
  LOG red "  - Equipment damage"
  LOG red "  - Safety hazards"
  
  if ! confirm_danger "WRITE to S7 PLC memory on $target. This may affect industrial process!"; then
    return 1
  fi
  
  # Select memory area type
  local area_choice
  area_choice=$(menu_pick "Memory Area Type" \
    "DB (Data Block)" \
    "M (Markers/Flags)" \
    "Q (Outputs)")
  
  local area_type
  case "$area_choice" in
    1) area_type="DB" ;;
    2) area_type="M" ;;
    3) area_type="Q" ;;
    0|"") return ;;
  esac
  
  local db_num=1
  if [[ "$area_type" == "DB" ]]; then
    db_num=$(NUMBER_PICKER "DB Number" 1)
    case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  fi
  
  local addr
  addr=$(NUMBER_PICKER "Address (byte offset)" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local data_type
  data_type=$(menu_pick "Data Type" \
    "BYTE (0-255)" \
    "INT (-32768 to 32767)" \
    "BOOL (0 or 1)")
  
  local value
  case "$data_type" in
    1)
      value=$(NUMBER_PICKER "BYTE value" 0)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    2)
      value=$(NUMBER_PICKER "INT value" 0)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    3)
      value=$(NUMBER_PICKER "BOOL value (0/1)" 0)
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      ;;
    0|"") return ;;
  esac
  
  LOG red "WRITING ${area_type}${db_num}.DBB${addr} = $value on $target"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    local area_code
    case "$area_type" in
      DB) area_code="0x84" ;;
      M)  area_code="0x83" ;;
      Q)  area_code="0x82" ;;
    esac
    
    local write_code
    case "$data_type" in
      1) write_code="client.write_area($area_code, $db_num, $addr, bytearray([$value]))" ;;
      2) write_code="import struct; client.write_area($area_code, $db_num, $addr, bytearray(struct.pack('>h', $value)))" ;;
      3) write_code="client.write_area($area_code, $db_num, $addr, bytearray([1 if $value else 0]))" ;;
    esac
    
    laptop_exec "python3 -c \"
import snap7
client = snap7.client.Client()
try:
    client.connect('$target', $rack, $slot)
    $write_code
    print('Write successful')
    client.disconnect()
except Exception as e:
    print(f'Write failed: {e}')
\" 2>&1" || LOG red "Write operation failed"
  else
    LOG red "Memory write requires laptop mode with python-snap7"
  fi
}

# List program blocks (OB, FC, FB, DB)
s7_list_blocks() {
  local target="$1" rack="$2" slot="$3"
  local outfile
  outfile="$ARTIFACT_DIR/s7_blocks_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Listing program blocks on $target"
  
  {
    echo "=== S7comm Program Blocks: $target ==="
    echo "Timestamp: $(date)"
    echo "Rack: $rack, Slot: $slot"
    echo ""
    
    if have nmap; then
      # nmap can enumerate some block info
      nmap -p 102 --script s7-info "$target" 2>&1
      echo ""
    fi
    
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "python3 -c \"
import snap7

client = snap7.client.Client()
try:
    client.connect('$target', $rack, $slot)
    
    block_types = [
        ('OB', snap7.types.Block_OB),
        ('FC', snap7.types.Block_FC),
        ('FB', snap7.types.Block_FB),
        ('DB', snap7.types.Block_DB),
        ('SFC', snap7.types.Block_SFC),
        ('SFB', snap7.types.Block_SFB),
    ]
    
    for name, block_type in block_types:
        try:
            blocks = client.list_blocks_of_type(block_type, 1024)
            if blocks:
                print(f'{name} blocks: {len(blocks)}')
                # Show first 20
                block_list = ', '.join(str(b) for b in blocks[:20])
                if len(blocks) > 20:
                    block_list += f', ... ({len(blocks)-20} more)'
                print(f'  {block_list}')
        except:
            pass
    
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
\" 2>&1" || echo "Block enumeration failed"
    else
      echo "Full block listing requires laptop mode with python-snap7"
      echo ""
      echo "To enable:"
      echo "  1. Set LAPTOP_ENABLED=1 in config.sh"
      echo "  2. Install snap7: pip3 install python-snap7"
      echo "  3. Install libsnap7 library on laptop"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}
