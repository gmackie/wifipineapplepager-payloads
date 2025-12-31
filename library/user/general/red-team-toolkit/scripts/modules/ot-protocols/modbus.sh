#!/bin/bash
# Modbus/TCP module - scan, read, write

rt_modbus() {
  local target
  target=$(IP_PICKER "Modbus target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 502)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "Modbus: $target:$port" \
    "Device Identification" \
    "Read Coils (0x)" \
    "Read Discrete Inputs (1x)" \
    "Read Holding Registers (4x)" \
    "Read Input Registers (3x)" \
    "Write Single Coil" \
    "Write Single Register")
  
  case "$choice" in
    1) modbus_identify "$target" "$port" ;;
    2) modbus_read "$target" "$port" "coils" ;;
    3) modbus_read "$target" "$port" "discrete" ;;
    4) modbus_read "$target" "$port" "holding" ;;
    5) modbus_read "$target" "$port" "input" ;;
    6) modbus_write_coil "$target" "$port" ;;
    7) modbus_write_register "$target" "$port" ;;
    0|"") return ;;
  esac
}

modbus_identify() {
  local target="$1" port="$2"
  local outfile
  outfile="$ARTIFACT_DIR/modbus_id_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Modbus device identification: $target:$port"
  
  {
    echo "=== Modbus Device ID: $target:$port ==="
    echo "Timestamp: $(date)"
    echo ""
    
    if have mbpoll; then
      # Read Device Identification (function 0x2B/0x0E)
      mbpoll -a 1 -t 0 -r 0 -c 1 -1 "$target" -p "$port" 2>&1 || true
    elif have nmap; then
      nmap -p "$port" --script modbus-discover "$target" 2>&1
    else
      # Raw: Send Report Server ID (0x11)
      LOG "Sending raw Report Server ID..."
      printf '\x00\x01\x00\x00\x00\x02\x01\x11' | \
        nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

modbus_read() {
  local target="$1" port="$2" type="$3"
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID (slave)" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local start_addr
  start_addr=$(NUMBER_PICKER "Start address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local count
  count=$(NUMBER_PICKER "Count" 10)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/modbus_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  local mbpoll_type
  case "$type" in
    coils) mbpoll_type=0 ;;
    discrete) mbpoll_type=1 ;;
    holding) mbpoll_type=4 ;;
    input) mbpoll_type=3 ;;
  esac
  
  LOG blue "Reading $type from $target (unit $unit_id, addr $start_addr, count $count)"
  
  {
    echo "=== Modbus Read: $type ==="
    echo "Target: $target:$port, Unit: $unit_id"
    echo "Address: $start_addr, Count: $count"
    echo ""
    
    if have mbpoll; then
      mbpoll -a "$unit_id" -t "$mbpoll_type" -r "$start_addr" -c "$count" -1 \
        "$target" -p "$port" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "mbpoll -a $unit_id -t $mbpoll_type -r $start_addr -c $count -1 $target -p $port"
    else
      LOG red "mbpoll not available"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

modbus_write_coil() {
  local target="$1" port="$2"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to Modbus coil on $target. This may affect process!"; then
    return 1
  fi
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local addr
  addr=$(NUMBER_PICKER "Coil address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(NUMBER_PICKER "Value (0=OFF, 1=ON)" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING coil $addr = $value on $target"
  
  if have mbpoll; then
    mbpoll -a "$unit_id" -t 0 -r "$addr" -1 "$target" -p "$port" -- "$value"
  else
    LOG red "mbpoll required for write operations"
  fi
}

modbus_write_register() {
  local target="$1" port="$2"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to Modbus register on $target. This may affect process!"; then
    return 1
  fi
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local addr
  addr=$(NUMBER_PICKER "Register address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(NUMBER_PICKER "Value" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING register $addr = $value on $target"
  
  if have mbpoll; then
    mbpoll -a "$unit_id" -t 4 -r "$addr" -1 "$target" -p "$port" -- "$value"
  else
    LOG red "mbpoll required for write operations"
  fi
}
