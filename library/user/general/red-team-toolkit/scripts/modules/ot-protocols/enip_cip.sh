#!/bin/bash
# EtherNet/IP (CIP) module - identity, tag enumeration, read/write

rt_enip_cip() {
  local target
  target=$(IP_PICKER "EtherNet/IP target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "EtherNet/IP: $target" \
    "Device Identity (List Identity)" \
    "List Services" \
    "Enumerate Tags (if supported)" \
    "Read Tag" \
    "Write Tag")
  
  case "$choice" in
    1) enip_identity "$target" ;;
    2) enip_services "$target" ;;
    3) enip_tags "$target" ;;
    4) enip_read_tag "$target" ;;
    5) enip_write_tag "$target" ;;
    0|"") return ;;
  esac
}

enip_identity() {
  local target="$1"
  local port=44818
  local outfile="$ARTIFACT_DIR/enip_id_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "EtherNet/IP List Identity: $target"
  
  {
    echo "=== EtherNet/IP Identity: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    if have nmap; then
      nmap -p "$port" --script enip-info "$target" 2>&1
    else
      # Raw List Identity request
      # EtherNet/IP encapsulation: Command 0x0063 (List Identity)
      LOG "Sending raw List Identity..."
      printf '\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
        nc -u -w 3 "$target" "$port" 2>/dev/null | hexdump -C
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

enip_services() {
  local target="$1"
  local port=44818
  local outfile="$ARTIFACT_DIR/enip_services_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "EtherNet/IP List Services: $target"
  
  {
    echo "=== EtherNet/IP Services: $target ==="
    
    # Raw List Services request (command 0x0004)
    printf '\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
      nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C
      
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

enip_tags() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/enip_tags_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Enumerating tags on $target..."
  LOG "Note: Requires cpppo or pycomm3 on laptop"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    {
      echo "=== EtherNet/IP Tags: $target ==="
      laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    tags = plc.get_tag_list()
    for tag in tags[:50]:  # First 50
        print(f'{tag.tag_name}: {tag.data_type}')
\" 2>&1" || echo "pycomm3 not available or connection failed"
    } | tee "$outfile"
  else
    LOG red "Tag enumeration requires laptop mode with pycomm3"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

enip_read_tag() {
  local target="$1"
  
  local tag_name
  tag_name=$(TEXT_PICKER "Tag name" "Program:MainProgram.TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Reading tag '$tag_name' from $target"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    result = plc.read('$tag_name')
    print(f'Value: {result.value}')
    print(f'Type: {result.type}')
\" 2>&1" || LOG red "Read failed"
  else
    LOG red "Tag read requires laptop mode with pycomm3"
  fi
}

enip_write_tag() {
  local target="$1"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to EtherNet/IP tag on $target. This may affect process!"; then
    return 1
  fi
  
  local tag_name
  tag_name=$(TEXT_PICKER "Tag name" "Program:MainProgram.TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(TEXT_PICKER "Value" "0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING tag '$tag_name' = $value on $target"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    result = plc.write('$tag_name', $value)
    print(f'Write result: {result}')
\" 2>&1" || LOG red "Write failed"
  else
    LOG red "Tag write requires laptop mode with pycomm3"
  fi
}
