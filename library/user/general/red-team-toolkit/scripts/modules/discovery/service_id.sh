#!/bin/bash
# Service identification and banner grabbing

rt_service_id() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "Service ID: $target" \
    "Banner Grab (common ports)" \
    "Full Service Scan (nmap -sV)" \
    "OT Port Check")
  
  case "$choice" in
    1) rt_banner_grab "$target" ;;
    2) rt_service_scan "$target" ;;
    3) rt_ot_port_check "$target" ;;
    0|"") return ;;
  esac
}

rt_banner_grab() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/banners_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  # Common ports to banner grab
  local ports=(21 22 23 25 80 110 143 443 445 993 995 3306 3389 5432 8080)
  
  LOG blue "Banner grabbing $target..."
  
  {
    for port in "${ports[@]}"; do
      if port_open "$target" "$port" 2; then
        echo "=== $target:$port ==="
        if have nc; then
          echo "" | nc -w 3 "$target" "$port" 2>/dev/null | head -5
        elif have bash; then
          timeout 3 bash -c "exec 3<>/dev/tcp/$target/$port; cat <&3" 2>/dev/null | head -5
        fi
        echo ""
      fi
    done
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

rt_service_scan() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/services_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Service scan: $target"
  
  if have nmap; then
    with_spinner "Service scan" bash -c "nmap -sV -Pn '$target' | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -sV -Pn $target -oN $LAPTOP_RESULTS_DIR/services.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/services.txt" "$outfile"
  else
    LOG red "nmap required for service scan"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_ot_port_check() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/ot_ports_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  # OT-specific ports
  declare -A ot_ports=(
    [102]="S7comm (Siemens)"
    [502]="Modbus/TCP"
    [2222]="EtherNet/IP (implicit)"
    [4840]="OPC UA"
    [4843]="OPC UA (secure)"
    [18245]="GE SRTP"
    [20000]="DNP3"
    [34962]="PROFINET RT"
    [34963]="PROFINET RT"
    [34964]="PROFINET RT"
    [44818]="EtherNet/IP (explicit)"
    [47808]="BACnet"
    [1911]="Niagara Fox"
    [9600]="OMRON FINS"
  )
  
  LOG blue "OT port check: $target"
  
  {
    echo "OT Port Scan: $target"
    echo "========================"
    for port in "${!ot_ports[@]}"; do
      local desc="${ot_ports[$port]}"
      if port_open "$target" "$port" 2; then
        echo "[OPEN] $port - $desc"
      fi
    done
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}
