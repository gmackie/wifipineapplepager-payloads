#!/bin/bash
# SNMP enumeration and community string brute force

rt_snmp_enum() {
  local target
  target=$(IP_PICKER "SNMP target" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "SNMP: $target" \
    "Community String Brute Force" \
    "SNMP Walk (with known community)" \
    "System Info (sysDescr, sysName)")
  
  case "$choice" in
    1) snmp_brute "$target" ;;
    2) snmp_walk "$target" ;;
    3) snmp_sysinfo "$target" ;;
    0|"") return ;;
  esac
}

snmp_brute() {
  local target="$1"
  local outfile
  outfile="$ARTIFACT_DIR/snmp_brute_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  if ! check_passive; then return 1; fi
  
  LOG blue "SNMP community string brute force: $target"
  
  {
    echo "=== SNMP Brute Force: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    local wordlist="$TOOLKIT_DIR/wordlists/snmp-communities.txt"
    
    if have onesixtyone && [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      LOG "Using onesixtyone..."
      laptop_exec "onesixtyone -c /dev/stdin $target" < "$wordlist"
    elif have snmpwalk; then
      LOG "Using snmpwalk..."
      while read -r community; do
        [[ -z "$community" || "$community" == \#* ]] && continue
        
        local result
        result=$(snmpwalk -v2c -c "$community" "$target" sysDescr.0 2>&1)
        
        if [[ "$result" != *"Timeout"* && "$result" != *"Unknown"* ]]; then
          echo "[+] VALID: $community"
          echo "    $result"
        fi
      done < "$wordlist"
    elif have snmpget; then
      LOG "Using snmpget..."
      while read -r community; do
        [[ -z "$community" || "$community" == \#* ]] && continue
        
        if snmpget -v2c -c "$community" "$target" sysDescr.0 2>/dev/null | grep -q "STRING"; then
          echo "[+] VALID: $community"
        fi
      done < "$wordlist"
    else
      LOG red "Need snmpwalk, snmpget, or onesixtyone"
      return 1
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

snmp_walk() {
  local target="$1"
  
  local community
  community=$(TEXT_PICKER "Community string" "public")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/snmp_walk_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "SNMP walk: $target (community: $community)"
  
  if have snmpwalk; then
    with_spinner "SNMP walk" bash -c "snmpwalk -v2c -c '$community' '$target' | head -200 | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "snmpwalk -v2c -c '$community' '$target'" | head -200 | tee "$outfile"
  else
    LOG red "snmpwalk not available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

snmp_sysinfo() {
  local target="$1"
  
  local community
  community=$(TEXT_PICKER "Community string" "public")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "SNMP system info: $target"
  
  local oids=(
    "sysDescr.0"
    "sysObjectID.0"
    "sysName.0"
    "sysLocation.0"
    "sysContact.0"
    "sysUpTime.0"
  )
  
  for oid in "${oids[@]}"; do
    local result
    if have snmpget; then
      result=$(snmpget -v2c -c "$community" "$target" "$oid" 2>/dev/null)
    elif have snmpwalk; then
      result=$(snmpwalk -v2c -c "$community" "$target" "$oid" 2>/dev/null)
    fi
    
    if [[ -n "$result" && "$result" != *"Timeout"* ]]; then
      LOG "$oid: $result"
    fi
  done
}
