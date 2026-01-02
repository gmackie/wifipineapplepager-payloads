#!/bin/bash
# Active Directory enumeration

rt_ad_enum() {
  local choice
  choice=$(menu_pick "AD Enumeration" \
    "Find Domain Controllers" \
    "Enumerate Users" \
    "Enumerate Groups" \
    "Enumerate Computers" \
    "BloodHound Collection" \
    "LDAP Anonymous Bind")
  
  case "$choice" in
    1) ad_find_dc ;;
    2) ad_enum_users ;;
    3) ad_enum_groups ;;
    4) ad_enum_computers ;;
    5) ad_bloodhound ;;
    6) ad_ldap_anon ;;
    0|"") return ;;
  esac
}

ad_find_dc() {
  local target
  target=$(TEXT_PICKER "Target (IP or domain)" "$TARGET_NETWORK")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Finding Domain Controllers..."
  ensure_dir "$ARTIFACT_DIR"
  
  {
    echo "=== Domain Controller Discovery ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    echo "--- DNS SRV Records ---"
    if have nslookup; then
      nslookup -type=srv _ldap._tcp.dc._msdcs."$target" 2>/dev/null || echo "(DNS lookup failed)"
      nslookup -type=srv _kerberos._tcp."$target" 2>/dev/null || true
    elif have dig; then
      dig +short SRV _ldap._tcp.dc._msdcs."$target" 2>/dev/null || echo "(DNS lookup failed)"
    fi
    
    echo ""
    echo "--- Port Scan for DC Services ---"
    
    local dc_ports="53,88,135,139,389,445,464,636,3268,3269"
    
    if have nmap; then
      nmap -Pn -p "$dc_ports" "$target" 2>/dev/null | grep -E 'open|filtered'
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "nmap -Pn -p $dc_ports '$target'" 2>/dev/null
    else
      for port in 88 389 445 636; do
        if port_open "$target" "$port"; then
          echo "  Port $port: OPEN"
        fi
      done
    fi
    
    echo ""
    echo "Key DC ports:"
    echo "  88  - Kerberos"
    echo "  389 - LDAP"
    echo "  636 - LDAPS"
    echo "  445 - SMB"
    echo "  3268 - Global Catalog"
    
  } | tee "$ARTIFACT_DIR/dc_discovery_$(ts).txt"
}

ad_enum_users() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Full AD enum requires laptop mode"
    ad_enum_users_basic
    return
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local username
  username=$(TEXT_PICKER "Username" "user")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local password
  password=$(TEXT_PICKER "Password" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Enumerating domain users..."
  
  laptop_exec "GetADUsers.py -all '$domain/$username:$password' -dc-ip '$dc_ip'" 2>&1 | \
    tee "$ARTIFACT_DIR/ad_users_$(ts).txt"
}

ad_enum_users_basic() {
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Basic user enumeration via RID cycling..."
  
  if have rpcclient; then
    rpcclient -U "" -N "$dc_ip" -c "enumdomusers" 2>/dev/null | \
      tee "$ARTIFACT_DIR/ad_users_basic_$(ts).txt"
  elif have enum4linux; then
    enum4linux -U "$dc_ip" 2>/dev/null | tee "$ARTIFACT_DIR/enum4linux_$(ts).txt"
  else
    LOG red "rpcclient or enum4linux required"
  fi
}

ad_enum_groups() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Requires laptop mode"
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local username
  username=$(TEXT_PICKER "Username" "user")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local password
  password=$(TEXT_PICKER "Password" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Enumerating domain groups..."
  
  {
    echo "=== High-Value Groups ==="
    laptop_exec "net rpc group members 'Domain Admins' -U '$domain/$username%$password' -S '$dc_ip'" 2>/dev/null
    echo ""
    laptop_exec "net rpc group members 'Enterprise Admins' -U '$domain/$username%$password' -S '$dc_ip'" 2>/dev/null
    echo ""
    laptop_exec "net rpc group members 'Administrators' -U '$domain/$username%$password' -S '$dc_ip'" 2>/dev/null
  } | tee "$ARTIFACT_DIR/ad_groups_$(ts).txt"
}

ad_enum_computers() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Requires laptop mode"
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local username
  username=$(TEXT_PICKER "Username" "user")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local password
  password=$(TEXT_PICKER "Password" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Enumerating domain computers..."
  
  laptop_exec "GetADComputers.py '$domain/$username:$password' -dc-ip '$dc_ip'" 2>&1 | \
    tee "$ARTIFACT_DIR/ad_computers_$(ts).txt"
}

ad_bloodhound() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "BloodHound requires laptop mode"
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local username
  username=$(TEXT_PICKER "Username" "user")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local password
  password=$(TEXT_PICKER "Password" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Running BloodHound collection..."
  
  local collection
  collection=$(menu_pick "Collection Method" \
    "All (comprehensive)" \
    "DCOnly (fast, no SMB)" \
    "Default (balanced)")
  
  local method
  case "$collection" in
    1) method="All" ;;
    2) method="DCOnly" ;;
    3) method="Default" ;;
    0|"") return ;;
  esac
  
  laptop_exec "bloodhound-python -c '$method' -u '$username' -p '$password' -d '$domain' -dc '$dc_ip' --zip -ns '$dc_ip'" 2>&1 | \
    tee "$ARTIFACT_DIR/bloodhound_$(ts).log"
  
  LOG green "BloodHound data collected"
  LOG "ZIP file created on laptop - import into BloodHound GUI"
  LOG ""
  LOG "Fetch with: laptop_fetch '*.zip' '$ARTIFACT_DIR/'"
}

ad_ldap_anon() {
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Testing anonymous LDAP bind..."
  
  ensure_dir "$ARTIFACT_DIR"
  
  {
    echo "=== Anonymous LDAP Test ==="
    echo "Target: $dc_ip"
    echo "Time: $(date)"
    echo ""
    
    if have ldapsearch; then
      echo "Testing anonymous bind..."
      ldapsearch -x -H "ldap://$dc_ip" -b "" -s base "(objectClass=*)" 2>&1 | head -30
      
      echo ""
      echo "Attempting to enumerate naming contexts..."
      ldapsearch -x -H "ldap://$dc_ip" -b "" -s base namingContexts 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "ldapsearch -x -H 'ldap://$dc_ip' -b '' -s base '(objectClass=*)'" 2>&1 | head -30
    else
      LOG red "ldapsearch required"
      LOG "Install: apt install ldap-utils"
    fi
    
  } | tee "$ARTIFACT_DIR/ldap_anon_$(ts).txt"
  
  LOG ""
  LOG "If anonymous bind works, try:"
  LOG "  ldapsearch -x -H ldap://$dc_ip -b 'DC=corp,DC=local' '(objectClass=user)'"
}
