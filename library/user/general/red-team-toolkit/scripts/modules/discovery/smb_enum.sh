#!/bin/bash
set -euo pipefail

# SMB Enumeration module
# Enumerates shares, users, sessions, and domain info via SMB

smb_enum_menu() {
  local choice
  choice=$(menu_pick "SMB Enumeration" \
    "shares:List SMB Shares" \
    "users:Enumerate Users" \
    "sessions:Active Sessions" \
    "domain:Domain Info" \
    "null_session:Null Session Check" \
    "signing:SMB Signing Check" \
    "full_enum:Full Enumeration")
  
  case "$choice" in
    shares)      smb_enum_shares ;;
    users)       smb_enum_users ;;
    sessions)    smb_enum_sessions ;;
    domain)      smb_enum_domain ;;
    null_session) smb_null_session ;;
    signing)     smb_signing_check ;;
    full_enum)   smb_full_enum ;;
    *)           return 1 ;;
  esac
}

smb_enum_shares() {
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_shares_$(ts).txt"
  LOG blue "Enumerating SMB shares on $target..."
  
  {
    echo "=== SMB Share Enumeration ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    # Try smbclient first (null session)
    if have smbclient; then
      echo "--- smbclient (null session) ---"
      smbclient -N -L "//$target" 2>&1 || echo "(smbclient failed or access denied)"
      echo ""
    fi
    
    # Try crackmapexec
    if have crackmapexec; then
      echo "--- CrackMapExec ---"
      crackmapexec smb "$target" --shares 2>&1 || echo "(CME failed)"
      echo ""
    fi
    
    # Try nmap scripts
    if have nmap; then
      echo "--- Nmap SMB Scripts ---"
      nmap -p445 --script smb-enum-shares "$target" 2>&1 || echo "(nmap failed)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_enum_users() {
  local target
  target=$(IP_PICKER "Target IP/DC" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_users_$(ts).txt"
  LOG blue "Enumerating users on $target..."
  
  {
    echo "=== SMB User Enumeration ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    # RID cycling with crackmapexec
    if have crackmapexec; then
      echo "--- CrackMapExec RID Brute ---"
      crackmapexec smb "$target" --users 2>&1 || echo "(CME users failed)"
      echo ""
      
      echo "--- CrackMapExec RID Cycling ---"
      crackmapexec smb "$target" --rid-brute 2>&1 || echo "(RID brute failed)"
      echo ""
    fi
    
    # enum4linux if available
    if have enum4linux; then
      echo "--- enum4linux ---"
      enum4linux -U "$target" 2>&1 || echo "(enum4linux failed)"
      echo ""
    fi
    
    # rpcclient null session
    if have rpcclient; then
      echo "--- rpcclient enumdomusers ---"
      echo "enumdomusers" | rpcclient -U "" -N "$target" 2>&1 || echo "(rpcclient failed)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_enum_sessions() {
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_sessions_$(ts).txt"
  LOG blue "Enumerating active sessions on $target..."
  
  {
    echo "=== SMB Session Enumeration ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    if have crackmapexec; then
      echo "--- CrackMapExec Sessions ---"
      crackmapexec smb "$target" --sessions 2>&1 || echo "(CME sessions failed)"
      echo ""
      
      echo "--- CrackMapExec Logged-on Users ---"
      crackmapexec smb "$target" --loggedon-users 2>&1 || echo "(loggedon failed)"
    fi
    
    if have nmap; then
      echo ""
      echo "--- Nmap SMB Sessions ---"
      nmap -p445 --script smb-enum-sessions "$target" 2>&1 || echo "(nmap failed)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_enum_domain() {
  local target
  target=$(IP_PICKER "Domain Controller IP" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_domain_$(ts).txt"
  LOG blue "Enumerating domain info from $target..."
  
  {
    echo "=== Domain Information ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    if have crackmapexec; then
      echo "--- CrackMapExec Domain Info ---"
      crackmapexec smb "$target" 2>&1
      echo ""
      
      echo "--- Password Policy ---"
      crackmapexec smb "$target" --pass-pol 2>&1 || echo "(pass-pol failed)"
      echo ""
      
      echo "--- Groups ---"
      crackmapexec smb "$target" --groups 2>&1 || echo "(groups failed)"
    fi
    
    if have enum4linux; then
      echo ""
      echo "--- enum4linux Domain Info ---"
      enum4linux -a "$target" 2>&1 | head -100 || echo "(enum4linux failed)"
    fi
    
    if have nmap; then
      echo ""
      echo "--- Nmap SMB Domain ---"
      nmap -p445 --script smb-os-discovery "$target" 2>&1 || echo "(nmap failed)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_null_session() {
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_null_$(ts).txt"
  LOG blue "Testing null session on $target..."
  
  {
    echo "=== Null Session Test ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    # Test with smbclient
    if have smbclient; then
      echo "--- smbclient null test ---"
      if smbclient -N -L "//$target" 2>&1 | grep -q "Sharename"; then
        echo "[+] NULL SESSION ALLOWED - Share listing succeeded"
      else
        echo "[-] Null session blocked for share listing"
      fi
      echo ""
    fi
    
    # Test with rpcclient
    if have rpcclient; then
      echo "--- rpcclient null test ---"
      if echo "getusername" | rpcclient -U "" -N "$target" 2>&1 | grep -q "Account"; then
        echo "[+] NULL SESSION ALLOWED - RPC access succeeded"
      else
        echo "[-] Null session blocked for RPC"
      fi
    fi
    
    # Test with crackmapexec
    if have crackmapexec; then
      echo ""
      echo "--- CrackMapExec null test ---"
      crackmapexec smb "$target" -u '' -p '' 2>&1
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_signing_check() {
  local network
  network=$(TEXT_PICKER "Target network" "$TARGET_NETWORK") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/smb_signing_$(ts).txt"
  LOG blue "Checking SMB signing on $network..."
  
  {
    echo "=== SMB Signing Analysis ==="
    echo "Network: $network"
    echo "Time: $(date)"
    echo ""
    
    if have crackmapexec; then
      echo "--- CrackMapExec Signing Check ---"
      crackmapexec smb "$network" --gen-relay-list "$ARTIFACT_DIR/relay_targets.txt" 2>&1
      echo ""
      echo "Relay targets saved to: $ARTIFACT_DIR/relay_targets.txt"
      if [[ -f "$ARTIFACT_DIR/relay_targets.txt" ]]; then
        echo ""
        echo "Hosts without SMB signing:"
        cat "$ARTIFACT_DIR/relay_targets.txt"
      fi
    elif have nmap; then
      echo "--- Nmap Signing Check ---"
      nmap -p445 --script smb-security-mode "$network" 2>&1 | \
        grep -E "(Host|message_signing)" || echo "(no results)"
    else
      echo "No tools available (need crackmapexec or nmap)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

smb_full_enum() {
  local target
  target=$(IP_PICKER "Target IP" "192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/smb_full_$(ts).txt"
  LOG blue "Running full SMB enumeration on $target..."
  
  local spinner_id
  spinner_id=$(START_SPINNER "Full SMB enumeration...")
  
  {
    echo "=== Full SMB Enumeration ==="
    echo "Target: $target"
    echo "Time: $(date)"
    echo ""
    
    # enum4linux-ng if available (best option)
    if have enum4linux-ng; then
      echo "--- enum4linux-ng ---"
      enum4linux-ng -A "$target" 2>&1 || echo "(enum4linux-ng failed)"
    elif have enum4linux; then
      echo "--- enum4linux ---"
      enum4linux -a "$target" 2>&1 || echo "(enum4linux failed)"
    fi
    
    echo ""
    echo "--- Nmap SMB Scripts ---"
    if have nmap; then
      nmap -p139,445 --script "smb-enum-*,smb-vuln-*,smb-os-discovery,smb-security-mode" "$target" 2>&1 || echo "(nmap failed)"
    fi
    
    echo ""
    echo "--- CrackMapExec Full ---"
    if have crackmapexec; then
      crackmapexec smb "$target" 2>&1
      crackmapexec smb "$target" --shares 2>&1 || true
      crackmapexec smb "$target" --users 2>&1 || true
      crackmapexec smb "$target" --pass-pol 2>&1 || true
    fi
  } > "$output" 2>&1
  
  STOP_SPINNER "$spinner_id"
  
  LOG green "Full enumeration complete"
  LOG "Results saved to $output"
  
  # Show summary
  LOG ""
  LOG "=== Quick Summary ==="
  grep -E "(ADMIN\$|C\$|IPC\$|Sharename|Domain:|OS:|\[\+\]|\[\*\])" "$output" 2>/dev/null | head -20 || true
}
