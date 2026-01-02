#!/bin/bash
# WPA/WPA2 handshake cracking integration

rt_wpa_crack() {
  local choice
  choice=$(menu_pick "WPA Cracking" \
    "Convert to Hashcat Format" \
    "Crack with Wordlist (laptop)" \
    "Crack with Rules (laptop)" \
    "Check Crack Status" \
    "View Cracked Passwords")
  
  case "$choice" in
    1) wpa_convert ;;
    2) wpa_crack_wordlist ;;
    3) wpa_crack_rules ;;
    4) wpa_crack_status ;;
    5) wpa_view_cracked ;;
    0|"") return ;;
  esac
}

wpa_convert() {
  LOG blue "Looking for captured handshakes..."
  
  local pcaps
  pcaps=$(find "$ARTIFACT_DIR" -name "*.pcap" -o -name "*.cap" 2>/dev/null)
  
  if [[ -z "$pcaps" ]]; then
    LOG red "No pcap files found in $ARTIFACT_DIR"
    return 1
  fi
  
  LOG "Found pcap files:"
  echo "$pcaps" | while read -r f; do
    LOG "  $(basename "$f")"
  done
  
  local pcap_file
  pcap_file=$(TEXT_PICKER "PCAP file path" "$(echo "$pcaps" | head -1)")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if [[ ! -f "$pcap_file" ]]; then
    LOG red "File not found: $pcap_file"
    return 1
  fi
  
  local hash_file="$ARTIFACT_DIR/$(basename "${pcap_file%.*}").hc22000"
  
  LOG blue "Converting to hashcat format..."
  
  if have hcxpcapngtool; then
    hcxpcapngtool -o "$hash_file" "$pcap_file" 2>&1
    
    if [[ -f "$hash_file" ]] && [[ -s "$hash_file" ]]; then
      local count
      count=$(wc -l < "$hash_file")
      LOG green "Extracted $count hash(es) to: $hash_file"
      LOG ""
      LOG "Hash format: WPA-PBKDF2-PMKID+EAPOL (mode 22000)"
      LOG ""
      head -3 "$hash_file"
    else
      LOG red "No valid handshakes found in pcap"
    fi
  elif have cap2hccapx; then
    local hccapx_file="${hash_file%.hc22000}.hccapx"
    cap2hccapx "$pcap_file" "$hccapx_file" 2>&1
    
    if [[ -f "$hccapx_file" ]]; then
      LOG green "Converted to: $hccapx_file"
      LOG "Hash format: WPA-EAPOL-PBKDF2 (mode 2500)"
    fi
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    LOG "Converting on laptop..."
    laptop_fetch "$pcap_file" "$LAPTOP_RESULTS_DIR/"
    laptop_exec "hcxpcapngtool -o '$LAPTOP_RESULTS_DIR/$(basename "$hash_file")' '$LAPTOP_RESULTS_DIR/$(basename "$pcap_file")'"
    LOG green "Hash file created on laptop"
  else
    LOG red "hcxpcapngtool or cap2hccapx required"
    LOG "Install: apt install hcxtools"
  fi
}

wpa_crack_wordlist() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Cracking requires laptop mode (GPU)"
    return 1
  fi
  
  if ! laptop_ping; then
    LOG red "Cannot reach laptop"
    return 1
  fi
  
  local hash_file
  hash_file=$(TEXT_PICKER "Hash file (on laptop)" "$LAPTOP_RESULTS_DIR/capture.hc22000")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local wordlist
  wordlist=$(TEXT_PICKER "Wordlist path" "/usr/share/wordlists/rockyou.txt")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting hashcat on laptop..."
  LOG "Hash: $hash_file"
  LOG "Wordlist: $wordlist"
  
  laptop_exec_bg "hashcat -m 22000 -a 0 '$hash_file' '$wordlist' --status --status-timer=60 -o '$LAPTOP_RESULTS_DIR/cracked.txt'" \
    "$LAPTOP_RESULTS_DIR/hashcat.log"
  
  LOG green "Hashcat started in background"
  LOG ""
  LOG "Monitor: WPA Cracking > Check Crack Status"
  LOG "Results: WPA Cracking > View Cracked Passwords"
}

wpa_crack_rules() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Cracking requires laptop mode"
    return 1
  fi
  
  local hash_file
  hash_file=$(TEXT_PICKER "Hash file" "$LAPTOP_RESULTS_DIR/capture.hc22000")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local wordlist
  wordlist=$(TEXT_PICKER "Wordlist" "/usr/share/wordlists/rockyou.txt")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local rule
  rule=$(menu_pick "Rule Set" \
    "best64 (fast)" \
    "rockyou-30000 (medium)" \
    "dive (thorough)" \
    "OneRuleToRuleThemAll")
  
  local rule_file
  case "$rule" in
    1) rule_file="/usr/share/hashcat/rules/best64.rule" ;;
    2) rule_file="/usr/share/hashcat/rules/rockyou-30000.rule" ;;
    3) rule_file="/usr/share/hashcat/rules/dive.rule" ;;
    4) rule_file="/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule" ;;
    0|"") return ;;
  esac
  
  LOG blue "Starting hashcat with rules..."
  
  laptop_exec_bg "hashcat -m 22000 -a 0 '$hash_file' '$wordlist' -r '$rule_file' --status -o '$LAPTOP_RESULTS_DIR/cracked.txt'" \
    "$LAPTOP_RESULTS_DIR/hashcat.log"
  
  LOG green "Hashcat (rule-based) started"
}

wpa_crack_status() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Laptop mode required"
    return 1
  fi
  
  LOG blue "Hashcat status:"
  LOG ""
  
  local running
  running=$(laptop_exec "pgrep -x hashcat" 2>/dev/null)
  
  if [[ -n "$running" ]]; then
    LOG green "Hashcat is RUNNING"
    LOG ""
    laptop_exec "tail -50 $LAPTOP_RESULTS_DIR/hashcat.log 2>/dev/null | grep -E '(Speed|Progress|Recovered|Time|Status)'" || true
  else
    LOG "Hashcat is NOT running"
    LOG ""
    LOG "Last log entries:"
    laptop_exec "tail -20 $LAPTOP_RESULTS_DIR/hashcat.log 2>/dev/null" || LOG "(no log)"
  fi
}

wpa_view_cracked() {
  LOG blue "Cracked passwords:"
  LOG ""
  
  if [[ -f "$ARTIFACT_DIR/cracked.txt" ]]; then
    LOG "=== Local ==="
    cat "$ARTIFACT_DIR/cracked.txt"
  fi
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    LOG ""
    LOG "=== Laptop ==="
    laptop_exec "cat $LAPTOP_RESULTS_DIR/cracked.txt 2>/dev/null" || LOG "(none)"
    
    LOG ""
    CONFIRMATION_DIALOG "Fetch cracked.txt to Pager?"
    if [[ $? -eq "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
      laptop_fetch "$LAPTOP_RESULTS_DIR/cracked.txt" "$ARTIFACT_DIR/"
      LOG green "Fetched to $ARTIFACT_DIR/cracked.txt"
    fi
  fi
  
  if [[ ! -f "$ARTIFACT_DIR/cracked.txt" ]]; then
    LOG "No cracked passwords yet"
  fi
}
