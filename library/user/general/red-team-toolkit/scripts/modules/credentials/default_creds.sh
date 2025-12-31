#!/bin/bash
# Default credential checker for OT/IT devices

rt_default_creds() {
  local choice
  choice=$(menu_pick "Default Credentials" \
    "Check Single Target" \
    "Check Target List" \
    "Check by Vendor" \
    "View Wordlist")
  
  case "$choice" in
    1) creds_single ;;
    2) creds_list ;;
    3) creds_vendor ;;
    4) creds_view_wordlist ;;
    0|"") return ;;
  esac
}

creds_single() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  if ! check_passive; then return 1; fi
  
  local outfile
  outfile="$ARTIFACT_DIR/creds_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Checking default credentials on $target..."
  
  {
    echo "=== Default Credential Check: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Detect open ports first
    local http_port="" ssh_port="" telnet_port="" vnc_port="" ftp_port=""
    
    port_open "$target" 80 2 && http_port=80
    port_open "$target" 443 2 && http_port=443
    port_open "$target" 8080 2 && http_port=8080
    port_open "$target" 22 2 && ssh_port=22
    port_open "$target" 23 2 && telnet_port=23
    port_open "$target" 5900 2 && vnc_port=5900
    port_open "$target" 21 2 && ftp_port=21
    
    LOG "Detected ports: HTTP=$http_port SSH=$ssh_port Telnet=$telnet_port VNC=$vnc_port FTP=$ftp_port"
    
    # Try HTTP basic auth
    if [[ -n "$http_port" ]]; then
      echo ""
      echo "=== HTTP Basic Auth ($http_port) ==="
      local proto="http"
      [[ "$http_port" == "443" ]] && proto="https"
      
      while IFS=, read -r vendor product protocol port user pass; do
        [[ "$protocol" != "HTTP" ]] && continue
        [[ "$user" == "username" ]] && continue  # Skip header
        
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" \
          --connect-timeout 3 -k "$proto://$target:$http_port/" 2>/dev/null)
        
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
          echo "[+] SUCCESS: $user:$pass (HTTP $code) - $vendor $product"
        fi
      done < "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
    fi
    
    # Try FTP
    if [[ -n "$ftp_port" ]]; then
      echo ""
      echo "=== FTP ($ftp_port) ==="
      
      while IFS=, read -r vendor product protocol port user pass; do
        [[ "$protocol" != "FTP" ]] && continue
        [[ "$user" == "username" ]] && continue
        
        if have curl; then
          if curl -s --connect-timeout 3 "ftp://$user:$pass@$target/" >/dev/null 2>&1; then
            echo "[+] SUCCESS: $user:$pass - $vendor $product"
          fi
        fi
      done < "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
    fi
    
    # Try Telnet (basic check)
    if [[ -n "$telnet_port" ]] && have nc; then
      echo ""
      echo "=== Telnet ($telnet_port) ==="
      echo "Note: Manual verification recommended"
      
      # Just check if banner contains login prompt
      local banner
      banner=$(echo "" | nc -w 3 "$target" "$telnet_port" 2>/dev/null | head -3)
      echo "Banner: $banner"
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

creds_list() {
  LOG "Enter targets (one per line, empty to finish):"
  
  local targets=()
  while true; do
    local t
    t=$(TEXT_PICKER "Target (empty=done)" "")
    case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") break ;; esac
    [[ -z "$t" ]] && break
    targets+=("$t")
  done
  
  if [[ ${#targets[@]} -eq 0 ]]; then
    LOG "No targets entered"
    return
  fi
  
  LOG blue "Checking ${#targets[@]} targets..."
  
  for target in "${targets[@]}"; do
    LOG "--- $target ---"
    creds_check_target "$target"
  done
}

creds_check_target() {
  local target="$1"
  
  # Quick check - just HTTP for speed
  for port in 80 443 8080; do
    if port_open "$target" "$port" 2; then
      local proto="http"
      [[ "$port" == "443" ]] && proto="https"
      
      for cred in "admin:admin" "admin:" "administrator:" "admin:1234"; do
        local user="${cred%%:*}"
        local pass="${cred#*:}"
        
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" \
          --connect-timeout 2 -k "$proto://$target:$port/" 2>/dev/null)
        
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
          LOG green "[+] $target:$port - $user:$pass works!"
          return 0
        fi
      done
    fi
  done
  
  LOG "$target - no default creds found"
}

creds_vendor() {
  local choice
  choice=$(menu_pick "Select Vendor" \
    "Siemens" \
    "Rockwell" \
    "Schneider" \
    "ABB" \
    "Honeywell" \
    "GE" \
    "Generic")
  
  local vendor
  case "$choice" in
    1) vendor="Siemens" ;;
    2) vendor="Rockwell" ;;
    3) vendor="Schneider" ;;
    4) vendor="ABB" ;;
    5) vendor="Honeywell" ;;
    6) vendor="GE" ;;
    7) vendor="Generic" ;;
    0|"") return ;;
  esac
  
  LOG blue "Default credentials for $vendor:"
  echo ""
  grep -i "^$vendor" "$TOOLKIT_DIR/wordlists/ot-defaults.csv" | \
    awk -F, '{printf "%-15s %-10s %s:%s\n", $2, $3, $5, $6}'
}

creds_view_wordlist() {
  LOG blue "=== OT Default Credentials Wordlist ==="
  head -50 "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
  LOG ""
  LOG "Total entries: $(wc -l < "$TOOLKIT_DIR/wordlists/ot-defaults.csv")"
}
