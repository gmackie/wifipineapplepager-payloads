#!/bin/bash
set -euo pipefail

# Web Scanning module
# Directory bruteforcing, basic vulnerability checks, technology fingerprinting

web_scan_menu() {
  local choice
  choice=$(menu_pick "Web Scanning" \
    "dirbrute:Directory Bruteforce" \
    "tech_detect:Technology Detection" \
    "headers:Security Headers Check" \
    "vulns:Basic Vuln Scan" \
    "robots:Robots/Sitemap" \
    "ssl:SSL/TLS Analysis" \
    "full:Full Web Recon")
  
  case "$choice" in
    dirbrute)    web_dirbrute ;;
    tech_detect) web_tech_detect ;;
    headers)     web_headers ;;
    vulns)       web_vuln_scan ;;
    robots)      web_robots ;;
    ssl)         web_ssl_check ;;
    full)        web_full_recon ;;
    *)           return 1 ;;
  esac
}

web_dirbrute() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  # Extract host for scope check
  local host
  host=$(echo "$url" | sed -E 's|https?://([^:/]+).*|\1|')
  
  local wordlist_choice
  wordlist_choice=$(menu_pick "Wordlist" \
    "common:Common paths (fast)" \
    "medium:Medium list" \
    "large:Large list" \
    "custom:Custom wordlist")
  
  local wordlist
  case "$wordlist_choice" in
    common) wordlist="$SCRIPT_DIR/../wordlists/web-common.txt" ;;
    medium) wordlist="$SCRIPT_DIR/../wordlists/web-medium.txt" ;;
    large)  wordlist="$SCRIPT_DIR/../wordlists/web-large.txt" ;;
    custom)
      wordlist=$(TEXT_PICKER "Wordlist path" "/usr/share/wordlists/dirb/common.txt") || return 1
      check_return_code || return 1
      ;;
    *) return 1 ;;
  esac
  
  # Check if wordlist exists, fallback to built-in
  if [[ ! -f "$wordlist" ]]; then
    LOG "Wordlist not found, using built-in common paths"
    wordlist=""
  fi
  
  local output="$ARTIFACT_DIR/dirbrute_$(ts).txt"
  LOG blue "Directory bruteforce on $url..."
  
  local spinner_id
  spinner_id=$(START_SPINNER "Bruteforcing directories...")
  
  {
    echo "=== Directory Bruteforce ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    # Try gobuster first
    if have gobuster && [[ -n "$wordlist" ]]; then
      echo "--- gobuster ---"
      gobuster dir -u "$url" -w "$wordlist" -t 10 -q 2>&1 || echo "(gobuster failed)"
    # Try feroxbuster
    elif have feroxbuster && [[ -n "$wordlist" ]]; then
      echo "--- feroxbuster ---"
      feroxbuster -u "$url" -w "$wordlist" -t 10 -q 2>&1 || echo "(feroxbuster failed)"
    # Try ffuf
    elif have ffuf && [[ -n "$wordlist" ]]; then
      echo "--- ffuf ---"
      ffuf -u "${url}/FUZZ" -w "$wordlist" -mc 200,204,301,302,307,401,403 -t 10 2>&1 || echo "(ffuf failed)"
    # Fallback to curl with common paths
    else
      echo "--- curl (built-in common paths) ---"
      local paths=(
        "admin" "administrator" "login" "wp-admin" "wp-login.php"
        "phpmyadmin" "cpanel" "webmail" "mail" "api" "v1" "v2"
        "backup" "backups" "config" "configuration" "conf"
        "database" "db" "sql" "dump" "uploads" "upload"
        "images" "img" "css" "js" "static" "assets"
        "test" "dev" "development" "staging" "demo"
        ".git" ".svn" ".env" ".htaccess" "robots.txt" "sitemap.xml"
        "server-status" "server-info" "phpinfo.php" "info.php"
      )
      
      for path in "${paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/${path}" 2>/dev/null || echo "000")
        if [[ "$code" != "404" && "$code" != "000" ]]; then
          printf "[%s] %s/%s\n" "$code" "$url" "$path"
        fi
      done
    fi
  } > "$output" 2>&1
  
  STOP_SPINNER "$spinner_id"
  
  LOG green "Scan complete"
  LOG "Results saved to $output"
  
  # Show findings
  LOG ""
  LOG "=== Interesting Paths Found ==="
  grep -E "^\[2|^\[3|^\[4" "$output" 2>/dev/null | head -20 || echo "(none)"
}

web_tech_detect() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/web_tech_$(ts).txt"
  LOG blue "Detecting technologies on $url..."
  
  {
    echo "=== Technology Detection ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    # whatweb if available
    if have whatweb; then
      echo "--- WhatWeb ---"
      whatweb -a 3 "$url" 2>&1 || echo "(whatweb failed)"
      echo ""
    fi
    
    # wappalyzer CLI if available
    if have wappalyzer; then
      echo "--- Wappalyzer ---"
      wappalyzer "$url" 2>&1 || echo "(wappalyzer failed)"
      echo ""
    fi
    
    # Manual detection via headers and content
    echo "--- Header Analysis ---"
    local headers
    headers=$(curl -sI -L --connect-timeout 5 "$url" 2>/dev/null || echo "")
    echo "$headers"
    echo ""
    
    echo "--- Technology Indicators ---"
    # Server header
    echo "$headers" | grep -i "^server:" || echo "Server: (not disclosed)"
    echo "$headers" | grep -i "^x-powered-by:" || true
    echo "$headers" | grep -i "^x-aspnet-version:" || true
    echo "$headers" | grep -i "^x-generator:" || true
    
    # Get page content for analysis
    local content
    content=$(curl -sL --connect-timeout 5 "$url" 2>/dev/null | head -200 || echo "")
    
    echo ""
    echo "--- Content Analysis ---"
    # WordPress
    if echo "$content" | grep -qi "wp-content\|wordpress"; then
      echo "[+] WordPress detected"
    fi
    # Drupal
    if echo "$content" | grep -qi "drupal\|sites/default"; then
      echo "[+] Drupal detected"
    fi
    # Joomla
    if echo "$content" | grep -qi "joomla\|com_content"; then
      echo "[+] Joomla detected"
    fi
    # React
    if echo "$content" | grep -qi "react\|__NEXT_DATA__"; then
      echo "[+] React/Next.js detected"
    fi
    # Angular
    if echo "$content" | grep -qi "ng-app\|angular"; then
      echo "[+] Angular detected"
    fi
    # Vue
    if echo "$content" | grep -qi "vue\|v-bind"; then
      echo "[+] Vue.js detected"
    fi
    # jQuery
    if echo "$content" | grep -qi "jquery"; then
      echo "[+] jQuery detected"
    fi
    # Bootstrap
    if echo "$content" | grep -qi "bootstrap"; then
      echo "[+] Bootstrap detected"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

web_headers() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/web_headers_$(ts).txt"
  LOG blue "Analyzing security headers on $url..."
  
  {
    echo "=== Security Headers Analysis ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    local headers
    headers=$(curl -sI -L --connect-timeout 5 "$url" 2>/dev/null || echo "")
    
    echo "--- Raw Headers ---"
    echo "$headers"
    echo ""
    
    echo "--- Security Header Checklist ---"
    
    # Check each security header
    if echo "$headers" | grep -qi "strict-transport-security"; then
      echo "[+] HSTS: Present"
    else
      echo "[-] HSTS: MISSING - No HTTPS enforcement"
    fi
    
    if echo "$headers" | grep -qi "x-frame-options"; then
      echo "[+] X-Frame-Options: Present"
    else
      echo "[-] X-Frame-Options: MISSING - Clickjacking possible"
    fi
    
    if echo "$headers" | grep -qi "x-content-type-options"; then
      echo "[+] X-Content-Type-Options: Present"
    else
      echo "[-] X-Content-Type-Options: MISSING - MIME sniffing possible"
    fi
    
    if echo "$headers" | grep -qi "x-xss-protection"; then
      echo "[+] X-XSS-Protection: Present"
    else
      echo "[-] X-XSS-Protection: MISSING (deprecated but still useful)"
    fi
    
    if echo "$headers" | grep -qi "content-security-policy"; then
      echo "[+] CSP: Present"
    else
      echo "[-] CSP: MISSING - XSS mitigation reduced"
    fi
    
    if echo "$headers" | grep -qi "referrer-policy"; then
      echo "[+] Referrer-Policy: Present"
    else
      echo "[-] Referrer-Policy: MISSING"
    fi
    
    if echo "$headers" | grep -qi "permissions-policy\|feature-policy"; then
      echo "[+] Permissions-Policy: Present"
    else
      echo "[-] Permissions-Policy: MISSING"
    fi
    
    echo ""
    echo "--- Information Disclosure ---"
    if echo "$headers" | grep -qi "server:"; then
      echo "[!] Server header discloses: $(echo "$headers" | grep -i "^server:" | cut -d: -f2-)"
    fi
    if echo "$headers" | grep -qi "x-powered-by:"; then
      echo "[!] X-Powered-By discloses: $(echo "$headers" | grep -i "^x-powered-by:" | cut -d: -f2-)"
    fi
    if echo "$headers" | grep -qi "x-aspnet-version:"; then
      echo "[!] ASP.NET version disclosed: $(echo "$headers" | grep -i "^x-aspnet-version:" | cut -d: -f2-)"
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

web_vuln_scan() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  if ! check_passive; then
    LOG red "Vulnerability scanning is active - blocked by PASSIVE_ONLY"
    return 1
  fi
  
  local output="$ARTIFACT_DIR/web_vulns_$(ts).txt"
  LOG blue "Basic vulnerability scan on $url..."
  
  local spinner_id
  spinner_id=$(START_SPINNER "Scanning for vulnerabilities...")
  
  {
    echo "=== Basic Vulnerability Scan ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    # nikto if available
    if have nikto; then
      echo "--- Nikto ---"
      nikto -h "$url" -Tuning 123bde -maxtime 300 2>&1 || echo "(nikto failed or timed out)"
      echo ""
    fi
    
    # nuclei if available
    if have nuclei; then
      echo "--- Nuclei (critical+high) ---"
      nuclei -u "$url" -s critical,high -silent 2>&1 || echo "(nuclei failed)"
      echo ""
    fi
    
    # Manual checks
    echo "--- Manual Checks ---"
    
    # Check for directory listing
    echo -n "Directory listing: "
    local dirlisting
    dirlisting=$(curl -sL --connect-timeout 5 "${url}/" 2>/dev/null || echo "")
    if echo "$dirlisting" | grep -qi "index of\|directory listing\|parent directory"; then
      echo "ENABLED (vulnerable)"
    else
      echo "Disabled"
    fi
    
    # Check for common backup files
    echo -n "Backup files: "
    local found_backups=""
    for ext in ".bak" ".old" ".backup" "~" ".swp" ".save"; do
      local code
      code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/index.php${ext}" 2>/dev/null || echo "000")
      if [[ "$code" == "200" ]]; then
        found_backups="$found_backups index.php${ext}"
      fi
    done
    if [[ -n "$found_backups" ]]; then
      echo "FOUND:$found_backups"
    else
      echo "None found"
    fi
    
    # Check for exposed git
    echo -n ".git exposure: "
    local gitcode
    gitcode=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/.git/HEAD" 2>/dev/null || echo "000")
    if [[ "$gitcode" == "200" ]]; then
      echo "EXPOSED (vulnerable)"
    else
      echo "Not exposed"
    fi
    
    # Check for exposed env
    echo -n ".env exposure: "
    local envcode
    envcode=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/.env" 2>/dev/null || echo "000")
    if [[ "$envcode" == "200" ]]; then
      echo "EXPOSED (critical!)"
    else
      echo "Not exposed"
    fi
    
  } > "$output" 2>&1
  
  STOP_SPINNER "$spinner_id"
  
  LOG green "Scan complete"
  LOG "Results saved to $output"
  
  # Show critical findings
  LOG ""
  LOG "=== Critical Findings ==="
  grep -iE "(vulnerable|critical|high|exposed|OSVDB)" "$output" 2>/dev/null | head -20 || echo "(none)"
}

web_robots() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/web_robots_$(ts).txt"
  LOG blue "Fetching robots.txt and sitemap from $url..."
  
  {
    echo "=== Robots & Sitemap ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    echo "--- robots.txt ---"
    curl -sL --connect-timeout 5 "${url}/robots.txt" 2>/dev/null || echo "(not found)"
    echo ""
    
    echo "--- sitemap.xml ---"
    local sitemap
    sitemap=$(curl -sL --connect-timeout 5 "${url}/sitemap.xml" 2>/dev/null || echo "")
    if [[ -n "$sitemap" ]] && echo "$sitemap" | grep -q "<?xml"; then
      echo "$sitemap" | head -50
      echo "(truncated to 50 lines)"
    else
      echo "(not found or invalid)"
    fi
    echo ""
    
    echo "--- sitemap_index.xml ---"
    curl -sL --connect-timeout 5 "${url}/sitemap_index.xml" 2>/dev/null | head -30 || echo "(not found)"
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

web_ssl_check() {
  local host
  host=$(TEXT_PICKER "Target host:port" "example.com:443") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/ssl_check_$(ts).txt"
  LOG blue "Analyzing SSL/TLS on $host..."
  
  {
    echo "=== SSL/TLS Analysis ==="
    echo "Host: $host"
    echo "Time: $(date)"
    echo ""
    
    # sslscan if available
    if have sslscan; then
      echo "--- sslscan ---"
      sslscan "$host" 2>&1 || echo "(sslscan failed)"
      echo ""
    fi
    
    # testssl.sh if available
    if have testssl.sh || have testssl; then
      echo "--- testssl ---"
      (testssl.sh "$host" 2>&1 || testssl "$host" 2>&1) | head -100 || echo "(testssl failed)"
      echo ""
    fi
    
    # OpenSSL fallback
    if have openssl; then
      echo "--- OpenSSL Certificate Info ---"
      echo | openssl s_client -connect "$host" -servername "${host%%:*}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -50 || echo "(openssl failed)"
      echo ""
      
      echo "--- Supported Protocols ---"
      for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        if echo | openssl s_client -connect "$host" "-${proto}" 2>/dev/null | grep -q "Cipher is"; then
          echo "[+] $proto: Supported"
        else
          echo "[-] $proto: Not supported"
        fi
      done 2>/dev/null
    fi
  } | tee "$output"
  
  LOG green "Results saved to $output"
}

web_full_recon() {
  local url
  url=$(TEXT_PICKER "Target URL" "http://192.168.1.1") || return 1
  check_return_code || return 1
  
  local output="$ARTIFACT_DIR/web_full_$(ts).txt"
  LOG blue "Running full web recon on $url..."
  
  local spinner_id
  spinner_id=$(START_SPINNER "Full web reconnaissance...")
  
  {
    echo "=== Full Web Reconnaissance ==="
    echo "URL: $url"
    echo "Time: $(date)"
    echo ""
    
    echo "========== TECHNOLOGY DETECTION =========="
    # Inline tech detection
    local headers
    headers=$(curl -sI -L --connect-timeout 5 "$url" 2>/dev/null || echo "")
    echo "$headers" | grep -iE "^(server|x-powered-by|x-aspnet|x-generator):" || true
    echo ""
    
    echo "========== SECURITY HEADERS =========="
    for hdr in "strict-transport-security" "x-frame-options" "x-content-type-options" "content-security-policy"; do
      if echo "$headers" | grep -qi "$hdr"; then
        echo "[+] $hdr: Present"
      else
        echo "[-] $hdr: MISSING"
      fi
    done
    echo ""
    
    echo "========== ROBOTS/SITEMAP =========="
    curl -sL --connect-timeout 5 "${url}/robots.txt" 2>/dev/null | head -20 || echo "(no robots.txt)"
    echo ""
    
    echo "========== COMMON PATHS =========="
    local paths=("admin" "login" "api" "wp-admin" ".git/HEAD" ".env" "backup" "phpmyadmin")
    for path in "${paths[@]}"; do
      local code
      code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/${path}" 2>/dev/null || echo "000")
      if [[ "$code" != "404" && "$code" != "000" ]]; then
        echo "[$code] /${path}"
      fi
    done
    echo ""
    
    echo "========== VULNERABILITY CHECKS =========="
    # Directory listing
    if curl -sL --connect-timeout 5 "${url}/" 2>/dev/null | grep -qi "index of"; then
      echo "[!] Directory listing enabled"
    fi
    # Git exposure
    if [[ "$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/.git/HEAD" 2>/dev/null)" == "200" ]]; then
      echo "[!] .git directory exposed"
    fi
    # Env exposure
    if [[ "$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${url}/.env" 2>/dev/null)" == "200" ]]; then
      echo "[!] .env file exposed"
    fi
    
  } > "$output" 2>&1
  
  STOP_SPINNER "$spinner_id"
  
  LOG green "Full recon complete"
  LOG "Results saved to $output"
  
  # Show summary
  LOG ""
  LOG "=== Key Findings ==="
  grep -E "^\[!|\[-\]|MISSING|exposed" "$output" 2>/dev/null | head -15 || echo "(none)"
}
