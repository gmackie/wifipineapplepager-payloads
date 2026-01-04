#!/bin/bash
# Title: Steganography Transfer
# Description: Hide data in images for covert exfiltration
# Author: Red Team Toolkit
# Version: 1.0
# Category: exfiltration
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Processing image
# - Cyan: Embedding data
# - Green: Complete
# - Red: Error
#
# Use Case: Conceal sensitive data within innocent-looking images
# Supports: LSB embedding, file appending, metadata injection

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/stego-transfer}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  LED OFF
}
trap cleanup EXIT

# LSB (Least Significant Bit) embedding for PNG/BMP
# Simple implementation - embeds data in least significant bits
embed_lsb() {
  local image="$1"
  local data="$2"
  local output="$3"
  
  LOG "Using LSB embedding..."
  
  # Check if steghide is available
  if have steghide; then
    local passphrase
    passphrase=$(TEXT_PICKER "Passphrase (encryption)" "redteam") || true
    [[ -z "$passphrase" ]] && passphrase="redteam"
    
    # Create temp file with data
    local tmp_data
    tmp_data=$(mktemp)
    echo -n "$data" > "$tmp_data"
    
    if steghide embed -cf "$image" -ef "$tmp_data" -sf "$output" -p "$passphrase" -q 2>/dev/null; then
      rm -f "$tmp_data"
      LOG green "Data embedded with steghide"
      return 0
    else
      rm -f "$tmp_data"
      LOG red "steghide embedding failed"
      return 1
    fi
  fi
  
  # Fallback: Simple file append technique (works with JPEG)
  LOG "Falling back to append method..."
  cp "$image" "$output"
  
  local marker="<!--STEGO_START-->"
  local end_marker="<!--STEGO_END-->"
  local encoded
  encoded=$(echo -n "$data" | base64)
  
  echo -n "${marker}${encoded}${end_marker}" >> "$output"
  
  LOG green "Data appended to image"
  return 0
}

# Extract data from stego image
extract_lsb() {
  local image="$1"
  local output="$2"
  
  LOG "Extracting hidden data..."
  
  if have steghide; then
    local passphrase
    passphrase=$(TEXT_PICKER "Passphrase" "redteam") || true
    [[ -z "$passphrase" ]] && passphrase="redteam"
    
    if steghide extract -sf "$image" -xf "$output" -p "$passphrase" -q 2>/dev/null; then
      LOG green "Data extracted with steghide"
      LOG "Output: $output"
      return 0
    else
      LOG red "steghide extraction failed"
    fi
  fi
  
  # Fallback: Extract appended data
  LOG "Trying append method..."
  local marker="<!--STEGO_START-->"
  local end_marker="<!--STEGO_END-->"
  
  local content
  content=$(cat "$image")
  
  if [[ "$content" == *"$marker"* ]]; then
    local encoded
    encoded=$(echo "$content" | sed -n "s/.*${marker}\(.*\)${end_marker}.*/\1/p")
    echo "$encoded" | base64 -d > "$output"
    LOG green "Data extracted"
    LOG "Output: $output"
    return 0
  fi
  
  LOG red "No hidden data found"
  return 1
}

# EXIF metadata injection
inject_metadata() {
  local image="$1"
  local data="$2"
  local output="$3"
  
  LOG "Injecting into EXIF metadata..."
  
  cp "$image" "$output"
  
  if have exiftool; then
    local encoded
    encoded=$(echo -n "$data" | base64)
    
    # Store in Comment, UserComment, or ImageDescription
    exiftool -overwrite_original \
      -Comment="$encoded" \
      -UserComment="$encoded" \
      "$output" 2>/dev/null
    
    LOG green "Data stored in EXIF metadata"
    return 0
  elif have exiv2; then
    local encoded
    encoded=$(echo -n "$data" | base64)
    
    exiv2 -M"set Exif.Photo.UserComment $encoded" "$output" 2>/dev/null
    
    LOG green "Data stored in EXIF metadata"
    return 0
  else
    LOG red "No EXIF tools available (exiftool/exiv2)"
    return 1
  fi
}

# Extract from EXIF
extract_metadata() {
  local image="$1"
  local output="$2"
  
  LOG "Extracting from EXIF metadata..."
  
  local encoded=""
  
  if have exiftool; then
    encoded=$(exiftool -Comment -b "$image" 2>/dev/null)
  elif have exiv2; then
    encoded=$(exiv2 -pa "$image" 2>/dev/null | grep UserComment | awk '{print $NF}')
  else
    LOG red "No EXIF tools available"
    return 1
  fi
  
  if [[ -n "$encoded" ]]; then
    echo "$encoded" | base64 -d > "$output"
    LOG green "Data extracted from EXIF"
    return 0
  fi
  
  LOG red "No hidden data in metadata"
  return 1
}

# Embed file into image (for larger payloads)
embed_file() {
  local image="$1"
  local file="$2"
  local output="$3"
  
  LOG "Embedding file: $file"
  
  if have steghide; then
    local passphrase
    passphrase=$(TEXT_PICKER "Passphrase" "redteam") || true
    [[ -z "$passphrase" ]] && passphrase="redteam"
    
    if steghide embed -cf "$image" -ef "$file" -sf "$output" -p "$passphrase" -q 2>/dev/null; then
      LOG green "File embedded successfully"
      return 0
    else
      LOG red "Embedding failed - file too large?"
      return 1
    fi
  fi
  
  # Fallback: ZIP append (works universally)
  LOG "Using ZIP append method..."
  
  cp "$image" "$output"
  
  local tmp_zip
  tmp_zip=$(mktemp --suffix=.zip)
  zip -q "$tmp_zip" "$file"
  cat "$tmp_zip" >> "$output"
  rm -f "$tmp_zip"
  
  LOG green "File appended as ZIP"
  LOG "Extract with: unzip -j $output"
  
  return 0
}

show_tool_status() {
  LOG blue "=== Available Tools ==="
  have steghide && LOG green "steghide: installed" || LOG red "steghide: not found"
  have exiftool && LOG green "exiftool: installed" || LOG red "exiftool: not found"
  have exiv2 && LOG green "exiv2: installed" || LOG red "exiv2: not found"
  have zip && LOG green "zip: installed" || LOG red "zip: not found"
  LOG ""
}

main() {
  LOG blue "=== Steganography Transfer ==="
  LOG "Hide data in images for covert exfil"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  show_tool_status
  
  # Select mode
  LOG "Select operation:"
  LOG "1. Embed string in image"
  LOG "2. Embed file in image"
  LOG "3. Extract hidden data"
  LOG "4. Inject into EXIF metadata"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-4)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "$mode" in
    1)  # Embed string
      local image
      image=$(TEXT_PICKER "Source image path" "/tmp/cover.jpg") || true
      [[ -z "$image" ]] && { LOG "Cancelled"; exit 1; }
      
      if [[ ! -f "$image" ]]; then
        ERROR_DIALOG "Image not found: $image"
        exit 1
      fi
      
      local data
      data=$(TEXT_PICKER "Data to hide" "") || true
      [[ -z "$data" ]] && { LOG "Cancelled"; exit 1; }
      
      local output="$ARTIFACTS_DIR/stego_$(date +%Y%m%d_%H%M%S).${image##*.}"
      
      LED Y SOLID
      embed_lsb "$image" "$data" "$output"
      
      LED G SOLID
      LOG ""
      LOG green "Output: $output"
      ;;
      
    2)  # Embed file
      local image
      image=$(TEXT_PICKER "Cover image path" "/tmp/cover.jpg") || true
      [[ -z "$image" || ! -f "$image" ]] && { ERROR_DIALOG "Image not found"; exit 1; }
      
      local file
      file=$(TEXT_PICKER "File to embed" "/tmp/secret.txt") || true
      [[ -z "$file" || ! -f "$file" ]] && { ERROR_DIALOG "File not found"; exit 1; }
      
      local output="$ARTIFACTS_DIR/stego_$(date +%Y%m%d_%H%M%S).${image##*.}"
      
      LED Y SOLID
      embed_file "$image" "$file" "$output"
      
      LED G SOLID
      LOG ""
      LOG green "Output: $output"
      ;;
      
    3)  # Extract
      local image
      image=$(TEXT_PICKER "Stego image path" "") || true
      [[ -z "$image" || ! -f "$image" ]] && { ERROR_DIALOG "Image not found"; exit 1; }
      
      local output="$ARTIFACTS_DIR/extracted_$(date +%Y%m%d_%H%M%S).bin"
      
      LED C SOLID
      if extract_lsb "$image" "$output"; then
        LED G SOLID
        LOG ""
        LOG "Content:"
        head -c 500 "$output"
      else
        LED R SOLID
      fi
      ;;
      
    4)  # EXIF metadata
      local image
      image=$(TEXT_PICKER "Image path" "/tmp/cover.jpg") || true
      [[ -z "$image" || ! -f "$image" ]] && { ERROR_DIALOG "Image not found"; exit 1; }
      
      local data
      data=$(TEXT_PICKER "Data to inject" "") || true
      [[ -z "$data" ]] && { LOG "Cancelled"; exit 1; }
      
      local output="$ARTIFACTS_DIR/exif_$(date +%Y%m%d_%H%M%S).${image##*.}"
      
      LED Y SOLID
      inject_metadata "$image" "$data" "$output"
      
      LED G SOLID
      LOG ""
      LOG green "Output: $output"
      ;;
      
    *)
      ERROR_DIALOG "Invalid mode"
      exit 1
      ;;
  esac
  
  VIBRATE
  PROMPT "Press button to exit"
}

main "$@"
