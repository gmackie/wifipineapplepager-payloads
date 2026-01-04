#!/bin/bash
# Title: Evidence Packager
# Description: Bundle /tmp/ artifacts with timestamps, hashes, and engagement ID
# Author: Red Team Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
#
# LED States
# - Amber: Scanning for artifacts
# - Blue: Packaging
# - Green: Complete
# - Red: Error

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-/root/evidence}"
ARTIFACTS_BASE="${ARTIFACTS_BASE:-/tmp}"
HASH_ALGO="${HASH_ALGO:-sha256}"

have() { command -v "$1" >/dev/null 2>&1; }

ARTIFACT_PATTERNS=(
  "recon-dashboard"
  "wifi-posture-audit"
  "rf-baseline"
  "pocsag-monitor"
  "handshake-capture"
  "evil-twin"
  "passive-recon"
  "mitm-setup"
  "packet-sniffer"
  "cred-harvester"
  "dns-tunnel"
  "http-exfil"
  "staged-transfer"
  "stego-transfer"
  "rogue-twin-radar"
  "beacon-anomaly"
  "wps-beacon"
  "enterprise-beacon"
  "ot-oui-scout"
  "probe-whisperer"
  "hidden-ssid"
  "p2p-hotspot"
  "channel-heatmap"
  "red-team-toolkit"
  "ssl-strip"
  "deauth"
)

FILE_COUNT=0
TOTAL_SIZE=0
HASH_MANIFEST=""

scan_artifacts() {
  local base_dir="$1"
  local found_dirs=()
  
  LOG "Scanning for artifacts in $base_dir..."
  
  for pattern in "${ARTIFACT_PATTERNS[@]}"; do
    local matches
    matches=$(find "$base_dir" -maxdepth 2 -type d -name "*${pattern}*" 2>/dev/null || true)
    
    for dir in $matches; do
      if [[ -d "$dir" ]]; then
        local file_count
        file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
        if [[ $file_count -gt 0 ]]; then
          found_dirs+=("$dir")
          LOG "  Found: $dir ($file_count files)"
        fi
      fi
    done
  done
  
  local pcaps
  pcaps=$(find "$base_dir" -maxdepth 3 -name "*.pcap" -o -name "*.cap" 2>/dev/null || true)
  local logs
  logs=$(find "$base_dir" -maxdepth 3 -name "*.log" 2>/dev/null || true)
  local csvs
  csvs=$(find "$base_dir" -maxdepth 3 -name "*.csv" 2>/dev/null || true)
  
  echo "${found_dirs[@]:-}"
}

calculate_hash() {
  local file="$1"
  
  if have sha256sum; then
    sha256sum "$file" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif have md5sum; then
    md5sum "$file" | awk '{print $1}'
  else
    echo "NO_HASH_TOOL"
  fi
}

create_manifest() {
  local pkg_dir="$1"
  local manifest_file="$2"
  
  {
    echo "========================================"
    echo "      EVIDENCE PACKAGE MANIFEST"
    echo "========================================"
    echo "Created: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Engagement: $ENGAGEMENT_ID"
    echo "Hostname: $(hostname)"
    echo "Hash Algorithm: $HASH_ALGO"
    echo ""
    echo "FILES"
    echo "-----"
    
    find "$pkg_dir" -type f ! -name "manifest.txt" | sort | while read -r file; do
      local rel_path="${file#$pkg_dir/}"
      local size
      size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
      local hash
      hash=$(calculate_hash "$file")
      local mtime
      mtime=$(stat -c%y "$file" 2>/dev/null || stat -f%Sm "$file" 2>/dev/null || echo "unknown")
      
      FILE_COUNT=$((FILE_COUNT + 1))
      TOTAL_SIZE=$((TOTAL_SIZE + size))
      
      echo ""
      echo "File: $rel_path"
      echo "  Size: $size bytes"
      echo "  Modified: $mtime"
      echo "  $HASH_ALGO: $hash"
    done
    
    echo ""
    echo "========================================"
    echo "SUMMARY"
    echo "========================================"
    echo "Total Files: $FILE_COUNT"
    echo "Total Size: $TOTAL_SIZE bytes"
    echo ""
    echo "Package Integrity Hash (this manifest):"
    echo "  Generated at package creation time"
    echo "========================================"
  } > "$manifest_file"
}

create_timeline() {
  local pkg_dir="$1"
  local timeline_file="$2"
  
  {
    echo "========================================"
    echo "      EVIDENCE TIMELINE"
    echo "========================================"
    echo "Engagement: $ENGAGEMENT_ID"
    echo ""
    
    find "$pkg_dir" -type f -name "*.log" -o -name "*.txt" 2>/dev/null | while read -r file; do
      grep -hEo '\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\[\d{2}:\d{2}:\d{2}\]' "$file" 2>/dev/null | head -20
    done | sort -u | head -100
    
    echo ""
    echo "========================================"
  } > "$timeline_file"
}

package_artifacts() {
  local engagement_id="$1"
  local artifact_dirs="$2"
  
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  local pkg_name="${engagement_id}_evidence_${timestamp}"
  local pkg_dir="$OUTPUT_DIR/$pkg_name"
  
  mkdir -p "$pkg_dir"
  
  LED B SLOW
  LOG "Creating evidence package: $pkg_name"
  LOG ""
  
  for dir in $artifact_dirs; do
    if [[ -d "$dir" ]]; then
      local dir_name
      dir_name=$(basename "$dir")
      LOG "  Copying: $dir_name"
      cp -r "$dir" "$pkg_dir/" 2>/dev/null || true
    fi
  done
  
  find "$ARTIFACTS_BASE" -maxdepth 3 \( -name "*.pcap" -o -name "*.cap" -o -name "*.hccapx" -o -name "*.22000" \) -exec cp {} "$pkg_dir/" \; 2>/dev/null || true
  
  LOG ""
  LOG "Generating manifest and hashes..."
  create_manifest "$pkg_dir" "$pkg_dir/manifest.txt"
  
  create_timeline "$pkg_dir" "$pkg_dir/timeline.txt"
  
  LOG "Creating archive..."
  local archive_name="${pkg_name}.tar.gz"
  tar -czf "$OUTPUT_DIR/$archive_name" -C "$OUTPUT_DIR" "$pkg_name" 2>/dev/null
  
  local archive_hash
  archive_hash=$(calculate_hash "$OUTPUT_DIR/$archive_name")
  
  {
    echo "Evidence Package: $archive_name"
    echo "Created: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Engagement: $engagement_id"
    echo ""
    echo "Archive Hash ($HASH_ALGO):"
    echo "$archive_hash"
    echo ""
    echo "Verification command:"
    echo "  sha256sum -c ${archive_name}.sha256"
  } > "$OUTPUT_DIR/${archive_name}.sha256"
  echo "$archive_hash  $archive_name" >> "$OUTPUT_DIR/${archive_name}.sha256"
  
  echo "$OUTPUT_DIR/$archive_name"
}

main() {
  LOG blue "=== Evidence Packager ==="
  LOG "Bundle artifacts with integrity verification"
  LOG ""
  
  ENGAGEMENT_ID=$(TEXT_PICKER "Engagement ID" "engagement-$(date +%Y%m%d)") || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  [[ -z "$ENGAGEMENT_ID" ]] && ENGAGEMENT_ID="engagement-$(date +%Y%m%d)"
  
  ENGAGEMENT_ID=$(echo "$ENGAGEMENT_ID" | tr ' ' '_' | tr -cd '[:alnum:]_-')
  
  LOG "Engagement: $ENGAGEMENT_ID"
  LOG ""
  
  mkdir -p "$OUTPUT_DIR"
  
  LED Y SLOW
  
  local spinner_id
  spinner_id=$(START_SPINNER "Scanning for artifacts...")
  
  local found_dirs
  found_dirs=$(scan_artifacts "$ARTIFACTS_BASE")
  
  STOP_SPINNER "$spinner_id"
  
  if [[ -z "$found_dirs" ]]; then
    LOG ""
    LOG red "No artifacts found in $ARTIFACTS_BASE"
    
    local resp
    resp=$(CONFIRMATION_DIALOG "No artifacts found. Create empty package?") || true
    case "$resp" in
      "$DUCKYSCRIPT_USER_DENIED")
        LOG "Cancelled"
        exit 0
        ;;
    esac
  fi
  
  LOG ""
  LOG "Found artifact directories:"
  for dir in $found_dirs; do
    LOG "  $(basename "$dir")"
  done
  
  local resp
  resp=$(CONFIRMATION_DIALOG "Package these artifacts?") || true
  case "$resp" in
    "$DUCKYSCRIPT_USER_DENIED")
      LOG "Cancelled"
      exit 0
      ;;
  esac
  
  spinner_id=$(START_SPINNER "Creating evidence package...")
  
  local archive
  archive=$(package_artifacts "$ENGAGEMENT_ID" "$found_dirs")
  
  STOP_SPINNER "$spinner_id"
  
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  
  LOG ""
  LOG green "=== Package Created ==="
  LOG "Archive: $archive"
  LOG "Files: $FILE_COUNT"
  LOG "Size: $((TOTAL_SIZE / 1024)) KB"
  LOG ""
  LOG "Integrity file: ${archive}.sha256"
  
  ALERT "Evidence package created: $FILE_COUNT files"
  
  PROMPT "Press button to exit"
}

main "$@"
