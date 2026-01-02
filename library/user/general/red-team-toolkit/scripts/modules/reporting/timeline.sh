#!/bin/bash
# Engagement timeline generation from artifacts

rt_timeline() {
  local choice
  choice=$(menu_pick "Timeline" \
    "Generate Timeline" \
    "View Timeline" \
    "Add Manual Entry" \
    "Export Timeline")
  
  case "$choice" in
    1) timeline_generate ;;
    2) timeline_view ;;
    3) timeline_add_entry ;;
    4) timeline_export ;;
    0|"") return ;;
  esac
}

timeline_generate() {
  local timeline_file="$ARTIFACT_DIR/timeline.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Generating engagement timeline..."
  
  {
    echo "=============================================="
    echo "ENGAGEMENT TIMELINE: $ENGAGEMENT_NAME"
    echo "Generated: $(date)"
    echo "=============================================="
    echo ""
    
    echo "=== ARTIFACT TIMELINE ==="
    echo ""
    
    if [[ -d "$ARTIFACT_DIR" ]]; then
      find "$ARTIFACT_DIR" -type f -name "*.txt" -o -name "*.pcap" -o -name "*.csv" 2>/dev/null | while read -r file; do
        local fname
        fname=$(basename "$file")
        local mtime
        mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null || stat -c "%y" "$file" 2>/dev/null | cut -d. -f1)
        local fsize
        fsize=$(stat -f "%z" "$file" 2>/dev/null || stat -c "%s" "$file" 2>/dev/null)
        
        echo "[$mtime] $fname ($fsize bytes)"
        
        case "$fname" in
          arp_scan*) echo "    -> Network scan: discovered hosts" ;;
          fingerprint*) echo "    -> OT device fingerprinting" ;;
          modbus*) echo "    -> Modbus protocol interaction" ;;
          enip*|cip*) echo "    -> EtherNet/IP activity" ;;
          opcua*) echo "    -> OPC UA interaction" ;;
          s7comm*) echo "    -> Siemens S7 protocol" ;;
          bacnet*) echo "    -> BACnet activity" ;;
          creds*|default*) echo "    -> Credential check" ;;
          ntlm*|hash*) echo "    -> Hash/credential capture" ;;
          handshake*) echo "    -> WiFi handshake capture" ;;
          deauth*) echo "    -> Deauth activity" ;;
          portal*) echo "    -> Captive portal" ;;
          inventory*) echo "    -> Asset inventory update" ;;
        esac
      done | sort
    fi
    
    echo ""
    echo "=== MANUAL ENTRIES ==="
    if [[ -f "$ARTIFACT_DIR/manual_entries.txt" ]]; then
      cat "$ARTIFACT_DIR/manual_entries.txt"
    else
      echo "(No manual entries)"
    fi
    
    echo ""
    echo "=== SUMMARY ==="
    local artifact_count
    artifact_count=$(find "$ARTIFACT_DIR" -type f 2>/dev/null | wc -l)
    echo "Total artifacts: $artifact_count"
    
    local cred_files
    cred_files=$(find "$ARTIFACT_DIR" -name "*cred*" -o -name "*hash*" -o -name "*ntlm*" 2>/dev/null | wc -l)
    echo "Credential-related: $cred_files"
    
    local pcaps
    pcaps=$(find "$ARTIFACT_DIR" -name "*.pcap" 2>/dev/null | wc -l)
    echo "Packet captures: $pcaps"
    
  } | tee "$timeline_file"
  
  LOG green "Timeline saved: $timeline_file"
}

timeline_view() {
  local timeline_file="$ARTIFACT_DIR/timeline.txt"
  
  if [[ -f "$timeline_file" ]]; then
    cat "$timeline_file"
  else
    LOG "No timeline generated yet"
    LOG "Run: Timeline > Generate Timeline"
  fi
}

timeline_add_entry() {
  local entry
  entry=$(TEXT_PICKER "Timeline entry" "")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if [[ -z "$entry" ]]; then
    LOG "No entry provided"
    return
  fi
  
  ensure_dir "$ARTIFACT_DIR"
  local manual_file="$ARTIFACT_DIR/manual_entries.txt"
  
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $entry" >> "$manual_file"
  
  LOG green "Entry added to timeline"
}

timeline_export() {
  local timeline_file="$ARTIFACT_DIR/timeline.txt"
  
  if [[ ! -f "$timeline_file" ]]; then
    LOG "Generate timeline first"
    return 1
  fi
  
  local format
  format=$(menu_pick "Export Format" \
    "Plain Text" \
    "CSV" \
    "JSON")
  
  case "$format" in
    1)
      LOG "Timeline already in: $timeline_file"
      ;;
    2)
      local csv_file="$ARTIFACT_DIR/timeline.csv"
      {
        echo "timestamp,artifact,type,size"
        find "$ARTIFACT_DIR" -type f -name "*.txt" -o -name "*.pcap" 2>/dev/null | while read -r file; do
          local fname mtime fsize
          fname=$(basename "$file")
          mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null || stat -c "%y" "$file" 2>/dev/null | cut -d. -f1)
          fsize=$(stat -f "%z" "$file" 2>/dev/null || stat -c "%s" "$file" 2>/dev/null)
          local ftype="${fname%%_*}"
          echo "\"$mtime\",\"$fname\",\"$ftype\",\"$fsize\""
        done
      } > "$csv_file"
      LOG green "Exported: $csv_file"
      ;;
    3)
      local json_file="$ARTIFACT_DIR/timeline.json"
      {
        echo "{"
        echo "  \"engagement\": \"$ENGAGEMENT_NAME\","
        echo "  \"generated\": \"$(date -Iseconds)\","
        echo "  \"artifacts\": ["
        local first=1
        find "$ARTIFACT_DIR" -type f -name "*.txt" -o -name "*.pcap" 2>/dev/null | while read -r file; do
          local fname mtime fsize
          fname=$(basename "$file")
          mtime=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%S" "$file" 2>/dev/null || stat -c "%y" "$file" 2>/dev/null | cut -d. -f1)
          fsize=$(stat -f "%z" "$file" 2>/dev/null || stat -c "%s" "$file" 2>/dev/null)
          [[ $first -eq 0 ]] && echo ","
          first=0
          echo "    {\"time\": \"$mtime\", \"file\": \"$fname\", \"size\": $fsize}"
        done
        echo "  ]"
        echo "}"
      } > "$json_file"
      LOG green "Exported: $json_file"
      ;;
    0|"") return ;;
  esac
}
