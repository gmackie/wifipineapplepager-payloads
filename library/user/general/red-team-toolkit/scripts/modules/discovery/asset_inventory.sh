#!/bin/bash
# Asset inventory aggregation and display

rt_asset_inventory() {
  local choice
  choice=$(menu_pick "Asset Inventory" \
    "View Current Inventory" \
    "Rebuild from Scan Results" \
    "Export to CSV" \
    "Clear Inventory")
  
  case "$choice" in
    1) rt_view_inventory ;;
    2) rt_rebuild_inventory ;;
    3) rt_export_inventory ;;
    4) rt_clear_inventory ;;
    0|"") return ;;
  esac
}

rt_view_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  
  if [[ ! -f "$inv_file" ]]; then
    LOG "No inventory yet. Run scans first, then rebuild."
    return
  fi
  
  LOG blue "=== Asset Inventory ==="
  cat "$inv_file"
  LOG ""
  LOG "Total entries: $(wc -l < "$inv_file")"
}

rt_rebuild_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Rebuilding inventory from scan results..."
  
  # Aggregate IPs from various scan outputs
  {
    echo "# Asset Inventory - $(date)"
    echo "# IP | MAC | Vendor | Ports | Type"
    echo "#-----------------------------------"
    
    # Parse ARP scan results
    if ls "$ARTIFACT_DIR"/arp_scan_*.txt 1>/dev/null 2>&1; then
      grep -h "^\([0-9]\)" "$ARTIFACT_DIR"/arp_scan_*.txt 2>/dev/null | \
        awk '{print $1 " | " $2 " | " $3}' | sort -u
    fi
    
    # Parse fingerprint results
    if ls "$ARTIFACT_DIR"/fingerprint_*.txt 1>/dev/null 2>&1; then
      for f in "$ARTIFACT_DIR"/fingerprint_*.txt; do
        local ip
        ip=$(grep "OT Fingerprint:" "$f" | awk '{print $NF}')
        local mac
        mac=$(grep "MAC Address:" "$f" | awk '{print $NF}')
        local vendor
        vendor=$(grep "Vendor (OUI):" "$f" | cut -d: -f2-)
        local dtype
        dtype=$(grep "Device Type:" "$f" | cut -d: -f2-)
        
        [[ -n "$ip" ]] && echo "$ip | ${mac:-?} | ${vendor:-?} | | ${dtype:-?}"
      done
    fi
    
    # Parse OT subnet scans
    if ls "$ARTIFACT_DIR"/ot_subnet_*.txt 1>/dev/null 2>&1; then
      grep -h "^\[OT\]" "$ARTIFACT_DIR"/ot_subnet_*.txt 2>/dev/null | \
        awk '{print $2 " | | | " substr($0, index($0,$4)) " | OT Device"}' | sort -u
    fi
    
  } | sort -t'|' -k1 -u > "$inv_file"
  
  LOG green "Inventory rebuilt: $inv_file"
  LOG "Entries: $(grep -c -v "^#" "$inv_file")"
}

rt_export_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  local csv_file
  csv_file="$ARTIFACT_DIR/inventory_$(ts).csv"
  
  if [[ ! -f "$inv_file" ]]; then
    LOG red "No inventory to export. Rebuild first."
    return 1
  fi
  
  LOG blue "Exporting to CSV..."
  
  {
    echo "IP,MAC,Vendor,Ports,Type"
    grep -v "^#" "$inv_file" | sed 's/ | /,/g'
  } > "$csv_file"
  
  LOG green "Exported: $csv_file"
}

rt_clear_inventory() {
  if confirm_danger "Clear asset inventory?"; then
    rm -f "$ARTIFACT_DIR/inventory.txt"
    LOG "Inventory cleared"
  fi
}
