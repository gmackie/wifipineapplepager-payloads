#!/bin/bash
# Executive summary and report export

rt_export() {
  local choice
  choice=$(menu_pick "Export Reports" \
    "Executive Summary" \
    "Technical Findings" \
    "Asset Inventory Report" \
    "Credential Report" \
    "Full Archive (tar.gz)")
  
  case "$choice" in
    1) export_executive ;;
    2) export_technical ;;
    3) export_assets ;;
    4) export_credentials ;;
    5) export_archive ;;
    0|"") return ;;
  esac
}

export_executive() {
  local report="$ARTIFACT_DIR/executive_summary.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Generating executive summary..."
  
  {
    echo "=============================================="
    echo "EXECUTIVE SUMMARY"
    echo "=============================================="
    echo ""
    echo "Engagement: $ENGAGEMENT_NAME"
    echo "Date: $(date '+%Y-%m-%d')"
    echo "Target Network: $TARGET_NETWORK"
    echo ""
    echo "----------------------------------------------"
    echo "KEY FINDINGS"
    echo "----------------------------------------------"
    echo ""
    
    local hosts_discovered=0
    local ot_devices=0
    local creds_found=0
    local vulns=0
    
    if [[ -f "$ARTIFACT_DIR/inventory.txt" ]]; then
      hosts_discovered=$(grep -c "^[0-9]" "$ARTIFACT_DIR/inventory.txt" 2>/dev/null || echo 0)
    fi
    
    ot_devices=$(find "$ARTIFACT_DIR" -name "fingerprint*.txt" -exec grep -l "OT\|ICS\|PLC\|HMI" {} \; 2>/dev/null | wc -l)
    
    creds_found=$(find "$ARTIFACT_DIR" -name "*cred*" -o -name "*hash*" 2>/dev/null | xargs grep -c "" 2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')
    
    vulns=$(find "$ARTIFACT_DIR" -name "*.txt" -exec grep -l "WARNING\|VULNERABLE\|default\|anonymous" {} \; 2>/dev/null | wc -l)
    
    echo "1. NETWORK DISCOVERY"
    echo "   - Hosts discovered: $hosts_discovered"
    echo "   - OT/ICS devices identified: $ot_devices"
    echo ""
    
    echo "2. CREDENTIAL EXPOSURE"
    echo "   - Credentials/hashes captured: $creds_found"
    if [[ -d "$ARTIFACT_DIR/responder" ]]; then
      local ntlm_count
      ntlm_count=$(find "$ARTIFACT_DIR/responder" -name "*NTLM*" 2>/dev/null | wc -l)
      echo "   - NTLM hashes: $ntlm_count files"
    fi
    echo ""
    
    echo "3. VULNERABILITIES"
    echo "   - Findings with security issues: $vulns"
    echo ""
    
    if [[ "$ot_devices" -gt 0 ]]; then
      echo "4. OT/ICS CONCERNS"
      echo "   - OT devices accessible from IT network"
      echo "   - Protocol-level access verified"
      echo ""
    fi
    
    echo "----------------------------------------------"
    echo "RISK ASSESSMENT"
    echo "----------------------------------------------"
    echo ""
    
    local risk="LOW"
    if [[ "$creds_found" -gt 10 ]] || [[ "$ot_devices" -gt 5 ]]; then
      risk="HIGH"
    elif [[ "$creds_found" -gt 0 ]] || [[ "$ot_devices" -gt 0 ]]; then
      risk="MEDIUM"
    fi
    
    echo "Overall Risk Level: $risk"
    echo ""
    
    case "$risk" in
      HIGH)
        echo "Immediate remediation recommended:"
        echo "  - Segment OT networks from IT"
        echo "  - Rotate compromised credentials"
        echo "  - Enable SMB signing"
        ;;
      MEDIUM)
        echo "Near-term remediation recommended:"
        echo "  - Review network segmentation"
        echo "  - Audit default credentials"
        ;;
      LOW)
        echo "Continue monitoring and periodic assessments."
        ;;
    esac
    
    echo ""
    echo "----------------------------------------------"
    echo "ARTIFACTS"
    echo "----------------------------------------------"
    echo ""
    echo "Full artifacts available in: $ARTIFACT_DIR"
    echo "Total files: $(find "$ARTIFACT_DIR" -type f 2>/dev/null | wc -l)"
    
  } | tee "$report"
  
  LOG green "Executive summary: $report"
}

export_technical() {
  local report="$ARTIFACT_DIR/technical_findings.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Generating technical findings..."
  
  {
    echo "=============================================="
    echo "TECHNICAL FINDINGS REPORT"
    echo "=============================================="
    echo ""
    echo "Engagement: $ENGAGEMENT_NAME"
    echo "Generated: $(date)"
    echo ""
    
    echo "=== NETWORK SCANS ==="
    for f in "$ARTIFACT_DIR"/arp_scan*.txt "$ARTIFACT_DIR"/ping_sweep*.txt "$ARTIFACT_DIR"/port_scan*.txt; do
      if [[ -f "$f" ]]; then
        echo ""
        echo "--- $(basename "$f") ---"
        head -50 "$f"
        local lines
        lines=$(wc -l < "$f")
        [[ "$lines" -gt 50 ]] && echo "... ($lines total lines)"
      fi
    done
    
    echo ""
    echo "=== SERVICE IDENTIFICATION ==="
    for f in "$ARTIFACT_DIR"/services*.txt "$ARTIFACT_DIR"/banners*.txt; do
      if [[ -f "$f" ]]; then
        echo ""
        echo "--- $(basename "$f") ---"
        head -50 "$f"
      fi
    done
    
    echo ""
    echo "=== OT DEVICE FINGERPRINTS ==="
    for f in "$ARTIFACT_DIR"/fingerprint*.txt; do
      if [[ -f "$f" ]]; then
        echo ""
        echo "--- $(basename "$f") ---"
        cat "$f"
      fi
    done
    
    echo ""
    echo "=== PROTOCOL INTERACTIONS ==="
    for f in "$ARTIFACT_DIR"/modbus*.txt "$ARTIFACT_DIR"/enip*.txt "$ARTIFACT_DIR"/opcua*.txt "$ARTIFACT_DIR"/s7comm*.txt "$ARTIFACT_DIR"/bacnet*.txt "$ARTIFACT_DIR"/dnp3*.txt; do
      if [[ -f "$f" ]]; then
        echo ""
        echo "--- $(basename "$f") ---"
        head -100 "$f"
      fi
    done
    
    echo ""
    echo "=== CREDENTIAL FINDINGS ==="
    for f in "$ARTIFACT_DIR"/creds*.txt "$ARTIFACT_DIR"/default*.txt "$ARTIFACT_DIR"/snmp*.txt; do
      if [[ -f "$f" ]]; then
        echo ""
        echo "--- $(basename "$f") ---"
        cat "$f"
      fi
    done
    
  } | tee "$report"
  
  LOG green "Technical findings: $report"
}

export_assets() {
  local report="$ARTIFACT_DIR/asset_report.txt"
  
  if [[ -f "$ARTIFACT_DIR/inventory.txt" ]]; then
    {
      echo "=============================================="
      echo "ASSET INVENTORY REPORT"
      echo "=============================================="
      echo ""
      echo "Engagement: $ENGAGEMENT_NAME"
      echo "Generated: $(date)"
      echo ""
      cat "$ARTIFACT_DIR/inventory.txt"
    } | tee "$report"
    
    LOG green "Asset report: $report"
  else
    LOG "No inventory found. Run: Discovery > View Asset Inventory"
  fi
}

export_credentials() {
  local report="$ARTIFACT_DIR/credential_report.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Generating credential report..."
  
  {
    echo "=============================================="
    echo "CREDENTIAL REPORT"
    echo "=============================================="
    echo ""
    echo "Engagement: $ENGAGEMENT_NAME"
    echo "Generated: $(date)"
    echo "WARNING: Contains sensitive data"
    echo ""
    
    echo "=== DEFAULT CREDENTIALS FOUND ==="
    for f in "$ARTIFACT_DIR"/default_creds*.txt "$ARTIFACT_DIR"/creds*.txt; do
      if [[ -f "$f" ]]; then
        grep -E "SUCCESS|VALID|authenticated" "$f" 2>/dev/null || true
      fi
    done
    
    echo ""
    echo "=== SNMP COMMUNITIES ==="
    for f in "$ARTIFACT_DIR"/snmp*.txt; do
      if [[ -f "$f" ]]; then
        grep -v "^#" "$f" 2>/dev/null | head -20
      fi
    done
    
    echo ""
    echo "=== CAPTURED HASHES ==="
    if [[ -d "$ARTIFACT_DIR/responder" ]]; then
      for f in "$ARTIFACT_DIR/responder"/*NTLM*.txt; do
        if [[ -f "$f" ]]; then
          echo "--- $(basename "$f") ---"
          head -10 "$f"
          echo "..."
        fi
      done
    fi
    
    echo ""
    echo "=== PLAINTEXT CAPTURES ==="
    for f in "$ARTIFACT_DIR"/plaintext*.txt "$ARTIFACT_DIR"/http_auth*.txt; do
      if [[ -f "$f" ]]; then
        echo "--- $(basename "$f") ---"
        cat "$f"
      fi
    done
    
    echo ""
    echo "=== CAPTIVE PORTAL ==="
    if [[ -f "$ARTIFACT_DIR/portal/captured_creds.txt" ]]; then
      cat "$ARTIFACT_DIR/portal/captured_creds.txt"
    fi
    
  } | tee "$report"
  
  LOG green "Credential report: $report"
}

export_archive() {
  local archive_name="${ENGAGEMENT_NAME}_$(date +%Y%m%d_%H%M%S).tar.gz"
  local archive_path="/tmp/$archive_name"
  
  LOG blue "Creating full archive..."
  
  if have tar; then
    tar -czf "$archive_path" -C "$(dirname "$ARTIFACT_DIR")" "$(basename "$ARTIFACT_DIR")" 2>/dev/null
    
    local size
    size=$(stat -f "%z" "$archive_path" 2>/dev/null || stat -c "%s" "$archive_path" 2>/dev/null)
    size=$((size / 1024))
    
    LOG green "Archive created: $archive_path (${size}KB)"
    LOG ""
    LOG "Transfer with:"
    LOG "  scp root@pager:$archive_path ."
  else
    LOG red "tar required"
  fi
}
