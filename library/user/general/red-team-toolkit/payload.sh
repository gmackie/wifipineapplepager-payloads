#!/bin/bash
# Title: Red Team Toolkit v2.4
# Description: Swiss-army-knife payload for IT/OT penetration testing
# Author: YourTeam
# Version: 2.4
# Category: general
# Net Mode: NAT
#
# LED States
# - Blue: Menu / idle
# - Amber: Working
# - Green: Success
# - Red: Error

set -euo pipefail

# Resolve script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and helpers
source "$DIR/scripts/config.sh"
source "$DIR/scripts/common.sh"
source "$DIR/scripts/menu.sh"
source "$DIR/scripts/modules/laptop/ssh_exec.sh"

# Ensure artifact directories exist
ensure_dir "$ARTIFACT_DIR" "$LOG_DIR"

# Source module files
for module_dir in discovery ot-protocols credentials wireless physical laptop reporting network automation; do
  if [[ -d "$DIR/scripts/modules/$module_dir" ]]; then
    for f in "$DIR/scripts/modules/$module_dir"/*.sh; do
      [[ -f "$f" ]] && source "$f"
    done
  fi
done

# === SUBMENUS ===

menu_discovery() {
  while true; do
    local choice
    choice=$(menu_pick "Discovery & Mapping" \
      "ARP/Network Scan" \
      "Port Scan" \
      "Service Identification" \
      "OT Device Fingerprint" \
      "Active Directory Enum" \
      "SMB Enumeration" \
      "Web Scanning" \
      "View Asset Inventory")
    
    case "$choice" in
      1) have rt_net_scan && rt_net_scan || LOG red "Module not implemented" ;;
      2) have rt_port_scan && rt_port_scan || LOG red "Module not implemented" ;;
      3) have rt_service_id && rt_service_id || LOG red "Module not implemented" ;;
      4) have rt_ot_fingerprint && rt_ot_fingerprint || LOG red "Module not implemented" ;;
      5) have rt_ad_enum && rt_ad_enum || LOG red "Module not implemented" ;;
      6) have smb_enum_menu && smb_enum_menu || LOG red "Module not implemented" ;;
      7) have web_scan_menu && web_scan_menu || LOG red "Module not implemented" ;;
      8) have rt_asset_inventory && rt_asset_inventory || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_ot_protocols() {
  while true; do
    local choice
    choice=$(menu_pick "OT Protocol Attacks" \
      "Modbus/TCP" \
      "EtherNet/IP (CIP)" \
      "OPC UA" \
      "DNP3" \
      "PROFINET" \
      "IEC 61850" \
      "BACnet" \
      "S7comm")
    
    case "$choice" in
      1) have rt_modbus && rt_modbus || LOG red "Module not implemented" ;;
      2) have rt_enip_cip && rt_enip_cip || LOG red "Module not implemented" ;;
      3) have rt_opcua && rt_opcua || LOG red "Module not implemented" ;;
      4) have rt_dnp3 && rt_dnp3 || LOG red "Module not implemented" ;;
      5) have rt_profinet && rt_profinet || LOG red "Module not implemented" ;;
      6) have rt_iec61850 && rt_iec61850 || LOG red "Module not implemented" ;;
      7) have rt_bacnet && rt_bacnet || LOG red "Module not implemented" ;;
      8) have rt_s7comm && rt_s7comm || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_credentials() {
  while true; do
    local choice
    choice=$(menu_pick "Credential Harvesting" \
      "Default Credential Check" \
      "SNMP Enumeration" \
      "Passive Hash Capture" \
      "Responder (laptop)" \
      "NTLM Relay (laptop)" \
      "Kerberos Attacks" \
      "Protocol Auth Sniff")
    
    case "$choice" in
      1) have rt_default_creds && rt_default_creds || LOG red "Module not implemented" ;;
      2) have rt_snmp_enum && rt_snmp_enum || LOG red "Module not implemented" ;;
      3) have rt_hash_capture && rt_hash_capture || LOG red "Module not implemented" ;;
      4) have rt_responder && rt_responder || LOG red "Module not implemented" ;;
      5) have rt_ntlm_relay && rt_ntlm_relay || LOG red "Module not implemented" ;;
      6) have rt_kerberos && rt_kerberos || LOG red "Module not implemented" ;;
      7) have rt_protocol_auth && rt_protocol_auth || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_wireless() {
  while true; do
    local choice
    choice=$(menu_pick "Wireless Attacks" \
      "Passive Recon" \
      "Handshake Capture" \
      "WPA Cracking" \
      "Targeted Deauth" \
      "Evil Twin AP" \
      "Deauth Watch")
    
    case "$choice" in
      1) have rt_passive_recon && rt_passive_recon "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error" ;;
      2) 
        if confirm_danger "Handshake capture may send deauth frames. Continue?"; then
          have rt_handshake_capture && rt_handshake_capture "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error"
        fi
        ;;
      3) have rt_wpa_crack && rt_wpa_crack || LOG red "Module not implemented" ;;
      4) have rt_deauth && rt_deauth || LOG red "Module not implemented" ;;
      5) have rt_evil_twin && rt_evil_twin || LOG red "Module not implemented" ;;
      6) have rt_deauth_watch && rt_deauth_watch "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_physical() {
  while true; do
    local choice
    choice=$(menu_pick "Physical/Serial" \
      "RS485 Serial Monitor" \
      "CAN Bus Monitor" \
      "RTL-SDR")
    
    case "$choice" in
      1) have rt_rs485_serial && rt_rs485_serial "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      2) have rt_can_monitor && rt_can_monitor "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      3) have rt_rtl_sdr && rt_rtl_sdr "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_laptop() {
  while true; do
    local choice
    choice=$(menu_pick "Laptop Tools" \
      "Test Connection" \
      "Run Nmap Scan" \
      "Run Responder" \
      "Fetch Results" \
      "Configure Laptop")
    
    case "$choice" in
      1)
        if laptop_ping; then
          LOG green "Laptop connection OK"
        else
          LOG red "Cannot reach laptop"
        fi
        ;;
      2)
        local target
        target=$(IP_PICKER "Target" "${TARGET_NETWORK%%/*}")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        run_with_fallback "nmap -sV $target" "nmap -sV $target -oA $LAPTOP_RESULTS_DIR/nmap_scan"
        ;;
      3)
        if ! check_passive; then continue; fi
        if confirm_danger "Start Responder? This will poison LLMNR/NBT-NS."; then
          laptop_exec_bg "responder -I eth0 -wrf" "$LAPTOP_RESULTS_DIR/responder.log"
          LOG green "Responder started in background"
        fi
        ;;
      4) laptop_fetch_results && LOG green "Results fetched to $ARTIFACT_DIR" ;;
      5)
        LOG "Current config:"
        LOG "  LAPTOP_ENABLED=$LAPTOP_ENABLED"
        LOG "  LAPTOP_HOST=$LAPTOP_HOST"
        LOG "  LAPTOP_KEY=$LAPTOP_KEY"
        LOG ""
        LOG "Edit scripts/config.sh to change"
        ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_configure() {
  while true; do
    local choice
    choice=$(menu_pick "Configure Engagement" \
      "Set Engagement Name" \
      "Set Target Network" \
      "Toggle SAFE_MODE" \
      "Toggle PASSIVE_ONLY" \
      "Toggle Laptop Mode" \
      "View Current Config")
    
    case "$choice" in
      1)
        local name
        name=$(TEXT_PICKER "Engagement Name" "$ENGAGEMENT_NAME")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        export ENGAGEMENT_NAME="$name"
        ARTIFACT_DIR="${TOOLKIT_DIR}/artifacts/${ENGAGEMENT_NAME}"
        LOG_DIR="${TOOLKIT_DIR}/logs/${ENGAGEMENT_NAME}"
        ensure_dir "$ARTIFACT_DIR" "$LOG_DIR"
        LOG green "Engagement: $ENGAGEMENT_NAME"
        ;;
      2)
        local net
        net=$(TEXT_PICKER "Target Network (CIDR)" "$TARGET_NETWORK")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        export TARGET_NETWORK="$net"
        LOG green "Target: $TARGET_NETWORK"
        ;;
      3)
        if [[ "$SAFE_MODE" -eq 1 ]]; then
          export SAFE_MODE=0
          LOG "SAFE_MODE: OFF (dangerous actions allowed)"
        else
          export SAFE_MODE=1
          LOG "SAFE_MODE: ON (confirmations required)"
        fi
        ;;
      4)
        if [[ "$PASSIVE_ONLY" -eq 1 ]]; then
          export PASSIVE_ONLY=0
          LOG "PASSIVE_ONLY: OFF (active attacks allowed)"
        else
          export PASSIVE_ONLY=1
          LOG "PASSIVE_ONLY: ON (active attacks blocked)"
        fi
        ;;
      5)
        if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
          export LAPTOP_ENABLED=0
          LOG "Laptop Mode: OFF"
        else
          export LAPTOP_ENABLED=1
          LOG "Laptop Mode: ON"
        fi
        ;;
      6)
        LOG ""
        LOG "=== Current Configuration ==="
        LOG "Engagement: $ENGAGEMENT_NAME"
        LOG "Target Network: $TARGET_NETWORK"
        LOG "Exclude IPs: ${EXCLUDE_IPS:-none}"
        LOG "OT Network: ${OT_NETWORK:-not set}"
        LOG "SAFE_MODE: $SAFE_MODE"
        LOG "PASSIVE_ONLY: $PASSIVE_ONLY"
        LOG "LAPTOP_ENABLED: $LAPTOP_ENABLED"
        LOG "LAPTOP_HOST: ${LAPTOP_HOST:-not set}"
        LOG "Artifact Dir: $ARTIFACT_DIR"
        ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_network() {
  while true; do
    local choice
    choice=$(menu_pick "Network Attacks" \
      "ARP Spoof / MITM" \
      "DNS Spoofing" \
      "VLAN Hopping")
    
    case "$choice" in
      1) have rt_mitm && rt_mitm || LOG red "Module not implemented" ;;
      2) have rt_dns_spoof && rt_dns_spoof || LOG red "Module not implemented" ;;
      3) have rt_vlan_hop && rt_vlan_hop || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_reporting() {
  while true; do
    local choice
    choice=$(menu_pick "Reporting" \
      "Generate Timeline" \
      "Executive Summary" \
      "Technical Findings" \
      "Credential Report" \
      "Export Archive")
    
    case "$choice" in
      1) have rt_timeline && rt_timeline || LOG red "Module not implemented" ;;
      2) have rt_export && rt_export || LOG red "Module not implemented" ;;
      3) have export_technical && export_technical || LOG red "Module not implemented" ;;
      4) have export_credentials && export_credentials || LOG red "Module not implemented" ;;
      5) have export_archive && export_archive || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

main_menu() {
  LOG green "Red Team Toolkit v2.4 loaded"
  LOG "Artifacts: $ARTIFACT_DIR"
  
  while true; do
    local choice
    choice=$(menu_pick "RED TEAM TOOLKIT v2.4" \
      "Discovery & Mapping" \
      "OT Protocol Attacks" \
      "Credential Harvesting" \
      "Network Attacks" \
      "Wireless Attacks" \
      "Passive Recon Monitors" \
      "Physical/Serial" \
      "Attack Chains" \
      "Notifications" \
      "Laptop Tools" \
      "Reporting" \
      "---" \
      "Configure Engagement")
    
    case "$choice" in
      1) menu_discovery ;;
      2) menu_ot_protocols ;;
      3) menu_credentials ;;
      4) menu_network ;;
      5) menu_wireless ;;
      6) have rt_recon_menu && rt_recon_menu || LOG red "Recon module not loaded" ;;
      7) menu_physical ;;
      8) have attack_chains_menu && attack_chains_menu || LOG red "Module error" ;;
      9) have notify_menu && notify_menu || LOG red "Module error" ;;
      10) menu_laptop ;;
      11) menu_reporting ;;
      12) ;;
      13) menu_configure ;;
      0|"")
        LOG "Exiting toolkit"
        exit 0
        ;;
    esac
  done
}

# Entry point
main_menu
