#!/bin/bash
# Title: Dependency Checker
# Description: Pre-flight compatibility check - list available vs missing tools
# Author: Red Team Toolkit
# Version: 1.0
# Category: general
# Net Mode: OFF
#
# LED States
# - Blue: Checking
# - Green: All critical tools available
# - Yellow: Some tools missing
# - Red: Critical tools missing

set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

declare -A CRITICAL_TOOLS=(
  ["bash"]="Shell interpreter"
  ["ip"]="Network interface management"
  ["awk"]="Text processing"
  ["grep"]="Pattern matching"
  ["sed"]="Stream editor"
)

declare -A NETWORK_TOOLS=(
  ["tcpdump"]="Packet capture"
  ["nc"]="Netcat - network utility"
  ["curl"]="HTTP client"
  ["wget"]="HTTP downloader"
  ["nmap"]="Network scanner"
  ["arp-scan"]="ARP discovery"
  ["fping"]="Fast ping"
  ["netcat"]="Network utility (alt)"
)

declare -A WIRELESS_TOOLS=(
  ["airmon-ng"]="Monitor mode management"
  ["airodump-ng"]="WiFi reconnaissance"
  ["aireplay-ng"]="Packet injection"
  ["aircrack-ng"]="WPA cracking"
  ["mdk4"]="Deauthentication attacks"
  ["hcxpcapngtool"]="Handshake conversion"
  ["hashcat"]="Password cracking"
  ["hostapd"]="Access point daemon"
  ["dnsmasq"]="DNS/DHCP server"
  ["wpa_supplicant"]="WPA client"
)

declare -A SDR_TOOLS=(
  ["rtl_power"]="RTL-SDR power scanning"
  ["rtl_fm"]="RTL-SDR FM receiver"
  ["rtl_sdr"]="RTL-SDR raw capture"
  ["multimon-ng"]="Signal decoder (POCSAG)"
  ["dump1090"]="ADS-B decoder"
  ["gqrx"]="SDR GUI (if X available)"
)

declare -A MITM_TOOLS=(
  ["arpspoof"]="ARP spoofing"
  ["ettercap"]="Network MITM"
  ["bettercap"]="Advanced MITM"
  ["sslstrip"]="SSL stripping"
  ["mitmproxy"]="HTTP/S proxy"
  ["responder"]="LLMNR/NBT-NS poisoning"
)

declare -A CREDENTIAL_TOOLS=(
  ["john"]="John the Ripper"
  ["hydra"]="Online brute force"
  ["medusa"]="Parallel brute force"
  ["snmpwalk"]="SNMP enumeration"
  ["impacket-secretsdump"]="Windows credential dump"
  ["impacket-GetUserSPNs"]="Kerberoasting"
  ["impacket-ntlmrelayx"]="NTLM relay"
  ["crackmapexec"]="SMB/WinRM attacks"
)

declare -A OT_TOOLS=(
  ["mbpoll"]="Modbus client"
  ["python3"]="Python interpreter"
  ["scapy"]="Packet manipulation"
  ["plcscan"]="PLC scanner"
  ["s7scan"]="Siemens S7 scanner"
)

declare -A SERIAL_TOOLS=(
  ["screen"]="Serial terminal"
  ["minicom"]="Serial communication"
  ["picocom"]="Lightweight serial"
  ["can-utils"]="CAN bus utilities"
  ["candump"]="CAN bus capture"
)

CRITICAL_MISSING=0
CRITICAL_FOUND=0
OPTIONAL_MISSING=0
OPTIONAL_FOUND=0
TOTAL_CHECKED=0

check_category() {
  local category_name="$1"
  local -n tools=$2
  local is_critical="${3:-0}"
  
  LOG ""
  LOG blue "=== $category_name ==="
  
  local found=0
  local missing=0
  
  for tool in "${!tools[@]}"; do
    local desc="${tools[$tool]}"
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
    
    if have "$tool"; then
      LOG green "  [OK] $tool - $desc"
      found=$((found + 1))
      if [[ $is_critical -eq 1 ]]; then
        CRITICAL_FOUND=$((CRITICAL_FOUND + 1))
      else
        OPTIONAL_FOUND=$((OPTIONAL_FOUND + 1))
      fi
    else
      if [[ $is_critical -eq 1 ]]; then
        LOG red "  [MISSING] $tool - $desc"
        CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
      else
        LOG "  [MISSING] $tool - $desc"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
      fi
      missing=$((missing + 1))
    fi
  done
  
  LOG "  Summary: $found/${#tools[@]} available"
}

check_python_modules() {
  LOG ""
  LOG blue "=== Python Modules ==="
  
  if ! have python3; then
    LOG red "  Python3 not available - skipping module check"
    return
  fi
  
  local modules=("opcua" "pycomm3" "scapy" "impacket" "requests" "dnspython")
  
  for mod in "${modules[@]}"; do
    if python3 -c "import $mod" 2>/dev/null; then
      LOG green "  [OK] $mod"
      OPTIONAL_FOUND=$((OPTIONAL_FOUND + 1))
    else
      LOG "  [MISSING] $mod"
      OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
    fi
  done
}

check_hardware() {
  LOG ""
  LOG blue "=== Hardware Detection ==="
  
  local wifi_ifaces
  wifi_ifaces=$(ip -o link | grep -E 'wlan|wlp|ath' | wc -l)
  if [[ $wifi_ifaces -gt 0 ]]; then
    LOG green "  [OK] WiFi interfaces: $wifi_ifaces"
    ip -o link | grep -E 'wlan|wlp|ath' | awk -F': ' '{print "       " $2}'
  else
    LOG "  [MISSING] No WiFi interfaces detected"
  fi
  
  if lsusb 2>/dev/null | grep -qi "RTL2838\|RTL2832"; then
    LOG green "  [OK] RTL-SDR device detected"
  else
    LOG "  [MISSING] No RTL-SDR device detected"
  fi
  
  local serial_ports
  serial_ports=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | wc -l)
  if [[ $serial_ports -gt 0 ]]; then
    LOG green "  [OK] Serial ports: $serial_ports"
  else
    LOG "  [INFO] No USB serial devices"
  fi
  
  if ip -o link | grep -q "can"; then
    LOG green "  [OK] CAN interface detected"
  else
    LOG "  [INFO] No CAN interface"
  fi
}

check_laptop_connectivity() {
  LOG ""
  LOG blue "=== Laptop Mode Check ==="
  
  if have ssh; then
    LOG green "  [OK] SSH client available"
  else
    LOG red "  [MISSING] SSH client"
    return
  fi
  
  if [[ -f "$HOME/.ssh/id_rsa" || -f "$HOME/.ssh/id_ed25519" ]]; then
    LOG green "  [OK] SSH key found"
  else
    LOG "  [INFO] No SSH key found (password auth required)"
  fi
  
  local config_file="/root/red-team-toolkit/scripts/config.sh"
  if [[ -f "$config_file" ]]; then
    LOG green "  [OK] Config file found"
    if grep -q "LAPTOP_ENABLED=1" "$config_file" 2>/dev/null; then
      LOG green "  [OK] Laptop mode enabled in config"
    else
      LOG "  [INFO] Laptop mode disabled in config"
    fi
  else
    LOG "  [INFO] No toolkit config found"
  fi
}

generate_report() {
  local report_file="/tmp/dependency-check-$(date +%Y%m%d_%H%M%S).txt"
  
  {
    echo "========================================"
    echo "     DEPENDENCY CHECK REPORT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo ""
    echo "SUMMARY"
    echo "--------"
    echo "Total Checked: $TOTAL_CHECKED"
    echo "Critical Found: $CRITICAL_FOUND"
    echo "Critical Missing: $CRITICAL_MISSING"
    echo "Optional Found: $OPTIONAL_FOUND"
    echo "Optional Missing: $OPTIONAL_MISSING"
    echo ""
    echo "CAPABILITIES"
    echo "-------------"
    
    [[ $CRITICAL_MISSING -eq 0 ]] && echo "[OK] Basic operation"
    have airodump-ng && echo "[OK] WiFi reconnaissance"
    have aireplay-ng && echo "[OK] WiFi attacks"
    have hashcat && echo "[OK] Password cracking"
    have rtl_fm && echo "[OK] SDR/RF monitoring"
    have arpspoof && echo "[OK] Network MITM"
    have responder && echo "[OK] Credential capture"
    have mbpoll && echo "[OK] OT/Modbus"
    have hostapd && echo "[OK] Evil twin"
    
    echo ""
    echo "MISSING CAPABILITIES"
    echo "---------------------"
    ! have airodump-ng && echo "[MISSING] WiFi reconnaissance - install aircrack-ng"
    ! have hashcat && echo "[MISSING] Password cracking - install hashcat"
    ! have rtl_fm && echo "[MISSING] SDR/RF - install rtl-sdr"
    ! have responder && echo "[MISSING] Credential capture - install responder"
    ! have mbpoll && echo "[MISSING] OT/Modbus - install libmodbus"
    
    echo ""
    echo "========================================"
  } > "$report_file"
  
  echo "$report_file"
}

render_summary() {
  LOG ""
  LOG blue "============================================"
  LOG blue "          DEPENDENCY CHECK SUMMARY          "
  LOG blue "============================================"
  LOG ""
  LOG "Total tools checked: $TOTAL_CHECKED"
  LOG ""
  
  if [[ $CRITICAL_MISSING -gt 0 ]]; then
    LOG red "CRITICAL: $CRITICAL_MISSING tools missing!"
  else
    LOG green "CRITICAL: All $CRITICAL_FOUND tools available"
  fi
  
  LOG ""
  LOG "Optional tools: $OPTIONAL_FOUND available, $OPTIONAL_MISSING missing"
  LOG blue "============================================"
}

main() {
  LOG blue "=== Dependency Checker ==="
  LOG "Pre-flight compatibility assessment"
  LOG ""
  
  LED B SLOW
  
  local spinner_id
  spinner_id=$(START_SPINNER "Checking dependencies...")
  
  check_category "Critical Tools" CRITICAL_TOOLS 1
  check_category "Network Tools" NETWORK_TOOLS 0
  check_category "Wireless Tools" WIRELESS_TOOLS 0
  check_category "SDR Tools" SDR_TOOLS 0
  check_category "MITM Tools" MITM_TOOLS 0
  check_category "Credential Tools" CREDENTIAL_TOOLS 0
  check_category "OT/ICS Tools" OT_TOOLS 0
  check_category "Serial/CAN Tools" SERIAL_TOOLS 0
  
  check_python_modules
  check_hardware
  check_laptop_connectivity
  
  STOP_SPINNER "$spinner_id"
  
  render_summary
  
  if [[ $CRITICAL_MISSING -gt 0 ]]; then
    LED R SOLID
    RINGTONE error 2>/dev/null || true
  elif [[ $OPTIONAL_MISSING -gt 20 ]]; then
    LED Y SOLID
  else
    LED G SOLID
    RINGTONE success 2>/dev/null || true
  fi
  
  local report
  report=$(generate_report)
  LOG ""
  LOG "Report saved: $report"
  
  if [[ $CRITICAL_MISSING -gt 0 ]]; then
    ALERT "Critical tools missing! Check report for details."
  elif [[ $OPTIONAL_MISSING -gt 10 ]]; then
    LOG ""
    LOG "Recommendation: Install missing tools for full capability"
    LOG "  apt install aircrack-ng nmap tcpdump hashcat rtl-sdr"
  fi
  
  PROMPT "Press button to exit"
}

main "$@"
