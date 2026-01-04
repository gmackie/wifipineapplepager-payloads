#!/bin/bash
# Title: Credential Logger
# Description: Log captured authentication attempts with categorization
# Author: Red Team Toolkit
# Version: 1.0
# Category: alerts
# Net Mode: OFF
#
# LED States
# - Magenta fast: Credential captured
# - Green: Logged

set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/captured-creds}"

mkdir -p "$LOG_DIR"

LED M FAST
VIBRATE 500
RINGTONE notify 2>/dev/null || true

timestamp=$(date '+%Y-%m-%d %H:%M:%S')

summary="${_ALERT_AUTH_SUMMARY:-Authentication captured}"
client_mac="${_ALERT_AUTH_CLIENT_MAC:-unknown}"
auth_type="${_ALERT_AUTH_TYPE:-unknown}"

cred_type="unknown"
case "$summary" in
  *HTTP*Basic*) cred_type="http_basic" ;;
  *HTTP*Form*|*POST*) cred_type="http_form" ;;
  *FTP*) cred_type="ftp" ;;
  *SMTP*|*POP3*|*IMAP*) cred_type="email" ;;
  *NTLM*|*NetNTLM*) cred_type="ntlm" ;;
  *Kerberos*) cred_type="kerberos" ;;
  *LDAP*) cred_type="ldap" ;;
  *Telnet*) cred_type="telnet" ;;
  *SSH*) cred_type="ssh_attempt" ;;
  *WPA*|*EAPOL*) cred_type="wpa_enterprise" ;;
  *) cred_type="other" ;;
esac

priority="low"
case "$cred_type" in
  ntlm|kerberos|ldap|wpa_enterprise) priority="high" ;;
  http_basic|http_form|email) priority="medium" ;;
  *) priority="low" ;;
esac

log_file="$LOG_DIR/credentials_$(date +%Y%m%d).log"
json_file="$LOG_DIR/cred_$(date +%Y%m%d%H%M%S)_${RANDOM}.json"

{
  echo "[$timestamp] AUTH_CAPTURED"
  echo "  Type: $cred_type"
  echo "  Priority: $priority"
  echo "  Client: $client_mac"
  echo "  Summary: $summary"
  echo ""
} >> "$log_file"

{
  echo "{"
  echo "  \"timestamp\": \"$timestamp\","
  echo "  \"type\": \"$cred_type\","
  echo "  \"priority\": \"$priority\","
  echo "  \"client_mac\": \"$client_mac\","
  echo "  \"auth_type\": \"$auth_type\","
  echo "  \"summary\": \"$summary\""
  echo "}"
} > "$json_file"

LED G SOLID

LOG magenta "=== Credential Captured ==="
LOG "$summary"
LOG ""
LOG "Type: $cred_type"
LOG "Priority: $priority"
LOG "Client: $client_mac"

if [[ "$priority" == "high" ]]; then
  LOG ""
  LOG red "!!! HIGH VALUE CREDENTIAL !!!"
  RINGTONE alarm 2>/dev/null || true
  VIBRATE 800
  ALERT "HIGH PRIORITY: $cred_type credential captured"
else
  ALERT "Captured: $cred_type from $client_mac"
fi

total_creds=$(wc -l < "$log_file" 2>/dev/null | tr -d ' ' || echo 0)
high_value=$(grep -c "Priority: high" "$log_file" 2>/dev/null || echo 0)

LOG ""
LOG "Session stats: $total_creds total, $high_value high-value"

LED OFF
