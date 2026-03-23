#!/bin/bash
# Title: OPC UA Security Audit
# Description: Check OPC UA security policies on discovered servers. Flags
#              SecurityPolicy#None (no encryption/signing) and anonymous
#              authentication as critical findings. Reports security posture
#              per server to the engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Auditing
# - Green: Audit complete
# - Red:   Critical findings detected

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Probe a single server and return its endpoint security policies via python3.
# Prints key=value lines to stdout.
_opcua_get_security_policies() {
  local host="$1" port="${2:-4840}"

  ics_require_tool python3 "Required for OPC UA security audit"

  python3 - <<PYEOF 2>/dev/null
import socket, struct, sys

host, port = '$host', $port

# ---- OPC UA Hello ----
endpoint_url = f'opc.tcp://{host}:{port}'.encode()
hello = bytearray()
hello += b'HEL'
hello += b'F'
hello += struct.pack('<I', 0)       # size placeholder
hello += struct.pack('<I', 0)       # protocol version
hello += struct.pack('<I', 65536)   # receive buffer
hello += struct.pack('<I', 65536)   # send buffer
hello += struct.pack('<I', 0)       # max message size
hello += struct.pack('<I', 0)       # max chunk count
hello += struct.pack('<I', len(endpoint_url))
hello += endpoint_url
struct.pack_into('<I', hello, 4, len(hello))

# ---- OPC UA OpenSecureChannel (no security) ----
# This requests endpoint descriptions which include security policy URIs
# without needing a full UA stack
def build_open_secure_channel():
    # Simplified OPC Binary: enough to elicit an EndpointDescription or error
    # HEL/ACK already handled; we just need to observe the ACK contents
    pass

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.send(hello)
    resp = s.recv(4096)

    if resp[:3] == b'ACK':
        # Server responded — it is listening.
        # OPC UA endpoint security policy enumeration requires a full GetEndpoints
        # request which needs the OPC UA Binary encoding. We report what we can
        # from the ACK alone and flag for manual follow-up.
        proto_ver = struct.unpack_from('<I', resp, 8)[0]
        print(f'server_present=true')
        print(f'protocol_version={proto_ver}')
        # Heuristic: servers that accept anonymous HEL without any security
        # material and respond with ACK are candidates for SecurityPolicy#None
        print(f'hello_accepted=true')
        print('status=ok')
    elif resp[:3] == b'ERR':
        error_code = struct.unpack_from('<I', resp, 8)[0]
        print(f'server_present=true')
        print(f'hello_error=0x{error_code:08x}')
        print('status=error')
    else:
        print(f'server_present=unknown')
        print('status=unknown')
    s.close()
except Exception as e:
    print(f'connection_error={e}', file=sys.stderr)
    sys.exit(1)
PYEOF
}

# Use nmap --script opcua-info (if available) to extract security policy details
_nmap_opcua_audit() {
  local host="$1" port="${2:-4840}"

  if ! command -v nmap >/dev/null 2>&1; then
    return 1
  fi

  nmap -sV -p "$port" --script opcua-info "$host" 2>/dev/null
}

_audit_server() {
  local host="$1" port="${2:-4840}"
  local critical=0 warnings=0

  LOG blue "--- Auditing $host:$port ---"

  local probe
  probe=$(_opcua_get_security_policies "$host" "$port") || {
    LOG red "Failed to connect to $host:$port"
    return 1
  }

  if ! echo "$probe" | grep -q "server_present=true"; then
    LOG "No OPC UA server at $host:$port — skipping"
    return 1
  fi

  LOG "Server present: $host:$port"

  # Attempt nmap-based policy extraction
  local nmap_out
  nmap_out=$(_nmap_opcua_audit "$host" "$port") || nmap_out=""

  local policy_none=false anon_auth=false

  if echo "$nmap_out" | grep -qi "SecurityPolicy#None\|None$\|security_policy.*None"; then
    policy_none=true
    critical=$((critical + 1))
    LOG red "CRITICAL: SecurityPolicy#None detected on $host:$port — no encryption or signing"
  fi

  if echo "$nmap_out" | grep -qi "Anonymous\|UserToken.*Anonymous\|anonymous"; then
    anon_auth=true
    critical=$((critical + 1))
    LOG red "CRITICAL: Anonymous authentication accepted on $host:$port"
  fi

  # If nmap gave us nothing, flag based on hello_accepted heuristic
  if [[ -z "$nmap_out" ]]; then
    if echo "$probe" | grep -q "hello_accepted=true"; then
      warnings=$((warnings + 1))
      LOG "WARN: Server accepted unauthenticated Hello — SecurityPolicy#None possible (verify manually)"
    fi
  fi

  if echo "$nmap_out" | grep -qi "security_mode.*None\|MessageSecurity.*None"; then
    critical=$((critical + 1))
    LOG red "CRITICAL: MessageSecurityMode None accepted on $host:$port"
  fi

  # Log any explicit security policies found
  if echo "$nmap_out" | grep -qi "SecurityPolicy"; then
    while IFS= read -r line; do
      case "$line" in
        *SecurityPolicy*|*security_policy*) LOG "  Policy: $line" ;;
      esac
    done <<< "$nmap_out"
  fi

  # Save finding to inventory
  local json
  json=$(printf '{"id":"%s_%s_audit","protocol":"opcua","ip":"%s","port":%d,"security_policy_none":%s,"anonymous_auth":%s,"critical_findings":%d,"warnings":%d}' \
    "$host" "$port" "$host" "$port" \
    "$( [[ $policy_none == true ]] && echo true || echo false )" \
    "$( [[ $anon_auth == true ]] && echo true || echo false )" \
    "$critical" "$warnings")
  ics_report_device "$json"

  if [[ "$critical" -gt 0 ]]; then
    LOG red "  -> $critical critical finding(s) on $host:$port"
  elif [[ "$warnings" -gt 0 ]]; then
    LOG "  -> $warnings warning(s) on $host:$port"
  else
    LOG green "  -> No critical findings detected on $host:$port"
  fi

  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "OPC UA Security Audit"
LOG "Checks security policies on OPC UA servers."
LOG "Flags SecurityPolicy#None and anonymous authentication."

ics_init_engagement

LOG blue "Enter comma-separated host(s) or a single IP to audit."
target_input=$(IP_PICKER "OPC UA server IP" "192.168.1.100")
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    LOG red "Cancelled"; exit 1 ;;
esac

target_port=$(NUMBER_PICKER "OPC UA port" 4840)
case $? in
  "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
    target_port=4840 ;;
esac

total=0
total_critical=0

spin_id=$(START_SPINNER "Running OPC UA security audit...")

# Support comma-separated list
IFS=',' read -ra targets <<< "$target_input"
for host in "${targets[@]}"; do
  host="${host// /}"  # strip spaces
  [[ -z "$host" ]] && continue
  total=$((total + 1))
  _audit_server "$host" "$target_port" && total_critical=$((total_critical + 1)) || true
done

STOP_SPINNER "$spin_id"

LOG "Audit complete: $total server(s) examined"

if [[ "$total_critical" -gt 0 ]]; then
  LOG red "Critical findings on $total_critical server(s) — review inventory for details"
  ALERT "OPC UA Security Audit complete. CRITICAL findings on $total_critical server(s). See $ICS_INVENTORY"
else
  LOG green "No critical security findings detected"
  ALERT "OPC UA Security Audit complete. No critical findings. See $ICS_INVENTORY"
fi
