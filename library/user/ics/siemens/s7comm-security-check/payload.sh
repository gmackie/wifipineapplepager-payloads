#!/bin/bash
# Title: S7comm Security Check
# Description: Check access protection level and password configuration on Siemens S7 CPUs.
#              Runs module identification first, then reads the protection level from the
#              SZL 0x0232 block. Flags unprotected CPUs as critical findings.
# Author: ICS Toolkit
# Version: 1.0
# Category: assessment
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Probing target
# - Green: Assessment complete
# - Red:   Critical finding (no protection) or error

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Read SZL 0x0232 (CPU protection level) via Python inline
_s7comm_check_protection() {
  local host="$1" port="${2:-102}"

  ics_require_tool python3 "Required for S7comm protocol"

  python3 -c "
import socket, struct, sys

host, port = '$host', $port

cotp_cr = bytes([
    0x03, 0x00, 0x00, 0x16,
    0x11, 0xe0, 0x00, 0x00,
    0x00, 0x01, 0x00,
    0xc0, 0x01, 0x0a,
    0xc1, 0x02, 0x01, 0x00,
    0xc2, 0x02, 0x01, 0x02,
])

s7_setup = bytes([
    0x03, 0x00, 0x00, 0x19,
    0x02, 0xf0, 0x80,
    0x32, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00,
    0xf0, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x01, 0xe0,
])

# SZL-ID 0x0232 = CPU protection level
szl_protection = bytes([
    0x03, 0x00, 0x00, 0x21,
    0x02, 0xf0, 0x80,
    0x32, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x08,
    0x00, 0x01, 0x12, 0x04,
    0x11, 0x44, 0x01, 0x00,
    0xff, 0x09, 0x00, 0x04,
    0x02, 0x32, 0x00, 0x00,  # SZL-ID=0x0232
])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(${ICS_TIMEOUT:-5})
    s.connect((host, port))

    s.send(cotp_cr)
    resp = s.recv(4096)
    if resp[5] != 0xd0:
        print('cotp_rejected')
        sys.exit(1)

    s.send(s7_setup)
    s.recv(4096)

    s.send(szl_protection)
    resp = s.recv(4096)
    s.close()

    # The SZL 0x0232 response contains protection level word at a known offset
    # Byte 37 (0-indexed): sch_schutz protection word
    if len(resp) > 37:
        prot_word = resp[37]
        # Protection levels: 0=no protection, 1=know-how protect, 2=write protect, 3=read/write protect
        level_map = {0:'no_protection', 1:'know_how_protect', 2:'write_protect', 3:'read_write_protect'}
        level_str = level_map.get(prot_word & 0x03, f'unknown_{prot_word}')
        print(f'protection_level={prot_word & 0x03}')
        print(f'protection_label={level_str}')
        # Check if password is set (byte 38: sch_param)
        sch_param = resp[38] if len(resp) > 38 else 0
        print(f'password_set={\"true\" if sch_param & 0x01 else \"false\"}')
        print('status=ok')
    else:
        print('status=no_data')
except Exception as e:
    print(f'connection_error={e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

_protection_description() {
  local level="$1"
  case "$level" in
    0) echo "No protection — full read/write access without credentials" ;;
    1) echo "Know-how protection — program blocks hidden but accessible" ;;
    2) echo "Write protection — read allowed, write requires password" ;;
    3) echo "Read/Write protection — both require password" ;;
    *) echo "Unknown protection level $level" ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  LOG blue "=== S7comm Security Check ==="
  LOG ""

  ics_init_engagement

  local host
  host=$(IP_PICKER "Target S7 CPU IP address" "192.168.1.10")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  local port=102
  LOG blue "Target: $host:$port"

  # --- Step 1: Module identification ---
  LOG "Step 1/2: Identifying CPU module..."
  local spinner_id
  spinner_id=$(START_SPINNER "Running S7comm module identification ...")

  local id_result
  id_result=$(s7comm_identify "$host" "$port" 2>/dev/null) || {
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "Failed to connect to $host:$port. Check IP and ensure port 102 is reachable."
    exit 1
  }
  STOP_SPINNER "$spinner_id"

  if echo "$id_result" | grep -q "status=ok"; then
    local module_type firmware
    module_type=$(echo "$id_result" | grep "^module_type=" | cut -d= -f2-)
    firmware=$(echo "$id_result"    | grep "^firmware="    | cut -d= -f2-)
    LOG green "CPU identified: ${module_type:-unknown} (FW: ${firmware:-unknown})"
  else
    LOG "Could not identify CPU module — continuing with protection check."
    module_type="unknown"
    firmware="unknown"
  fi

  # --- Step 2: Protection level check ---
  LOG ""
  LOG "Step 2/2: Checking protection level..."
  spinner_id=$(START_SPINNER "Reading S7 protection level ...")

  local prot_result
  prot_result=$(_s7comm_check_protection "$host" "$port" 2>/dev/null) || {
    STOP_SPINNER "$spinner_id"
    ERROR_DIALOG "Protection level check failed. The CPU may have rejected the SZL read."
    exit 1
  }
  STOP_SPINNER "$spinner_id"

  if echo "$prot_result" | grep -q "status=ok"; then
    local prot_level prot_label password_set
    prot_level=$(echo "$prot_result"  | grep "^protection_level=" | cut -d= -f2)
    prot_label=$(echo "$prot_result"  | grep "^protection_label=" | cut -d= -f2)
    password_set=$(echo "$prot_result" | grep "^password_set="    | cut -d= -f2)

    local description
    description=$(_protection_description "${prot_level:-0}")

    LOG ""
    LOG blue "  Protection level : ${prot_level:-unknown} (${prot_label:-unknown})"
    LOG blue "  Password set     : ${password_set:-unknown}"
    LOG blue "  Description      : $description"

    # Flag critical finding if unprotected
    local risk="low"
    if [[ "${prot_level:-0}" == "0" ]]; then
      risk="critical"
      LOG red ""
      LOG red "  [CRITICAL] CPU has NO access protection configured!"
      LOG red "  Anyone on the network can read and write PLC program and data."
    elif [[ "${prot_level:-0}" == "1" ]]; then
      risk="high"
      LOG "  [HIGH] Know-how protection only — program logic is obscured but accessible."
    elif [[ "${prot_level:-0}" == "2" ]] && [[ "$password_set" != "true" ]]; then
      risk="high"
      LOG "  [HIGH] Write protection configured but no password is set."
    else
      LOG green "  Protection appears adequate for this device."
    fi

    # Save artifact
    local artifact_content
    artifact_content=$(printf \
      '{"host":"%s","port":%d,"module_type":"%s","firmware":"%s","protection_level":%s,"protection_label":"%s","password_set":%s,"risk":"%s"}' \
      "$host" "$port" "${module_type:-unknown}" "${firmware:-unknown}" \
      "${prot_level:-0}" "${prot_label:-unknown}" \
      "$([ "$password_set" = "true" ] && echo "true" || echo "false")" "$risk")
    ics_save_artifact "s7comm-security-${host}" "$artifact_content"

    # Report to inventory
    local json
    json=$(printf \
      '{"id":"%s_%d","protocol":"s7comm","ip":"%s","port":%d,"vendor":"Siemens","model":"%s","firmware":"%s","protection_level":%s,"protection_label":"%s","password_set":%s,"risk":"%s","status":"assessed"}' \
      "$host" "$port" "$host" "$port" "${module_type:-unknown}" "${firmware:-unknown}" \
      "${prot_level:-0}" "${prot_label:-unknown}" \
      "$([ "$password_set" = "true" ] && echo "true" || echo "false")" "$risk")
    ics_report_device "$json"

    if [[ "$risk" == "critical" ]]; then
      ALERT "CRITICAL: $host has NO S7 access protection! Immediate remediation required."
    else
      ALERT "S7 security check complete for $host — risk: $risk"
    fi

  elif echo "$prot_result" | grep -q "status=no_data"; then
    LOG "Protection SZL read returned no data. The CPU firmware may not support SZL 0x0232."
  elif echo "$prot_result" | grep -q "cotp_rejected"; then
    ERROR_DIALOG "COTP connection rejected on second attempt. Device state may have changed."
    exit 1
  else
    ERROR_DIALOG "Unexpected response when reading protection level."
    exit 1
  fi

  LOG ""
  LOG blue "Done. Results saved to engagement: $ICS_ENGAGEMENT"
}

main "$@"
