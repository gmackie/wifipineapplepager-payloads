#!/bin/bash
# Title: EtherNet/IP Device Discovery
# Description: Send ListIdentity requests on port 44818 to discover EtherNet/IP
#              (CIP) devices. Supports both broadcast sweeps and unicast targets.
#              Parses vendor ID, product name, and serial number from responses,
#              then reports each device to the engagement inventory.
# Author: ICS Toolkit
# Version: 1.0
# Category: reconnaissance
# Net Mode: NAT
#
# LED States
# - Blue:  Idle / waiting for input
# - Amber: Sweeping
# - Green: Discovery complete
# - Red:   Error

set -euo pipefail

source "$(dirname "$0")/../../lib/ics_protocols.sh"

# ---------------------------------------------------------------------------
# CIP / EtherNet/IP vendor ID table (partial)
# ---------------------------------------------------------------------------

_vendor_name() {
  local vid="$1"
  case "$vid" in
    1)   echo "Rockwell Automation / Allen-Bradley" ;;
    2)   echo "Namco" ;;
    3)   echo "Carl Valentin" ;;
    7)   echo "Numatics" ;;
    8)   echo "Parker Hannifin" ;;
    10)  echo "Horner Electric" ;;
    16)  echo "Turck" ;;
    24)  echo "Pepperl+Fuchs" ;;
    36)  echo "Phoenix Contact" ;;
    52)  echo "Allen Bradley (OEM)" ;;
    54)  echo "Omron" ;;
    86)  echo "Wago" ;;
    91)  echo "Siemens" ;;
    108) echo "Schneider Electric" ;;
    119) echo "Molex" ;;
    *)   echo "Vendor#$vid" ;;
  esac
}

# Parse a hex-encoded ListIdentity response and emit key=value lines.
# EtherNet/IP encapsulation header is 24 bytes; the CPF (Common Packet Format)
# follows. For ListIdentity the structure is:
#   [24 encap hdr][2 item count][2 item type=0x000c][2 item len]
#   [CIP Identity Item: 2 encap proto ver, 2+2 sockaddr family+port, 4 IP,
#    8 pad, 2 vendor, 2 device_type, 2 product_code, 1+1 major+minor rev,
#    2 status, 4 serial, 1+n product_name, 1 state]
_parse_listidentity() {
  local hexdata="$1"

  # Minimum viable response: 24-byte encap + CPF header + identity item
  [[ "${#hexdata}" -lt 72 ]] && return 1

  # Bytes are pairs of hex chars. Offset in nibbles = offset_bytes * 2
  # Encap header: bytes 0-23 (48 nibbles)
  # After header: item_count (2 bytes / 4 nibbles) at offset 48
  # item_type (2 bytes) at 52, item_length (2 bytes) at 56
  # Identity item starts at byte 30 (nibble 60)

  # offset 30 (nibble 60): encap protocol version (2 bytes, LE)
  # offset 32 (nibble 64): socket address — family (2 BE), port (2 BE), IP (4 BE)
  local port_hi port_lo
  port_hi="${hexdata:68:2}"
  port_lo="${hexdata:70:2}"
  local port=$(( (0x${port_hi} << 8) | 0x${port_lo} ))

  local ip_b0 ip_b1 ip_b2 ip_b3
  ip_b0=$(( 0x${hexdata:72:2} ))
  ip_b1=$(( 0x${hexdata:74:2} ))
  ip_b2=$(( 0x${hexdata:76:2} ))
  ip_b3=$(( 0x${hexdata:78:2} ))
  local ip="${ip_b0}.${ip_b1}.${ip_b2}.${ip_b3}"

  # offset 48 (nibble 96): vendor ID (2 bytes LE)
  local vid_lo vid_hi
  vid_lo="${hexdata:96:2}"
  vid_hi="${hexdata:98:2}"
  local vendor_id=$(( (0x${vid_hi} << 8) | 0x${vid_lo} ))

  # offset 50 (nibble 100): device type (2 bytes LE)
  local dtype_lo dtype_hi
  dtype_lo="${hexdata:100:2}"
  dtype_hi="${hexdata:102:2}"
  local device_type=$(( (0x${dtype_hi} << 8) | 0x${dtype_lo} ))

  # offset 52 (nibble 104): product code (2 bytes LE)
  local pc_lo pc_hi
  pc_lo="${hexdata:104:2}"
  pc_hi="${hexdata:106:2}"
  local product_code=$(( (0x${pc_hi} << 8) | 0x${pc_lo} ))

  # offset 54 (nibble 108): revision major, minor (1 byte each)
  local rev_major rev_minor
  rev_major=$(( 0x${hexdata:108:2} ))
  rev_minor=$(( 0x${hexdata:110:2} ))

  # offset 56 (nibble 112): status (2 bytes LE) — skip
  # offset 58 (nibble 116): serial number (4 bytes LE)
  local s0="${hexdata:116:2}"
  local s1="${hexdata:118:2}"
  local s2="${hexdata:120:2}"
  local s3="${hexdata:122:2}"
  local serial
  serial=$(printf '%02x%02x%02x%02x' "0x${s3}" "0x${s2}" "0x${s1}" "0x${s0}" 2>/dev/null || echo "unknown")

  # offset 62 (nibble 124): product name length (1 byte), then ASCII name
  local name_len
  name_len=$(( 0x${hexdata:124:2} ))
  local name_hex="${hexdata:126:$(( name_len * 2 ))}"
  local product_name
  product_name=$(echo "$name_hex" | xxd -r -p 2>/dev/null | tr -d '\000' || echo "unknown")

  echo "ip=$ip"
  echo "port=$port"
  echo "vendor_id=$vendor_id"
  echo "vendor_name=$(_vendor_name "$vendor_id")"
  echo "device_type=$device_type"
  echo "product_code=$product_code"
  echo "revision=${rev_major}.${rev_minor}"
  echo "serial=$serial"
  echo "product_name=$product_name"
}

_probe_enip() {
  local host="$1" mode="${2:-unicast}"
  local port=44818

  local raw_hex
  raw_hex=$(enip_list_identity "$host" "$port" 2>/dev/null) || return 1
  [[ -z "$raw_hex" ]] && return 1

  local parsed
  parsed=$(_parse_listidentity "$raw_hex") || {
    # Still report the host even if full parse fails
    parsed="ip=$host
port=$port
vendor_name=unknown
product_name=unknown
serial=unknown
revision=unknown"
  }

  local ip vendor product serial revision
  ip=$(echo "$parsed" | grep "^ip=" | cut -d= -f2)
  vendor=$(echo "$parsed" | grep "^vendor_name=" | cut -d= -f2-)
  product=$(echo "$parsed" | grep "^product_name=" | cut -d= -f2-)
  serial=$(echo "$parsed" | grep "^serial=" | cut -d= -f2)
  revision=$(echo "$parsed" | grep "^revision=" | cut -d= -f2)
  local vid
  vid=$(echo "$parsed" | grep "^vendor_id=" | cut -d= -f2)

  LOG green "Found: ${ip}:${port}  vendor=\"${vendor}\"  product=\"${product}\"  serial=${serial}  rev=${revision}"

  local json
  json=$(printf '{"id":"%s_%d","protocol":"ethernet_ip","ip":"%s","port":%d,"vendor_id":%s,"vendor_name":"%s","product_name":"%s","serial_number":"%s","revision":"%s","discovery_mode":"%s"}' \
    "${ip:-$host}" "$port" "${ip:-$host}" "$port" "${vid:-0}" \
    "$vendor" "$product" "$serial" "$revision" "$mode")
  ics_report_device "$json"
  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALERT "EtherNet/IP Device Discovery"
LOG "Sends ListIdentity requests on port 44818 to discover CIP devices."

ics_init_engagement

# Ask scan mode
mode_resp=$(CONFIRMATION_DIALOG "Use broadcast sweep? (Yes = broadcast, No = unicast/range)")
case "$mode_resp" in
  "$DUCKYSCRIPT_USER_CONFIRMED") scan_mode="broadcast" ;;
  "$DUCKYSCRIPT_USER_DENIED")    scan_mode="unicast" ;;
  *) LOG red "Cancelled"; exit 1 ;;
esac

if [[ "$scan_mode" == "broadcast" ]]; then
  LOG blue "Enter the broadcast address for the target subnet."
  bcast=$(IP_PICKER "Broadcast address" "192.168.1.255")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG red "Cancelled"; exit 1 ;;
  esac

  spin_id=$(START_SPINNER "Sending ListIdentity broadcast to $bcast:44818...")
  _probe_enip "$bcast" "broadcast" || LOG "No broadcast response from $bcast"
  STOP_SPINNER "$spin_id"

else
  LOG blue "Enter the target — single IP or CIDR (e.g. 192.168.1.0/24)."
  target=$(IP_PICKER "Target IP / subnet" "192.168.1.100")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG red "Cancelled"; exit 1 ;;
  esac

  found=0
  total=0

  # Expand CIDR using nmap if available, else treat as single host
  if echo "$target" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' && command -v nmap >/dev/null 2>&1; then
    host_list=$(nmap -sL -n "$target" 2>/dev/null | awk '/Nmap scan report/{print $NF}')
  else
    host_list="$target"
  fi

  spin_id=$(START_SPINNER "Sweeping for EtherNet/IP devices...")
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    total=$((total + 1))
    if _probe_enip "$host" "unicast"; then
      found=$((found + 1))
    fi
  done <<< "$host_list"
  STOP_SPINNER "$spin_id"

  LOG "Sweep complete: $found EtherNet/IP device(s) found from $total hosts"
fi

ALERT "EtherNet/IP discovery complete. Results saved to $ICS_INVENTORY"
