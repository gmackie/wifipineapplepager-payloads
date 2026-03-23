#!/bin/bash
# Title: ICS Protocol Discovery Library
# Description: Network-based ICS/OT protocol discovery and enumeration
# Author: ICS Toolkit
# Version: 1.0
#
# Source this file in payloads that need network ICS protocol functions:
#   source "$(dirname "$0")/../lib/ics_protocols.sh"
#
# Dependencies: nc (netcat), printf, xxd (minimal)
# Optional: python3 (required for OPC UA and S7comm), nmap

# --- Configuration ---
ICS_TIMEOUT="${ICS_TIMEOUT:-5}"
ICS_ENGAGEMENT="${ICS_ENGAGEMENT:-}"
ICS_LOOT_DIR="/root/loot/ics"
ICS_INVENTORY=""

# --- Common Helpers ---

ics_log() {
  local severity="${1:-info}" protocol="${2:-general}" msg="${3:-}"
  local ts
  ts=$(date '+%Y-%m-%dT%H:%M:%S')
  LOG "[$ts] [$severity] [$protocol] $msg"
}

ics_require_tool() {
  local tool="$1" reason="${2:-Required for this payload}"
  if ! command -v "$tool" >/dev/null 2>&1; then
    ERROR_DIALOG "$tool not found. $reason"
    exit 1
  fi
}

ics_init_engagement() {
  if [[ -z "$ICS_ENGAGEMENT" ]]; then
    ICS_ENGAGEMENT=$(TEXT_PICKER "Engagement name" "ics-assessment")
    case $? in
      "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
        LOG "Cancelled"; exit 1 ;;
    esac
  fi

  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  mkdir -p "$eng_dir/raw" "$eng_dir/reports"

  if [[ ! -w "$eng_dir" ]]; then
    ERROR_DIALOG "Cannot write to $eng_dir"
    exit 1
  fi

  ICS_INVENTORY="$eng_dir/inventory.json"

  if [[ ! -f "$ICS_INVENTORY" ]]; then
    echo '{"schema_version":1,"devices":[]}' > "$ICS_INVENTORY"
  fi

  chmod 700 "$eng_dir"
  ics_log "info" "general" "Engagement: $ICS_ENGAGEMENT"
}

ics_save_artifact() {
  local name="$1" content="$2"
  local eng_dir="$ICS_LOOT_DIR/$ICS_ENGAGEMENT"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  local path="$eng_dir/raw/${name}-${ts}.json"
  echo "$content" > "$path"
  ics_log "info" "general" "Artifact saved: $path"
  echo "$path"
}

ics_report_device() {
  local json_device="$1"

  [[ -z "$ICS_INVENTORY" || ! -f "$ICS_INVENTORY" ]] && return 1

  local ip port bus slave_addr
  ip=$(echo "$json_device" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
  port=$(echo "$json_device" | sed -n 's/.*"port":\([0-9]*\).*/\1/p')
  bus=$(echo "$json_device" | sed -n 's/.*"bus":"\([^"]*\)".*/\1/p')
  slave_addr=$(echo "$json_device" | sed -n 's/.*"slave_addr":\([0-9]*\).*/\1/p')

  # Dedup check
  if [[ -n "$ip" && -n "$port" ]]; then
    if grep -q "\"ip\":\"$ip\"" "$ICS_INVENTORY" && grep -q "\"port\":$port" "$ICS_INVENTORY"; then
      return 0
    fi
  elif [[ -n "$bus" && -n "$slave_addr" ]]; then
    if grep -q "\"bus\":\"$bus\"" "$ICS_INVENTORY" && grep -q "\"slave_addr\":$slave_addr" "$ICS_INVENTORY"; then
      return 0
    fi
  fi

  # Atomic append with file locking
  (
    flock -w 5 200 || { ics_log "error" "general" "Failed to lock inventory"; return 1; }

    local tmp
    tmp=$(mktemp)
    # Remove trailing ]} and append new device
    sed '$ s/\]}//' "$ICS_INVENTORY" > "$tmp"
    local count
    count=$(grep -c '"id"' "$tmp" 2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]]; then
      echo ",$json_device]}" >> "$tmp"
    else
      echo "$json_device]}" >> "$tmp"
    fi
    mv "$tmp" "$ICS_INVENTORY"
  ) 200>"${ICS_INVENTORY}.lock"
}

# --- Port Fingerprinting ---

ICS_PORTS="20000,44818,47808,502,4840,102,9600,789,1089,1090,1091,2222,2404,4000,18245,28784,34962,34963,34964,55000,55003"

ics_port_fingerprint() {
  local port="$1"
  case "$port" in
    502)   echo "modbus_tcp" ;;
    4840)  echo "opcua" ;;
    44818) echo "ethernet_ip" ;;
    47808) echo "bacnet" ;;
    20000) echo "dnp3" ;;
    102)   echo "s7comm" ;;
    9600)  echo "fins" ;;
    2404)  echo "iec104" ;;
    34962|34963|34964) echo "profinet" ;;
    *)     echo "unknown" ;;
  esac
}

# --- Modbus TCP (Level B) ---

modbus_tcp_scan() {
  local host="$1" port="${2:-502}"

  [[ -z "$host" ]] && { ics_log "error" "modbus" "No host specified"; return 1; }

  # FC43 sub14 = Read Device Identification
  # MBAP header (7 bytes) + PDU (3 bytes)
  local packet
  packet=$(printf '\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00')

  local resp
  resp=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -w "$ICS_TIMEOUT" "$host" "$port" 2>/dev/null | xxd -p)

  if [[ -n "$resp" ]]; then
    ics_log "info" "modbus" "Modbus TCP response from $host:$port"
    echo "$resp"
    return 0
  fi
  return 1
}

# --- Ethernet/IP (Level B) ---

enip_list_identity() {
  local host="$1" port="${2:-44818}"

  [[ -z "$host" ]] && { ics_log "error" "enip" "No host specified"; return 1; }

  # ListIdentity command: 24-byte encapsulation header
  # Command=0x0063, Length=0, Session=0, Status=0, Context=0, Options=0
  local packet
  packet=$(printf '\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

  local resp
  resp=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -w "$ICS_TIMEOUT" "$host" "$port" 2>/dev/null | xxd -p)

  if [[ -n "$resp" ]]; then
    ics_log "info" "enip" "EtherNet/IP response from $host:$port"
    echo "$resp"
    return 0
  fi
  return 1
}

# --- BACnet (Level B) ---

bacnet_whois() {
  local broadcast="${1:-255.255.255.255}" port="${2:-47808}"

  # BACnet Who-Is: BVLC header + NPDU + APDU
  # BVLC: type=0x81, function=0x0b (broadcast), length=0x000c
  # NPDU: version=0x01, control=0x20 (expect reply)
  # APDU: type=0x10 (unconfirmed), service=0x08 (who-is)
  local packet
  packet=$(printf '\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08')

  local resp
  resp=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -u -w "$ICS_TIMEOUT" "$broadcast" "$port" 2>/dev/null | xxd -p)

  if [[ -n "$resp" ]]; then
    ics_log "info" "bacnet" "BACnet I-Am response received"
    echo "$resp"
    return 0
  fi
  return 1
}

# --- DNP3 (Level B) ---

dnp3_detect() {
  local host="$1" port="${2:-20000}"

  [[ -z "$host" ]] && { ics_log "error" "dnp3" "No host specified"; return 1; }

  # DNP3 data link layer: start=0x0564, length, control, destination, source
  # Minimal confirm frame
  local packet
  packet=$(printf '\x05\x64\x05\x00\x01\x00\x00\x00\x00\x00')

  local resp
  resp=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -w "$ICS_TIMEOUT" "$host" "$port" 2>/dev/null | xxd -p)

  if [[ -n "$resp" ]] && echo "$resp" | grep -q "^0564"; then
    ics_log "info" "dnp3" "DNP3 detected on $host:$port"
    echo "$resp"
    return 0
  fi
  return 1
}

# --- OPC UA (Level B) — Requires Python ---

opcua_discover() {
  local host="$1" port="${2:-4840}"

  [[ -z "$host" ]] && { ics_log "error" "opcua" "No host specified"; return 1; }
  ics_require_tool python3 "Required for OPC UA protocol"

  python3 -c "
import socket, struct, sys

host, port = '$host', $port

# OPC UA Hello message
endpoint = f'opc.tcp://{host}:{port}'.encode()
hello = bytearray()
hello += b'HEL'                          # message type
hello += b'F'                            # chunk type (final)
hello += struct.pack('<I', 0)            # size (filled later)
hello += struct.pack('<I', 0)            # protocol version
hello += struct.pack('<I', 65536)        # receive buffer
hello += struct.pack('<I', 65536)        # send buffer
hello += struct.pack('<I', 0)            # max message size
hello += struct.pack('<I', 0)            # max chunk count
hello += struct.pack('<I', len(endpoint))
hello += endpoint
struct.pack_into('<I', hello, 4, len(hello))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($ICS_TIMEOUT)
    s.connect((host, port))
    s.send(hello)
    resp = s.recv(4096)
    s.close()

    if resp[:3] == b'ACK':
        print(f'opcua_server={host}:{port}')
        print(f'protocol_version={struct.unpack_from(\"<I\", resp, 8)[0]}')
        print('status=ok')
    elif resp[:3] == b'ERR':
        error_code = struct.unpack_from('<I', resp, 8)[0]
        print(f'opcua_error={error_code}')
        print('status=error')
    else:
        print(f'unexpected_response={resp[:3]}')
        print('status=unknown')
except Exception as e:
    print(f'connection_error={e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null

  local rc=$?
  if [[ $rc -eq 0 ]]; then
    ics_log "info" "opcua" "OPC UA server found at $host:$port"
  fi
  return $rc
}

# --- S7comm / Siemens (Level B) — Requires Python ---

s7comm_identify() {
  local host="$1" port="${2:-102}"

  [[ -z "$host" ]] && { ics_log "error" "s7comm" "No host specified"; return 1; }
  ics_require_tool python3 "Required for S7comm protocol"

  python3 -c "
import socket, struct, sys

host, port = '$host', $port

# COTP Connection Request
cotp_cr = bytes([
    0x03, 0x00, 0x00, 0x16,  # TPKT: version, reserved, length
    0x11, 0xe0, 0x00, 0x00,  # COTP: length, CR, dst-ref
    0x00, 0x01, 0x00,        # src-ref, class
    0xc0, 0x01, 0x0a,        # TPDU size param
    0xc1, 0x02, 0x01, 0x00,  # src-tsap
    0xc2, 0x02, 0x01, 0x02,  # dst-tsap
])

# S7 Setup Communication
s7_setup = bytes([
    0x03, 0x00, 0x00, 0x19,  # TPKT
    0x02, 0xf0, 0x80,        # COTP DT
    0x32, 0x01, 0x00, 0x00,  # S7: protocol, job
    0x00, 0x00, 0x00, 0x08,  # ref, param length
    0x00, 0x00,              # data length
    0xf0, 0x00, 0x00, 0x01,  # setup: function, reserved, max-amq-calling
    0x00, 0x01, 0x01, 0xe0,  # max-amq-called, pdu-length
])

# SZL Read (System Status List) - Module Identification
szl_read = bytes([
    0x03, 0x00, 0x00, 0x21,  # TPKT
    0x02, 0xf0, 0x80,        # COTP DT
    0x32, 0x07, 0x00, 0x00,  # S7: protocol, userdata
    0x00, 0x00, 0x00, 0x08,  # ref, param length
    0x00, 0x08,              # data length
    0x00, 0x01, 0x12, 0x04,  # param
    0x11, 0x44, 0x01, 0x00,  # SZL read
    0xff, 0x09, 0x00, 0x04,  # data header
    0x00, 0x11, 0x00, 0x00,  # SZL-ID=0x0011 (module identification)
])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($ICS_TIMEOUT)
    s.connect((host, port))

    # Step 1: COTP Connect
    s.send(cotp_cr)
    resp = s.recv(4096)
    if resp[5] != 0xd0:  # CC (Connection Confirm)
        print('cotp_rejected')
        sys.exit(1)

    # Step 2: S7 Setup
    s.send(s7_setup)
    resp = s.recv(4096)

    # Step 3: SZL Read
    s.send(szl_read)
    resp = s.recv(4096)
    s.close()

    if len(resp) > 27:
        # Parse SZL response for module identification strings
        data = resp[27:]  # Skip headers
        # SZL data contains null-terminated strings
        parts = data.split(b'\\x00')
        strings = [p.decode('ascii', errors='replace').strip() for p in parts if len(p) > 1]
        if strings:
            print(f'module_type={strings[0] if len(strings) > 0 else \"unknown\"}')
            print(f'serial_number={strings[1] if len(strings) > 1 else \"unknown\"}')
            print(f'firmware={strings[2] if len(strings) > 2 else \"unknown\"}')
            print(f'module_name={strings[3] if len(strings) > 3 else \"unknown\"}')
        print('status=ok')
    else:
        print('status=no_data')
except Exception as e:
    print(f'connection_error={e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null

  local rc=$?
  if [[ $rc -eq 0 ]]; then
    ics_log "info" "s7comm" "S7comm device identified at $host:$port"
  fi
  return $rc
}

# --- FINS / Omron (Level B) ---

fins_identify() {
  local host="$1" port="${2:-9600}"

  [[ -z "$host" ]] && { ics_log "error" "fins" "No host specified"; return 1; }

  # FINS/UDP: header + memory area read
  # This is a minimal FINS node address data send
  local packet
  packet=$(printf '\x46\x49\x4e\x53\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

  local resp
  resp=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -u -w "$ICS_TIMEOUT" "$host" "$port" 2>/dev/null | xxd -p)

  if [[ -n "$resp" ]] && echo "$resp" | grep -q "^46494e53"; then
    ics_log "info" "fins" "FINS device detected at $host:$port"
    echo "$resp"
    return 0
  fi
  return 1
}

# --- Multi-Protocol Sweep (Level B) ---

ics_full_discovery() {
  local target="$1"

  [[ -z "$target" ]] && { ics_log "error" "general" "No target specified"; return 1; }

  ics_log "info" "general" "Starting full ICS discovery on $target"

  local found=0

  # Modbus TCP
  if modbus_tcp_scan "$target" 502 >/dev/null 2>&1; then
    ics_log "info" "modbus" "Modbus TCP on $target:502"
    found=$((found + 1))
  fi

  # OPC UA
  if command -v python3 >/dev/null 2>&1; then
    if opcua_discover "$target" 4840 >/dev/null 2>&1; then
      ics_log "info" "opcua" "OPC UA on $target:4840"
      found=$((found + 1))
    fi

    # S7comm
    if s7comm_identify "$target" 102 >/dev/null 2>&1; then
      ics_log "info" "s7comm" "S7comm on $target:102"
      found=$((found + 1))
    fi
  fi

  # Ethernet/IP
  if enip_list_identity "$target" 44818 >/dev/null 2>&1; then
    ics_log "info" "enip" "EtherNet/IP on $target:44818"
    found=$((found + 1))
  fi

  # DNP3
  if dnp3_detect "$target" 20000 >/dev/null 2>&1; then
    ics_log "info" "dnp3" "DNP3 on $target:20000"
    found=$((found + 1))
  fi

  # FINS
  if fins_identify "$target" 9600 >/dev/null 2>&1; then
    ics_log "info" "fins" "FINS on $target:9600"
    found=$((found + 1))
  fi

  ics_log "info" "general" "Discovery complete: $found protocols found on $target"
  echo "$found"
}

# --- Passive Sniffing ---

ics_traffic_sniff() {
  local iface="$1" duration="${2:-60}" output_file="$3"

  [[ -z "$iface" ]] && { ics_log "error" "general" "No interface specified"; return 1; }
  ics_require_tool tcpdump "Required for passive traffic sniffing"

  local filter="port 502 or port 4840 or port 44818 or port 47808 or port 20000 or port 102 or port 9600"

  if [[ -n "$output_file" ]]; then
    timeout "$duration" tcpdump -i "$iface" -w "$output_file" "$filter" 2>/dev/null &
    echo $!
  else
    timeout "$duration" tcpdump -i "$iface" -c 100 "$filter" 2>/dev/null
  fi
}

# --- Level C Interaction (Confirmation-gated) ---

opcua_browse_nodes() {
  local host="$1" port="${2:-4840}"

  [[ -z "$host" ]] && return 1
  ics_require_tool python3 "Required for OPC UA protocol"

  local resp
  resp=$(CONFIRMATION_DIALOG "Browse OPC UA node tree on $host:$port? This sends read requests to the server.")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") ;;
    *) LOG "Cancelled"; return 1 ;;
  esac

  ics_log "info" "opcua" "Browsing OPC UA nodes on $host:$port (Level C)"
  # Node browsing requires a full OPC UA session — defer to python3 opcua library
  LOG "OPC UA node browsing requires python3-opcua. Install with: pip3 install opcua"
}

modbus_tcp_read() {
  local host="$1" port="${2:-502}" unit="${3:-1}" reg="${4:-0}" count="${5:-10}"

  [[ -z "$host" ]] && return 1

  local resp
  resp=$(CONFIRMATION_DIALOG "Read $count registers starting at $reg from $host:$port unit $unit?")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") ;;
    *) LOG "Cancelled"; return 1 ;;
  esac

  # FC03 Read Holding Registers
  local packet
  packet=$(printf '\x00\x01\x00\x00\x00\x06\x%02x\x03\x%02x\x%02x\x00\x%02x' \
    "$unit" "$(( (reg >> 8) & 0xff ))" "$((reg & 0xff))" "$count")

  local result
  result=$(printf '%s' "$packet" | timeout "$ICS_TIMEOUT" nc -w "$ICS_TIMEOUT" "$host" "$port" 2>/dev/null | xxd -p)
  echo "$result"
}

enip_get_attributes() {
  local host="$1" port="${2:-44818}"

  [[ -z "$host" ]] && return 1

  local resp
  resp=$(CONFIRMATION_DIALOG "Read CIP attributes from $host:$port? This sends read requests to the device.")
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") ;;
    *) LOG "Cancelled"; return 1 ;;
  esac

  ics_log "info" "enip" "Reading CIP attributes from $host:$port (Level C)"
  LOG "CIP attribute reading requires extended EtherNet/IP session — use enip_list_identity for discovery"
}
