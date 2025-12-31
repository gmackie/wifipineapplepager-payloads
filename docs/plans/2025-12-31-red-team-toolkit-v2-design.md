# Red Team Toolkit v2.0 - Design Document

> Swiss Army Knife for IT/OT Penetration Testing Engagements

**Date:** 2025-12-31  
**Status:** Approved  
**Target Platform:** WiFi Pineapple Pager (standalone + laptop-assisted)

---

## Executive Summary

Expand the existing `red-team-toolkit` into a comprehensive engagement platform for IT/OT penetration testing. The toolkit operates in standalone mode on the Pager or leverages a connected laptop via SSH for heavy tools.

**Priority Capabilities:**
1. Network Discovery & Mapping
2. OT Protocol Attacks (Modbus, EtherNet/IP, OPC UA, DNP3, etc.)
3. Credential Harvesting (Windows AD, OT default creds)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    WiFi Pineapple Pager                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │              red-team-toolkit/                   │   │
│  │  payload.sh (main menu)                         │   │
│  │  scripts/common.sh (shared helpers)             │   │
│  │  scripts/config.sh (engagement config)          │   │
│  │  scripts/modules/                               │   │
│  │    ├── discovery/    (network mapping)          │   │
│  │    ├── ot-protocols/ (ICS attacks)              │   │
│  │    ├── credentials/  (harvesting)               │   │
│  │    ├── wireless/     (existing + expansion)     │   │
│  │    ├── physical/     (CAN, RS485, SDR)          │   │
│  │    └── laptop/       (SSH-to-laptop wrappers)   │   │
│  │  wordlists/          (default creds, users)     │   │
│  │  artifacts/          (engagement outputs)       │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         │ (optional SSH)
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Laptop (heavy tools)                 │
│  Responder, Impacket, Nmap, Metasploit, Wireshark      │
└─────────────────────────────────────────────────────────┘
```

### Operating Modes

| Mode | Description |
|------|-------------|
| **Standalone** | Pager runs lightweight tools directly (arp-scan, tcpdump, netcat probes) |
| **Laptop-assisted** | Pager triggers SSH commands on laptop for heavy tools |
| **Hybrid** | Auto-detects: uses local tools if available, falls back to laptop if configured |

### Safety Controls

- `SAFE_MODE=1` - Confirm before destructive/active attacks (writes to PLCs, poisoning)
- `PASSIVE_ONLY=0` - Toggle to disable all active attacks for sensitive environments
- Scope controls: `TARGET_NETWORK`, `EXCLUDE_IPS`, `OT_NETWORK`

---

## Module Specifications

### 1. Discovery Modules (`scripts/modules/discovery/`)

#### net_scan.sh - Network Scanning

| Capability | Standalone | Laptop-assisted |
|------------|------------|-----------------|
| ARP scan | `arp-scan -l` | `nmap -sn -PR` |
| Ping sweep | `ping` loop, `fping` | `nmap -sn` |
| Port scan | `nc -zv` on common ports | `nmap -sS`, `masscan` |
| TCP connect | `bash /dev/tcp` | Full nmap |

#### service_id.sh - Service Identification

- Banner grabbing via netcat (standalone)
- Full version scan via `nmap -sV` (laptop)
- OT-specific port checks:
  - 502 (Modbus)
  - 44818 (EtherNet/IP)
  - 4840 (OPC UA)
  - 20000 (DNP3)
  - 47808 (BACnet)
  - 102 (S7comm)

#### ot_fingerprint.sh - OT Device Identification

- MAC OUI lookup against ICS vendor database (Siemens, Rockwell, Schneider, ABB, Honeywell, Emerson, GE, etc.)
- Port-based classification: PLC vs HMI vs Historian vs Engineering Workstation
- Passive broadcast listening: ARP, mDNS, LLDP, Profinet DCP

#### asset_inventory.sh - Results Aggregation

- Merges scan results into `artifacts/inventory.csv`
- Fields: IP, MAC, OUI Vendor, Hostname, Open Ports, Device Type, Confidence
- JSON export option for tooling integration

---

### 2. OT Protocol Modules (`scripts/modules/ot-protocols/`)

#### Protocol Priority

| Tier | Protocols |
|------|-----------|
| **Tier 1** | Modbus/TCP, EtherNet/IP (CIP), OPC UA |
| **Tier 2** | DNP3, PROFINET |
| **Tier 3** | IEC 61850, BACnet, S7comm |

#### Capability Matrix

| Protocol | File | Discover | Read | Write | Standalone Tool | Laptop Tool |
|----------|------|----------|------|-------|-----------------|-------------|
| Modbus/TCP | `modbus.sh` | ✓ | ✓ | ⚠️ | `mbpoll`, netcat | `mbtget`, Python |
| EtherNet/IP | `enip_cip.sh` | ✓ | ✓ | ⚠️ | nmap `enip-info` | `cpppo`, Python |
| OPC UA | `opcua.sh` | ✓ | ✓ | ⚠️ | Python opcua | Full client |
| DNP3 | `dnp3.sh` | ✓ | ✓ | ✗ | nmap scripts | `dnp3-master` |
| PROFINET | `profinet.sh` | ✓ | ✗ | ✗ | `pndcp` | Wireshark dissector |
| IEC 61850 | `iec61850.sh` | ✓ | ✓ | ✗ | `libiec61850` | Full stack |
| BACnet | `bacnet.sh` | ✓ | ✓ | ⚠️ | `bacnet-stack` | Full client |
| S7comm | `s7comm.sh` | ✓ | ✓ | ⚠️ | `snap7`, nmap | `python-snap7` |

⚠️ = Write gated behind SAFE_MODE confirmation

#### Common Module Pattern

```bash
rt_modbus() {
  local target port unit_id action
  
  # 1. Target picker
  target=$(IP_PICKER "Modbus target" "192.168.1.10")
  port=$(NUMBER_PICKER "Port" 502)
  unit_id=$(NUMBER_PICKER "Unit ID" 1)
  
  # 2. Action menu
  LOG "1) Scan/Identify"
  LOG "2) Read Coils"
  LOG "3) Read Holding Registers"
  LOG "4) Write Coil (SAFE_MODE)"
  LOG "5) Write Register (SAFE_MODE)"
  action=$(NUMBER_PICKER "Action" 1)
  
  # 3. Execute with tool fallback
  case "$action" in
    1) modbus_scan "$target" "$port" ;;
    2) modbus_read_coils "$target" "$port" "$unit_id" ;;
    4) 
      if safe_confirm "WRITE to PLC coil. Proceed?" "$SAFE_MODE"; then
        modbus_write_coil "$target" "$port" "$unit_id"
      fi
      ;;
  esac
  
  # 4. Log artifacts
  # -> artifacts/ot/modbus_<target>_<timestamp>.log
}
```

---

### 3. Credential Modules (`scripts/modules/credentials/`)

#### Files

| File | Purpose | Mode |
|------|---------|------|
| `default_creds.sh` | OT/IT default credential checker | Active |
| `snmp_enum.sh` | SNMP community string brute | Active |
| `hash_capture.sh` | Passive NTLM/NetNTLM capture | Passive |
| `responder.sh` | LLMNR/NBT-NS/mDNS poisoning | ⚠️ Active (laptop) |
| `ntlm_relay.sh` | SMB relay attacks | ⚠️ Active (laptop) |
| `protocol_auth.sh` | Sniff auth from OT protocols | Passive |

#### default_creds.sh - OT Default Credential Checker

Primary tool for OT engagements. Checks common defaults against discovered services.

**Wordlist Format (`wordlists/ot-defaults.csv`):**
```csv
vendor,product,protocol,port,username,password
Siemens,S7-1200,HTTP,80,admin,admin
Siemens,S7-1200,HTTP,80,admin,<blank>
Rockwell,PanelView,VNC,5900,admin,1234
Schneider,M340,FTP,21,USER,USER
Schneider,M340,Telnet,23,USER,USER
GE,Cimplicity,HTTP,80,administrator,<blank>
Allen-Bradley,ControlLogix,HTTP,80,admin,1234
Honeywell,Experion,HTTP,80,admin,admin
ABB,AC500,HTTP,80,admin,admin
```

**Standalone checks:**
- HTTP/HTTPS: `curl` with basic auth
- FTP: `ftp` or netcat
- Telnet: `expect` script or netcat
- VNC: `vncauth` check
- SSH: `ssh` with password (if `sshpass` available)

**Laptop checks:**
- `hydra` for multi-protocol brute
- `medusa` for parallel checking
- Custom scripts for proprietary protocols

#### protocol_auth.sh - OT Protocol Auth Sniffing

Passive capture of authentication traffic:

| Protocol | What to Capture |
|----------|-----------------|
| Modbus | No auth (log Unit IDs for enumeration) |
| EtherNet/IP | Session handles, connection parameters |
| OPC UA | Username/password if unencrypted (Security Mode: None) |
| VNC | Challenge/response for offline cracking |
| Telnet | Plaintext credentials |
| FTP | Plaintext credentials |
| HTTP | Basic auth headers, form posts |

---

### 4. Laptop Integration (`scripts/modules/laptop/`)

#### Configuration (`scripts/config.sh`)

```bash
# Laptop Integration
LAPTOP_ENABLED=0                    # 0=standalone, 1=laptop mode
LAPTOP_HOST="operator@10.0.0.50"    # user@ip
LAPTOP_KEY="/root/.ssh/id_rsa"      # Pre-shared SSH key
LAPTOP_TOOLS_DIR="/opt/tools"       # Where tools live on laptop
LAPTOP_RESULTS_DIR="/tmp/pager"     # Where to stage results
```

#### ssh_exec.sh - Core Wrapper

```bash
laptop_exec() {
  local cmd="$1"
  if [[ "$LAPTOP_ENABLED" -eq 0 ]]; then
    LOG red "Laptop mode not configured"
    return 1
  fi
  ssh -i "$LAPTOP_KEY" -o BatchMode=yes -o ConnectTimeout=5 "$LAPTOP_HOST" "$cmd"
}

laptop_exec_bg() {
  local cmd="$1"
  laptop_exec "nohup $cmd > '$LAPTOP_RESULTS_DIR/out.log' 2>&1 & echo \$!"
}

laptop_fetch() {
  local remote_path="$1"
  local local_path="$2"
  scp -i "$LAPTOP_KEY" "$LAPTOP_HOST:$remote_path" "$local_path"
}
```

#### Auto-Fallback Pattern

```bash
run_nmap() {
  local args="$*"
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "nmap $args"
  elif have nmap; then
    nmap $args
  else
    LOG red "nmap unavailable - enable laptop mode or install locally"
    return 1
  fi
}
```

---

### 5. Engagement Configuration (`scripts/config.sh`)

```bash
#!/bin/bash
# === ENGAGEMENT CONFIG ===
# Edit at start of each engagement

# --- Scope Controls ---
ENGAGEMENT_NAME="client-2025-01"
TARGET_NETWORK="192.168.1.0/24"
EXCLUDE_IPS="192.168.1.1,192.168.1.2"  # Gateway, safety systems
OT_NETWORK=""                           # Separate OT segment if known

# --- Safety Controls ---
SAFE_MODE=1                # 1=confirm before destructive actions
PASSIVE_ONLY=0             # 1=disable all active attacks
MAX_DURATION_SEC=300       # Timebox for long scans

# --- WiFi Scope ---
CHANNEL_ALLOWLIST="1 6 11"
BSSID_SCOPE=""

# --- Laptop Integration ---
LAPTOP_ENABLED=0
LAPTOP_HOST=""
LAPTOP_KEY=""
LAPTOP_TOOLS_DIR="/opt/tools"
LAPTOP_RESULTS_DIR="/tmp/pager-results"

# --- Artifacts ---
ARTIFACT_DIR="artifacts/$ENGAGEMENT_NAME"
LOG_DIR="logs/$ENGAGEMENT_NAME"
```

---

### 6. Menu Structure

#### Main Menu

```
┌─────────────────────────────────┐
│   RED TEAM TOOLKIT v2.0         │
│   [client-2025-01]              │
│   ───────────────────────────── │
│   SAFE:ON  LAPTOP:OFF  PASSIVE:OFF
├─────────────────────────────────┤
│ 1) Discovery & Mapping          │
│ 2) OT Protocol Attacks          │
│ 3) Credential Harvesting        │
│ 4) Wireless Attacks             │
│ 5) Physical/Serial              │
│ 6) Laptop Tools                 │
│ ─────────────────────────────── │
│ 8) Configure Engagement         │
│ 9) Export Artifacts             │
│ 0) Exit                         │
└─────────────────────────────────┘
```

#### Submenus

**1) Discovery & Mapping:**
```
1) ARP/Network Scan
2) Port Scan
3) Service Identification
4) OT Device Fingerprint
5) View Asset Inventory
0) Back
```

**2) OT Protocol Attacks:**
```
1) Modbus/TCP
2) EtherNet/IP (CIP)
3) OPC UA
4) DNP3
5) PROFINET
6) IEC 61850
7) BACnet
8) S7comm
0) Back
```

**3) Credential Harvesting:**
```
1) Default Credential Check
2) SNMP Enumeration
3) Passive Hash Capture
4) Responder (laptop)
5) NTLM Relay (laptop)
6) Protocol Auth Sniff
0) Back
```

---

## File Structure

```
library/user/general/red-team-toolkit/
├── payload.sh                      # Main entry, top-level menu
├── README.md                       # Usage documentation
├── scripts/
│   ├── common.sh                   # Shared helpers (existing)
│   ├── config.sh                   # Engagement configuration
│   ├── menu.sh                     # Menu rendering helpers
│   └── modules/
│       ├── discovery/
│       │   ├── net_scan.sh
│       │   ├── service_id.sh
│       │   ├── asset_inventory.sh
│       │   └── ot_fingerprint.sh
│       ├── ot-protocols/
│       │   ├── modbus.sh           # Enhanced from existing
│       │   ├── enip_cip.sh         # Enhanced from existing
│       │   ├── opcua.sh            # Enhanced from existing
│       │   ├── dnp3.sh             # New
│       │   ├── profinet.sh         # New
│       │   ├── iec61850.sh         # New
│       │   ├── bacnet.sh           # New
│       │   └── s7comm.sh           # New
│       ├── credentials/
│       │   ├── default_creds.sh    # New
│       │   ├── snmp_enum.sh        # New
│       │   ├── hash_capture.sh     # New
│       │   ├── responder.sh        # New (laptop wrapper)
│       │   ├── ntlm_relay.sh       # New (laptop wrapper)
│       │   └── protocol_auth.sh    # New
│       ├── wireless/
│       │   ├── passive_recon.sh    # Existing
│       │   ├── handshake_capture.sh # Existing
│       │   └── deauth_watch.sh     # Existing
│       ├── physical/
│       │   ├── can_monitor.sh      # Existing
│       │   ├── rs485_serial.sh     # Existing
│       │   └── rtl_sdr.sh          # Existing
│       └── laptop/
│           ├── ssh_config.sh       # New
│           ├── ssh_exec.sh         # New
│           └── results_fetch.sh    # New
├── wordlists/
│   ├── ot-defaults.csv             # Vendor default credentials
│   ├── snmp-communities.txt        # Common SNMP strings
│   ├── common-users.txt            # admin, operator, etc.
│   └── ics-oui.txt                 # ICS vendor MAC prefixes
└── artifacts/
    └── .gitkeep
```

---

## Implementation Phases

| Phase | Scope | Files | Effort |
|-------|-------|-------|--------|
| **Phase 1: Foundation** | Config system, menu refactor, laptop SSH core | `config.sh`, `menu.sh`, `payload.sh`, `laptop/*.sh` | 1-2 days |
| **Phase 2: Discovery** | Network scanning and OT fingerprinting | `discovery/*.sh`, `wordlists/ics-oui.txt` | 2-3 days |
| **Phase 3: OT Tier 1** | Modbus R/W, EtherNet/IP, OPC UA expansion | `ot-protocols/modbus.sh`, `enip_cip.sh`, `opcua.sh` | 2-3 days |
| **Phase 4: Credentials** | Default creds, SNMP, hash capture | `credentials/default_creds.sh`, `snmp_enum.sh`, `hash_capture.sh`, `wordlists/ot-defaults.csv` | 2 days |
| **Phase 5: OT Tier 2-3** | DNP3, PROFINET, IEC 61850, BACnet, S7 | `ot-protocols/dnp3.sh`, `profinet.sh`, `iec61850.sh`, `bacnet.sh`, `s7comm.sh` | 3-4 days |
| **Phase 6: Active Attacks** | Responder, relay integration | `credentials/responder.sh`, `ntlm_relay.sh`, `protocol_auth.sh` | 2 days |
| **Phase 7: Polish** | Documentation, testing, wordlist expansion | `README.md`, all modules | 1-2 days |

**Total Estimate:** 13-18 days

---

## Wordlists

### ot-defaults.csv

Initial vendor coverage:
- Siemens (S7-1200, S7-1500, WinCC, TIA Portal)
- Rockwell/Allen-Bradley (ControlLogix, CompactLogix, PanelView)
- Schneider Electric (M340, M580, Unity, Vijeo)
- ABB (AC500, Freelance, 800xA)
- Honeywell (Experion, C300)
- Emerson (DeltaV, Ovation)
- GE (Cimplicity, iFIX, Mark VIe)
- Yokogawa (Centum, ProSafe)
- Generic (HMI panels, historians, SCADA servers)

### snmp-communities.txt

```
public
private
community
SNMP
snmp
admin
default
read
write
monitor
```

### ics-oui.txt

MAC OUI prefixes for ICS vendor identification:
```
00:00:BC,Rockwell Automation
00:01:05,Beckhoff
00:0B:AB,Advantech
00:0E:8C,Siemens
00:1C:06,Siemens
00:80:F4,Telemecanique (Schneider)
...
```

---

## Success Criteria

1. **Standalone viability:** Core discovery and OT scanning works without laptop
2. **Tool fallback:** Each module gracefully degrades based on available tools
3. **Safety controls:** SAFE_MODE blocks all destructive actions until confirmed
4. **Artifact consistency:** All outputs logged to predictable paths
5. **Engagement portability:** Single config file customizes entire toolkit per engagement

---

## Future Expansion (Out of Scope for v2.0)

- Evil twin / captive portal (wireless expansion)
- Bluetooth/BLE reconnaissance
- Zigbee/Z-Wave attacks
- RFID cloning integration
- Multi-Pager coordination
- C2 framework integration (Sliver, Mythic)
- Automated reporting / evidence timeline
