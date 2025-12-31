# Red Team Toolkit v2.0

Swiss-army-knife payload for IT/OT penetration testing engagements on the WiFi Pineapple Pager.

## Features

### Discovery & Mapping
- ARP scan, ping sweep, port scan
- Service identification and banner grabbing
- OT device fingerprinting (MAC OUI, port-based classification)
- Passive broadcast listening (mDNS, LLDP, Profinet DCP)
- Asset inventory aggregation

### OT Protocol Attacks
- **Modbus/TCP**: Device ID, read/write coils and registers
- **EtherNet/IP (CIP)**: Identity, tag enumeration, read/write
- **OPC UA**: Browse, read, write, security audit
- *(More protocols in development: DNP3, PROFINET, BACnet, S7comm)*

### Credential Harvesting
- Default credential checker (50+ OT vendor defaults)
- SNMP community string enumeration
- Passive hash capture (NTLM, HTTP Basic)
- Responder integration (laptop mode)

### Wireless & Physical
- WiFi passive recon, handshake capture
- RS485 serial monitoring
- CAN bus monitoring
- RTL-SDR

## Operating Modes

| Mode | Description |
|------|-------------|
| **Standalone** | Pager runs lightweight tools directly |
| **Laptop-assisted** | Heavy tools via SSH to connected laptop |
| **Hybrid** | Auto-fallback: local tools first, then laptop |

## Quick Start

1. Copy this folder to your Pager
2. Edit `scripts/config.sh` with engagement details
3. Launch from Pager UI
4. Select module from main menu

## Configuration

Edit `scripts/config.sh`:

```bash
# Engagement
ENGAGEMENT_NAME="client-2025"
TARGET_NETWORK="192.168.1.0/24"
EXCLUDE_IPS="192.168.1.1"

# Safety
SAFE_MODE=1              # Confirm before destructive actions
PASSIVE_ONLY=0           # Set to 1 to block all active attacks

# Laptop Integration
LAPTOP_ENABLED=0         # Set to 1 to enable
LAPTOP_HOST="user@10.0.0.50"
LAPTOP_KEY="/root/.ssh/id_rsa"
```

## Directory Structure

```
red-team-toolkit/
├── payload.sh              # Main entry point
├── scripts/
│   ├── config.sh           # Engagement configuration
│   ├── common.sh           # Shared helpers
│   ├── menu.sh             # Menu system
│   └── modules/
│       ├── discovery/      # Network scanning
│       ├── ot-protocols/   # ICS protocol attacks
│       ├── credentials/    # Credential harvesting
│       ├── wireless/       # WiFi attacks
│       ├── physical/       # Serial, CAN, SDR
│       └── laptop/         # SSH wrappers
├── wordlists/
│   ├── ot-defaults.csv     # Vendor default creds
│   ├── snmp-communities.txt
│   └── ics-oui.txt         # MAC vendor lookup
└── artifacts/              # Scan outputs
```

## Laptop Setup (Optional)

For full capability, set up a laptop with:

```bash
# Install tools
apt install nmap responder impacket-scripts snmp

# Python libraries
pip3 install pycomm3 opcua

# SSH key exchange
ssh-copy-id user@pager-ip
```

## Safety Features

- **SAFE_MODE**: Requires confirmation before writes, poisoning, etc.
- **PASSIVE_ONLY**: Blocks all active attacks when enabled
- **Scope controls**: TARGET_NETWORK and EXCLUDE_IPS enforce boundaries
- **Timeboxing**: Long scans auto-terminate

## Artifacts

All outputs saved to `artifacts/<engagement_name>/`:
- `arp_scan_*.txt` - ARP scan results
- `fingerprint_*.txt` - OT device profiles
- `inventory.txt` - Aggregated asset inventory
- `modbus_*.txt` - Modbus interaction logs
- `creds_*.txt` - Credential check results
- `*.pcap` - Packet captures

## Requirements

### Standalone (basic functionality)
- tcpdump, netcat, curl (usually pre-installed)

### Full functionality
- nmap, arp-scan, fping
- snmpwalk, mbpoll
- python3 with opcua library

### Laptop-assisted
- SSH access to laptop with pentest tools
- Responder, Impacket, Nmap, pycomm3
