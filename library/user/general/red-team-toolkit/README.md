# Red Team Toolkit v2.2

Swiss-army-knife payload for IT/OT penetration testing engagements on the WiFi Pineapple Pager.

## Features

### Discovery & Mapping
- ARP scan, ping sweep, port scan
- Service identification and banner grabbing
- OT device fingerprinting (MAC OUI, port-based classification)
- Active Directory enumeration (users, groups, computers, BloodHound)
- Asset inventory aggregation

### OT Protocol Attacks (8 protocols)
- **Modbus/TCP**: Device ID, read/write coils and registers
- **EtherNet/IP (CIP)**: Identity, tag enumeration, read/write
- **OPC UA**: Browse, read, write, security audit
- **DNP3**: Device identification, point read, integrity scan
- **PROFINET**: DCP discovery, passive traffic capture
- **BACnet**: Who-Is discovery, property read/write
- **S7comm**: CPU info, memory read/write
- **IEC 61850**: MMS browse, GOOSE sniffing

### Credential Harvesting
- Default credential checker (50+ OT vendor defaults)
- SNMP community string enumeration
- Passive hash capture (NTLM, HTTP Basic, FTP, Telnet)
- Responder integration with full control (laptop mode)
- NTLM relay attacks (SMB, LDAP, HTTP)
- Kerberos attacks (Kerberoasting, AS-REP roasting)
- OT protocol authentication sniffing

### Network Attacks
- ARP spoofing / MITM with traffic capture
- SSL stripping
- DNS spoofing and hijacking
- DNS rebinding setup
- VLAN hopping (DTP, double tagging)

### Wireless Attacks
- WiFi passive recon
- Handshake capture
- WPA/WPA2 cracking (hashcat integration)
- Targeted deauthentication (single/broadcast/continuous)
- Evil Twin AP with captive portal

### Physical/Serial
- RS485 serial monitoring
- CAN bus monitoring
- RTL-SDR

### Reporting
- Engagement timeline generation
- Executive summary export
- Technical findings report
- Credential report
- Full archive export (tar.gz)

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
ENGAGEMENT_NAME="client-2025"
TARGET_NETWORK="192.168.1.0/24"
EXCLUDE_IPS="192.168.1.1"

SAFE_MODE=1              # Confirm before destructive actions
PASSIVE_ONLY=0           # Set to 1 to block all active attacks

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
│       ├── discovery/      # Network scanning (5 modules)
│       ├── ot-protocols/   # ICS protocol attacks (8 modules)
│       ├── credentials/    # Credential harvesting (7 modules)
│       ├── network/        # Network attacks (3 modules)
│       ├── wireless/       # WiFi attacks (6 modules)
│       ├── physical/       # Serial, CAN, SDR (3 modules)
│       ├── reporting/      # Timeline and export (2 modules)
│       └── laptop/         # SSH wrappers
├── wordlists/
│   ├── ot-defaults.csv     # 39 vendor default creds
│   ├── snmp-communities.txt # 25 community strings
│   └── ics-oui.txt         # 27 ICS vendor MACs
└── artifacts/              # Scan outputs
```

## Laptop Setup (Optional)

For full capability, set up a laptop with:

```bash
apt install nmap responder impacket-scripts snmp hostapd dnsmasq \
    arpspoof ettercap-text-only sslstrip yersinia bloodhound

pip3 install pycomm3 opcua scapy

ssh-copy-id user@pager-ip
```

## Safety Features

- **SAFE_MODE**: Requires confirmation before writes, poisoning, etc.
- **PASSIVE_ONLY**: Blocks all active attacks when enabled
- **Scope controls**: TARGET_NETWORK and EXCLUDE_IPS enforce boundaries
- **Timeboxing**: Long scans auto-terminate

## Artifacts

All outputs saved to `artifacts/<engagement_name>/`:

| Pattern | Description |
|---------|-------------|
| `arp_scan_*.txt` | ARP scan results |
| `fingerprint_*.txt` | OT device profiles |
| `inventory.txt` | Aggregated asset inventory |
| `ad_*.txt` | Active Directory enumeration |
| `modbus_*.txt` | Modbus interaction logs |
| `enip_*.txt` | EtherNet/IP results |
| `opcua_*.txt` | OPC UA interactions |
| `s7comm_*.txt` | Siemens S7 results |
| `bacnet_*.txt` | BACnet discoveries |
| `creds_*.txt` | Credential check results |
| `kerberoast_*.txt` | Kerberos hashes |
| `responder/` | Captured NTLM hashes |
| `portal/` | Captive portal credentials |
| `mitm_*.pcap` | MITM traffic captures |
| `timeline.txt` | Engagement timeline |
| `executive_summary.txt` | Executive report |
| `*.pcap` | Packet captures |

## Module Count

| Category | Modules |
|----------|---------|
| Discovery | 5 |
| OT Protocols | 8 |
| Credentials | 7 |
| Network | 3 |
| Wireless | 6 |
| Physical | 3 |
| Reporting | 2 |
| Laptop | 1 |
| **Total** | **35** |

## Requirements

### Standalone (basic functionality)
- tcpdump, netcat, curl (usually pre-installed)

### Full functionality
- nmap, arp-scan, fping
- snmpwalk, mbpoll
- python3 with opcua library
- aireplay-ng or mdk4 (for deauth)
- hostapd, dnsmasq (for evil twin)
- arpspoof, ettercap (for MITM)
- hcxpcapngtool (for WPA hash conversion)

### Laptop-assisted
- SSH access to laptop with pentest tools
- Responder, Impacket (ntlmrelayx, GetUserSPNs), Nmap
- hashcat with GPU support
- BloodHound (bloodhound-python)
- CrackMapExec
