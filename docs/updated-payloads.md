# Fork Additions - Payload Catalog

> **Fork**: gmackie/wifipineapplepager-payloads  
> **Upstream**: hak5/wifipineapplepager-payloads  
> **Version**: 2.5.0  
> **Last Updated**: January 2025

This document catalogs all payloads added to this fork beyond the upstream Hak5 repository.

## Quick Reference

| Category | Count | Risk Level |
|----------|-------|------------|
| Reconnaissance | 10 | Passive |
| Alert-Triggered | 4 | Reactive |
| Exfiltration | 4 | Active |
| Interception | 4 | Active |
| Utilities | 2 | Passive |
| SDR/RF | 2 | Passive |
| Red Team Toolkit | 39+ modules | Mixed |

---

## Payload Overview Table

| Payload | Path | Trigger | Phase | Risk | Dependencies |
|---------|------|---------|-------|------|--------------|
| **RECONNAISSANCE** |
| Rogue Twin Radar | `reconnaissance/rogue-twin-radar/` | User | Recon | Passive | airodump-ng |
| Beacon Anomaly Watch | `reconnaissance/beacon-anomaly-watch/` | User | Recon | Passive | airodump-ng |
| WPS Beacon Flagger | `reconnaissance/wps-beacon-flagger/` | User | Recon | Passive | wash, airodump-ng |
| Enterprise Beacon Finder | `reconnaissance/enterprise-beacon-finder/` | User | Recon | Passive | airodump-ng |
| OT OUI Scout | `reconnaissance/ot-oui-scout/` | User | Recon | Passive | airodump-ng |
| Probe Whisperer | `reconnaissance/probe-whisperer/` | User | Recon | Passive | airodump-ng |
| Hidden SSID Counter | `reconnaissance/hidden-ssid-counter/` | User | Recon | Passive | airodump-ng |
| P2P Hotspot Spotter | `reconnaissance/p2p-hotspot-spotter/` | User | Recon | Passive | airodump-ng |
| Channel Heatmap | `reconnaissance/channel-heatmap/` | User | Recon | Passive | airodump-ng |
| Recon Dashboard | `reconnaissance/recon-dashboard/` | User | Recon | Passive | airodump-ng |
| Wireless Posture Auditor | `reconnaissance/wifi-posture-audit/` | User | Recon | Passive | airodump-ng |
| **ALERT-TRIGGERED** |
| Auto Crack | `alerts/handshake_captured/auto-crack/` | Alert | Exploit | Active | hashcat, aircrack-ng |
| Attack Logger | `alerts/deauth_flood_detected/attack-logger/` | Alert | Detect | Passive | - |
| Client Profiler | `alerts/pineapple_client_connected/client-profiler/` | Alert | Recon | Passive | - |
| Credential Logger | `alerts/pineapple_auth_captured/credential-logger/` | Alert | Collect | Passive | - |
| **EXFILTRATION** |
| DNS Tunnel | `exfiltration/dns-tunnel/` | User | Exfil | Active | nslookup/dig |
| HTTP POST Exfil | `exfiltration/http-post-exfil/` | User | Exfil | Active | curl/wget |
| Staged Transfer | `exfiltration/staged-transfer/` | User | Exfil | Active | curl/nc/scp |
| Stego Transfer | `exfiltration/stego-transfer/` | User | Exfil | Active | steghide (optional) |
| **INTERCEPTION** |
| MITM Setup | `interception/mitm-setup/` | User | Access | Active | arpspoof/ettercap |
| Packet Sniffer | `interception/packet-sniffer/` | User | Collect | Passive | tcpdump/tshark |
| Credential Harvester | `interception/cred-harvester/` | User | Collect | Active | tshark |
| SSL Strip Helper | `interception/ssl-strip-helper/` | User | Access | Active | sslstrip/bettercap |
| **UTILITIES** |
| Evidence Packager | `general/evidence-packager/` | User | Report | Passive | tar, sha256sum |
| Dependency Checker | `general/dependency-checker/` | User | Setup | Passive | - |
| **SDR/RF** |
| RF Baseline Alert | `general/rf-baseline-alert/` | User | Recon | Passive | rtl_power |
| POCSAG Monitor | `general/pocsag-monitor/` | User | Recon | Passive | rtl_fm, multimon-ng |

---

## Payload Details

### Reconnaissance Payloads

#### Rogue Twin Radar
**Path**: `library/user/reconnaissance/rogue-twin-radar/`  
**Risk**: Passive  
**Dependencies**: airodump-ng, monitor mode interface

Detects potential evil twin attacks by monitoring for:
- New BSSIDs appearing for known SSIDs
- Security downgrades (WPA2 → Open)
- RSSI anomalies indicating rogue APs

**Artifacts**: `/tmp/rogue-twin-radar/twins_*.txt`

---

#### Wireless Posture Auditor
**Path**: `library/user/reconnaissance/wifi-posture-audit/`  
**Risk**: Passive  
**Dependencies**: airodump-ng, monitor mode interface

Comprehensive wireless security assessment:
- WPA2/WPA3 mode detection
- PMF (802.11w) presence check
- WPS exposure flagging
- Weak encryption identification
- Channel congestion analysis

**Artifacts**: `/tmp/wifi-posture-audit/report_*.txt`

---

#### Recon Dashboard
**Path**: `library/user/reconnaissance/recon-dashboard/`  
**Risk**: Passive  
**Dependencies**: airodump-ng

Unified live monitoring combining:
- Evil twin detection
- Hidden network tracking
- Probe request analysis
- Hotspot/P2P detection
- Enterprise network flagging

**Artifacts**: `/tmp/recon-dashboard/`

---

### Alert-Triggered Payloads

#### Auto Crack
**Path**: `library/alerts/handshake_captured/auto-crack/`  
**Trigger**: `handshake_captured` alert  
**Risk**: Active (CPU/GPU intensive)  
**Dependencies**: hashcat or aircrack-ng, wordlists

Automatically attempts dictionary attack on captured handshakes using:
- Hashcat (preferred, GPU-accelerated)
- Aircrack-ng (fallback, CPU-based)

**Environment Variables**:
- `$_ALERT_HANDSHAKE_PCAP_PATH`
- `$_ALERT_HANDSHAKE_HASHCAT_PATH`

---

### Exfiltration Payloads

#### DNS Tunnel
**Path**: `library/user/exfiltration/dns-tunnel/`  
**Risk**: Active  
**Dependencies**: nslookup, dig, or host

Exfiltrates data via DNS queries:
- Base32/hex encoding in subdomains
- Configurable chunk sizes
- Rate limiting to avoid detection

**Configuration**: Set `DNS_DOMAIN` to your receiving server.

---

#### Staged Transfer
**Path**: `library/user/exfiltration/staged-transfer/`  
**Risk**: Active  
**Dependencies**: curl, wget, nc, or scp

Reliable chunked file transfer with:
- Resume capability
- Multiple protocols (HTTP/FTP/SCP/NC)
- Checksum verification
- Progress tracking

---

### Interception Payloads

#### MITM Setup
**Path**: `library/user/interception/mitm-setup/`  
**Risk**: Active  
**Dependencies**: arpspoof, ettercap, or bettercap

Configures network for man-in-the-middle:
- IP forwarding setup
- NAT/masquerade rules
- ARP spoofing
- Port redirection

---

### SDR/RF Payloads

#### RF Baseline Alert
**Path**: `library/user/general/rf-baseline-alert/`  
**Risk**: Passive  
**Dependencies**: rtl_power, RTL-SDR dongle

Establishes RF baseline and alerts on anomalies:
- Configurable frequency bands
- Baseline heatmap generation
- New emitter detection
- Threshold-based alerting

---

#### POCSAG Monitor
**Path**: `library/user/general/pocsag-monitor/`  
**Risk**: Passive  
**Dependencies**: rtl_fm, multimon-ng, RTL-SDR dongle

Passive pager/POCSAG signal monitoring:
- Decodes POCSAG/FLEX protocols
- Message logging (with privacy caveats)
- Activity detection mode

**Legal Notice**: POCSAG interception may be regulated in your jurisdiction.

---

### Utility Payloads

#### Evidence Packager
**Path**: `library/user/general/evidence-packager/`  
**Risk**: Passive  
**Dependencies**: tar, sha256sum

One-button evidence collection:
- Gathers all artifacts from `/tmp/`
- Timestamps and hashes
- Creates portable archive
- Engagement ID tagging

---

#### Dependency Checker
**Path**: `library/user/general/dependency-checker/`  
**Risk**: Passive  
**Dependencies**: None

Pre-flight compatibility check:
- Lists available vs missing tools
- Standalone vs laptop-assisted modes
- Recommended payload suggestions

---

## Red Team Toolkit v2.5

**Path**: `library/user/general/red-team-toolkit/`

Comprehensive modular toolkit with 39+ modules:

### Module Categories

| Category | Modules |
|----------|---------|
| Discovery | AD enum, asset inventory, net scan, OT fingerprint, SMB enum, web scan, service ID, recon launchers |
| OT Protocols | Modbus, DNP3, BACnet, S7comm, EtherNet/IP, OPC-UA, PROFINET, IEC 61850 |
| Credentials | Default creds, hash capture, Kerberos, NTLM relay, Responder, SNMP enum, protocol auth |
| Network | DNS spoof, MITM, VLAN hop |
| Wireless | Deauth, evil twin, handshake capture, WPA crack, passive recon |
| Physical | CAN bus monitor, RS485 serial, RTL-SDR |
| Laptop | SSH exec (remote command execution) |
| Reporting | Export, timeline |
| Automation | Attack chains, notifications |

---

## Canonical Workflows

### New Site Quick Recon (15 min)
1. Run `dependency-checker` to verify tools
2. Launch `recon-dashboard` for live monitoring
3. Run `wifi-posture-audit` for security summary
4. Run `channel-heatmap` for RF environment
5. Package with `evidence-packager`

### Wireless Assessment Day-1
1. `wifi-posture-audit` → identify weak targets
2. `enterprise-beacon-finder` → map 802.1X networks
3. `probe-whisperer` → capture client preferences
4. `hidden-ssid-counter` → reveal hidden networks
5. `rogue-twin-radar` (background) → monitor for threats

### OT/ICS Segment Triage
1. `ot-oui-scout` → identify industrial devices
2. Red Team Toolkit → OT protocol enumeration
3. `rf-baseline-alert` → monitor ISM bands
4. `evidence-packager` → bundle findings

### Credential Harvesting (Authorized)
1. `mitm-setup` → configure interception
2. `cred-harvester` → monitor protocols
3. `packet-sniffer` → capture traffic
4. Alert payloads → auto-process captures

---

## Compatibility Matrix

| Feature | Pager Standalone | Laptop-Assisted |
|---------|------------------|-----------------|
| Passive WiFi recon | ✅ | ✅ |
| Active WiFi attacks | ✅ | ✅ |
| WPA cracking (GPU) | ❌ | ✅ |
| WPA cracking (CPU) | ⚠️ Slow | ✅ |
| RTL-SDR monitoring | ✅ | ✅ |
| POCSAG decoding | ✅ | ✅ |
| Heavy packet analysis | ⚠️ Limited | ✅ |
| Large file exfil | ⚠️ Staged | ✅ |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.5.0 | Jan 2025 | Added SDR payloads, utilities, documentation |
| 2.4.0 | Jan 2025 | Added exfiltration, interception payloads |
| 2.3.0 | Dec 2024 | Red Team Toolkit v2.3, alert payloads |
| 2.0.0 | Dec 2024 | Initial fork with reconnaissance payloads |
