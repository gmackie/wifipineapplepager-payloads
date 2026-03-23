# ICS/OT Probe — WiFi Pineapple Pager Design Document

**Date:** 2026-03-23
**Status:** Draft
**Scope:** Hardware peripheral + firmware + pager-side payloads for ICS/OT penetration testing

---

## 1. Architecture Overview

The system has three layers:

### 1.1 ESP32 USB Peripheral ("ICS Probe")

A custom ESP32 board with transceiver ICs that plugs into the pager's USB port. It presents as a USB CDC serial device (`/dev/ttyACM0`). The ESP32 firmware handles all timing-critical physical-layer protocols — Modbus RTU framing, CAN arbitration, RS-232 serial, 4-20mA ADC reads — and exposes them through a simple JSON command protocol over serial. BLE scanning runs natively on the ESP32 and reports discovered devices over the same channel.

### 1.2 Pager-Side Shell Library (`library/user/ics/lib/`)

A set of shell scripts that payloads `source` to communicate with the ESP32 and perform network-based ICS protocol operations. Two main libraries:

- **`esp32.sh`** — Serial communication with the probe (send commands, parse JSON responses, probe detection, error handling)
- **`ics_protocols.sh`** — Pure network-based ICS discovery functions (OPC UA, Ethernet/IP, BACnet, Modbus TCP, DNP3) that work with or without the ESP32 attached

### 1.3 Payload Collection (`library/user/ics/`)

Individual payloads organized by protocol and function. Each follows the existing `payload.sh` convention with DuckyScript UI commands. Payloads that need the ESP32 check for it at startup and fail gracefully. Network-only payloads work with just the pager's Ethernet/WiFi.

**Key principle:** The ESP32 does the hard real-time work, the pager does the UI and orchestration. Payloads stay simple shell scripts.

---

## 2. ESP32 Hardware Design

### 2.1 MCU

**ESP32-S3** — Dual-core, USB-OTG native, BLE 5.0, 8MB flash. The S3's native USB means no external USB-to-UART chip — it enumerates as CDC directly.

### 2.2 Transceiver ICs

| Bus | IC | ESP32 Pins | Notes |
|---|---|---|---|
| RS-485 (Modbus RTU) | MAX3485 | UART1 TX/RX + GPIO DE/RE | Half-duplex, auto-direction via DE/RE toggle. 300–115200 baud. |
| RS-232 (Legacy SCADA) | MAX3232 | UART2 TX/RX | Full-duplex. For old RTUs, serial consoles, HMI debug ports. |
| CAN bus | SN65HVD230 + MCP2515 | SPI (MOSI/MISO/CLK/CS) + INT | MCP2515 handles CAN controller, SN65HVD230 is the physical transceiver. 125k–1M baud. |
| 4-20mA ADC | INA219 current sensor | I2C (SDA/SCL) | Reads 4-20mA loop current through a 250Ω sense resistor. Proves you can read live process values. |
| BLE | On-chip | — | Free. Scans for WirelessHART gateways, ISA100.11a adapters, BLE-enabled sensors. |

### 2.3 Physical Form Factor

Small PCB, roughly USB-stick sized. DB9 or screw terminal breakout on one end for RS-485/RS-232/CAN connections. A short pigtail or right-angle USB-A plug connects to the pager. Status LED on board (activity indicator).

### 2.4 Power

Bus-powered from USB (5V, ~200mA typical). All transceivers run off 3.3V regulated from USB 5V. CAN and RS-485 are galvanically isolated from the ESP32 side via optocouplers or an isolated DC-DC for safety when connecting to live field buses.

### 2.5 Optional Galvanic Isolation

An ADUM1201 or similar digital isolator between the ESP32 UART and the MAX3485 prevents ground loops when connecting to field equipment on different ground references — common in plant environments.

---

## 3. ESP32 Serial Command Protocol

The pager sends newline-terminated JSON commands to `/dev/ttyACM0`. The ESP32 responds with newline-terminated JSON. Every response includes a `status` field.

### 3.1 Message Format

**Command:**
```json
{"cmd":"<module>.<action>", "params":{...}, "id":"<optional-correlation-id>"}
```

**Response:**
```json
{"status":"ok|error", "id":"<correlation-id>", "data":{...}}
```

### 3.2 Command Catalog

| Command | Description | Example params |
|---|---|---|
| `modbus.read_holding` | Read holding registers | `{"addr":1, "reg":40001, "count":10}` |
| `modbus.read_input` | Read input registers | `{"addr":1, "reg":30001, "count":5}` |
| `modbus.read_coils` | Read coil status | `{"addr":1, "reg":1, "count":16}` |
| `modbus.write_register` | Write single register (opt-in level C) | `{"addr":1, "reg":40001, "value":100}` |
| `modbus.scan_bus` | Enumerate responding slave IDs | `{"range":[1,247]}` |
| `modbus.device_id` | Read device identification (FC43) | `{"addr":1}` |
| `serial.send` | Raw RS-232 send/receive | `{"data":"hex-encoded", "baud":9600, "timeout_ms":2000}` |
| `serial.passthrough` | Enter raw serial passthrough mode | `{"baud":9600}` |
| `can.listen` | Passive CAN sniff | `{"baud":500000, "duration_s":30}` |
| `can.send` | Send CAN frame | `{"id":"0x7E0", "data":"hex"}` |
| `can.scan_ids` | Enumerate active CAN IDs | `{"baud":500000, "duration_s":10}` |
| `adc.read` | Read 4-20mA current | `{}` |
| `adc.stream` | Continuous ADC readings | `{"interval_ms":500, "duration_s":60}` |
| `ble.scan` | BLE device discovery | `{"duration_s":15, "filter":"ics"}` |
| `probe.info` | Firmware version, capabilities | `{}` |
| `probe.selftest` | Test all transceivers | `{}` |

### 3.3 Safety Features

- `modbus.write_register` and `can.send` require a `"confirm":true` flag or they return an error. The pager-side library prompts the user with `CONFIRMATION_DIALOG` before setting that flag.
- Streaming commands (`can.listen`, `adc.stream`) send one JSON line per event. A `{"cmd":"stop"}` halts them.
- Commands time out after a configurable period (default 5s) so a payload never hangs waiting on a dead bus.

---

## 4. ESP32 Firmware Architecture

The ESP32-S3 firmware is structured as a command dispatcher with protocol handlers.

```
USB CDC Serial ←→ JSON Parser ←→ Command Router
                                      │
                    ┌─────────┬───────┼────────┬──────────┐
                    ▼         ▼       ▼        ▼          ▼
                 Modbus    RS-232    CAN     ADC/I2C     BLE
                 Handler   Handler  Handler  Handler   Scanner
                    │         │       │        │          │
                 MAX3485   MAX3232  MCP2515  INA219    On-chip
                 (UART1)   (UART2)  (SPI)    (I2C)
```

### 4.1 Firmware Modules

| Module | Responsibility |
|---|---|
| `main.cpp` | USB CDC init, JSON parse loop, command routing |
| `modbus_handler.cpp` | Modbus RTU master — read/write functions, bus scan, device ID. Manages DE/RE pin for half-duplex RS-485 direction control. Handles inter-frame timing (3.5 char silence). |
| `serial_handler.cpp` | Raw RS-232 send/receive, baud auto-detection (tries common rates, looks for printable ASCII), passthrough mode. |
| `can_handler.cpp` | MCP2515 init via SPI, passive listen with frame buffering, active send, ID enumeration by collecting unique arbitration IDs over a window. |
| `adc_handler.cpp` | INA219 current read over I2C, converts to mA, streaming mode with configurable interval. |
| `ble_scanner.cpp` | BLE scan with ICS device filtering — looks for known manufacturer IDs (Emerson, Honeywell, ABB BLE beacons), WirelessHART gateway advertisement patterns, and generic industrial sensor profiles. |
| `safety.cpp` | Enforces `confirm:true` requirement on write commands. Rate-limits commands to prevent bus flooding. Watchdog timer resets the probe if firmware hangs. |

### 4.2 Build System

PlatformIO with ESP-IDF framework. Single `platformio.ini`. Flash over USB-DFU (the same USB port used for CDC, so you can update firmware from the pager itself if `esptool.py` is installed).

### 4.3 Handler State Machine

IDLE → BUSY → RESPONSE_READY → IDLE. Only one command per handler at a time. Multiple handlers can run concurrently (e.g., CAN listen while doing a Modbus read).

---

## 5. Pager-Side Shell Libraries

Two libraries in `library/user/ics/lib/` that payloads source.

### 5.1 `esp32.sh` — ESP32 Probe Communication

```bash
# Detection and setup
esp32_detect()          # Find /dev/ttyACM*, verify probe.info response
esp32_require()         # Call esp32_detect, ERROR_DIALOG + exit if missing
esp32_send()            # Send JSON command, return response. Handles timeout.
esp32_stream_start()    # Start streaming command, return PID
esp32_stream_stop()     # Stop streaming, kill background reader

# Convenience wrappers
modbus_read_holding()   # $1=addr $2=reg $3=count → prints register values
modbus_read_input()     # Same pattern
modbus_scan_bus()       # $1=start $2=end → prints responding slave IDs
modbus_device_id()      # $1=addr → prints vendor, product, version
modbus_write_register() # Prompts CONFIRMATION_DIALOG before sending
can_listen()            # $1=baud $2=duration → streams CAN frames to stdout
can_scan_ids()          # $1=baud → prints active arbitration IDs
adc_read_ma()           # Reads 4-20mA, prints milliamps
ble_scan_ics()          # Scans for ICS-related BLE devices
probe_selftest()        # Runs selftest, reports pass/fail per bus
```

### 5.2 `ics_protocols.sh` — Network-Based ICS Discovery

No ESP32 required. Uses the pager's Ethernet/WiFi interfaces with `nmap`, `nping`, raw sockets, or Python one-liners if available.

```bash
# Discovery (active level B — safe discovery packets)
opcua_discover()        # OPC UA FindServers on port 4840. Returns endpoints.
enip_list_identity()    # Ethernet/IP ListIdentity on port 44818. Returns device name, vendor, serial.
bacnet_whois()          # BACnet Who-Is broadcast on port 47808. Returns device instances.
modbus_tcp_scan()       # Modbus TCP FC17 device ID on port 502. Returns vendor string.
dnp3_detect()           # DNP3 data link layer probe on port 20000.
s7comm_identify()       # Siemens S7comm SZL request on port 102. Returns CPU type, firmware.
fins_identify()         # Omron FINS UDP identity on port 9600.

# Passive
ics_port_fingerprint()  # Given nmap output, classify open ports by ICS protocol
ics_traffic_sniff()     # Passive capture, identify ICS protocols by signature

# Multi-protocol sweep
ics_full_discovery()    # Runs all discovery functions against a target/subnet
                        # Returns unified JSON asset inventory

# Interaction (level C — opt-in with confirmation)
opcua_browse_nodes()    # Browse OPC UA node tree. CONFIRMATION_DIALOG gated.
enip_get_attributes()   # Read Ethernet/IP CIP attributes.
modbus_tcp_read()       # Read Modbus TCP registers from remote device.
```

### 5.3 Common Helpers

```bash
ics_log()               # Structured logging: timestamp, protocol, severity, message
ics_save_artifact()     # Save findings to /root/loot/ics/<engagement>/
ics_report_device()     # Add device to running asset inventory JSON
ics_require_tool()      # Check for dependency (nmap, python3, etc), helpful error if missing
```

All level-C interaction functions call `CONFIRMATION_DIALOG` internally before sending anything.

---

## 6. Payload Collection

### 6.1 Directory Structure

```
library/user/ics/
  lib/
    esp32.sh
    ics_protocols.sh
  discovery/
    ics-network-sweep/          # Full subnet scan: all protocols, unified asset inventory
    ics-port-scanner/           # Fast nmap scan for known ICS ports
    ics-passive-sniffer/        # Passive traffic ID — no packets sent
    ble-sensor-scout/           # ESP32 BLE scan for WirelessHART, ISA100, BLE sensors
  modbus/
    modbus-tcp-enum/            # Enumerate Modbus TCP devices on subnet, read device IDs
    modbus-rtu-bus-scan/        # ESP32: scan RS-485 bus for responding slave addresses
    modbus-rtu-register-dump/   # ESP32: read register ranges from a specific slave (level C)
    modbus-rtu-live-monitor/    # ESP32: continuous register polling, show value changes
  opcua/
    opcua-server-discovery/     # Find OPC UA servers, list endpoints and security policies
    opcua-node-browser/         # Browse node tree, list variables and types (level C)
    opcua-security-audit/       # Check for None security, anonymous auth, exposed endpoints
  ethernet_ip/
    enip-device-discovery/      # ListIdentity sweep, vendor/product/serial inventory
    enip-cip-enum/              # Read CIP attributes (level C)
  bacnet/
    bacnet-device-discovery/    # Who-Is broadcast, collect I-Am responses
    bacnet-object-enum/         # Read object lists, present values (level C)
  siemens/
    s7comm-cpu-identify/        # S7comm SZL read — CPU type, firmware, module info
    s7comm-security-check/      # Check for password protection, access level
  fieldbus/
    can-bus-sniffer/            # ESP32: passive CAN capture, decode arbitration IDs
    can-bus-enum/               # ESP32: identify active nodes, traffic patterns
    serial-console-probe/       # ESP32: RS-232 baud detection, banner grab
    analog-loop-reader/         # ESP32: read 4-20mA, display as process value with scaling
  assessment/
    ics-asset-report/           # Compile all findings into structured pentest report
    ics-posture-scorecard/      # Rate segmentation, protocol security, exposed services
    ics-risk-heatmap/           # Visual risk ranking by device criticality and exposure
```

23 payloads across 8 subcategories. Each is a self-contained `payload.sh` following the existing header convention. ESP32-dependent payloads call `esp32_require` at the top. Network-only payloads work with just the pager.

The three `assessment/` payloads don't discover anything new — they consume artifacts from prior runs in `/root/loot/ics/` and produce deliverables.

---

## 7. Data Model

### 7.1 Engagement Workflow

```
1. Plug in ESP32 probe → run probe.selftest to verify hardware
2. discovery/ics-network-sweep     → asset inventory over Ethernet/WiFi
3. discovery/ble-sensor-scout      → wireless ICS sensors in the area
4. fieldbus/can-bus-sniffer        → passive listen on any CAN connections
5. modbus/modbus-rtu-bus-scan      → enumerate RS-485 bus
6. Protocol-specific deep dives    → per target as needed
7. assessment/ics-asset-report     → generate deliverable
```

### 7.2 Loot Directory Structure

```
/root/loot/ics/
  <engagement-name>/              # Set via TEXT_PICKER at first payload run
    inventory.json                # Unified asset inventory (all payloads append here)
    raw/
      network-sweep-<timestamp>.json
      modbus-rtu-scan-<timestamp>.json
      can-capture-<timestamp>.log
      ble-scan-<timestamp>.json
      ...
    reports/
      asset-report-<timestamp>.txt
      posture-scorecard-<timestamp>.txt
      risk-heatmap-<timestamp>.txt
```

### 7.3 `inventory.json` Schema

```json
{
  "devices": [
    {
      "id": "auto-generated-uuid",
      "ip": "192.168.1.100",
      "mac": "00:0E:8C:AA:BB:CC",
      "vendor": "Siemens",
      "protocol": "s7comm",
      "port": 102,
      "product": "S7-1200 CPU 1214C",
      "firmware": "V4.5.2",
      "bus": "ethernet",
      "risk": null,
      "notes": [],
      "discovered_by": "ics-network-sweep",
      "timestamp": "2026-03-23T14:30:00Z"
    },
    {
      "id": "...",
      "ip": null,
      "mac": null,
      "vendor": "Honeywell",
      "protocol": "modbus_rtu",
      "slave_addr": 3,
      "product": "UDC3200",
      "bus": "rs485",
      "discovered_by": "modbus-rtu-bus-scan",
      "timestamp": "..."
    }
  ]
}
```

Every payload that discovers a device calls `ics_report_device()` which appends to this file, deduplicating by IP+port or bus+slave_addr.

---

## 8. Network Protocol Implementation Details

### 8.1 Protocol-Specific Packet Crafting

**OPC UA Discovery (TCP port 4840):** Send a `FindServersRequest` — a 60-byte binary message. Can be crafted with `printf` and piped through `nc`. Response contains server application name, URI, and discovery endpoint URLs. Follow up with `GetEndpointsRequest` to enumerate security policies (None, Sign, SignAndEncrypt) and authentication modes. A server accepting `SecurityPolicy#None` is a critical finding.

**Ethernet/IP (TCP port 44818):** `ListIdentity` is a 24-byte encapsulation header with command `0x0063`. Send via `nc`, parse the response for vendor ID, device type, product name, serial number, and product code. UDP broadcast on port 44818 catches everything on the subnet at once.

**BACnet (UDP port 47808):** `Who-Is` broadcast is a simple BACnet NPDU+APDU (~12 bytes). Devices respond with `I-Am` containing their device instance, vendor ID, and segmentation support.

**Modbus TCP (TCP port 502):** Connect, send FC17 (Report Slave ID) or FC43/14 (Read Device Identification). Returns vendor name, product code, and firmware revision. 12-byte request.

**S7comm / Siemens (TCP port 102):** COTP connection request → S7 setup communication → SZL read (System Status List). Returns CPU type, firmware version, module inventory, and protection level. ~80-byte handshake sequence.

**DNP3 (TCP port 20000):** Data link layer frame with function code 0 (confirm) or integrity poll. Detection by port + response framing (0x0564 start bytes).

**FINS / Omron (UDP port 9600):** FINS header with memory area read command. Discovery via FINS node address broadcast.

### 8.2 Dependency Strategy

- **Minimal (default):** `nc` (netcat) + `printf` + `xxd` for hex encoding. Available on OpenWrt.
- **Enhanced (if available):** `python3` with `struct` module makes packet crafting cleaner. The library checks for Python and falls back to shell.
- **Optional:** `nmap` with NSE scripts (`modbus-discover`, `bacnet-info`, `s7-info`) if installed. The library wraps these when present but doesn't require them.

---

## 9. Interaction Depth Model

### Level B (Default) — Active Discovery

Standard discovery packets identical to what vendor engineering tools send. Safe for OT environments. All discovery payloads operate at this level.

### Level C (Opt-In) — Full Interaction

Read registers, browse node trees, pull configuration. Every level-C function gates behind `CONFIRMATION_DIALOG`. Payloads clearly labeled in their headers.

---

## 10. Design Decisions Summary

| Decision | Choice | Rationale |
|---|---|---|
| Hardware + software | Parallel development | Payload framework abstracts transport from day one |
| Physical buses | RS-485 + RS-232 + CAN + 4-20mA + BLE | Covers ~90% of plant floor protocols. BLE is free on ESP32. |
| Pager ↔ ESP32 protocol | USB CDC serial + JSON | Simplest, most debuggable, zero kernel modules needed |
| Interaction depth | B default, C opt-in | Safe for OT; full interaction requires explicit confirmation |
| Payload organization | `library/user/ics/` with protocol subcategories | ICS is large enough domain for its own top-level category |
| Network protocol crafting | `nc` + `printf` + `xxd`, Python fallback | Minimal dependencies on OpenWrt |

---

<!-- /autoplan restore point: /Users/mackieg/.gstack/projects/gmackie-wifipineapplepager-payloads/master-autoplan-restore-20260323-084706.md -->

<!-- AUTONOMOUS DECISION LOG -->
## Decision Audit Trail

| # | Phase | Decision | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|
| 1 | CEO | Mode: SELECTIVE EXPANSION | P1+P6 | Per autoplan override | SCOPE EXPANSION, HOLD SCOPE, REDUCTION |
| 2 | CEO | Accept premises 1-3 (platform fit, ESP32 capability, USB CDC) | P6 | Premises are technically sound | — |
| 3 | CEO | Flag OPC UA/S7comm shell crafting as fragile | P5 | Complex stateful binary protocols don't fit nc+printf well | Treating Python as optional |
| 4 | CEO | Recommend phased delivery (network first, then ESP32) | P3+P6 | Derisks hardware dependency, ships value early | Big-bang delivery |
| 5 | CEO | Add ESP32 brownout detection to firmware spec | P1 | Silent failure on power issues unacceptable | Ignoring brownout |
| 6 | CEO | Add explicit engagement directory writability check | P5 | Prevent silent payload failures | Implicit mkdir -p only |
| 7 | CEO | Add input validation to esp32.sh wrappers | P5 | Prevent sending malformed commands to probe | Trust caller |
| 8 | CEO | Add probe.log firmware debug command | P1 | Essential for field debugging | No firmware logging |
| 9 | CEO | Add schema_version to inventory.json | P1 | Forward compatibility for schema evolution | Unversioned schema |
| 10 | CEO | Galvanic isolation: mandatory not optional | P1 | Plant environments have unpredictable ground references | Optional isolation |
| 11 | CEO | Add file locking for inventory.json writes | P1 | Concurrent payload runs could corrupt shared file | No locking |
| 12 | CEO | Add loot directory permissions (700) | P3 | Security hygiene for pentest artifacts | Default permissions |
| 13 | Eng | Add firmware version negotiation in esp32_detect() | P5 | Graceful degradation when firmware/library versions mismatch | No version check |
| 14 | Eng | Require set -euo pipefail in all new payloads | P5 | Consistent error handling, matches best existing payloads | Inconsistent |
| 15 | CEO-TASTE | 23 payloads scope for v1 | P1 vs P3 | Complete coverage vs shipping faster with fewer | See taste decision |
| 16 | CEO-TASTE | Python required for OPC UA/S7comm → APPROVED by user | P1 | Reliability for complex binary protocols | Shell-only for these protocols |

---

## Autoplan Review Amendments

### Amendment 1: Brownout Detection (Decision #5)
Add to Section 4.1 Firmware Modules: `safety.cpp` includes ESP32-S3 brownout detector callback that sends `{"status":"error","error":"brownout","msg":"USB power insufficient"}` before reset.

### Amendment 2: Galvanic Isolation Mandatory (Decision #10)
Change Section 2.5 from "Optional Galvanic Isolation" to **"Required Galvanic Isolation"**. ADUM1201 between ESP32 UART1 and MAX3485. Isolated DC-DC for CAN transceiver. Non-negotiable for field safety.

### Amendment 3: inventory.json Improvements (Decisions #9, #11)
- Add `"schema_version": 1` to root of inventory.json
- `ics_report_device()` uses `flock` on inventory.json for atomic writes
- Deduplication by IP+port for network devices, bus+slave_addr for fieldbus devices

### Amendment 4: Firmware Version Negotiation (Decision #13)
`esp32_detect()` queries `probe.info`, stores firmware version. Library functions that use commands added in later firmware versions check the version and fail gracefully with a "firmware update needed" message.

### Amendment 5: Probe Debug Logging (Decision #8)
Add `probe.log` command to Section 3.2 Command Catalog: returns last 50 entries from ESP32's internal ring buffer of commands received, responses sent, and errors encountered.

### Amendment 6: Python Required for OPC UA + S7comm (Decision #16)
`ics_protocols.sh` functions `opcua_discover()`, `opcua_browse_nodes()`, `s7comm_identify()`, and `s7comm_security_check()` require `python3`. They call `ics_require_tool python3 "Required for OPC UA/S7comm protocols"` at invocation. Payloads in `opcua/` and `siemens/` document this dependency in their headers.

### Amendment 7: Consistent Shell Conventions (Decision #14)
All new ICS payloads include `set -euo pipefail` after the shebang. Input validation in `esp32.sh` wrapper functions before sending to probe. Engagement directory writability check in `ics_save_artifact()`.

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAN | 12 auto-decided, 2 taste decisions approved |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | UNAVAILABLE | — |
| Eng Review | `/plan-eng-review` | Architecture & tests | 1 | CLEAN | Version negotiation, test plan written |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | SKIPPED | No UI scope |

**VERDICT:** APPROVED — Plan reviewed by CEO + Eng. 7 amendments incorporated. Test plan artifact written to `~/.gstack/projects/`. Ready for implementation.
