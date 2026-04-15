# Industrial Gateway v2 — Design Notes

**Date:** 2026-04-15
**Status:** Parked (not active work)
**Relationship to v1:** v1 is `2026-03-23-ics-ot-probe-design.md` (USB-tethered
ICS probe). v2 is a separate, larger product in the same product line — do
not start v2 until v1 ships and real field feedback is in hand.

---

## Purpose

Capture the expanded scope that surfaced during a 2026-04-15 brainstorming
session, so the ideas don't get lost while v1 ships. This file is a **notes
document, not a design** — it's not reviewed, not approved, and the decisions
below are tentative leans, not commitments.

## Product Framing

v2 is a **standalone industrial consulting gateway** pitched at proof-of-concept
engagements in plant, building automation, and OT environments. Two operating
modes on the same hardware:

1. **Tethered diagnostic mode** — USB-attached to the pager or a laptop,
   functions like v1's probe but with wider protocol coverage. Hands-on
   troubleshooting.
2. **Standalone gateway mode** — powered locally, auto-discovers devices on
   whatever buses are wired in, translates protocols, buffers data, and
   uploads to a cloud dashboard. Left on-site for days or weeks to collect
   baselines and demonstrate value to prospective clients.

The consulting use case is the forcing function: an engineer walks onto a
site cold, plugs in, and within an hour is showing the client a live
dashboard of their own equipment. That sales motion is the target experience.

## Architectural Direction

### MCU

Leaning **ESP32-P4 + ESP32-C6 co-processor** rather than scaling v1's S3:

- **ESP32-P4** — dual-core RISC-V, native RMII Ethernet MAC (no W5500 needed),
  more RAM, MIPI-DSI for a local display, crypto acceleration. Handles
  protocol stacks, cloud connectivity, and local UI.
- **ESP32-C6** — Wi-Fi 6, BLE 5, Thread, Zigbee, Matter. Wireless co-processor
  talking to the P4 over SDIO or UART. Matter support is a real selling
  point for modern IoT pitches.

Alternative to evaluate: a single-chip solution like an i.MX RT1170 or STM32H7
with external wireless. More powerful but adds Linux/RTOS complexity and
departs from the Espressif ecosystem v1 is built on.

### Power

- **USB-C PD in** (5–20V negotiation) for bench/portable use
- **12–24V industrial input** via Phoenix terminal for panel mounting
- **PoE+ in** via integrated PD controller (Ag9905M, Si3402-B) — power and
  network on one drop, the dream for "plug and leave" deployments
- **Isolated DC-DC** per bus domain (unchanged principle from v1, expanded)

### Enclosure

- **DIN rail mountable** for panel installations
- IP54 or IP65 for field use (open question — drives connector choice)
- Status display: small OLED or color LCD driven by P4's MIPI-DSI
- LED status per bus: activity, fault, link

---

## Protocol Coverage Wishlist

Inherits everything from v1, plus:

### New physical-layer hardware

| Capability | Part | Rationale |
|---|---|---|
| **Industrial Ethernet** | Native P4 RMII + PHY (LAN8720A) | Modbus TCP, BACnet/IP, OPC UA, PROFINET, EtherNet/IP, EtherCAT (sniff only with SOEM GPL concerns), MQTT |
| **IO-Link master** | **MAX14819A** (2-ch) | Modern factory smart sensor bus; exploding in new installations |
| **HART modem** | **AD5700** or AD74413R | Overlay on 4-20mA loops; universal-commands-only OSS stack (see v1 HART notes) |
| **Thermocouple input** | **MAX31856** (K/J/T/N/R/S/E/B) | Process monitoring, no POC is complete without it |
| **RTD input** | **MAX31865** (Pt100/Pt1000) | Same rationale; AD74413R can cover this too |
| **Software-configurable analog I/O** | **AD74413R** | 4-ch runtime-reconfigurable as voltage in, current in/out, digital in, RTD — the magic demo chip (±15V rails required) |
| **Sub-GHz radio** | **SX1262** | LoRa + FSK 150–960 MHz; wireless M-Bus, LoRaWAN, 433/868/915 general |
| **Cellular uplink** | **Quectel BG95** or SIMCom A7672 (LTE-M/NB-IoT) | Gateway mode without site Wi-Fi/Ethernet |
| **M-Bus (wired)** | **TSS721A** slave interface | European utility meters |
| **Industrial Vibration** | **LSM6DSV** or IEPE frontend | "Is this motor healthy" instant demo |
| **Wide-range DI** | **MAX22190** | 8-ch IEC 61131-2 digital inputs (scaling from v1's MAX14906) |
| **SD card slot** | microSD socket | Local buffering for offline logging |
| **RTC with battery** | **DS3231** | Timestamped logs when offline |

### New protocol stacks (firmware)

| Protocol | Stack | License gotcha |
|---|---|---|
| Modbus RTU/TCP | libmodbus, nanomodbus | BSD — clean |
| **BACnet MS/TP + BACnet/IP** | BACnet Stack by Steve Karg (MIT-style) | Open OK for POC; commercial required for BTL certification |
| **BACnet/SC** (Secure Connect) | Same + TLS/WebSocket layer | Firmware-only work |
| OPC UA | open62541 | MPL 2.0 — clean |
| MQTT / Sparkplug B | Mosquitto + Eclipse Tahu | EPL — clean |
| EtherNet/IP (CIP) | OpENer | BSD, but ODVA membership for commercial shipping |
| PROFINET | P-Net (open), Molex/HMS (paid) | PI certification expensive |
| EtherCAT (master) | **SOEM** | **GPLv2 viral** — commercial landmine, evaluate carefully |
| LoRaWAN | LMIC, TTN stack | BSD |
| CANopen | CANopenNode | Apache 2.0 |
| J1939 | Open-J1939 | MIT |
| HART | **Roll-your-own universal commands** | Commands 0–30 only; read-only POC scope |
| DNP3 | OpenDNP3 | Apache 2.0 |
| IEC 61850 | libiec61850 | GPLv3 / commercial dual |

**Two licensing landmines to watch**: EtherCAT (SOEM is GPL) and HART (full
spec is paywalled). For v2's initial POC release, treat both as read-only
observational and sidestep the commercial issues.

### Phase 2: Passive Discovery & Fingerprinting

Once read-only protocol support is working, the next capability layer is
**industrial-grade asset discovery**:

- Passive listening on every bus simultaneously
- Protocol fingerprinting by frame signature, timing, and response patterns
- Automatic cataloging into the unified `inventory.json` schema (reusing
  v1's data model, extended for gateway mode)
- "Industrial nmap" — point it at a site and get a complete asset inventory
- Cross-bus correlation: a device seen on Modbus TCP is the same device seen
  on RS485 (by vendor signature, serial number, or cross-referenced tags)

This is the feature that sells the consulting engagement.

---

## Consulting Workflow (Target Experience)

1. Arrive on site, plug gateway into any available: Ethernet drop, RS485
   bus, 24V power, cellular, or USB-C PD from a laptop
2. Gateway auto-detects what buses are wired and what protocols are present
3. On-device display shows live asset discovery count climbing as devices
   are cataloged
4. Engineer opens cloud dashboard on laptop/phone — live data streaming
   within ~60 seconds of power-up
5. Leave on site for hours/days for baseline collection
6. Consulting pitch uses the real collected data as the pitch deck

## Connectors

Still undecided:
- **Phoenix MC 1.5mm screw terminals** — cheap, field-rewirable, dev-friendly
- **M12 circular connectors** — A-coded (CAN/sensors), B-coded (RS485/Profibus),
  D-coded (Ethernet). Rugged, IP-rated, ~$8 each
- Likely answer: **Phoenix for v2.0 dev kit SKU, M12 for v2.1 "rugged" SKU**

## Certifications (open questions)

- **CE** marking — required for EU sales
- **FCC Part 15** — required for any wireless device sold in US
- **UL 61010** — required for industrial control equipment in North America
- **ATEX / IECEx Zone 2** — required for petrochem/hazardous environments.
  Major re-engineering; treat as "hazloc SKU" v2.2+ at earliest
- **BTL** (BACnet Testing Laboratories) — optional; needed if clients demand
  certified BACnet rather than "BACnet-compatible"

## Known Unknowns

- **Form factor budget**: DIN rail handheld? Bench unit? Pocket? Not locked.
- **Display**: required for standalone mode UX, or phone-only?
- **Firmware architecture**: bare-metal ESP-IDF or embedded Linux (Buildroot
  on an i.MX RT)? v1 is ESP-IDF; v2 might justify the Linux jump.
- **BOM budget per unit**: drives single-chip (AD74413R) vs discrete splits
- **Production quantity**: drives PCB/assembly cost modeling
- **Who writes firmware**: single dev or team? Drives RTOS and test strategy
- **Cloud dashboard stack**: this is half the product and not scoped at all.
  Existing gmac.io infrastructure? New service? Customer-hosted?
- **Engagement-to-product handoff**: after a POC, do clients buy the hardware
  or a SaaS subscription to the dashboard? Business model affects design.

---

## Ideas Explicitly Deferred from v1 (2026-03-23 design)

These items were discussed and explicitly deferred to v2:

- **ESP32-P4 + C6** MCU upgrade (v1 keeps S3)
- **Native Ethernet MAC** via P4 RMII (v1 uses W5500)
- **AD74413R** software-configurable analog I/O with ±15V rails (v1 uses
  AD5420 for write + existing INA219 for read)
- **Gateway / standalone mode** with cloud uplink (v1 is USB-tethered only)
- **Cellular uplink** (not in v1)
- **IO-Link master (MAX14819A)** (not in v1)
- **HART modem** (not in v1)
- **Thermocouple / RTD** inputs (not in v1)
- **Sub-GHz radio (SX1262)** (not in v1)
- **PoE input** (not in v1)
- **BACnet protocol stack** integration (v1 has BACnet discovery over network
  only via `ics_protocols.sh`, not a full stack on probe firmware)
- **M-Bus** (not in v1)
- **Vibration / IEPE** analog frontend (not in v1)
- **Local display** (not in v1)
- **DIN rail / IP-rated enclosure** (v1 is a USB-stick form factor)
- **SD card buffering** (not in v1)
- **RTC** (not in v1)

## Next Steps

**Do not start v2 work until v1 ships.** When v1 is in the field and real
engagements have surfaced real requirements, revisit this file and decide:

1. Is the v2 scope still right, or has field experience changed priorities?
2. Is the ESP32-P4 + C6 architecture still the right call?
3. What protocols did we never actually need? What did we urgently need
   that isn't on this list?
4. Run a full brainstorming + CEO + Eng review cycle before opening an
   implementation plan.

v1 is the learning vehicle. v2 should be informed by what v1 taught us.
