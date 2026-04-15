# EdgeOps Pager Agent — Design Document

**Date:** 2026-04-15
**Status:** Draft
**Depends on:** ICS Probe v1.1 hardware bring-up, EdgeOps Python SDK

---

## 1. Product Architecture

The ICS consulting toolkit is three layers that snap together:

**Layer 1 — ICS Probe (hardware, code-complete, pending bring-up).** A USB
peripheral with an ESP32-S3, industrial transceivers (RS-485, RS-232, CAN,
W5500 Ethernet, MAX14906 24V DIO, AD5420 4-20mA output), and galvanic
isolation. It's a dumb I/O breakout board — it speaks a JSON command protocol
over USB CDC serial and does whatever the host tells it. No intelligence, no
connectivity, no UI. Design doc:
`docs/plans/2026-03-23-ics-ot-probe-design.md` (with v1.1 amendments).

**Layer 2 — Wi-Fi Pineapple Pager (compute + connectivity + UI).** Runs
OpenWrt 24.10.1 with bash and Python 3. Provides the display (222x480
DuckyScript UI), Wi-Fi uplink, persistent storage (`/root/`), and the runtime
environment. This is the brain.

**Layer 3 — EdgeOps Gateway Agent (software, runs on the pager).** A Python
service using the EdgeOps Python SDK that enrolls the pager as an edge node
in Controls Foundry. It discovers industrial devices through the probe, polls
their data on a schedule, buffers readings locally, and streams telemetry to
the cloud. Controls Foundry sees the pager as a first-class gateway in the
device fleet — same as a USR-300.

The consulting workflow: plug the probe into the pager, plug field wires into
the probe's Phoenix connectors, start the agent payload. Within 60 seconds,
live process data from the client's equipment is streaming to Controls
Foundry. The DuckyScript UI on the pager shows local status. The client
watches their own data appear on the dashboard.

### Relationship to Other Products

- **ICS Probe v1 / v1.1** — the hardware layer. USB stick form factor. Built
  in this repo (`firmware/ics-probe/`). Existing standalone ICS payloads
  (`library/user/ics/`) continue to work without the agent.
- **USR-300** — commercial off-the-shelf hardware for permanent leave-behind
  installations. Runs the TypeScript EdgeOps gateway agent. Used for
  production deployments after the consulting engagement converts.
- **Controls Foundry** — the Next.js control plane UI in the EdgeOps platform
  (`edgeOps/apps/edgeops-nextjs/`). The dashboard the client sees.
- **EdgeOps Python SDK** — `edgeOps/packages/sdk-python/`. The pager agent's
  interface to the control plane.

---

## 2. Software Architecture

The EdgeOps agent on the pager is a Python process with four components:

### 2.1 ProbeTransport

Owns the USB serial connection to the ESP32 (`/dev/ttyACM0`). Sends JSON
commands, receives JSON responses. Thread-safe via a `threading.Lock` —
multiple adapters share it without trampling each other's SPI transactions
on the probe. This is a Python port of the existing `esp32.sh` shell library,
but as a class with proper locking.

Responsibilities:
- Probe detection (scan `/dev/ttyACM*`, send `probe.info`, verify response)
- Reconnection if the probe is unplugged and re-plugged
- Firmware version negotiation (check `fw_version`, warn if mismatched)
- Command timeout handling (default 5s, configurable per-command)
- Streaming command support (background thread reads lines until `stop`)

### 2.2 Protocol Adapters

Each adapter mirrors the TypeScript `ProtocolAdapter` interface from
`edgeOps/edge/gateway-agent/src/adapters/types.ts`:

```python
class ProtocolAdapter(ABC):
    name: str
    type: str  # matches AdapterType enum

    async def initialize(self, config: AdapterConfig) -> None: ...
    async def shutdown(self) -> None: ...
    async def discover(self) -> AsyncGenerator[DiscoveredDevice]: ...
    async def poll(self, signals: list[SignalConfig]) -> list[SignalReading]: ...
    async def execute(self, command: RemoteCommand) -> CommandResult: ...
    def get_status(self) -> AdapterStatus: ...
```

Every adapter gets a reference to the shared `ProbeTransport`. Initial set:

| Adapter | Probe commands | AdapterType |
|---------|---------------|-------------|
| `ModbusRTUAdapter` | `modbus.*` | `modbus-rtu` |
| `CANAdapter` | `can.*` | `can` |
| `DIOAdapter` | `dio.*` | (new type: `digital-io`) |
| `CurrentOutputAdapter` | `iout.*` | (new type: `analog-output`) |
| `EthernetAdapter` | `net.*` → TCP/UDP | `modbus-tcp`, `ethernet-ip` |

Each adapter produces `SignalReading` objects with the same schema the
TypeScript agent uses — `signal_id`, `value`, `quality`, `timestamp`.
Controls Foundry doesn't need to know these came from a pager vs a USR-300.

### 2.3 Agent Core

The polling loop, signal buffer, and health reporter.

- Reads adapter configs from `/root/edgeops/agent-config.json`
- Runs the poll cycle per adapter at configured intervals
- Writes `SignalReading` records to a local SQLite database under
  `/root/edgeops/buffer.db`
- Flushes the buffer to Controls Foundry via the Python SDK when connected
- If Wi-Fi drops, readings accumulate locally and sync when connectivity
  returns
- Health reporter sends heartbeats to Controls Foundry (agent version,
  uptime, adapter statuses, buffer depth)

### 2.4 DuckyScript UI Bridge

A thin layer that calls DuckyScript commands (`LOG`, `ALERT`,
`START_SPINNER`) to show agent status on the pager's screen:

- Connection state (probe detected, cloud connected, Wi-Fi status)
- Device count per protocol
- Last poll timestamp
- Error alerts (probe disconnected, adapter fault, buffer full)
- Signal preview (last N readings for a selected signal)

---

## 3. Data Flow

Three data paths through the system:

### 3.1 Discovery

When the agent starts (or on-demand from the pager UI), it calls `discover()`
on each active adapter. The Modbus RTU adapter sends `modbus.scan_bus`
through the probe, the CAN adapter sends `can.scan_ids`, etc. Each
discovered device becomes a `DiscoveredDevice` record matching the EdgeOps
schema — address, manufacturer, model, protocols, capabilities.

These flow up to Controls Foundry's asset inventory via the Python SDK. The
same devices also get written to the existing `inventory.json` loot format
so the v1 ICS assessment payloads still work.

### 3.2 Polling

The agent core maintains a poll schedule per adapter. Each cycle:

1. Call `poll(signals)` on the adapter
2. Get back `SignalReading` objects
3. Write them to the local SQLite buffer
4. Flush the buffer to Controls Foundry

The buffer is the resilience layer — if the cloud is unreachable (no Wi-Fi,
client site has no internet), readings accumulate on disk. When connectivity
returns, the buffer drains in order. Max buffer size configurable (default
50MB); oldest readings evict when full.

### 3.3 Commands (Level C)

Controls Foundry can send remote commands back down — "write this Modbus
register," "set this 4-20mA output." The agent receives these via the Python
SDK's command channel, routes them to the appropriate adapter, which
translates to a probe JSON command with `"confirm": true`.

The DuckyScript UI prompts the operator on the pager screen before
executing — the human-in-the-loop safety gate from v1 is preserved. No
remote write happens without someone physically pressing "Yes" on the pager.

---

## 4. File Layout

```
library/user/ics/
  agent/                          # EdgeOps agent payload
    payload.sh                    # Entry point: DuckyScript UI menu
    edgeops_agent/                # Python package
      __init__.py
      agent_core.py               # Poll loop, buffer flush, health reporting
      probe_transport.py          # USB CDC JSON protocol (Python port of esp32.sh)
      config.py                   # Adapter configs, enrollment token, poll intervals
      ui_bridge.py                # DuckyScript command wrappers
      adapters/
        __init__.py
        base.py                   # ProtocolAdapter ABC
        modbus_rtu.py
        can.py
        dio.py
        current_output.py
        ethernet.py               # Modbus TCP, BACnet, OPC UA via probe W5500
      vendor/                     # Vendored dependencies (no pip on device)
        edgeops_sdk/              # EdgeOps Python SDK (copied from edgeOps repo)
        paho_mqtt/                # If SDK uses MQTT (pure Python, vendorable)
    enrollment/
      enroll.sh                   # One-time enrollment payload
  lib/
    esp32.sh                      # Existing — unchanged, still works for standalone payloads
    ics_protocols.sh              # Existing — unchanged
```

**`payload.sh`** is the DuckyScript entry point. Menu: Start Agent, Stop
Agent, View Status, Configure, Enroll Device. "Start Agent" launches
`python3 -m edgeops_agent` as a background process, writes the PID to
`/tmp/edgeops-agent.pid`, and returns to the menu. The agent runs headless;
`payload.sh` polls its status via a file-based IPC (`/tmp/edgeops-status.json`)
to update the pager screen.

**`enroll.sh`** is a separate one-time payload. Runs the enrollment flow
matching the existing `enrollment.ts` behavior — gets a token from the
operator (via `TEXT_PICKER`), registers with Controls Foundry, and writes
the enrollment config to `/root/edgeops/enrollment.json` (persists across
firmware updates).

Existing v1 payloads (`modbus-rtu-bus-scan`, `can-bus-sniffer`, etc.)
continue to work unchanged — they use `esp32.sh` directly and don't know
about the agent.

---

## 5. Dependencies & Constraints

### Python Dependencies

OpenWrt's Python 3 is minimal — no pip by default, limited stdlib. The agent
is careful about imports:

- **EdgeOps Python SDK** — vendored into `edgeops_agent/vendor/`
- **sqlite3** — part of Python stdlib, available on OpenWrt's python3 package
- **json, threading, socket, time, os, struct, pathlib** — all stdlib
- **paho-mqtt** — vendored if needed by the SDK (pure Python)
- **No numpy, pandas, or heavy deps.** All signal math is basic arithmetic.

### Resource Constraints

- **RAM** — likely 128-256MB. Agent must be lightweight — no in-memory caches
  beyond a few MB. SQLite buffer on flash handles the heavy lifting.
- **Flash** — `/root/` persists but is limited. Cap SQLite buffer at 50MB
  default, configurable. Rotate oldest readings on eviction.
- **CPU** — single or dual core. Poll loop must sleep between cycles. Three
  threads max: polling, cloud flush, UI IPC. No thread pools.

### Offline-First

Many client sites have no internet on the OT network. The agent works fully
disconnected — discover, poll, buffer, show data on pager screen. Cloud sync
is opportunistic, not required. The pager's Wi-Fi can be configured to
connect to a phone hotspot for the live demo moment, then disconnect.

### Enrollment

Matches the existing `enrollment.ts` flow in the TypeScript gateway agent.
The pager enrolls as a standard EdgeOps edge node — Controls Foundry manages
it the same way as a USR-300. Enrollment token stored in
`/root/edgeops/enrollment.json`.

---

## 6. Engagement Workflow

The consulting sales motion this design optimizes for:

**Before arrival.** Run `enroll.sh` on the pager to pair it with your
Controls Foundry tenant. Create a new engagement in Controls Foundry.

**On site — first 5 minutes.**
1. Plug ICS probe into pager USB port
2. Connect field wires to probe's Phoenix connectors
3. Start the agent payload on the pager
4. Agent auto-discovers devices on every connected bus
5. Pager screen shows: "Found 12 devices across 3 protocols"

**On site — the demo moment (5-15 minutes).**
1. Connect pager Wi-Fi to phone hotspot or client guest Wi-Fi
2. Agent syncs discovered devices + buffered readings to Controls Foundry
3. Open Controls Foundry on laptop/tablet
4. Client watches their own process values streaming live
5. Point at a trend chart: "This is your chiller loop right now."

**The pitch.** "We can leave a permanent gateway that does this 24/7 and
feeds into your operations platform. This demo was your data, on our
platform, in 15 minutes."

**After the visit.** Pull the probe, take the pager home. The SQLite buffer
has a full recording. Export via `ics-asset-report` payload. Controls Foundry
retains the cloud copy.

---

## 7. What This Design Does NOT Cover

Explicitly out of scope — to be addressed in follow-up designs:

- **Controls Foundry UI changes** for ICS-specific views (trend charts,
  asset maps, risk scores). The existing dashboard works; ICS-optimized
  views are a Controls Foundry feature, not a pager concern.
- **v2 probe hardware** (ESP32-P4, AD74413R, IO-Link, HART, sub-GHz,
  thermocouple). See `docs/plans/2026-04-15-industrial-gateway-v2-notes.md`.
  The adapter architecture accommodates new protocols by adding adapter
  classes — no agent core changes needed.
- **USR-300 configuration workflow.** The USR-300 runs the TypeScript agent
  independently. This design only covers the pager.
- **Multi-probe support.** One probe per pager for v1. Multiple USB devices
  would need `ProbeTransport` refactoring.
- **Firmware OTA for the probe.** Updating ESP32 firmware from the pager
  is desirable but not in this scope.

---

## 8. Implementation Prerequisites

Before implementation can start:

1. **ICS Probe v1.1 hardware bring-up** — the agent needs a working probe
   to talk to. Blocked on parts arrival.
2. **EdgeOps Python SDK review** — need to understand the SDK's API surface,
   authentication flow, and telemetry ingestion endpoints. Read
   `edgeOps/packages/sdk-python/`.
3. **Enrollment flow audit** — read `edgeOps/edge/gateway-agent/src/enrollment.ts`
   and confirm the Python SDK exposes the same flow.
4. **Controls Foundry signal ingestion** — confirm how `SignalReading` records
   are received by the control plane API. Read
   `edgeOps/services/control-plane-api/`.

Once those four are understood, implementation can proceed using the
`superpowers:writing-plans` skill to produce a task-level plan.
