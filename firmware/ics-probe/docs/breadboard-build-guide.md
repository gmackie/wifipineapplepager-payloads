# ICS Probe — Breadboard Build Guide

Step-by-step instructions for building the ICS Probe on a breadboard
with the ESP32-S3 DevKitC-1. Each phase adds one peripheral, tests it,
then moves on. **Do not skip ahead** — build and verify one at a time.

Pin assignments match `include/config.h`. See `docs/wiring-diagram.md`
for schematics and BOM.

---

## Prerequisites

- ESP32-S3 DevKitC-1 with working firmware (probe.info responds)
- Full-size breadboard (830 tie points)
- 22 AWG solid-core hookup wire
- Multimeter (continuity + voltage)
- Components from the BOM

### Parts Ordering Note

For breadboard prototyping, prefer **DIP/through-hole packages** where possible:
- MAX3232ECPE+ (DIP-16) — breadboard-friendly
- MCP2515-I/P (DIP-18) — breadboard-friendly
- MAX3485ESA+ (SOIC-8) — needs SOIC-to-DIP adapter board (~$1)
- SN65HVD230DR (SOIC-8) — needs SOIC-to-DIP adapter board
- INA219BIDR (SOIC-8) — needs SOIC-to-DIP adapter board, OR use INA219 breakout board (~$3, Adafruit #904)
- ADUM1201ARZ (SOIC-8) — needs SOIC-to-DIP adapter board

**Easier alternative:** Buy breakout boards for the SOIC-8 parts:
- Adafruit INA219 breakout (#904) — includes sense resistor and pullups
- SparkFun CAN Bus breakout (BOB-13262) — MCP2515 + transceiver on one board
- Generic MAX3485 module (Amazon/AliExpress) — RS-485 with screw terminals
- Generic MAX3232 module — RS-232 with DB9

---

## Breadboard Layout

```
+----------------------------------------------------------------------+
|  ESP32-S3 DevKitC-1 (plugged across center channel)                  |
|  [=============================USB================================]  |
|                                                                      |
|  Left side of board:              Right side of board:               |
|  ┌─────────────────┐              ┌─────────────────┐               |
|  │   MAX3232        │              │   MCP2515       │               |
|  │   (RS-232)       │              │   (CAN ctrl)    │               |
|  │   GPIO 15,16     │              │   SPI: 34-37    │               |
|  └─────────────────┘              └────────┬────────┘               |
|                                            │                         |
|  ┌─────────────────┐              ┌────────▼────────┐               |
|  │   MAX3485        │              │   SN65HVD230    │               |
|  │   (RS-485)       │              │   (CAN xcvr)    │               |
|  │   GPIO 17,18,8   │              │                 │               |
|  └─────────────────┘              └─────────────────┘               |
|                                                                      |
|  ┌─────────────────┐                                                 |
|  │   INA219         │              Screw terminals at board edge:    |
|  │   (4-20mA)       │              [RS-485 A/B] [CAN H/L] [4-20mA] |
|  │   I2C: GPIO 1,2  │              [RS-232 DB9]                     |
|  └─────────────────┘                                                 |
+----------------------------------------------------------------------+
```

---

## Phase 0: Verify Base Firmware (Already Done)

**Test command:**
```bash
python3 -c "
import serial, json, time
port = serial.Serial('/dev/cu.usbmodem101', 115200, timeout=2)
time.sleep(3); port.reset_input_buffer(); time.sleep(0.5)
port.write(b'{\"cmd\":\"probe.info\",\"params\":{}}\n')
port.flush(); time.sleep(1)
for _ in range(20):
    if port.in_waiting:
        data = port.read(port.in_waiting).decode(errors='replace')
        for line in data.split('\n'):
            if line.strip().startswith('{'):
                print(json.dumps(json.loads(line.strip()), indent=2))
                break
    time.sleep(0.1)
port.close()
"
```

**Expected:**
```json
{"status":"ok","fw_version":"1.0.0","capabilities":["modbus","serial","can","adc","ble","log"]}
```

---

## Phase 1: RS-232 (MAX3232)

### Why first
Simplest wiring (4 caps + 4 signal wires). No direction control. Full duplex.
Useful for connecting to HMI debug ports, old RTU serial consoles.

### Parts needed
- MAX3232ECPE+ (DIP-16) or MAX3232 module
- 4x 100nF (0.1µF) ceramic capacitors (charge pump)
- DB9 female connector or just flying leads

### Wiring

```
ESP32-S3                MAX3232 (DIP-16)           DB9 Female
─────────               ────────────────           ──────────
                        Pin 1 (C1+) ──┐
                        Pin 3 (C1-) ──┤── 100nF cap
                        Pin 4 (C2+) ──┐
                        Pin 5 (C2-) ──┤── 100nF cap
                        Pin 2 (V+)  ──┐── 100nF cap to GND
                        Pin 6 (V-)  ──┤── 100nF cap to GND
                        Pin 16 (VCC) ── 3.3V
                        Pin 15 (GND) ── GND

GPIO 15 (TX) ────────── Pin 11 (T1IN)
GPIO 16 (RX) ────────── Pin 12 (R1OUT)
                        Pin 14 (T1OUT) ────── DB9 Pin 3 (TXD)
                        Pin 13 (R1IN)  ────── DB9 Pin 2 (RXD)
                                               DB9 Pin 5 (GND) ── GND
```

### DB9 Pinout (DCE — for connecting to DTE devices like PLCs)
```
DB9 Female (solder side):
  1: DCD (not connected)
  2: RXD ← MAX3232 R1IN (Pin 13)
  3: TXD → MAX3232 T1OUT (Pin 14)
  4: DTR (not connected)
  5: GND
  6: DSR (not connected)
  7: RTS (not connected)
  8: CTS (not connected)
  9: RI (not connected)
```

### Verification steps

1. **Power check:** Multimeter on MAX3232 VCC pin — should read 3.3V
2. **Charge pump check:** Measure V+ pin (pin 2) — should be ~5.5V. Measure V- (pin 6) — should be ~-5.5V. If both read 0V, caps are wrong.
3. **Loopback test:** Connect T1OUT (pin 14) to R1IN (pin 13) with a wire. This loops RS-232 TX back to RX.

### Firmware change

In `main.c`, uncomment:
```c
serial_init();   // MAX3232 wired on GPIO 15/16
```

### Build-flash-test

```bash
cd firmware/ics-probe
source ~/esp/esp-idf/export.sh
idf.py build && idf.py -p /dev/cu.usbmodem101 flash
```

### Test command (with loopback wire)

```json
{"cmd":"serial.send","params":{"data":"48656c6c6f","baud":9600,"timeout_ms":2000}}
```

`48656c6c6f` = "Hello" in hex. With loopback wired, you should get the same hex back in the response.

### Test command (auto-baud detection)

```json
{"cmd":"serial.auto_baud","params":{}}
```

With a device connected, this tries common baud rates and reports which one gets a response.

---

## Phase 2: RS-485 / Modbus RTU (MAX3485)

### Why second
One more wire than RS-232 (the DE/RE direction control). This is the most
important bus for ICS — nearly every PLC speaks Modbus RTU.

### Parts needed
- MAX3485 module (with screw terminals) OR MAX3485ESA+ on SOIC adapter
- 120Ω termination resistor (optional — only needed at end of bus)
- 2-position screw terminal
- For isolated version: ADUM1201 + B0505S DC-DC (can add later)

### Wiring (non-isolated, simplest)

```
ESP32-S3                MAX3485                   RS-485 Bus
─────────               ───────                   ─────────
GPIO 17 (TX) ────────── DI (Data In)
GPIO 18 (RX) ────────── RO (Read Out)
GPIO 8  (DE) ──┬─────── DE (Driver Enable)
               └─────── RE̅ (Receiver Enable, active low)
3.3V ────────────────── VCC
GND ─────────────────── GND
                        A ─────────────────────── A (Bus+)
                        B ─────────────────────── B (Bus-)
                                                  [120Ω between A and B
                                                   at last device on bus]
```

**Note:** DE and RE̅ are tied together. When GPIO 8 is HIGH, the MAX3485
transmits. When LOW, it receives. The firmware handles this automatically
with proper timing.

### Verification steps

1. **Power check:** 3.3V on VCC, GND on GND
2. **Direction default:** GPIO 8 should be LOW at idle (RX mode). Measure with multimeter.
3. **Bus voltage:** With no devices, A and B float. With a device, idle state: A > B by ~200mV.

### Firmware change

In `main.c`, uncomment:
```c
modbus_init();   // MAX3485 wired on GPIO 17/18/8
```

### Test commands

**Scan for Modbus devices on the bus:**
```json
{"cmd":"modbus.scan_bus","params":{"range":[1,10]}}
```

**Read device ID from slave address 1:**
```json
{"cmd":"modbus.device_id","params":{"addr":1}}
```

**Read 10 holding registers starting at 40001:**
```json
{"cmd":"modbus.read_holding","params":{"addr":1,"reg":40001,"count":10}}
```

### Testing without a real PLC

Use a USB-to-RS485 adapter on your laptop + `pymodbus` to simulate:
```bash
pip install pymodbus
# Run a Modbus slave simulator:
pymodbus.simulator --modbus-server serial --serial-port /dev/cu.usbserial-XXX --serial-baudrate 9600
```

---

## Phase 3: CAN Bus (MCP2515 + SN65HVD230)

### Why third
More wiring (SPI + interrupt), but CAN is common in robotics cells,
automotive-adjacent ICS, and some Beckhoff/WAGO systems.

### Parts needed
- MCP2515-I/P (DIP-18) or CAN breakout module
- SN65HVD230 (SOIC adapter) or included on breakout
- 8 MHz crystal (HC49 through-hole)
- 2x 22pF ceramic capacitors (crystal load caps)
- 120Ω termination resistor
- 2-position screw terminal

### Wiring

```
ESP32-S3                MCP2515 (DIP-18)           SN65HVD230
─────────               ────────────────           ──────────
GPIO 35 (MOSI) ──────── Pin 14 (SI)
GPIO 37 (MISO) ──────── Pin 15 (SO)
GPIO 36 (CLK)  ──────── Pin 13 (SCK)
GPIO 34 (CS)   ──────── Pin 16 (CS̅)
GPIO 33 (INT)  ──────── Pin 12 (IN̅T)
3.3V ────────────────── Pin 18 (VDD)               Pin 3 (VCC) ── 3.3V
GND ─────────────────── Pin 9 (VSS)                Pin 2 (GND) ── GND
                        Pin 7 (OSC1) ──┐
                        Pin 8 (OSC2) ──┤── 8MHz crystal
                                       ├── 22pF to GND (each side)
                        Pin 1 (TXCAN) ────────── Pin 1 (TXD)
                        Pin 2 (RXCAN) ────────── Pin 4 (RXD)
                                                 Pin 6 (CANH) ── Bus H
                                                 Pin 7 (CANL) ── Bus L
                                                 [120Ω H to L at end]
```

### Critical: Crystal

The MCP2515 **requires** an external crystal. Without it, the chip won't
respond to SPI. The 8 MHz crystal goes between OSC1/OSC2 with 22pF caps
to ground on each side. This is the #1 gotcha with MCP2515 breadboarding.

### Verification steps

1. **Crystal check:** Oscilloscope on OSC1 — should see 8 MHz. If no scope, just verify crystal is soldered/connected.
2. **SPI check:** Firmware will log MCP2515 register read results during init.
3. **Bus check:** With CAN listen running, CANH-CANL should show differential signaling if there's traffic.

### Firmware change

In `main.c`, uncomment:
```c
can_init();      // MCP2515 on SPI (GPIO 34-37), INT on GPIO 33
```

### Test commands

**Passive listen (5 seconds):**
```json
{"cmd":"can.listen","params":{"baud":500000,"duration_s":5}}
```

**Enumerate active CAN IDs:**
```json
{"cmd":"can.scan_ids","params":{"baud":500000,"duration_s":10}}
```

### Testing without real CAN devices

Use a second MCP2515 module on a USB-CAN adapter, or:
```bash
# Linux with socketcan:
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
cangen vcan0  # generates random CAN traffic
```

---

## Phase 4: 4-20mA ADC (INA219)

### Why fourth
Only 2 wires (I2C) but needs careful current loop setup.
Proves you can read live process values — very impressive in pentest reports.

### Parts needed
- INA219 breakout board (Adafruit #904, MUCH easier than bare SOIC)
  OR INA219BIDR on SOIC adapter + 250Ω sense resistor
- 2x 4.7kΩ pull-up resistors (for I2C — included on Adafruit breakout)

### Wiring (with Adafruit INA219 breakout)

```
ESP32-S3                INA219 Breakout            4-20mA Loop
─────────               ───────────────            ──────────
GPIO 1 (SDA) ────────── SDA
GPIO 2 (SCL) ────────── SCL
3.3V ────────────────── VCC
GND ─────────────────── GND
                        VIN+ ──────────────────── Loop + (from transmitter)
                        VIN- ──────────────────── Loop - (to power supply)
```

The Adafruit breakout includes a 0.1Ω sense resistor (for high-current
measurement). For 4-20mA, you may want to add an external 250Ω resistor
in series to get a 1-5V voltage drop that's easier to measure. The
firmware's calibration assumes 250Ω — adjust in `config.h` if using the
breakout's built-in 0.1Ω.

### Wiring (bare INA219 + 250Ω sense resistor)

```
ESP32-S3                INA219 (SOIC)              4-20mA Loop
─────────               ─────────────              ──────────
GPIO 1 (SDA) ──[4.7kΩ to 3.3V]── Pin 6 (SDA)
GPIO 2 (SCL) ──[4.7kΩ to 3.3V]── Pin 5 (SCL)
3.3V ────────────────── Pin 3 (VS)
GND ─────────────────── Pin 2 (GND)
                        Pin 8 (VIN+) ──┐
                                       ├── 250Ω sense resistor
                        Pin 7 (VIN-) ──┘
                        VIN+ ──── Loop + input
                        VIN- ──── Loop - output
                        Pin 1 (A0) ── GND  (address 0x40)
                        Pin 4 (A1) ── GND  (address 0x40)
```

### Verification steps

1. **I2C scan:** Use `i2cdetect` or the firmware's init log to confirm device at 0x40
2. **No-load test:** With nothing connected to VIN+/VIN-, reading should be ~0 mA
3. **Resistor test:** Put a 1kΩ resistor across VIN+/VIN- and apply 5V — should read ~5mA

### Firmware change

In `main.c`, uncomment:
```c
adc_init();      // INA219 on I2C (GPIO 1/2)
```

### Test commands

**Single reading:**
```json
{"cmd":"adc.read","params":{}}
```

**Stream readings every 500ms for 10 seconds:**
```json
{"cmd":"adc.stream","params":{"interval_ms":500,"duration_s":10}}
```

### Testing without a real 4-20mA transmitter

Use a bench power supply:
- Connect 24V supply through a 1kΩ resistor → INA219 VIN+ → VIN- → back to supply
- This gives ~24mA (over-range but proves the reading works)
- Or use a smaller voltage/bigger resistor to hit the 4-20mA range

---

## Phase 5: Adding Galvanic Isolation (ADUM1201 + B0505S)

### When to add
After Phase 2 (RS-485) is verified working. Isolation prevents ground
loops when connecting to field equipment in industrial plants.

### Parts needed
- ADUM1201ARZ on SOIC adapter
- B0505S-1WR2 isolated DC-DC converter (SIP-4)
- 100nF decoupling caps (2x)

### Wiring

```
ESP32 Side (3.3V)         ADUM1201              Field Side (isolated 5V)
─────────────────         ────────              ────────────────────────
3.3V ── VDD1 (Pin 1)                VDD2 (Pin 8) ── B0505S VOUT+
GND ─── GND1 (Pin 4)                GND2 (Pin 5) ── B0505S VOUT-

GPIO 17 ── VIA (Pin 2)   ────►     VOA (Pin 7) ── MAX3485 DI
GPIO 18 ── VIB (Pin 3)   ◄────     VOB (Pin 6) ── MAX3485 RO

                          B0505S (SIP-4)
                          ────────────────
3.3V ── VIN+ (Pin 1)     VOUT+ (Pin 3) ── Isolated 5V → MAX3485 VCC
GND ─── VIN- (Pin 2)     VOUT- (Pin 4) ── Isolated GND → MAX3485 GND
```

**Key:** The MAX3485 now runs on the isolated power domain. The ADUM1201
passes the UART signals across the isolation barrier. GPIO 8 (DE/RE)
needs a second isolator channel or can be driven from the isolated side
with a pull-up/pull-down scheme.

---

## Quick Reference: Which init to uncomment

| Phase | Peripheral | `main.c` line to uncomment | Test command |
|-------|-----------|---------------------------|-------------|
| 0 | Base (BLE) | `ble_init()` (already enabled) | `probe.info` |
| 1 | RS-232 | `serial_init()` | `serial.send` with loopback |
| 2 | RS-485 | `modbus_init()` | `modbus.scan_bus` |
| 3 | CAN | `can_init()` | `can.listen` |
| 4 | 4-20mA | `adc_init()` | `adc.read` |
| 5 | Isolation | (no code change — hardware only) | Same as Phase 2 |

## Build-Flash-Test Cycle

After each hardware change:

```bash
# 1. Edit main.c to uncomment the relevant init
# 2. Build
cd firmware/ics-probe
idf.py build

# 3. Flash
idf.py -p /dev/cu.usbmodem101 flash

# 4. Test with Python
python3 -c "
import serial, json, time
port = serial.Serial('/dev/cu.usbmodem101', 115200, timeout=2)
time.sleep(4); port.reset_input_buffer(); time.sleep(0.5)
cmd = input('Command JSON: ')
port.write((cmd + '\n').encode())
port.flush()
all_data = b''
start = time.time()
while time.time() - start < 10:
    if port.in_waiting:
        all_data += port.read(port.in_waiting)
    time.sleep(0.05)
for line in all_data.decode(errors='replace').split('\n'):
    if line.strip().startswith('{'):
        try: print(json.dumps(json.loads(line.strip()), indent=2))
        except: pass
port.close()
"
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Guru Meditation after uncommenting `*_init()` | Hardware not connected, ESP crashes in interrupt allocator | Verify wiring, check VCC/GND |
| Init succeeds but no response to commands | Wrong baud rate, TX/RX swapped | Swap TX/RX wires, check baud in params |
| Modbus scan returns empty | Wrong slave address range, bus not terminated | Try wider range, add 120Ω termination |
| CAN listen shows nothing | Wrong baud rate, crystal not oscillating | Try 250k/125k, verify 8MHz crystal |
| INA219 reads 0 always | I2C address wrong, sense resistor missing | Check address jumpers, verify 250Ω |
| RS-232 loopback fails | Charge pump caps wrong/missing | Verify all 4 caps, check V+/V- voltages |
