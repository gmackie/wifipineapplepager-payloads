# ESP32-S3 ICS Probe - Wiring Diagram

**Hardware Revision:** 1.0 (Breadboard Prototype)
**MCU:** ESP32-S3-DevKitC-1 (N8R2 or N16R8 variant)
**Date:** 2026-03-23

---

## 1. Bill of Materials (BOM)

| # | Component | IC / Part Number | Package | Qty | Est. Cost | Supplier / Part Number |
|---|-----------|-----------------|---------|-----|-----------|----------------------|
| 1 | ESP32-S3 DevKitC-1 | ESP32-S3-WROOM-1-N8R2 | Dev Board | 1 | $10.00 | Digikey: 1965-ESP32-S3-DEVKITC-1-N8R2-ND |
| 2 | RS-485 Transceiver | MAX3485ESA+ | SOIC-8 | 1 | $3.50 | Digikey: MAX3485ESA+-ND / Mouser: 700-MAX3485ESA |
| 3 | RS-232 Transceiver | MAX3232ECPE+ | DIP-16 | 1 | $4.20 | Digikey: MAX3232ECPE+-ND / Mouser: 700-MAX3232ECPE |
| 4 | CAN Controller | MCP2515-I/P | DIP-18 | 1 | $2.50 | Digikey: MCP2515-I/P-ND / Mouser: 579-MCP2515-I-P |
| 5 | CAN Transceiver | SN65HVD230DR | SOIC-8 | 1 | $2.80 | Digikey: 296-23205-1-ND / Mouser: 595-SN65HVD230DR |
| 6 | Current Sensor ADC | INA219BIDR | SOIC-8 | 1 | $3.00 | Digikey: 296-46427-1-ND / Mouser: 595-INA219BIDR |
| 7 | Digital Isolator | ADUM1201ARZ | SOIC-8 | 1 | $4.50 | Digikey: ADUM1201ARZ-ND / Mouser: 584-ADUM1201ARZ |
| 8 | Isolated DC-DC | B0505S-1WR2 | SIP-4 | 1 | $3.80 | Digikey: 945-1649-5-ND / Mouser: 418-B0505S-1WR2 |
| 9 | 3.3V LDO Regulator | AMS1117-3.3 | SOT-223 | 1 | $0.50 | Digikey: 2351-AMS1117-3.3CT-ND |
| 10 | 8 MHz Crystal | HC49US 8.000MHz | HC49/US | 1 | $0.60 | Digikey: 535-9032-1-ND |
| 11 | Crystal Load Caps | 22pF ceramic | 0805 | 2 | $0.10 | Digikey: 399-C0805C220J5GACTU-ND |
| 12 | RS-232 Charge Pump Caps | 100nF / 0.1uF ceramic | 0805 | 4 | $0.20 | Digikey: 399-C0805C104K5RACTU-ND |
| 13 | Decoupling Caps | 100nF / 0.1uF ceramic | 0805 | 6 | $0.30 | (same as above) |
| 14 | Bulk Decoupling Caps | 10uF electrolytic | Radial | 3 | $0.30 | Digikey: 399-6597-ND |
| 15 | Bus Termination Resistor | 120 ohm 1/4W | Axial | 2 | $0.10 | Digikey: CF14JT120RCT-ND |
| 16 | 4-20mA Sense Resistor | 250 ohm 0.1% 1/4W | Axial | 1 | $1.50 | Digikey: RN55D2500FCT-ND |
| 17 | I2C Pull-up Resistors | 4.7k ohm 1/4W | Axial | 2 | $0.10 | Digikey: CF14JT4K70CT-ND |
| 18 | Screw Terminal 2-pos | 5.08mm pitch | Through-hole | 3 | $1.50 | Digikey: ED10561-ND |
| 19 | DB9 Female Connector | DE-9S | Through-hole | 1 | $1.80 | Digikey: AE10968-ND |
| 20 | Status LED (RGB) | WS2812B or on-board | — | 0 | $0.00 | Built into DevKitC-1 (GPIO 48) |
| 21 | Breadboard | Full-size 830 tie points | — | 1 | $5.00 | — |
| 22 | Hookup Wire Kit | 22 AWG solid core | — | 1 | $8.00 | — |
| — | **TOTAL** | | | | **~$54.00** | |

---

## 2. ESP32-S3 DevKitC-1 Pin Map

```
+---------------------------------------------------------------+
| ESP32-S3 DevKitC-1 Pin Assignments                            |
+----------+--------+-------------------------------------------+
| GPIO     | Dir    | Function                                  |
+----------+--------+-------------------------------------------+
|                    UART1 / RS-485 (Modbus RTU)                |
+----------+--------+-------------------------------------------+
| GPIO 17  | OUT    | RS-485 TX  -> ADUM1201 VOA -> MAX3485 DI  |
| GPIO 18  | IN     | RS-485 RX  <- ADUM1201 VOB <- MAX3485 RO  |
| GPIO 8   | OUT    | RS-485 DE/RE (direction control)          |
+----------+--------+-------------------------------------------+
|                    UART2 / RS-232 (Legacy SCADA)              |
+----------+--------+-------------------------------------------+
| GPIO 19  | OUT    | RS-232 TX  -> MAX3232 T1IN (pin 11)       |
| GPIO 20  | IN     | RS-232 RX  <- MAX3232 R1OUT (pin 12)      |
+----------+--------+-------------------------------------------+
|                    SPI / CAN Bus (MCP2515 + SN65HVD230)       |
+----------+--------+-------------------------------------------+
| GPIO 35  | OUT    | SPI MOSI   -> MCP2515 SI (pin 14)         |
| GPIO 37  | IN     | SPI MISO   <- MCP2515 SO (pin 15)         |
| GPIO 36  | OUT    | SPI CLK    -> MCP2515 SCK (pin 13)        |
| GPIO 34  | OUT    | SPI CS     -> MCP2515 CS (pin 16)         |
| GPIO 33  | IN     | CAN INT    <- MCP2515 INT (pin 12)        |
+----------+--------+-------------------------------------------+
|                    I2C / 4-20mA ADC (INA219)                  |
+----------+--------+-------------------------------------------+
| GPIO 1   | I/O    | I2C SDA    <-> INA219 SDA (addr 0x40)     |
| GPIO 2   | OUT    | I2C SCL    -> INA219 SCL                  |
+----------+--------+-------------------------------------------+
|                    Miscellaneous                               |
+----------+--------+-------------------------------------------+
| GPIO 48  | OUT    | Status LED (built-in RGB on DevKitC-1)    |
| USB      | I/O    | USB CDC serial to pager (/dev/ttyACM0)    |
+----------+--------+-------------------------------------------+
|                    Power                                       |
+----------+--------+-------------------------------------------+
| 5V       | PWR    | USB 5V input -> AMS1117-3.3 -> 3.3V rail  |
| 3V3      | PWR    | 3.3V regulated output (ESP32 + ICs)       |
| GND      | PWR    | Common ground                             |
+----------+--------+-------------------------------------------+
```

**Unused GPIOs available for expansion:** 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 21, 38, 39, 40, 41, 42

---

## 3. Subsystem Wiring Diagrams

### 3a. RS-485 / Modbus RTU (Isolated)

The ADUM1201 digital isolator sits between the ESP32 and the MAX3485, providing
galvanic isolation. The isolated side is powered by a B0505S isolated DC-DC converter.

```
                          ISOLATION BARRIER
                               |||
  ESP32 Side (3.3V)            |||     Isolated Side (5V_ISO -> 3.3V_ISO)
                               |||
                               |||
  +----------+          +------|||------+          +-----------+
  |  ESP32   |          |   ADUM1201    |          |  MAX3485  |
  |  S3      |          |              |          |           |
  | GPIO 17 -|---> TX --|-VIA  ->  VOA-|--------->|- DI    A -|---+---> A (Screw Term)
  |  (TX)    |          |              |          |           |   |
  | GPIO 18 -|---< RX --|-VIB  <-  VOB-|-----+---|- RO    B -|---+-+-> B (Screw Term)
  |  (RX)    |          |              |      |   |           |   | |
  | GPIO 8  -|----------+------>-------+------+-->|- DE       |   | |
  |  (DE/RE) |          |              |      +-->|- RE       |   | |
  |          |          | VDD1    VDD2 |          |    GND   |   | |
  |    3V3 --|---+------|- VDD1        |    +-----|- VCC     |   | |
  |          |   |      |         VDD2-|----+     |    GND  -|---+ |
  |    GND --|---+------|- GND1        |    |     +-----------+   | |
  +----------+   |      |         GND2-|--+ |                     | |
                 |      +------|||------+ | |     [120R term.]    | |
                 |             |||        | |       optional       | |
                 |             |||        | |     +---/\/\/---+    | |
                 |                        | |     |           |    | |
                 |                        | +-----+-----------+----+ |
                 |                        |       |                  |
                 |  +----------+          +-------+------------------+
                 |  | B0505S   |                  |
                 |  | DC-DC    |                  |
                 +--|- VIN     |                  |
                 |  |     VOUT-|--- 5V_ISO        |
                 +--|- GND     |       |          |
                    |    GND_O-|-------+--- GND_ISO
                    +----------+
                    (add 10uF + 100nF caps on both input and output)
```

**Key connections:**
- DE and RE on MAX3485 are tied together, driven by GPIO 8 through the ADUM1201
- GPIO 8 HIGH = transmit mode, LOW = receive mode
- The ADUM1201 channel A carries TX (ESP32 -> MAX3485 DI)
- The ADUM1201 channel B carries RX (MAX3485 RO -> ESP32)
- DE/RE can share one of the ADUM channels or use a separate GPIO-to-isolator path;
  for simplicity, wire GPIO 8 -> VIA on a second ADUM1201, or use a 3-channel
  isolator (ADUM1301). Alternatively, route DE/RE through an optocoupler.
- 120 ohm termination resistor across A/B is optional -- only needed at the two
  endpoints of the RS-485 bus. Add a jumper to enable/disable.

**Simplified breadboard version (no isolation for bench testing):**

```
  +----------+                    +-----------+
  |  ESP32   |                    |  MAX3485  |
  |          |                    |           |
  | GPIO 17 -|------------------->|- DI    A -|---> A (Screw Terminal)
  | GPIO 18 -|<-------------------|- RO    B -|---> B (Screw Terminal)
  | GPIO 8  -|---------+-------->|- DE       |
  |          |         +-------->|- RE       |        [120R]
  |    3V3 --|----+------------->|- VCC      |    A --/\/\/-- B
  |    GND --|----+--+---------->|- GND      |    (optional)
  +----------+    |  |           +-----------+
                  |  |
              [100nF] [10uF]  (decoupling caps, VCC to GND)
```

### 3b. RS-232 / Legacy SCADA

```
  +----------+          +-----------------+            DB9 Female
  |  ESP32   |          |    MAX3232      |          (DTE pinout)
  |          |          |                 |         +----------+
  | GPIO 19 -|--------->|- T1IN    T1OUT -|-------->| Pin 3 TX |
  |  (TX)    |          |                 |         |          |
  | GPIO 20 -|<---------|- R1OUT   R1IN  -|<--------| Pin 2 RX |
  |  (RX)    |          |                 |         |          |
  |          |          |            GND  -|-------->| Pin 5 GND|
  |    3V3 --|---+----->|- VCC            |         +----------+
  |    GND --|---+--+-->|- GND            |
  +----------+   |  |   |                 |
                 |  |   |  Charge Pump    |
                 |  |   |  Capacitors:    |
                 |  |   |                 |
                 |  |   | C1+ (pin 1) -|--+--[100nF]--+
                 |  |   | C1- (pin 3) -|--------------+
                 |  |   |                 |
                 |  |   | C2+ (pin 4) -|--+--[100nF]--+
                 |  |   | C2- (pin 5) -|--------------+
                 |  |   |                 |
                 |  |   | V+ (pin 2)  -|--+--[100nF]--+-- GND
                 |  |   | V- (pin 6)  -|--+--[100nF]--+-- GND
                 |  |   +-----------------+
                 |  |
             [100nF] [10uF]  (VCC decoupling)
```

**MAX3232 pinout reference (DIP-16):**

```
          +----v----+
  C1+  1 -|         |- 16  VCC
  V+   2 -|         |- 15  GND
  C1-  3 -|         |- 14  T1OUT  --> DB9 pin 3
  C2+  4 -| MAX3232 |- 13  R1IN   <-- DB9 pin 2
  C2-  5 -|         |- 12  R1OUT  --> GPIO 20
  V-   6 -|         |- 11  T1IN   <-- GPIO 19
  T2OUT 7-|         |- 10  T2IN   (unused)
  R2IN  8-|         |-  9  R2OUT  (unused)
          +---------+
```

**DB9 Female connector pinout (as wired):**

```
  DB9 Female (solder side)
  +-------------------+
  | 1   2   3   4   5 |    Pin 2 = RX (from remote TX) -> MAX3232 R1IN
  |   6   7   8   9   |    Pin 3 = TX (to remote RX)   <- MAX3232 T1OUT
  +-------------------+    Pin 5 = GND
                           Pin 7 = RTS (optional, tie to pin 8 for loopback test)
                           Pin 8 = CTS (optional, tie to pin 7 for loopback test)
```

### 3c. CAN Bus (MCP2515 + SN65HVD230)

```
  +----------+       +-------------------+        +-------------+
  |  ESP32   |       |     MCP2515       |        | SN65HVD230  |
  |          |       |                   |        |             |
  | GPIO 35 -|------>|- SI (14)   TXCAN -|------->|- TXD   CANH-|--+--> CANH
  |  (MOSI)  |       |            (1)    |        |             |  |    (Screw
  | GPIO 37 -|<------|- SO (15)   RXCAN -|<-------|- RXD   CANL-|--+--> Terminal)
  |  (MISO)  |       |            (2)    |        |             |  |
  | GPIO 36 -|------>|- SCK (13)        |        |    3V3  VCC-|--+
  |  (CLK)   |       |                   |        |        GND -|--+
  | GPIO 34 -|------>|- CS (16)         |        +-------------+  |
  |  (CS)    |       |                   |                        |
  | GPIO 33 -|<------|- INT (12)        |          [120R term.]  |
  |  (INT)   |       |                   |        CANH --/\/\/-- CANL
  |          |       | VDD (18) ---------+---+     (optional)    |
  |    3V3 --|---+-->|                   |   |                    |
  |    GND --|---+-->|- VSS (9,10)      |   |                    |
  +----------+   |   |                   |   +--------------------+
                 |   |  OSC1 (7)  OSC2 (8)|
                 |   |    |          |    |
                 |   |    +--[XTAL]--+    |     8 MHz Crystal
                 |   |    |          |    |     with 22pF load caps
                 |   |  [22pF]    [22pF]  |
                 |   |    |          |    |
                 |   |    +--- GND --+    |
                 |   +-------------------+
                 |
             [100nF] + [10uF]  (VDD decoupling, close to pin 18)
```

**MCP2515 pinout reference (DIP-18):**

```
           +----v----+
  TXCAN 1 -|         |- 18  VDD (3.3V)
  RXCAN 2 -|         |- 17  RESET (tie to VDD via 10k, or VDD direct)
  CLKOUT 3-|         |- 16  CS    <-- GPIO 34
  TX0BF 4 -|         |- 15  SO    --> GPIO 37
  TX1BF 5 -| MCP2515 |- 14  SI    <-- GPIO 35
  TX2BF 6 -|         |- 13  SCK   <-- GPIO 36
  OSC1  7 -|         |- 12  INT   --> GPIO 33
  OSC2  8 -|         |- 11  RX1BF
  VSS   9 -|         |- 10  RX0BF
           +---------+

  Pin 9  (VSS)   -> GND
  Pin 17 (RESET) -> 3.3V (or tie to VDD through 10k pull-up)
  Pin 3  (CLKOUT)-> leave unconnected or tie to GND via 10k
  Pins 4-6, 10-11 -> leave unconnected (open drain, inactive by default)
```

**SN65HVD230 pinout (SOIC-8):**

```
          +----v----+
  TXD  1 -|         |- 8  NC
  GND  2 -|         |- 7  RS (slope control, tie to GND for max speed)
  VCC  3 -|         |- 6  CANL
  RXD  4 -|         |- 5  CANH
          +---------+

  Pin 3 (VCC) -> 3.3V
  Pin 2 (GND) -> GND
  Pin 7 (RS)  -> GND (full speed) or 10k-100k to GND (slope control)
  Add 100nF cap between VCC and GND, close to IC.
```

### 3d. 4-20mA ADC (INA219 via I2C)

```
  +----------+        +-------------+
  |  ESP32   |        |   INA219    |        Field Loop
  |          |        |             |        (4-20mA source)
  | GPIO 1  -|--+---->|- SDA   VIN+-|<---------+  LOOP+
  |  (SDA)   |  |     |             |           |
  | GPIO 2  -|--+---->|- SCL   VIN--|--->-[250R sense]--->  LOOP-
  |  (SCL)   |  |     |             |           |
  |          |  |     |    VS+ (Vcc)|           |
  |    3V3 --|--+---->|-  VS+       |    The 250 ohm resistor is IN
  |          |  |     |    VS- (GND)|    the current loop path.
  |    GND --|--+---->|-  VS-       |    V = I * R = 20mA * 250R = 5V max
  +----------+  |     |             |    INA219 measures voltage across it.
                |     |  A0    A1   |
                |     |  |      |   |    I2C Address = 0x40
                |     |  GND   GND  |    (A0=GND, A1=GND)
                |     +-------------+
                |
          [4.7k]  [4.7k]   I2C pull-up resistors to 3.3V
                |
              3.3V
```

**INA219 wiring detail:**

```
    LOOP+  ------>------+
                        |
                      VIN+  (INA219 pin)
                        |
                      VIN-  (INA219 pin)
                        |
                    [250 ohm]  (precision sense resistor, 0.1% tolerance)
                        |
    LOOP-  ------<------+


    The INA219 measures the differential voltage across VIN+ and VIN-
    (i.e., across the 250 ohm resistor).

    At  4mA:  V = 0.004 * 250 = 1.000V
    At 20mA:  V = 0.020 * 250 = 5.000V

    INA219 full-scale shunt voltage = +/-320mV at default gain.
    IMPORTANT: Set INA219 PGA gain to /8 (320mV * 8 = 2.56V range)
    or use a smaller sense resistor. With 250 ohm at 20mA = 5V,
    you need PGA = /1 with bus voltage measurement instead, or
    reduce the sense resistor to 50 ohm (1V at 20mA, within range
    at PGA /4).

    Recommended alternative: Use 50 ohm 0.1% resistor
      At  4mA: 0.200V
      At 20mA: 1.000V
    This fits within PGA /4 range (1.28V max).

    The firmware config defines 250 ohm; adjust calibration accordingly
    or change SENSE_RESISTOR_OHMS in config.h to match your resistor.
```

### 3e. Power Supply

```
    USB 5V (from pager)
        |
        +--------+--------+----------------------------+
        |        |        |                            |
      [10uF]  [100nF]    |                            |
        |        |     +--+----------+          +------+------+
        +--------+     |  AMS1117    |          |   B0505S    |
        |              |  -3.3       |          |   DC-DC     |
       GND             |             |          |   Isolated  |
                       | VIN   VOUT -|--+       |             |
                       |             |  |       | VIN    VOUT-|--- 5V_ISO
                       |    GND     |  |       |             |      |
                       +-----+------+  |       | GND   GND_O-|--- GND_ISO
                             |         |       +-------------+      |
                            GND        |           |    |          |
                                       +---+     [10uF][100nF]  [10uF][100nF]
                                       |   |       |    |          |    |
                                     [10uF][100nF] GND  GND      GND_ISO
                                       |   |
                                       GND GND

                         3.3V Rail                    5V_ISO Rail
                    (ESP32, MAX3232,              (ADUM1201 VDD2,
                     MCP2515, SN65HVD230,          MAX3485 VCC)
                     INA219, ADUM1201 VDD1)

    Note: The DevKitC-1 has its own on-board 3.3V regulator from USB.
    For breadboard prototyping, you can use the DevKitC's 3V3 pin
    to power external ICs directly (up to ~500mA available).
    The external AMS1117-3.3 is only needed for a standalone PCB build.
```

**Power budget estimate:**

```
  +-------------------+---------+
  | Component         | Current |
  +-------------------+---------+
  | ESP32-S3          | 150 mA  |
  | MAX3485           |   1 mA  |
  | MAX3232           |   4 mA  |
  | MCP2515           |  10 mA  |
  | SN65HVD230        |  10 mA  |
  | INA219            |   1 mA  |
  | ADUM1201          |   3 mA  |
  | B0505S (load)     |  15 mA  |
  +-------------------+---------+
  | TOTAL             | ~194 mA |
  +-------------------+---------+
  Well within USB 500mA budget.
```

---

## 4. Complete System Diagram

```
                                  USB to WiFi Pineapple Pager
                                  (/dev/ttyACM0 - CDC Serial)
                                           |
                                           |
                    +----------------------+----------------------+
                    |            ESP32-S3 DevKitC-1               |
                    |                                             |
                    |  GPIO 48 = Status LED (RGB)                 |
                    |                                             |
                    |  +-----------+   +-----------+              |
                    |  | UART1     |   | UART2     |              |
                    |  | TX=GPIO17 |   | TX=GPIO19 |              |
                    |  | RX=GPIO18 |   | RX=GPIO20 |              |
                    |  | DE=GPIO8  |   +-----------+              |
                    |  +-----------+        |                     |
                    |       |               |                     |
                    |  +-----------+   +-----------+              |
                    |  | SPI       |   | I2C       |              |
                    |  | MOSI=GP35 |   | SDA=GPIO1 |              |
                    |  | MISO=GP37 |   | SCL=GPIO2 |              |
                    |  | CLK=GP36  |   +-----------+              |
                    |  | CS=GP34   |        |                     |
                    |  | INT=GP33  |        |                     |
                    |  +-----------+        |                     |
                    +------|--------|-------+---------------------+
                           |        |       |
         +---------+       |        |       |        +---------+
         |ISOLATION|       |        |       |        |         |
         | BARRIER |       |        |       |        |         |
         |  |||    |       |        |       |        |         |
    +----+--|||----+--+    |        |       |   +----+---------+----+
    |    ADUM1201     |    |        |       |   |      INA219       |
    |    (isolator)   |    |        |       |   |    (I2C 0x40)     |
    +--------+--------+    |        |       |   +----+----+---------+
             |             |        |       |        |    |
    +--------+--------+   |   +----+----+  |   [250R sense]
    |     MAX3485      |   |   | MAX3232 |  |        |    |
    |  (RS-485 xcvr)   |   |   |(RS-232) |  |     LOOP+  LOOP-
    +----+----+--------+   |   +--+---+--+  |   (4-20mA field
         |    |            |      |   |     |    instrument)
         A    B            |   T1OUT R1IN   |
         |    |            |      |   |     |
    [Screw Terminal]       |   [DB9 Female] |
     RS-485 Bus            |    RS-232 port |
     (Modbus RTU)          |                |
                           |                |
                    +------+------+         |
                    |   MCP2515   |         |
                    | (CAN ctrl)  |         |
                    |  [8MHz XTAL]|         |
                    +------+------+         |
                           |                |
                    +------+------+         |
                    |  SN65HVD230 |         |
                    | (CAN xcvr)  |         |
                    +------+------+
                           |
                        CANH CANL
                           |    |
                      [Screw Terminal]
                        CAN Bus


    ============================================================
    LEGEND
    ============================================================

    [Screw Terminal]  = 2-position 5.08mm screw terminal block
    [DB9 Female]      = DE-9S connector for RS-232
    [250R sense]      = 250 ohm precision sense resistor
    [8MHz XTAL]       = 8 MHz crystal + 2x 22pF load caps
    ISOLATION BARRIER = ADUM1201 + B0505S isolated DC-DC
    All ICs powered from 3.3V rail except isolated MAX3485 side
```

---

## 5. Assembly Notes

### 5.1 Recommended Build Order

Build and test one subsystem at a time. This isolates problems and builds
confidence incrementally.

**Phase 0 -- USB CDC (no external hardware)**
1. Flash the ESP32-S3 DevKitC-1 with the ICS Probe firmware via USB.
2. Connect to the pager (or a laptop for testing).
3. Verify the probe enumerates as `/dev/ttyACM0`.
4. Send `{"cmd":"probe.info"}` and confirm a JSON response.
5. Send `{"cmd":"probe.selftest"}` -- all buses will report "not connected"
   but the command loop is validated.

**Phase 1 -- RS-232 (simplest analog circuit)**
1. Wire the MAX3232 with its four 100nF charge pump capacitors.
2. Connect GPIO 19 (TX) to T1IN, GPIO 20 (RX) to R1OUT.
3. Add VCC decoupling (100nF + 10uF).
4. Loopback test: jumper T1OUT to R1IN (DB9 pin 3 to pin 2).
5. Send `{"cmd":"serial.send","params":{"data":"48656C6C6F","baud":9600}}`
   and verify you receive "Hello" back.
6. If working, connect to a real RS-232 device (serial console, old RTU).

**Phase 2 -- RS-485 / Modbus RTU (without isolation first)**
1. Wire the MAX3485: DI to GPIO 17, RO to GPIO 18, DE+RE tied to GPIO 8.
2. Add VCC decoupling.
3. Connect A/B to a known Modbus RTU device or a second USB-RS485 adapter
   for loopback testing.
4. Send `{"cmd":"modbus.scan_bus","params":{"range":[1,10]}}`.
5. Once working, add the ADUM1201 isolator and B0505S DC-DC between the
   ESP32 and the MAX3485 for field-safe operation.

**Phase 3 -- CAN Bus**
1. Solder or mount the 8 MHz crystal onto the MCP2515 with 22pF caps to GND.
2. Wire SPI: SI, SO, SCK, CS, INT per the pin map.
3. Wire MCP2515 TXCAN/RXCAN to SN65HVD230 TXD/RXD.
4. Add decoupling caps on both ICs.
5. Tie MCP2515 RESET to VDD (or through 10k pull-up).
6. Connect CANH/CANL to a CAN bus or a second CAN adapter for testing.
7. Send `{"cmd":"can.listen","params":{"baud":500000,"duration_s":5}}`.

**Phase 4 -- 4-20mA ADC**
1. Wire INA219 I2C: SDA to GPIO 1, SCL to GPIO 2, with 4.7k pull-ups to 3.3V.
2. Tie A0 and A1 to GND (address 0x40).
3. Place the 250 ohm sense resistor between VIN+ and VIN-.
4. For bench testing without a real 4-20mA source: use a bench power supply
   set to ~5V through a 250 ohm resistor (gives ~20mA through the sense path).
   Or use a potentiometer as a variable current source.
5. Send `{"cmd":"adc.read"}` and verify a milliamp reading.

**Phase 5 -- Full Integration**
1. Power everything from USB 5V.
2. Run `{"cmd":"probe.selftest"}` -- all buses should report OK.
3. Test each bus with real field equipment.
4. Add galvanic isolation (ADUM1201 + B0505S) for RS-485 before connecting
   to live plant equipment.

### 5.2 Common Gotchas

**MCP2515 Crystal**
- The MCP2515 will not initialize without a working crystal oscillator.
  If `can.listen` times out or returns errors, check the crystal and its
  22pF load capacitors. The caps must go from each crystal pin to GND, not
  to each other.
- Use exactly 8 MHz. The firmware assumes 8 MHz for baud rate calculation.
  A 16 MHz crystal will result in doubled baud rates.
- Keep crystal traces/wires short (under 1 inch / 25mm). Long wires on
  a breadboard can prevent oscillation. Mount the crystal as close to the
  MCP2515 as physically possible.

**MAX3232 Charge Pump Capacitors**
- All four 100nF capacitors are required. Missing even one will cause the
  charge pump to fail and RS-232 voltage levels will be wrong.
- Use ceramic capacitors, not electrolytic. Polarity does not matter.
- If you see garbled RS-232 data, check that all four caps are present and
  properly connected per the datasheet pinout.
- The MAX3232E (enhanced version) works with caps as small as 100nF.
  The original MAX3232 may need 1uF caps -- check your specific part.

**RS-485 Termination**
- The 120 ohm termination resistor goes across A and B at each physical end
  of the bus. If your probe is the only device, or in the middle of the bus,
  do NOT add the termination resistor.
- Use a 2-pin jumper header across the termination resistor so you can
  enable/disable it without desoldering.
- Incorrect termination causes signal reflections that appear as CRC errors
  in Modbus RTU communications.

**RS-485 Direction Control (DE/RE)**
- DE and RE must switch within microseconds of the last TX byte completing.
  The firmware handles this timing, but if you see the last byte of a
  response getting cut off, the switchover may be too fast. The firmware
  uses a small delay after TX complete before switching to RX.
- If the bus appears dead, verify GPIO 8 is toggling with a multimeter
  or logic analyzer. A stuck-high DE/RE means the transceiver is always
  transmitting and cannot receive.

**I2C Pull-ups**
- The ESP32-S3 has internal pull-ups but they are weak (~45k ohm). Always
  add external 4.7k pull-up resistors on SDA and SCL to 3.3V.
- Without pull-ups, I2C may work intermittently or not at all, especially
  at 400 kHz. The INA219 runs fine at 100 kHz with proper pull-ups.

**Power**
- Do NOT attempt to power the ESP32-S3 from both USB and an external 3.3V
  supply simultaneously. Use USB power only for the prototype.
- The DevKitC-1 board's 3V3 pin can source ~500mA. All external ICs combined
  draw under 50mA, so this is safe.
- Add 100nF decoupling caps close to the VCC/VDD pin of every IC. This is
  not optional. Without decoupling, digital switching noise will cause
  analog circuits (RS-485, CAN) to produce bit errors.

**ESP32-S3 Pin Conflicts**
- GPIO 0 is a strapping pin (boot mode). Do not use it for peripherals.
- GPIO 19 and GPIO 20 are USB D-/D+ on some S3 modules. On the DevKitC-1
  with native USB, these are repurposed as general GPIO when USB-OTG is
  using the dedicated USB pins. Verify your specific board variant.
- GPIO 35-37 are connected to the PSRAM on WROOM-1 modules with octal PSRAM.
  The N8R2 variant uses quad PSRAM and leaves these GPIOs free for SPI.
  Do NOT use an N8R8 (octal PSRAM) variant -- SPI pins will conflict.

### 5.3 Test Equipment Recommendations

- **Multimeter** -- Verify 3.3V and 5V rails, check continuity.
- **Logic analyzer** (optional but very helpful) -- Verify SPI, I2C, UART
  signals. A Saleae Logic 8 or cheap 24 MHz clone works fine.
- **USB-RS485 adapter** -- For loopback testing the Modbus RTU interface
  without a real Modbus device.
- **CAN bus adapter** (e.g., PCAN-USB, Canable) -- For CAN testing.
- **Bench power supply** -- For simulating 4-20mA current loops.

### 5.4 Wire Color Convention (Suggested)

```
  Red    = 5V / 3.3V power
  Black  = GND
  Yellow = SPI CLK, I2C SCL (clock signals)
  Green  = SPI MISO, I2C SDA, UART RX (data to ESP32)
  Blue   = SPI MOSI, UART TX (data from ESP32)
  White  = SPI CS, interrupt lines
  Orange = RS-485 A / CANH (bus positive)
  Brown  = RS-485 B / CANL (bus negative)
```
