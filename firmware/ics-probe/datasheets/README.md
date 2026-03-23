# ICS Probe Datasheets

Datasheets for ICs used in the ESP32-S3 ICS Probe project.

## IC Reference

### ESP32-S3 (Espressif) -- Main MCU

| Item | Detail |
|------|--------|
| **Role** | Main microcontroller -- Wi-Fi, BLE 5, dual-core Xtensa LX7, runs probe firmware |
| **Datasheet** | [esp32-s3-datasheet.pdf](esp32-s3-datasheet.pdf) -- [Espressif official](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf) |
| **Tech Ref Manual** | [esp32-s3-technical-reference.pdf](esp32-s3-technical-reference.pdf) -- [Espressif official](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf) |
| **Key pins/peripherals** | SPI2/SPI3 (for MCP2515), I2C0/I2C1 (for INA219), UART0/UART1/UART2 (for RS-485/RS-232 transceivers), GPIO for transceiver enable/direction pins |
| **Key registers** | SPI, I2C, UART, and GPIO peripheral registers in the TRM |

---

### MAX3485 (Maxim / Analog Devices) -- RS-485 Transceiver

| Item | Detail |
|------|--------|
| **Role** | Half-duplex RS-485/RS-422 transceiver for industrial bus probing |
| **Datasheet** | [max3485-datasheet.pdf](max3485-datasheet.pdf) -- [Analog Devices official](https://www.analog.com/media/en/technical-documentation/data-sheets/max3483-max3491.pdf) |
| **Key pins** | `RO` (pin 1, receiver output to ESP32 UART RX), `RE` (pin 2, receiver enable, active low), `DE` (pin 3, driver enable, active high), `DI` (pin 4, driver input from ESP32 UART TX), `A`/`B` (pins 6/7, differential bus lines), `VCC` (pin 8, 3.3V) |
| **Key specs** | 3.3V supply, up to 10 Mbps, half-duplex, ESD protected |
| **Design notes** | Tie RE and DE together for auto-direction control via a single GPIO, or wire separately for independent RX/TX enable. 120-ohm termination resistor across A/B at end of bus. |

---

### MAX3232 (Texas Instruments) -- RS-232 Transceiver

| Item | Detail |
|------|--------|
| **Role** | RS-232 level shifter for legacy serial port probing |
| **Datasheet** | [max3232-datasheet.pdf](max3232-datasheet.pdf) -- [TI official](https://www.ti.com/lit/ds/symlink/max3232.pdf) |
| **Key pins** | `T1IN`/`T2IN` (TTL-level TX inputs from ESP32), `T1OUT`/`T2OUT` (RS-232 TX outputs), `R1IN`/`R1OUT` (RS-232 RX input / TTL output to ESP32), `C1+`/`C1-`/`C2+`/`C2-` (charge pump caps), `V+`/`V-` (charge pump outputs) |
| **Key specs** | 3.0V to 5.5V supply, dual driver/receiver, charge pump generates +/-5.5V from 3.3V, up to 250 kbps |
| **Design notes** | Requires 4 external 100nF capacitors for the charge pump. Place caps close to IC pins. |

---

### MCP2515 (Microchip) -- CAN Controller

| Item | Detail |
|------|--------|
| **Role** | Stand-alone CAN 2.0B controller with SPI interface for CAN bus probing |
| **Datasheet** | [mcp2515-datasheet.pdf](mcp2515-datasheet.pdf) -- [Microchip official](https://ww1.microchip.com/downloads/aemDocuments/documents/APID/ProductDocuments/DataSheets/MCP2515-Family-Data-Sheet-DS20001801K.pdf) |
| **Key pins** | `SCK` (SPI clock), `SI` (SPI MOSI), `SO` (SPI MISO), `CS` (SPI chip select, active low), `INT` (interrupt output to ESP32 GPIO), `TXCAN`/`RXCAN` (connect to SN65HVD230), `OSC1`/`OSC2` (8 MHz or 16 MHz crystal) |
| **Key registers** | `CANSTAT` (status), `CANCTRL` (mode control), `CNF1`/`CNF2`/`CNF3` (bit timing), `TXBnCTRL`/`TXBnSIDH` etc. (TX buffers), `RXBnCTRL`/`RXBnSIDH` etc. (RX buffers), `CANINTF`/`CANINTE` (interrupts), `RXFnSIDH`/`RXMnSIDH` (filters/masks) |
| **Design notes** | Requires external 8 MHz or 16 MHz crystal. SPI mode 0,0. Connect TXCAN/RXCAN to SN65HVD230 TXD/RXD. Set bit timing registers based on crystal frequency and desired CAN baud rate. |

---

### SN65HVD230 (Texas Instruments) -- CAN Bus Transceiver

| Item | Detail |
|------|--------|
| **Role** | 3.3V CAN bus physical layer transceiver, interfaces MCP2515 to the CAN bus |
| **Datasheet** | [sn65hvd230-datasheet.pdf](sn65hvd230-datasheet.pdf) -- [TI official](https://www.ti.com/lit/ds/symlink/sn65hvd230.pdf) |
| **Key pins** | `TXD` (pin 1, TX input from MCP2515 TXCAN), `GND` (pin 2), `VCC` (pin 3, 3.3V), `RXD` (pin 4, RX output to MCP2515 RXCAN), `Vref` (pin 5, VCC/2 reference output), `CANH` (pin 6), `CANL` (pin 7), `RS` (pin 8, mode select) |
| **Key specs** | 3.3V supply, up to 1 Mbps, ISO 11898-2 compliant, +/-16 kV HBM ESD on bus pins |
| **Design notes** | RS pin: tie to GND for high-speed mode, connect slope-control resistor (10k-100k) for EMI reduction, or tie to VCC for low-power listen-only mode. 120-ohm termination at bus ends. 100nF bypass cap on VCC. |

---

### INA219 (Texas Instruments) -- Current/Power Monitor

| Item | Detail |
|------|--------|
| **Role** | High-side current and power monitor via I2C for measuring target device power consumption |
| **Datasheet** | [ina219-datasheet.pdf](ina219-datasheet.pdf) -- [TI official](https://www.ti.com/lit/ds/symlink/ina219.pdf) |
| **Key pins** | `A0`/`A1` (I2C address select), `SDA`/`SCL` (I2C bus), `VS` (3.3V-5V supply), `VIN+`/`VIN-` (high-side sense inputs across shunt resistor) |
| **Key registers** | `0x00` Configuration (PGA gain, bus/shunt ADC resolution, mode), `0x01` Shunt Voltage, `0x02` Bus Voltage, `0x03` Power, `0x04` Current, `0x05` Calibration |
| **Design notes** | Place shunt resistor (e.g., 100 mOhm) in series with target VCC high side. Set Calibration register based on shunt value and desired LSB. I2C address set by A0/A1 to GND/VS/SDA/SCL (16 possible addresses, default 0x40). |

---

### ADUM1201 (Analog Devices) -- Digital Isolator

| Item | Detail |
|------|--------|
| **Role** | Galvanic isolation between ESP32 and probed bus interfaces for safety and ground loop prevention |
| **Datasheet** | [adum1201-datasheet.pdf](adum1201-datasheet.pdf) -- [Analog Devices official](https://www.analog.com/media/en/technical-documentation/data-sheets/adum1200_1201.pdf) |
| **Key pins** | `VDD1` (pin 1, side-1 supply), `VIA` (pin 2, side-1 input channel A), `VOB` (pin 3, side-1 output channel B), `GND1` (pin 4), `GND2` (pin 5), `VIB` (pin 6, side-2 input channel B), `VOA` (pin 7, side-2 output channel A), `VDD2` (pin 8, side-2 supply) |
| **Key specs** | 2.7V-5.5V per side (can be different), 1/1 channel directionality (one channel each direction), up to 25 Mbps (BRW grade), 2.5 kV rms isolation rating |
| **Design notes** | ADUM1201 has 1 channel in each direction (suitable for UART TX/RX isolation). Use 100nF bypass caps on both VDD1 and VDD2, placed close to pins. Keep PCB ground planes on each side separate. For SPI isolation, use ADUM1401 (4-channel) instead. |

## Source URLs

| IC | Manufacturer URL | Mirror Used |
|----|-----------------|-------------|
| MAX3485 | https://www.analog.com/media/en/technical-documentation/data-sheets/max3483-max3491.pdf | Farnell |
| MAX3232 | https://www.ti.com/lit/ds/symlink/max3232.pdf | Direct from TI |
| MCP2515 | https://ww1.microchip.com/downloads/aemDocuments/documents/APID/ProductDocuments/DataSheets/MCP2515-Family-Data-Sheet-DS20001801K.pdf | Direct from Microchip |
| SN65HVD230 | https://www.ti.com/lit/ds/symlink/sn65hvd230.pdf | Direct from TI |
| INA219 | https://www.ti.com/lit/ds/symlink/ina219.pdf | Direct from TI |
| ADUM1201 | https://www.analog.com/media/en/technical-documentation/data-sheets/adum1200_1201.pdf | Reichelt CDN |
| ESP32-S3 DS | https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf | Adafruit CDN |
| ESP32-S3 TRM | https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf | Waveshare |
