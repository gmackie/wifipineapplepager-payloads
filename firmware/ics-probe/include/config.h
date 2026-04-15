#pragma once

// --- Pin Assignments (ESP32-S3 DevKitC-1) ---

// RS-485 (Modbus RTU) - UART1
#define RS485_TX_PIN        17
#define RS485_RX_PIN        18
#define RS485_DE_RE_PIN     8    // Direction control (HIGH=TX, LOW=RX)
#define RS485_BAUD_DEFAULT  9600

// RS-232 (Legacy SCADA) - UART2
// NOTE: GPIO 19/20 are USB D-/D+ on S3 — cannot use when USB is active
#define RS232_TX_PIN        15
#define RS232_RX_PIN        16
#define RS232_BAUD_DEFAULT  9600

// CAN Bus - SPI (MCP2515)
#define CAN_SPI_MOSI        35
#define CAN_SPI_MISO        37
#define CAN_SPI_CLK         36
#define CAN_SPI_CS          34
#define CAN_INT_PIN         33
#define CAN_BAUD_DEFAULT    500000

// 4-20mA ADC (INA219) - I2C
#define I2C_SDA_PIN         1
#define I2C_SCL_PIN         2
#define INA219_ADDR         0x40
#define SENSE_RESISTOR_OHMS 250  // 250Ω sense resistor for 4-20mA

// Status LED
#define STATUS_LED_PIN      48   // Built-in RGB LED on most S3 DevKitC boards

// --- Protocol Settings ---
#define JSON_BUFFER_SIZE    2048
#define SERIAL_BUFFER_SIZE  512
#define CMD_TIMEOUT_MS      5000
#define MODBUS_INTER_FRAME_US 4000  // 3.5 char silence at 9600 baud ~= 4ms
#define MAX_LOG_ENTRIES     50

// --- Safety ---
#define RATE_LIMIT_MS       100  // Minimum ms between commands to same handler
#define WATCHDOG_TIMEOUT_S  30

// =============================================================================
// v1.1 additions — shared SPI bus for W5500 / MCP2515 / MAX14906 / AD5420
// =============================================================================
//
// All four chips share one SPI bus (SPI3 / HSPI). MCP2515 already uses
// pins defined above. The new chips add their own CS/INT/etc lines.
//
// Logical bus map (SPI3):
//   MOSI  = CAN_SPI_MOSI (35)
//   MISO  = CAN_SPI_MISO (37)
//   CLK   = CAN_SPI_CLK  (36)
//
// The ADUM1401 digital isolator sits between the ESP32 and the MAX14906/AD5420
// pair. It does not need its own GPIO — it's transparent to the SPI bus.

// --- W5500 Ethernet controller ---
#define W5500_CS_PIN        4
#define W5500_INT_PIN       5
#define W5500_RST_PIN       6
#define W5500_PHY_ADDR      1
#define W5500_SPI_MHZ       20

// --- MAX14906 4-channel 24V DIO (24V field domain) ---
#define MAX14906_CS_PIN     7
#define MAX14906_FAULT_PIN  9
#define MAX14906_SPI_MHZ    10
#define DIO_CHANNELS        4

// --- AD5420 4-20mA current output DAC (24V field domain) ---
#define AD5420_CS_PIN       10
#define AD5420_FAULT_PIN    11
#define AD5420_SPI_MHZ      10
#define IOUT_MIN_MA         0.00f
#define IOUT_MAX_MA         24.00f   // chip supports >20mA, clamp in handler
#define IOUT_OPERATING_MIN  4.00f
#define IOUT_OPERATING_MAX  20.00f
