#pragma once

// --- Pin Assignments (ESP32-S3 DevKitC-1) ---

// RS-485 (Modbus RTU) - UART1
#define RS485_TX_PIN        17
#define RS485_RX_PIN        18
#define RS485_DE_RE_PIN     8    // Direction control (HIGH=TX, LOW=RX)
#define RS485_BAUD_DEFAULT  9600

// RS-232 (Legacy SCADA) - UART2
#define RS232_TX_PIN        19
#define RS232_RX_PIN        20
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
