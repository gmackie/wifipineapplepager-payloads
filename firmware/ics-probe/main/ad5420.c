// ad5420.c — AD5420 SPI register driver
//
// 24-bit SPI frame layout (MSB first):
//   Byte 0: 8-bit register address
//   Bytes 1..2: 16-bit data (big-endian)
//
// The AD5420 shares SPI3 (HSPI) with W5500 / MCP2515 / MAX14906. spi_bus_initialize
// is idempotent-tolerant here (ESP_ERR_INVALID_STATE is treated as already-
// initialised, matching the net_handler / max14906 pattern).
//
// SPI mode: mode 1 (CPOL=0, CPHA=1). The AD5420 clocks MOSI in on the
// falling edge of SCLK, which is satisfied by either mode 1 or mode 2.
// The shared SPI3 bus already hosts the MAX14906 in mode 0, and ESP-IDF's
// SPI master supports per-device mode switching, so we pick the mode-0-
// compatible falling-edge option (mode 1) to minimise SCLK idle-level
// transitions between devices on the same bus.
//
// v1.1 simplification: ad5420_read_status() is stubbed to 0x0000.
// A full status-register read-back frame is a v1.2 concern.

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_master.h"
#include "esp_log.h"

#include "config.h"
#include "ad5420.h"

static const char* TAG = "ad5420";

// ─── Register map ───────────────────────────────────────────────────────────
#define AD5420_REG_NOP        0x00
#define AD5420_REG_DAC_DATA   0x01
#define AD5420_REG_READ       0x02  // write this addr with data=0x0002 to request read-back
#define AD5420_REG_CONTROL    0x55
#define AD5420_REG_RESET      0x56

// Control register bit fields. 0x0005 = output enable + 4-20mA source range.
//   bit [0]: DAISY_CHAIN    (0 = disabled)
//   bit [1]: OUTEN          (1 = output enabled)
//   bit [2]: SREN           (1 = slew-rate disabled / 0 = enabled)
//   bits[5:3]: R2:R0 output range (000 = 4-20mA)
// 0x0005 = OUTEN | DAISY_CHAIN(0) | 4-20mA range(000) with SREN=1
#define AD5420_CTRL_4_20MA_EN 0x0005

// ─── Module state ───────────────────────────────────────────────────────────
static spi_device_handle_t s_spi = NULL;
static bool                s_initialized = false;

// ─── Low-level SPI helpers ──────────────────────────────────────────────────
static bool ad5420_write_reg(uint8_t addr, uint16_t data)
{
    if (!s_spi) return false;

    uint8_t tx[3] = {
        addr,
        (uint8_t)((data >> 8) & 0xFF),
        (uint8_t)(data & 0xFF),
    };

    spi_transaction_t t = {
        .length    = 24,
        .tx_buffer = tx,
        .rx_buffer = NULL,
    };
    esp_err_t err = spi_device_transmit(s_spi, &t);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI transfer failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

// ─── Public init ────────────────────────────────────────────────────────────
bool ad5420_init(void)
{
    if (s_initialized) return true;

    // Ensure SPI3 bus is initialised. Other handlers on SPI3 may have done
    // this already — ESP_ERR_INVALID_STATE means "already initialised" and is
    // treated as success (matches max14906 / net_handler pattern).
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = CAN_SPI_MOSI,
        .miso_io_num = CAN_SPI_MISO,
        .sclk_io_num = CAN_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 32,
    };
    esp_err_t err = spi_bus_initialize(SPI3_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "SPI3 bus init failed: %s — AD5420 disabled",
                 esp_err_to_name(err));
        return false;
    }

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = AD5420_SPI_MHZ * 1000 * 1000,
        .mode           = 1,  // CPOL=0, CPHA=1 — see file header
        .spics_io_num   = AD5420_CS_PIN,
        .queue_size     = 4,
    };
    err = spi_bus_add_device(SPI3_HOST, &dev_cfg, &s_spi);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI device add failed: %s — AD5420 disabled",
                 esp_err_to_name(err));
        s_spi = NULL;
        return false;
    }

    // Program the control register for 4-20mA source range with output enable.
    if (!ad5420_write_reg(AD5420_REG_CONTROL, AD5420_CTRL_4_20MA_EN)) {
        ESP_LOGW(TAG, "control-register write failed — AD5420 absent?");
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        return false;
    }

    // Drive the loop to its minimum (4mA) code as a deterministic startup state.
    (void)ad5420_write_reg(AD5420_REG_DAC_DATA, 0x0000);

    s_initialized = true;
    ESP_LOGI(TAG, "AD5420 initialised (control=0x%04X, 4-20mA source mode)",
             AD5420_CTRL_4_20MA_EN);
    return true;
}

// ─── Set current ────────────────────────────────────────────────────────────
bool ad5420_set_ma(float ma)
{
    if (!s_initialized) return false;

    // Clamp to chip-safe range.
    if (ma < IOUT_MIN_MA) ma = IOUT_MIN_MA;
    if (ma > IOUT_MAX_MA) ma = IOUT_MAX_MA;

    // 4-20mA range has no DAC code below 4mA — further clamp so the
    // subtraction below never underflows.
    float ma_code = ma;
    if (ma_code < 4.0f)  ma_code = 4.0f;
    if (ma_code > 20.0f) ma_code = 20.0f;

    uint16_t code = (uint16_t)(((ma_code - 4.0f) / 16.0f) * 65535.0f);
    return ad5420_write_reg(AD5420_REG_DAC_DATA, code);
}

// ─── Off ────────────────────────────────────────────────────────────────────
// Writes DAC code 0x0000, which in 4-20mA source mode corresponds to the
// minimum (4mA). The loop stays alive — a hardware relay would be needed
// to truly break the current loop.
bool ad5420_off(void)
{
    if (!s_initialized) return false;
    return ad5420_write_reg(AD5420_REG_DAC_DATA, 0x0000);
}

// ─── Status readback (stub) ─────────────────────────────────────────────────
// TODO(v1.2): implement read-back frame — write AD5420_REG_READ with 0x0002
// to request status, then clock out a second 24-bit frame with MOSI held
// at NOP and capture the returned data on MISO. Requires a 6-byte half-duplex
// transaction; the current ad5420_write_reg helper is TX-only.
uint16_t ad5420_read_status(void)
{
    if (!s_initialized) return 0;
    return 0x0000;
}
