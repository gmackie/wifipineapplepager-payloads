// max14906.c — MAX14906 SPI register driver
//
// 16-bit SPI frame layout (MSB first):
//   Byte 0: [7:1] register address  [0] R/W  (0=write, 1=read)
//   Byte 1: data to write / ignored on read
//   Response byte 1: previous register contents on read
//
// The chip shares SPI3 (HSPI) with the W5500 and MCP2515. spi_bus_initialize
// is idempotent-tolerant here (ESP_ERR_INVALID_STATE is treated as already-
// initialised, matching the net_handler pattern).

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_master.h"
#include "esp_log.h"

#include "config.h"
#include "max14906.h"

static const char* TAG = "max14906";

// ─── Register map ───────────────────────────────────────────────────────────
#define MAX14906_REG_SETOUT     0x00
#define MAX14906_REG_SETLED     0x01
#define MAX14906_REG_DOILEVEL   0x02
#define MAX14906_REG_INTERRUPT  0x03
#define MAX14906_REG_OVRLDCHF   0x04
#define MAX14906_REG_CONFIG1    0x0A
#define MAX14906_REG_CONFIG2    0x0B
#define MAX14906_REG_DOILVL     0x0D

// Config1 per-channel mode encoding (2 bits per channel, ch0 in bits [1:0]):
//   00 = high-side output
//   01 = high-side output with open-load detect
//   10 = input
//   11 = disabled / push-pull
#define MAX14906_CFG1_OUTPUT    0b00
#define MAX14906_CFG1_INPUT     0b10

// ─── Module state ───────────────────────────────────────────────────────────
static spi_device_handle_t s_spi = NULL;
static bool                s_initialized = false;

// ─── Low-level SPI helpers ──────────────────────────────────────────────────
static bool max_xfer(uint8_t addr, bool read, uint8_t data_in, uint8_t* data_out)
{
    if (!s_spi) return false;

    uint8_t tx[2] = {
        (uint8_t)((addr << 1) | (read ? 0x01 : 0x00)),
        data_in,
    };
    uint8_t rx[2] = { 0 };

    spi_transaction_t t = {
        .length    = 16,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t err = spi_device_transmit(s_spi, &t);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI transfer failed: %s", esp_err_to_name(err));
        return false;
    }
    if (data_out) *data_out = rx[1];
    return true;
}

static bool max_write_reg(uint8_t addr, uint8_t val)
{
    return max_xfer(addr, false, val, NULL);
}

static bool max_read_reg(uint8_t addr, uint8_t* out)
{
    return max_xfer(addr, true, 0x00, out);
}

// ─── Public init ────────────────────────────────────────────────────────────
bool max14906_init(void)
{
    if (s_initialized) return true;

    // Ensure SPI3 bus is initialised. Other handlers on SPI3 may have done
    // this already — ESP_ERR_INVALID_STATE means "already initialised" and is
    // treated as success (matches net_handler graceful-detection pattern).
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
        ESP_LOGW(TAG, "SPI3 bus init failed: %s — MAX14906 disabled",
                 esp_err_to_name(err));
        return false;
    }

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = MAX14906_SPI_MHZ * 1000 * 1000,
        .mode           = 0,
        .spics_io_num   = MAX14906_CS_PIN,
        .queue_size     = 4,
    };
    err = spi_bus_add_device(SPI3_HOST, &dev_cfg, &s_spi);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI device add failed: %s — MAX14906 disabled",
                 esp_err_to_name(err));
        s_spi = NULL;
        return false;
    }

    // Probe: write a known pattern to Config1 (all four channels = input)
    // and read it back.
    const uint8_t probe_pattern = 0xAA; // 4x 10 = all channels in input mode
    if (!max_write_reg(MAX14906_REG_CONFIG1, probe_pattern)) {
        ESP_LOGW(TAG, "probe write failed — MAX14906 absent?");
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        return false;
    }
    uint8_t readback = 0;
    if (!max_read_reg(MAX14906_REG_CONFIG1, &readback)) {
        ESP_LOGW(TAG, "probe read failed — MAX14906 absent?");
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        return false;
    }
    if (readback != probe_pattern) {
        ESP_LOGW(TAG, "probe mismatch (wrote 0x%02X read 0x%02X) — MAX14906 absent?",
                 probe_pattern, readback);
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        return false;
    }

    // Clear any latched fault flags.
    (void)max_write_reg(MAX14906_REG_INTERRUPT, 0x00);

    s_initialized = true;
    ESP_LOGI(TAG, "MAX14906 initialised (Config1=0x%02X)", readback);
    return true;
}

// ─── Mode / output / input / fault accessors ────────────────────────────────
bool max14906_set_mode(int ch, dio_mode_t mode)
{
    if (!s_initialized) return false;
    if (ch < 0 || ch >= DIO_CHANNELS) return false;

    uint8_t cfg1 = 0;
    if (!max_read_reg(MAX14906_REG_CONFIG1, &cfg1)) return false;

    // 2 bits per channel in Config1
    uint8_t field = (mode == DIO_MODE_OUTPUT_HS)
                    ? MAX14906_CFG1_OUTPUT
                    : MAX14906_CFG1_INPUT;
    uint8_t shift = (uint8_t)(ch * 2);
    cfg1 &= (uint8_t)~(0x03 << shift);
    cfg1 |= (uint8_t)(field << shift);

    return max_write_reg(MAX14906_REG_CONFIG1, cfg1);
}

bool max14906_write_output(int ch, bool high)
{
    if (!s_initialized) return false;
    if (ch < 0 || ch >= DIO_CHANNELS) return false;

    uint8_t setout = 0;
    if (!max_read_reg(MAX14906_REG_SETOUT, &setout)) return false;

    uint8_t bit = (uint8_t)(1 << ch);
    if (high) setout |= bit;
    else      setout &= (uint8_t)~bit;

    return max_write_reg(MAX14906_REG_SETOUT, setout);
}

bool max14906_read_inputs(uint8_t* out_mask)
{
    if (!s_initialized || !out_mask) return false;

    uint8_t lvl = 0;
    if (!max_read_reg(MAX14906_REG_DOILEVEL, &lvl)) return false;
    *out_mask = (uint8_t)(lvl & 0x0F);
    return true;
}

uint16_t max14906_read_faults(void)
{
    if (!s_initialized) return 0;

    uint8_t intr = 0;
    uint8_t ovrld = 0;
    (void)max_read_reg(MAX14906_REG_INTERRUPT, &intr);
    (void)max_read_reg(MAX14906_REG_OVRLDCHF, &ovrld);
    return (uint16_t)(((uint16_t)ovrld << 8) | intr);
}
