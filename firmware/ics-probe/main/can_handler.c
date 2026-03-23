// can_handler.c — CAN bus via MCP2515 over SPI
// Uses ESP-IDF SPI master driver + cJSON for structured output.

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char *TAG = "can_handler";

// ─── MCP2515 SPI instruction set ────────────────────────────────────────────

#define MCP_RESET       0xC0
#define MCP_READ        0x03
#define MCP_WRITE       0x02
#define MCP_RTS_TX0     0x81  // Request-to-send TX buffer 0
#define MCP_READ_STATUS 0xA0
#define MCP_BIT_MODIFY  0x05

// ─── MCP2515 register map ───────────────────────────────────────────────────

#define MCP_CANSTAT     0x0E
#define MCP_CANCTRL     0x0F
#define MCP_CNF3        0x28
#define MCP_CNF2        0x29
#define MCP_CNF1        0x2A
#define MCP_CANINTE     0x2B
#define MCP_CANINTF     0x2C
#define MCP_RXB0CTRL    0x60
#define MCP_RXB1CTRL    0x70
#define MCP_RXB0SIDH    0x61  // Start of RX buffer 0 data
#define MCP_TXB0CTRL    0x30
#define MCP_TXB0SIDH    0x31  // Start of TX buffer 0 data

// CANCTRL mode bits
#define MCP_MODE_NORMAL       0x00
#define MCP_MODE_SLEEP        0x20
#define MCP_MODE_LOOPBACK     0x40
#define MCP_MODE_LISTEN_ONLY  0x60
#define MCP_MODE_CONFIG       0x80
#define MCP_MODE_MASK         0xE0

// RXB0CTRL / RXB1CTRL: accept all frames (mask = 0, filter bypassed)
#define MCP_RXB_RX_ANY        0x60

// CANINTE: RX buffer interrupt enable bits
#define MCP_RX0IF             0x01
#define MCP_RX1IF             0x02

// ─── Module state ───────────────────────────────────────────────────────────

static spi_device_handle_t s_spi = NULL;
static bool s_initialized = false;

// External stop flag — set to true by main loop / UART command to abort
// long-running actions early (e.g. listen, scan_ids).
extern volatile bool g_stop_requested;

// ─── Low-level SPI helpers ──────────────────────────────────────────────────

static esp_err_t mcp_spi_transfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
    if (!s_spi) return ESP_ERR_INVALID_STATE;

    spi_transaction_t t = {
        .length    = len * 8,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    return spi_device_transmit(s_spi, &t);
}

static void mcp_write_reg(uint8_t reg, uint8_t val)
{
    uint8_t tx[3] = { MCP_WRITE, reg, val };
    mcp_spi_transfer(tx, NULL, 3);
}

static uint8_t mcp_read_reg(uint8_t reg)
{
    uint8_t tx[3] = { MCP_READ, reg, 0x00 };
    uint8_t rx[3] = { 0 };
    mcp_spi_transfer(tx, rx, 3);
    return rx[2];
}

// Write a contiguous block of registers starting at `reg`.
static void mcp_write_regs(uint8_t reg, const uint8_t *data, size_t len)
{
    uint8_t tx[2 + 13]; // max frame header + 8 data bytes
    if (len > sizeof(tx) - 2) len = sizeof(tx) - 2;
    tx[0] = MCP_WRITE;
    tx[1] = reg;
    memcpy(&tx[2], data, len);
    mcp_spi_transfer(tx, NULL, 2 + len);
}

// Read a contiguous block of registers.
static void mcp_read_regs(uint8_t reg, uint8_t *out, size_t len)
{
    uint8_t tx[2 + 13] = { MCP_READ, reg };
    uint8_t rx[2 + 13] = { 0 };
    if (len > sizeof(tx) - 2) len = sizeof(tx) - 2;
    mcp_spi_transfer(tx, rx, 2 + len);
    memcpy(out, &rx[2], len);
}

static void mcp_bit_modify(uint8_t reg, uint8_t mask, uint8_t val)
{
    uint8_t tx[4] = { MCP_BIT_MODIFY, reg, mask, val };
    mcp_spi_transfer(tx, NULL, 4);
}

// ─── MCP2515 higher-level operations ────────────────────────────────────────

static void mcp_reset(void)
{
    uint8_t tx[1] = { MCP_RESET };
    mcp_spi_transfer(tx, NULL, 1);
    vTaskDelay(pdMS_TO_TICKS(10));  // MCP2515 needs ~2 ms after reset
}

// Wait until CANSTAT shows the desired mode (up to ~50 ms).
static bool mcp_set_mode(uint8_t mode)
{
    mcp_bit_modify(MCP_CANCTRL, MCP_MODE_MASK, mode);
    for (int i = 0; i < 10; i++) {
        vTaskDelay(pdMS_TO_TICKS(5));
        uint8_t stat = mcp_read_reg(MCP_CANSTAT);
        if ((stat & MCP_MODE_MASK) == mode) return true;
    }
    ESP_LOGE(TAG, "mode transition timeout (wanted 0x%02X, got 0x%02X)",
             mode, mcp_read_reg(MCP_CANSTAT) & MCP_MODE_MASK);
    return false;
}

// ─── Baud-rate configuration (8 MHz MCP2515 crystal) ────────────────────────
//
// CNF1 = SJW | BRP    CNF2 = BTLMODE | SAM | PHSEG1 | PRSEG
// CNF3 = SOF | WAKFIL | PHSEG2
//
// Bit timing summary for 8 MHz clock:
//   TQ = 2 * (BRP+1) / Fosc
//   TBit = (1 + PROP+PHSEG1 + PHSEG2) * TQ
//
// Values below give ~75% sample point.

typedef struct {
    uint32_t baud;
    uint8_t cnf1, cnf2, cnf3;
} baud_entry_t;

static const baud_entry_t s_baud_table[] = {
    // 125 kbps  BRP=3 → TQ=1µs  Tbit=16TQ(1+7+8? — 1+PHSEG1(6)+PRSEG(1)+PHSEG2(4))
    // Using MCP2515 datasheet recommended values at 8MHz
    { 125000,  0x03, 0xB6, 0x04 },
    // 250 kbps
    { 250000,  0x01, 0xB6, 0x04 },
    // 500 kbps
    { 500000,  0x00, 0xB6, 0x04 },
    // 1 Mbps   BRP=0 TQ=250ns  Tbit=8TQ (1+3+1+3)
    { 1000000, 0x00, 0x92, 0x02 },
};

static bool mcp_set_baud(uint32_t baud)
{
    for (size_t i = 0; i < sizeof(s_baud_table) / sizeof(s_baud_table[0]); i++) {
        if (s_baud_table[i].baud == baud) {
            mcp_write_reg(MCP_CNF1, s_baud_table[i].cnf1);
            mcp_write_reg(MCP_CNF2, s_baud_table[i].cnf2);
            mcp_write_reg(MCP_CNF3, s_baud_table[i].cnf3);
            return true;
        }
    }
    ESP_LOGE(TAG, "unsupported baud rate %lu", (unsigned long)baud);
    return false;
}

// ─── Frame I/O ───────────────────────────────────────────────────────────────

typedef struct {
    uint32_t arb_id;   // 11-bit standard or 29-bit extended
    bool     extended; // true = 29-bit
    bool     rtr;
    uint8_t  dlc;
    uint8_t  data[8];
} can_frame_t;

// Returns true if a frame was available and written to `out`.
static bool mcp_rx_frame(can_frame_t *out)
{
    uint8_t intf = mcp_read_reg(MCP_CANINTF);
    uint8_t buf_base;

    if (intf & MCP_RX0IF) {
        buf_base = MCP_RXB0SIDH;
    } else if (intf & MCP_RX1IF) {
        buf_base = MCP_RXB1CTRL + 1; // RXB1SIDH = 0x71
    } else {
        return false;
    }

    // Read 5 header bytes: SIDH, SIDL, EID8, EID0, DLC
    uint8_t hdr[5];
    mcp_read_regs(buf_base, hdr, 5);

    bool extended = (hdr[1] & 0x08) != 0; // EXIDE bit in SIDL
    uint32_t id;
    if (extended) {
        id  = ((uint32_t)(hdr[0]) << 21);
        id |= ((uint32_t)(hdr[1] & 0xE0) << 13);
        id |= ((uint32_t)(hdr[1] & 0x03) << 16);
        id |= ((uint32_t)(hdr[2]) << 8);
        id |= (uint32_t)(hdr[3]);
    } else {
        id = ((uint32_t)hdr[0] << 3) | ((hdr[1] >> 5) & 0x07);
    }

    uint8_t dlc = hdr[4] & 0x0F;
    bool rtr    = (hdr[4] & 0x40) != 0;

    uint8_t data[8] = { 0 };
    if (dlc > 0 && !rtr) {
        mcp_read_regs(buf_base + 5, data, dlc);
    }

    out->arb_id   = id;
    out->extended = extended;
    out->rtr      = rtr;
    out->dlc      = dlc;
    memcpy(out->data, data, sizeof(data));

    // Clear the interrupt flag for whichever buffer we just read
    if (intf & MCP_RX0IF) {
        mcp_bit_modify(MCP_CANINTF, MCP_RX0IF, 0x00);
    } else {
        mcp_bit_modify(MCP_CANINTF, MCP_RX1IF, 0x00);
    }

    return true;
}

// Transmit a CAN frame via TX buffer 0.
static bool mcp_tx_frame(const can_frame_t *f)
{
    // Wait for TX buffer 0 to become free (TXREQ bit clear)
    for (int i = 0; i < 20; i++) {
        uint8_t ctrl = mcp_read_reg(MCP_TXB0CTRL);
        if (!(ctrl & 0x08)) break;  // TXREQ = bit3
        vTaskDelay(pdMS_TO_TICKS(5));
        if (i == 19) {
            ESP_LOGE(TAG, "TX buffer 0 busy");
            return false;
        }
    }

    uint8_t hdr[5];
    if (f->extended) {
        hdr[0] = (f->arb_id >> 21) & 0xFF;
        hdr[1] = ((f->arb_id >> 13) & 0xE0) | 0x08 | ((f->arb_id >> 16) & 0x03);
        hdr[2] = (f->arb_id >> 8) & 0xFF;
        hdr[3] = f->arb_id & 0xFF;
    } else {
        hdr[0] = (f->arb_id >> 3) & 0xFF;
        hdr[1] = (f->arb_id & 0x07) << 5;
        hdr[2] = 0;
        hdr[3] = 0;
    }
    hdr[4] = (f->rtr ? 0x40 : 0x00) | (f->dlc & 0x0F);

    mcp_write_regs(MCP_TXB0SIDH, hdr, 5);
    if (f->dlc > 0) {
        mcp_write_regs(MCP_TXB0SIDH + 5, f->data, f->dlc);
    }

    // Request-to-send TX buffer 0
    uint8_t rts = MCP_RTS_TX0;
    mcp_spi_transfer(&rts, NULL, 1);

    return true;
}

// ─── Public init ────────────────────────────────────────────────────────────

void can_init(void)
{
    if (s_initialized) return;

    // SPI bus config
    spi_bus_config_t bus_cfg = {
        .mosi_io_num   = CAN_SPI_MOSI,
        .miso_io_num   = CAN_SPI_MISO,
        .sclk_io_num   = CAN_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 32,
    };
    esp_err_t err = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI bus init failed: %s (no CAN hardware?)", esp_err_to_name(err));
        return;
    }

    // MCP2515 device: max 10 MHz SPI clock, mode 0,0
    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = 10 * 1000 * 1000,
        .mode           = 0,
        .spics_io_num   = CAN_SPI_CS,
        .queue_size     = 4,
    };
    err = spi_bus_add_device(SPI2_HOST, &dev_cfg, &s_spi);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SPI device add failed: %s (no CAN hardware?)", esp_err_to_name(err));
        spi_bus_free(SPI2_HOST);
        return;
    }

    // CAN_INT_PIN as input (active-low interrupt from MCP2515)
    gpio_config_t int_cfg = {
        .pin_bit_mask = (1ULL << CAN_INT_PIN),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    err = gpio_config(&int_cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "GPIO config failed: %s (no CAN hardware?)", esp_err_to_name(err));
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        spi_bus_free(SPI2_HOST);
        return;
    }

    // MCP2515 init sequence
    mcp_reset();

    // Probe: read CANSTAT register — should be 0x80 (config mode after reset)
    uint8_t canstat = mcp_read_reg(MCP_CANSTAT);
    if ((canstat & MCP_MODE_MASK) != MCP_MODE_CONFIG) {
        ESP_LOGW(TAG, "MCP2515 not detected (CANSTAT=0x%02X, expected config mode)", canstat);
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        spi_bus_free(SPI2_HOST);
        return;
    }
    ESP_LOGI(TAG, "MCP2515 detected (CANSTAT=0x%02X)", canstat);

    if (!mcp_set_mode(MCP_MODE_CONFIG)) {
        ESP_LOGE(TAG, "failed to enter config mode");
        return;
    }

    // Default baud rate from config.h
    mcp_set_baud(CAN_BAUD_DEFAULT);

    // Accept all frames on both RX buffers (masks = 0, filters disabled)
    mcp_write_reg(MCP_RXB0CTRL, MCP_RXB_RX_ANY);
    mcp_write_reg(MCP_RXB1CTRL, MCP_RXB_RX_ANY | 0x01); // also roll over to RXB1

    // Enable RX interrupts (not strictly required for polling, but good practice)
    mcp_write_reg(MCP_CANINTE, MCP_RX0IF | MCP_RX1IF);

    mcp_set_mode(MCP_MODE_NORMAL);

    s_initialized = true;
    ESP_LOGI(TAG, "MCP2515 initialized at %lu bps", (unsigned long)CAN_BAUD_DEFAULT);
}

// ─── Helper: parse baud parameter (accepts int or common string) ─────────────

static uint32_t parse_baud(cJSON *params)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(params, "baud");
    if (!item) return CAN_BAUD_DEFAULT;
    if (cJSON_IsNumber(item)) return (uint32_t)item->valuedouble;
    if (cJSON_IsString(item)) {
        const char *s = item->valuestring;
        if (strcmp(s, "125k") == 0)  return 125000;
        if (strcmp(s, "250k") == 0)  return 250000;
        if (strcmp(s, "500k") == 0)  return 500000;
        if (strcmp(s, "1M")   == 0)  return 1000000;
        return (uint32_t)atol(s);
    }
    return CAN_BAUD_DEFAULT;
}

// ─── Helper: build hex string from bytes ────────────────────────────────────

static void bytes_to_hex(const uint8_t *bytes, uint8_t len, char *out, size_t out_size)
{
    out[0] = '\0';
    for (uint8_t i = 0; i < len && (i * 2 + 2) < (int)out_size; i++) {
        snprintf(out + i * 2, 3, "%02X", bytes[i]);
    }
}

// ─── Helper: parse hex string into byte array. Returns byte count or -1. ────

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    // Strip optional "0x" / "0X" prefix
    if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex     += 2;
        hex_len -= 2;
    }
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;

    size_t n = hex_len / 2;
    for (size_t i = 0; i < n; i++) {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return (int)n;
}

// ─── Action: "listen" ───────────────────────────────────────────────────────
//
// params: { "baud": <int|str>, "duration_s": <int> }
// Output: one JSON line per frame to stdout, then returns summary object.

static cJSON *action_listen(cJSON *params)
{
    uint32_t baud      = parse_baud(params);
    cJSON *dur_item    = cJSON_GetObjectItemCaseSensitive(params, "duration_s");
    uint32_t duration  = dur_item && cJSON_IsNumber(dur_item) ? (uint32_t)dur_item->valuedouble : 10;

    // Switch to requested baud in listen-only mode
    if (!mcp_set_mode(MCP_MODE_CONFIG)) {
        return cJSON_CreateString("error: could not enter config mode");
    }
    if (!mcp_set_baud(baud)) {
        mcp_set_mode(MCP_MODE_NORMAL);
        return cJSON_CreateString("error: unsupported baud rate");
    }
    mcp_set_mode(MCP_MODE_LISTEN_ONLY);

    uint64_t deadline = (uint64_t)esp_timer_get_time() + (uint64_t)duration * 1000000ULL;
    uint32_t frame_count = 0;

    while (esp_timer_get_time() < deadline && !g_stop_requested) {
        can_frame_t frame;
        if (mcp_rx_frame(&frame)) {
            char hex[17] = "";
            bytes_to_hex(frame.data, frame.dlc, hex, sizeof(hex));

            char line[JSON_BUFFER_SIZE];
            snprintf(line, sizeof(line),
                     "{\"arb_id\":\"0x%03lX\",\"dlc\":%u,\"data\":\"%s\",\"ts\":%llu}",
                     (unsigned long)frame.arb_id,
                     frame.dlc,
                     hex,
                     (unsigned long long)(esp_timer_get_time() / 1000));
            printf("%s\n", line);
            frame_count++;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    mcp_set_mode(MCP_MODE_NORMAL);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "status", "done");
    cJSON_AddNumberToObject(result, "frames_received", frame_count);
    cJSON_AddNumberToObject(result, "duration_s", duration);
    return result;
}

// ─── Action: "send" ─────────────────────────────────────────────────────────
//
// params: { "id": "0x123", "data": "DEADBEEF", "confirm": "YES_I_UNDERSTAND" }

static cJSON *action_send(cJSON *params)
{
    if (!safety_check_confirm(params)) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "safety_check_failed");
        cJSON_AddStringToObject(err, "detail",
            "Set param 'confirm' to 'YES_I_UNDERSTAND' to transmit CAN frames");
        return err;
    }

    cJSON *id_item   = cJSON_GetObjectItemCaseSensitive(params, "id");
    cJSON *data_item = cJSON_GetObjectItemCaseSensitive(params, "data");

    if (!id_item || !cJSON_IsString(id_item)) {
        return cJSON_CreateString("error: 'id' (hex string) required");
    }

    // Parse arbitration ID
    const char *id_str = id_item->valuestring;
    uint32_t arb_id = (uint32_t)strtol(
        (strncmp(id_str, "0x", 2) == 0 || strncmp(id_str, "0X", 2) == 0)
            ? id_str + 2 : id_str,
        NULL, 16);

    can_frame_t frame = { 0 };
    frame.arb_id   = arb_id;
    frame.extended = (arb_id > 0x7FF); // use extended for >11-bit IDs

    if (data_item && cJSON_IsString(data_item)) {
        int n = hex_to_bytes(data_item->valuestring, frame.data, 8);
        if (n < 0) {
            return cJSON_CreateString("error: 'data' must be a valid hex string (max 8 bytes)");
        }
        frame.dlc = (uint8_t)n;
    }

    bool ok = mcp_tx_frame(&frame);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "status", ok ? "sent" : "error");
    char id_hex[12];
    snprintf(id_hex, sizeof(id_hex), "0x%03lX", (unsigned long)arb_id);
    cJSON_AddStringToObject(result, "arb_id", id_hex);
    cJSON_AddNumberToObject(result, "dlc", frame.dlc);
    return result;
}

// ─── Action: "scan_ids" ─────────────────────────────────────────────────────
//
// params: { "baud": <int|str>, "duration_s": <int> }
// Returns sorted list of unique arbitration IDs with frame counts.

#define MAX_UNIQUE_IDS 256

typedef struct {
    uint32_t arb_id;
    uint32_t count;
} id_entry_t;

static int id_entry_cmp(const void *a, const void *b)
{
    const id_entry_t *ea = (const id_entry_t *)a;
    const id_entry_t *eb = (const id_entry_t *)b;
    if (ea->arb_id < eb->arb_id) return -1;
    if (ea->arb_id > eb->arb_id) return  1;
    return 0;
}

static cJSON *action_scan_ids(cJSON *params)
{
    uint32_t baud     = parse_baud(params);
    cJSON *dur_item   = cJSON_GetObjectItemCaseSensitive(params, "duration_s");
    uint32_t duration = dur_item && cJSON_IsNumber(dur_item) ? (uint32_t)dur_item->valuedouble : 10;

    if (!mcp_set_mode(MCP_MODE_CONFIG)) {
        return cJSON_CreateString("error: could not enter config mode");
    }
    if (!mcp_set_baud(baud)) {
        mcp_set_mode(MCP_MODE_NORMAL);
        return cJSON_CreateString("error: unsupported baud rate");
    }
    mcp_set_mode(MCP_MODE_LISTEN_ONLY);

    id_entry_t ids[MAX_UNIQUE_IDS] = { 0 };
    int unique_count = 0;
    uint32_t total_frames = 0;

    uint64_t deadline = (uint64_t)esp_timer_get_time() + (uint64_t)duration * 1000000ULL;

    while (esp_timer_get_time() < deadline && !g_stop_requested) {
        can_frame_t frame;
        if (!mcp_rx_frame(&frame)) {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }
        total_frames++;

        // Search existing IDs
        bool found = false;
        for (int i = 0; i < unique_count; i++) {
            if (ids[i].arb_id == frame.arb_id) {
                ids[i].count++;
                found = true;
                break;
            }
        }
        if (!found && unique_count < MAX_UNIQUE_IDS) {
            ids[unique_count].arb_id = frame.arb_id;
            ids[unique_count].count  = 1;
            unique_count++;
        }
    }

    mcp_set_mode(MCP_MODE_NORMAL);

    // Sort by arb_id
    qsort(ids, (size_t)unique_count, sizeof(id_entry_t), id_entry_cmp);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "total_frames", total_frames);
    cJSON_AddNumberToObject(result, "unique_ids",   unique_count);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < unique_count; i++) {
        cJSON *entry = cJSON_CreateObject();
        char id_hex[12];
        snprintf(id_hex, sizeof(id_hex), "0x%03lX", (unsigned long)ids[i].arb_id);
        cJSON_AddStringToObject(entry, "arb_id", id_hex);
        cJSON_AddNumberToObject(entry, "count",  ids[i].count);
        cJSON_AddItemToArray(arr, entry);
    }
    cJSON_AddItemToObject(result, "ids", arr);
    return result;
}

// ─── Public command dispatcher ───────────────────────────────────────────────

bool can_is_ready(void) { return s_initialized; }

cJSON *can_handle_command(const char *action, cJSON *params)
{
    if (!s_initialized) {
        return cJSON_CreateString("error: CAN handler not initialized");
    }
    if (strcmp(action, "listen") == 0)   return action_listen(params);
    if (strcmp(action, "send") == 0)     return action_send(params);
    if (strcmp(action, "scan_ids") == 0) return action_scan_ids(params);

    cJSON *err = cJSON_CreateObject();
    cJSON_AddStringToObject(err, "error", "unknown action");
    cJSON_AddStringToObject(err, "available", "listen | send | scan_ids");
    return err;
}
