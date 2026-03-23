/*
 * modbus_handler.c — Modbus RTU master over RS-485 (UART1)
 *
 * Supports FC01 (read coils), FC03 (read holding registers),
 * FC04 (read input registers), FC06 (write single register),
 * FC17 (report slave ID / bus scan), FC43/sub14 (device identification).
 *
 * RS-485 half-duplex direction is controlled via RS485_DE_RE_PIN:
 *   HIGH = transmit (driver enabled / receiver disabled)
 *   LOW  = receive  (driver disabled / receiver enabled)
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char *TAG = "modbus";

#define MODBUS_UART         UART_NUM_1
#define MODBUS_BUF_SIZE     256
#define MODBUS_RESP_TIMEOUT_MS  1000   /* Max wait for a slave response      */
#define MODBUS_TX_SETTLE_US     100    /* DE→TX propagation guard time       */
#define MODBUS_RX_SETTLE_US     100    /* TX complete → RE assert guard time */

/* -------------------------------------------------------------------------
 * CRC-16/IBM (Modbus)
 * Initial value 0xFFFF, polynomial 0xA001 (reflected 0x8005)
 * ------------------------------------------------------------------------- */
static uint16_t modbus_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

/* -------------------------------------------------------------------------
 * Direction control helpers
 * ------------------------------------------------------------------------- */
static inline void rs485_tx_mode(void)
{
    gpio_set_level(RS485_DE_RE_PIN, 1);
    esp_rom_delay_us(MODBUS_TX_SETTLE_US);
}

static inline void rs485_rx_mode(void)
{
    /* Wait for UART TX FIFO to drain before dropping DE */
    uart_wait_tx_done(MODBUS_UART, pdMS_TO_TICKS(100));
    esp_rom_delay_us(MODBUS_RX_SETTLE_US);
    gpio_set_level(RS485_DE_RE_PIN, 0);
}

/* -------------------------------------------------------------------------
 * Inter-frame silence
 * ------------------------------------------------------------------------- */
static inline void modbus_frame_delay(void)
{
    esp_rom_delay_us(MODBUS_INTER_FRAME_US);
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ------------------------------------------------------------------------- */
void modbus_init(void)
{
    /* GPIO — DE/RE direction pin */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << RS485_DE_RE_PIN),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(RS485_DE_RE_PIN, 0); /* Default: RX mode */

    /* UART1 */
    uart_config_t uart_cfg = {
        .baud_rate  = RS485_BAUD_DEFAULT,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(MODBUS_UART,
                                        MODBUS_BUF_SIZE * 2,
                                        MODBUS_BUF_SIZE * 2,
                                        0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(MODBUS_UART, &uart_cfg));
    ESP_ERROR_CHECK(uart_set_pin(MODBUS_UART,
                                 RS485_TX_PIN, RS485_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    /* Enable RS-485 half-duplex mode in the UART hardware */
    ESP_ERROR_CHECK(uart_set_mode(MODBUS_UART, UART_MODE_RS485_HALF_DUPLEX));

    ESP_LOGI(TAG, "Modbus RTU initialised on UART%d (%d baud)",
             MODBUS_UART, RS485_BAUD_DEFAULT);
}

/* -------------------------------------------------------------------------
 * Low-level frame TX/RX
 *
 * Builds the complete ADU: [addr][function][data...][CRC lo][CRC hi]
 * Sends it, then switches to RX and waits up to timeout_ms for a response.
 * Returns number of bytes received (0 = timeout/error).
 * ------------------------------------------------------------------------- */
static int modbus_transaction(const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t resp_max,
                              int timeout_ms)
{
    /* Flush any stale RX bytes */
    uart_flush(MODBUS_UART);

    modbus_frame_delay();
    rs485_tx_mode();
    uart_write_bytes(MODBUS_UART, (const char *)req, req_len);
    rs485_rx_mode();
    modbus_frame_delay();

    int total = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (esp_timer_get_time() < deadline) {
        int avail = uart_read_bytes(MODBUS_UART,
                                    resp + total,
                                    resp_max - total,
                                    pdMS_TO_TICKS(20));
        if (avail > 0) {
            total += avail;
            /* Stop reading once we have at least 4 bytes and the inter-frame
             * silence has elapsed (no new data within ~5 ms). */
            if (total >= 4) {
                int extra = uart_read_bytes(MODBUS_UART,
                                            resp + total,
                                            resp_max - total,
                                            pdMS_TO_TICKS(5));
                if (extra <= 0) break;
                total += extra;
            }
        }
    }

    return total;
}

/* -------------------------------------------------------------------------
 * Build a request frame in-place and return its length.
 * 'pdu' must point to a buffer of at least (2 + data_len) bytes after the
 * address and function-code prefix; caller supplies the complete PDU content
 * in buf[1..1+pdu_len-1] and we prepend addr and append CRC.
 *
 * Layout written into buf:
 *   buf[0]          = slave_addr
 *   buf[1]          = function_code
 *   buf[2..N-1]     = data (caller fills before calling)
 *   buf[N]          = CRC lo
 *   buf[N+1]        = CRC hi
 *
 * 'total' = 2 (addr+fc) + data_len
 * ------------------------------------------------------------------------- */
static size_t modbus_build_request(uint8_t *buf, uint8_t slave_addr,
                                   uint8_t function_code,
                                   const uint8_t *data, size_t data_len)
{
    buf[0] = slave_addr;
    buf[1] = function_code;
    if (data && data_len) {
        memcpy(buf + 2, data, data_len);
    }
    size_t frame_len = 2 + data_len;
    uint16_t crc = modbus_crc16(buf, frame_len);
    buf[frame_len]     = (uint8_t)(crc & 0xFF);
    buf[frame_len + 1] = (uint8_t)(crc >> 8);
    return frame_len + 2;
}

/* Verify CRC on a received frame. */
static bool modbus_check_crc(const uint8_t *frame, size_t len)
{
    if (len < 4) return false;
    uint16_t calc = modbus_crc16(frame, len - 2);
    uint16_t recv = (uint16_t)frame[len - 2] | ((uint16_t)frame[len - 1] << 8);
    return calc == recv;
}

/* -------------------------------------------------------------------------
 * Error response helpers
 * ------------------------------------------------------------------------- */
static cJSON *modbus_error(const char *msg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "error");
    cJSON_AddStringToObject(root, "error", msg);
    return root;
}

static cJSON *modbus_ok(cJSON *data)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ok");
    if (data) cJSON_AddItemToObject(root, "data", data);
    return root;
}

/* Determine whether a Modbus exception response was received.
 * An exception response has bit 7 set in the function code byte. */
static const char *modbus_exception_str(uint8_t code)
{
    switch (code) {
        case 0x01: return "Illegal Function";
        case 0x02: return "Illegal Data Address";
        case 0x03: return "Illegal Data Value";
        case 0x04: return "Slave Device Failure";
        case 0x05: return "Acknowledge";
        case 0x06: return "Slave Device Busy";
        case 0x08: return "Memory Parity Error";
        case 0x0A: return "Gateway Path Unavailable";
        case 0x0B: return "Gateway Target Device Failed to Respond";
        default:   return "Unknown Exception";
    }
}

/* -------------------------------------------------------------------------
 * Read registers (FC03 / FC04) — shared implementation
 * params: {addr, reg, count}
 * ------------------------------------------------------------------------- */
static cJSON *modbus_read_registers(cJSON *params, uint8_t function_code)
{
    cJSON *j_addr  = cJSON_GetObjectItemCaseSensitive(params, "addr");
    cJSON *j_reg   = cJSON_GetObjectItemCaseSensitive(params, "reg");
    cJSON *j_count = cJSON_GetObjectItemCaseSensitive(params, "count");

    if (!cJSON_IsNumber(j_addr) || !cJSON_IsNumber(j_reg) ||
        !cJSON_IsNumber(j_count)) {
        return modbus_error("Missing or invalid params: addr, reg, count required");
    }

    uint8_t  slave = (uint8_t)j_addr->valueint;
    uint16_t reg   = (uint16_t)j_reg->valueint;
    uint16_t count = (uint16_t)j_count->valueint;

    if (count < 1 || count > 125) {
        return modbus_error("count must be 1-125");
    }

    uint8_t pdu_data[4] = {
        (uint8_t)(reg >> 8),   (uint8_t)(reg & 0xFF),
        (uint8_t)(count >> 8), (uint8_t)(count & 0xFF),
    };
    uint8_t req[8];
    size_t req_len = modbus_build_request(req, slave, function_code,
                                          pdu_data, sizeof(pdu_data));

    uint8_t resp[MODBUS_BUF_SIZE] = {0};
    int rlen = modbus_transaction(req, req_len, resp, sizeof(resp),
                                  MODBUS_RESP_TIMEOUT_MS);

    if (rlen < 5) return modbus_error("No response or too short");
    if (!modbus_check_crc(resp, rlen)) return modbus_error("CRC mismatch");
    if (resp[1] & 0x80) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Exception %02X: %s",
                 resp[2], modbus_exception_str(resp[2]));
        return modbus_error(msg);
    }
    if (resp[1] != function_code) return modbus_error("Unexpected function code");

    uint8_t byte_count = resp[2];
    if (rlen < (int)(3 + byte_count + 2)) return modbus_error("Response truncated");

    cJSON *values = cJSON_CreateArray();
    for (int i = 0; i < byte_count / 2; i++) {
        uint16_t val = ((uint16_t)resp[3 + i * 2] << 8) | resp[4 + i * 2];
        cJSON_AddItemToArray(values, cJSON_CreateNumber(val));
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "addr",        slave);
    cJSON_AddNumberToObject(data, "reg",         reg);
    cJSON_AddNumberToObject(data, "count",       count);
    cJSON_AddItemToObject(data, "values", values);
    return modbus_ok(data);
}

/* -------------------------------------------------------------------------
 * Read coils (FC01)
 * params: {addr, reg, count}
 * ------------------------------------------------------------------------- */
static cJSON *modbus_read_coils(cJSON *params)
{
    cJSON *j_addr  = cJSON_GetObjectItemCaseSensitive(params, "addr");
    cJSON *j_reg   = cJSON_GetObjectItemCaseSensitive(params, "reg");
    cJSON *j_count = cJSON_GetObjectItemCaseSensitive(params, "count");

    if (!cJSON_IsNumber(j_addr) || !cJSON_IsNumber(j_reg) ||
        !cJSON_IsNumber(j_count)) {
        return modbus_error("Missing or invalid params: addr, reg, count required");
    }

    uint8_t  slave = (uint8_t)j_addr->valueint;
    uint16_t reg   = (uint16_t)j_reg->valueint;
    uint16_t count = (uint16_t)j_count->valueint;

    if (count < 1 || count > 2000) {
        return modbus_error("count must be 1-2000");
    }

    uint8_t pdu_data[4] = {
        (uint8_t)(reg >> 8),   (uint8_t)(reg & 0xFF),
        (uint8_t)(count >> 8), (uint8_t)(count & 0xFF),
    };
    uint8_t req[8];
    size_t req_len = modbus_build_request(req, slave, 0x01, pdu_data, 4);

    uint8_t resp[MODBUS_BUF_SIZE] = {0};
    int rlen = modbus_transaction(req, req_len, resp, sizeof(resp),
                                  MODBUS_RESP_TIMEOUT_MS);

    if (rlen < 5) return modbus_error("No response or too short");
    if (!modbus_check_crc(resp, rlen)) return modbus_error("CRC mismatch");
    if (resp[1] & 0x80) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Exception %02X: %s",
                 resp[2], modbus_exception_str(resp[2]));
        return modbus_error(msg);
    }
    if (resp[1] != 0x01) return modbus_error("Unexpected function code");

    uint8_t byte_count = resp[2];
    if (rlen < (int)(3 + byte_count + 2)) return modbus_error("Response truncated");

    /* Expand packed bits into an array of booleans */
    cJSON *values = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        int byte_idx = i / 8;
        int bit_idx  = i % 8;
        bool coil = (resp[3 + byte_idx] >> bit_idx) & 0x01;
        cJSON_AddItemToArray(values, cJSON_CreateBool(coil));
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "addr",  slave);
    cJSON_AddNumberToObject(data, "reg",   reg);
    cJSON_AddNumberToObject(data, "count", count);
    cJSON_AddItemToObject(data, "values", values);
    return modbus_ok(data);
}

/* -------------------------------------------------------------------------
 * Write single register (FC06)
 * params: {addr, reg, value, confirm}
 * Requires safety_check_confirm().
 * ------------------------------------------------------------------------- */
static cJSON *modbus_write_register(cJSON *params)
{
    if (!safety_check_confirm(params)) {
        return modbus_error("Write blocked: confirm field missing or false");
    }

    cJSON *j_addr  = cJSON_GetObjectItemCaseSensitive(params, "addr");
    cJSON *j_reg   = cJSON_GetObjectItemCaseSensitive(params, "reg");
    cJSON *j_value = cJSON_GetObjectItemCaseSensitive(params, "value");

    if (!cJSON_IsNumber(j_addr) || !cJSON_IsNumber(j_reg) ||
        !cJSON_IsNumber(j_value)) {
        return modbus_error("Missing or invalid params: addr, reg, value required");
    }

    uint8_t  slave = (uint8_t)j_addr->valueint;
    uint16_t reg   = (uint16_t)j_reg->valueint;
    uint16_t value = (uint16_t)j_value->valueint;

    uint8_t pdu_data[4] = {
        (uint8_t)(reg >> 8),   (uint8_t)(reg & 0xFF),
        (uint8_t)(value >> 8), (uint8_t)(value & 0xFF),
    };
    uint8_t req[8];
    size_t req_len = modbus_build_request(req, slave, 0x06, pdu_data, 4);

    uint8_t resp[MODBUS_BUF_SIZE] = {0};
    int rlen = modbus_transaction(req, req_len, resp, sizeof(resp),
                                  MODBUS_RESP_TIMEOUT_MS);

    if (rlen < 8) return modbus_error("No response or too short");
    if (!modbus_check_crc(resp, rlen)) return modbus_error("CRC mismatch");
    if (resp[1] & 0x80) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Exception %02X: %s",
                 resp[2], modbus_exception_str(resp[2]));
        return modbus_error(msg);
    }
    if (resp[1] != 0x06) return modbus_error("Unexpected function code");

    /* Echo-back verification */
    uint16_t echo_reg = ((uint16_t)resp[2] << 8) | resp[3];
    uint16_t echo_val = ((uint16_t)resp[4] << 8) | resp[5];
    if (echo_reg != reg || echo_val != value) {
        return modbus_error("Echo mismatch: write may have failed");
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "addr",  slave);
    cJSON_AddNumberToObject(data, "reg",   reg);
    cJSON_AddNumberToObject(data, "value", value);
    cJSON_AddStringToObject(data, "result", "written");
    return modbus_ok(data);
}

/* -------------------------------------------------------------------------
 * Scan bus (FC17 — Report Slave ID)
 * params: {range: [start, end]}
 * Iterates slave addresses and records those that respond.
 * ------------------------------------------------------------------------- */
static cJSON *modbus_scan_bus(cJSON *params)
{
    cJSON *j_range = cJSON_GetObjectItemCaseSensitive(params, "range");
    if (!cJSON_IsArray(j_range) || cJSON_GetArraySize(j_range) != 2) {
        return modbus_error("range must be a 2-element array [start, end]");
    }

    int start = cJSON_GetArrayItem(j_range, 0)->valueint;
    int end   = cJSON_GetArrayItem(j_range, 1)->valueint;

    if (start < 1 || end > 247 || start > end) {
        return modbus_error("range values must satisfy 1 <= start <= end <= 247");
    }

    cJSON *found = cJSON_CreateArray();

    for (int addr = start; addr <= end; addr++) {
        uint8_t req[4];
        /* FC17 (0x11) Report Slave ID — no data bytes */
        size_t req_len = modbus_build_request(req, (uint8_t)addr,
                                              0x11, NULL, 0);
        uint8_t resp[MODBUS_BUF_SIZE] = {0};
        /* Use a shorter timeout during scan to keep it responsive */
        int rlen = modbus_transaction(req, req_len, resp, sizeof(resp), 300);

        if (rlen >= 4 && modbus_check_crc(resp, rlen) && !(resp[1] & 0x80)) {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddNumberToObject(entry, "addr", addr);
            /* Include raw slave ID data if present */
            if (rlen > 4 && resp[1] == 0x11) {
                uint8_t byte_count = resp[2];
                if (byte_count > 0 && rlen >= (int)(3 + byte_count + 2)) {
                    /* Byte 3 is the slave ID, byte 4 is run indicator */
                    cJSON_AddNumberToObject(entry, "slave_id", resp[3]);
                    if (byte_count >= 2) {
                        cJSON_AddBoolToObject(entry, "run_indicator",
                                              resp[4] == 0xFF);
                    }
                }
            }
            cJSON_AddItemToArray(found, entry);
        }

        /* Brief inter-frame pause between scan probes */
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "scanned",  end - start + 1);
    cJSON_AddItemToObject(data, "devices", found);
    return modbus_ok(data);
}

/* -------------------------------------------------------------------------
 * Read Device Identification (FC43 / MEI 0x0E, sub 0x01)
 * params: {addr}
 * Returns vendor, product, version strings (objects 0x00, 0x01, 0x02).
 * ------------------------------------------------------------------------- */
static cJSON *modbus_device_id(cJSON *params)
{
    cJSON *j_addr = cJSON_GetObjectItemCaseSensitive(params, "addr");
    if (!cJSON_IsNumber(j_addr)) {
        return modbus_error("Missing param: addr required");
    }
    uint8_t slave = (uint8_t)j_addr->valueint;

    /*
     * FC43 / MEI Type 0x0E request:
     *   [addr][0x2B][0x0E][read_device_id_code=0x01][object_id=0x00][CRC lo][CRC hi]
     * read_device_id_code 0x01 = request stream of basic objects.
     */
    uint8_t pdu_data[3] = {0x0E, 0x01, 0x00};
    uint8_t req[7];
    size_t req_len = modbus_build_request(req, slave, 0x2B,
                                          pdu_data, sizeof(pdu_data));

    uint8_t resp[MODBUS_BUF_SIZE] = {0};
    int rlen = modbus_transaction(req, req_len, resp, sizeof(resp),
                                  MODBUS_RESP_TIMEOUT_MS);

    if (rlen < 8) return modbus_error("No response or too short");
    if (!modbus_check_crc(resp, rlen)) return modbus_error("CRC mismatch");
    if (resp[1] & 0x80) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Exception %02X: %s",
                 resp[2], modbus_exception_str(resp[2]));
        return modbus_error(msg);
    }
    if (resp[1] != 0x2B || resp[2] != 0x0E) {
        return modbus_error("Unexpected MEI response");
    }

    /*
     * Response layout (after addr+fc+mei_type+read_dev_id_code):
     *   [3] MEI type     = 0x0E
     *   [4] Read Dev ID  = 0x01
     *   [5] Conformity   = 0x01/0x02/0x03/0x81/0x82/0x83
     *   [6] More/Next    = 0x00 (no more)
     *   [7] Next ObjId   = 0x00
     *   [8] Num Objects
     *   then repeated: [obj_id][obj_len][obj_data...]
     */
    if (rlen < 10) return modbus_error("MEI response too short");

    uint8_t num_objects = resp[8];
    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "addr",        slave);
    cJSON_AddNumberToObject(data, "conformity",  resp[5]);

    int pos = 9;
    for (int i = 0; i < num_objects && pos + 1 < rlen - 2; i++) {
        uint8_t obj_id  = resp[pos];
        uint8_t obj_len = resp[pos + 1];
        pos += 2;
        if (pos + obj_len > rlen - 2) break;

        char str_val[128] = {0};
        size_t copy_len = obj_len < sizeof(str_val) - 1 ? obj_len : sizeof(str_val) - 1;
        memcpy(str_val, &resp[pos], copy_len);
        str_val[copy_len] = '\0';
        pos += obj_len;

        switch (obj_id) {
            case 0x00: cJSON_AddStringToObject(data, "vendor",  str_val); break;
            case 0x01: cJSON_AddStringToObject(data, "product", str_val); break;
            case 0x02: cJSON_AddStringToObject(data, "version", str_val); break;
            default: {
                char key[16];
                snprintf(key, sizeof(key), "obj_%02x", obj_id);
                cJSON_AddStringToObject(data, key, str_val);
            }
        }
    }

    return modbus_ok(data);
}

/* -------------------------------------------------------------------------
 * Public command dispatcher
 * ------------------------------------------------------------------------- */
cJSON *modbus_handle_command(const char *action, cJSON *params)
{
    if (!action || !params) {
        return modbus_error("action and params are required");
    }

    if (!safety_rate_limit("modbus")) {
        return modbus_error("Rate limit exceeded — wait before sending another command");
    }

    if (strcmp(action, "read_holding") == 0) {
        return modbus_read_registers(params, 0x03);
    } else if (strcmp(action, "read_input") == 0) {
        return modbus_read_registers(params, 0x04);
    } else if (strcmp(action, "read_coils") == 0) {
        return modbus_read_coils(params);
    } else if (strcmp(action, "write_register") == 0) {
        return modbus_write_register(params);
    } else if (strcmp(action, "scan_bus") == 0) {
        return modbus_scan_bus(params);
    } else if (strcmp(action, "device_id") == 0) {
        return modbus_device_id(params);
    }

    char msg[80];
    snprintf(msg, sizeof(msg), "Unknown action: %s", action);
    return modbus_error(msg);
}
