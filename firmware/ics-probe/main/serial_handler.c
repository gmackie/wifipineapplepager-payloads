/*
 * serial_handler.c — RS-232 raw serial handler (UART2)
 *
 * Actions:
 *   "send"        — hex-decode input, write to UART, return hex-encoded response
 *   "passthrough" — bridge USB CDC ↔ RS-232 until "stop" command
 *   "auto_baud"   — probe common baud rates, return first that gives printable ASCII
 */

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char *TAG = "serial";
static bool s_initialized = false;

#define SERIAL_UART         UART_NUM_2
#define SERIAL_BUF_SIZE     SERIAL_BUFFER_SIZE   /* from config.h */

/* Common baud rates tried during auto-detection, slowest → fastest */
static const int auto_baud_rates[] = {
    1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200
};
#define NUM_AUTO_BAUD_RATES  (int)(sizeof(auto_baud_rates) / sizeof(auto_baud_rates[0]))

/* Current configured baud so we can skip redundant reconfiguration */
static int s_current_baud = RS232_BAUD_DEFAULT;

/* Passthrough active flag (set/cleared by task or command context) */
static volatile bool s_passthrough_active = false;

/* -------------------------------------------------------------------------
 * UART2 reconfiguration (baud rate only; 8N1 fixed)
 * ------------------------------------------------------------------------- */
static esp_err_t serial_set_baud(int baud)
{
    if (baud == s_current_baud) return ESP_OK;
    esp_err_t err = uart_set_baudrate(SERIAL_UART, (uint32_t)baud);
    if (err == ESP_OK) {
        s_current_baud = baud;
        ESP_LOGI(TAG, "Baud rate set to %d", baud);
    } else {
        ESP_LOGE(TAG, "Failed to set baud rate %d: %s", baud, esp_err_to_name(err));
    }
    return err;
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ------------------------------------------------------------------------- */
void serial_init(void)
{
    uart_config_t uart_cfg = {
        .baud_rate  = RS232_BAUD_DEFAULT,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t err;
    err = uart_param_config(SERIAL_UART, &uart_cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "RS-232 param config failed: %s (no hardware?)", esp_err_to_name(err));
        return;
    }
    err = uart_set_pin(SERIAL_UART, RS232_TX_PIN, RS232_RX_PIN,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "RS-232 set_pin failed: %s", esp_err_to_name(err));
        return;
    }
    err = uart_driver_install(SERIAL_UART, SERIAL_BUF_SIZE * 2,
                              SERIAL_BUF_SIZE * 2, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "RS-232 driver install failed: %s", esp_err_to_name(err));
        return;
    }

    s_current_baud = RS232_BAUD_DEFAULT;
    ESP_LOGI(TAG, "RS-232 initialised on UART%d (%d baud)",
             SERIAL_UART, RS232_BAUD_DEFAULT);
    s_initialized = true;
}

/* -------------------------------------------------------------------------
 * Hex encoding / decoding utilities
 * ------------------------------------------------------------------------- */

/* Decode a hex string into binary. Returns decoded length or -1 on error.
 * dst must be at least strlen(hex)/2 bytes. */
static int hex_decode(const char *hex, uint8_t *dst, size_t dst_max)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;

    size_t out_len = hex_len / 2;
    if (out_len > dst_max) return -1;

    for (size_t i = 0; i < out_len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];

        /* Convert each nibble */
        uint8_t hi_val, lo_val;
        if      (hi >= '0' && hi <= '9') hi_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_val = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi_val = hi - 'A' + 10;
        else return -1;

        if      (lo >= '0' && lo <= '9') lo_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_val = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo_val = lo - 'A' + 10;
        else return -1;

        dst[i] = (hi_val << 4) | lo_val;
    }
    return (int)out_len;
}

/* Encode binary data as a lowercase hex string.
 * dst must be at least src_len*2 + 1 bytes. */
static void hex_encode(const uint8_t *src, size_t src_len, char *dst)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < src_len; i++) {
        dst[i * 2]     = hex_chars[src[i] >> 4];
        dst[i * 2 + 1] = hex_chars[src[i] & 0x0F];
    }
    dst[src_len * 2] = '\0';
}

/* -------------------------------------------------------------------------
 * Error / ok response helpers
 * ------------------------------------------------------------------------- */
static cJSON *serial_error(const char *msg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "error");
    cJSON_AddStringToObject(root, "error", msg);
    return root;
}

static cJSON *serial_ok(cJSON *data)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ok");
    if (data) cJSON_AddItemToObject(root, "data", data);
    return root;
}

/* -------------------------------------------------------------------------
 * Action: "send"
 * params: {data (hex string), baud (optional), timeout_ms (optional)}
 *
 * Reconfigures baud if requested, hex-decodes the payload, writes to UART,
 * waits up to timeout_ms for response bytes, returns hex-encoded response.
 * ------------------------------------------------------------------------- */
static cJSON *serial_send(cJSON *params)
{
    cJSON *j_data    = cJSON_GetObjectItemCaseSensitive(params, "data");
    cJSON *j_baud    = cJSON_GetObjectItemCaseSensitive(params, "baud");
    cJSON *j_timeout = cJSON_GetObjectItemCaseSensitive(params, "timeout_ms");

    if (!cJSON_IsString(j_data) || !j_data->valuestring) {
        return serial_error("Missing param: data (hex string) required");
    }

    /* Optional baud override */
    if (cJSON_IsNumber(j_baud) && j_baud->valueint > 0) {
        if (serial_set_baud(j_baud->valueint) != ESP_OK) {
            return serial_error("Failed to set requested baud rate");
        }
    }

    int timeout_ms = CMD_TIMEOUT_MS;
    if (cJSON_IsNumber(j_timeout) && j_timeout->valueint > 0) {
        timeout_ms = j_timeout->valueint;
    }

    /* Hex-decode the input payload */
    uint8_t tx_buf[SERIAL_BUF_SIZE];
    int tx_len = hex_decode(j_data->valuestring, tx_buf, sizeof(tx_buf));
    if (tx_len < 0) {
        return serial_error("Invalid hex string in data param");
    }
    if (tx_len == 0) {
        return serial_error("data param is empty");
    }

    /* Flush stale RX bytes before sending */
    uart_flush(SERIAL_UART);

    /* Transmit */
    uart_write_bytes(SERIAL_UART, (const char *)tx_buf, tx_len);

    /* Collect response with rolling timeout */
    uint8_t rx_buf[SERIAL_BUF_SIZE];
    int total = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (esp_timer_get_time() < deadline && total < (int)sizeof(rx_buf)) {
        int got = uart_read_bytes(SERIAL_UART,
                                  rx_buf + total,
                                  sizeof(rx_buf) - total,
                                  pdMS_TO_TICKS(20));
        if (got > 0) {
            total += got;
            /* After receiving data, extend deadline slightly to capture
             * trailing bytes, but do not exceed the original timeout. */
            int64_t extended = esp_timer_get_time() + 100 * 1000; /* +100 ms */
            if (extended < deadline) {
                /* already within deadline, keep reading */
            }
        }
    }

    /* Hex-encode the response */
    char *hex_resp = NULL;
    if (total > 0) {
        size_t hex_len = (size_t)total * 2 + 1;
        hex_resp = malloc(hex_len);
        if (!hex_resp) return serial_error("Memory allocation failed");
        hex_encode(rx_buf, total, hex_resp);
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "baud",       s_current_baud);
    cJSON_AddNumberToObject(data, "tx_bytes",   tx_len);
    cJSON_AddNumberToObject(data, "rx_bytes",   total);
    cJSON_AddStringToObject(data, "response",   hex_resp ? hex_resp : "");

    if (hex_resp) free(hex_resp);
    return serial_ok(data);
}

/* -------------------------------------------------------------------------
 * Action: "passthrough"
 * params: {baud (optional)}
 *
 * Bridges bytes between USB CDC (JTAG serial) and RS-232 until the host
 * sends the ASCII string "stop\r\n" or "stop\n" over USB CDC.
 *
 * On ESP32-S3, USB serial is accessed via usb_serial_jtag driver.
 * The function blocks until stopped; call from a task that can afford to.
 * ------------------------------------------------------------------------- */
static cJSON *serial_passthrough(cJSON *params)
{
    cJSON *j_baud = cJSON_GetObjectItemCaseSensitive(params, "baud");
    if (cJSON_IsNumber(j_baud) && j_baud->valueint > 0) {
        if (serial_set_baud(j_baud->valueint) != ESP_OK) {
            return serial_error("Failed to set requested baud rate");
        }
    }

    uart_flush(SERIAL_UART);
    s_passthrough_active = true;

    ESP_LOGI(TAG, "Passthrough mode active at %d baud — send 'stop' to exit",
             s_current_baud);

    /* Small buffer for USB CDC → UART direction */
    uint8_t usb_buf[64];
    uint8_t uart_buf[64];
    /* Rolling buffer to detect "stop" command from host */
    char cmd_detect[8] = {0};
    int  cmd_pos       = 0;

    while (s_passthrough_active) {
        /* --- USB CDC → RS-232 --- */
        int usb_got = usb_serial_jtag_read_bytes(usb_buf, sizeof(usb_buf),
                                                  pdMS_TO_TICKS(5));
        if (usb_got > 0) {
            /* Check for "stop" sentinel before forwarding */
            for (int i = 0; i < usb_got; i++) {
                char c = (char)usb_buf[i];
                if (c == '\r' || c == '\n') {
                    cmd_detect[cmd_pos] = '\0';
                    if (strcmp(cmd_detect, "stop") == 0) {
                        s_passthrough_active = false;
                        break;
                    }
                    cmd_pos = 0;
                } else {
                    if (cmd_pos < (int)(sizeof(cmd_detect) - 1)) {
                        cmd_detect[cmd_pos++] = c;
                    }
                }
            }
            if (s_passthrough_active) {
                uart_write_bytes(SERIAL_UART, (const char *)usb_buf, usb_got);
            }
        }

        /* --- RS-232 → USB CDC --- */
        int uart_got = uart_read_bytes(SERIAL_UART, uart_buf,
                                       sizeof(uart_buf), pdMS_TO_TICKS(5));
        if (uart_got > 0) {
            usb_serial_jtag_write_bytes(uart_buf, uart_got, pdMS_TO_TICKS(10));
        }
    }

    ESP_LOGI(TAG, "Passthrough mode stopped");

    cJSON *data = cJSON_CreateObject();
    cJSON_AddNumberToObject(data, "baud", s_current_baud);
    cJSON_AddStringToObject(data, "result", "passthrough_stopped");
    return serial_ok(data);
}

/* -------------------------------------------------------------------------
 * Action: "auto_baud"
 * No required params.
 *
 * Iterates candidate baud rates, sends \r\n, waits 500 ms, checks whether
 * any bytes in the response are printable ASCII. Returns the first matching
 * baud rate and the (hex-encoded) response, or an error if none matched.
 * ------------------------------------------------------------------------- */
static bool response_has_printable(const uint8_t *buf, int len)
{
    for (int i = 0; i < len; i++) {
        if (isprint((unsigned char)buf[i]) || buf[i] == '\r' || buf[i] == '\n') {
            return true;
        }
    }
    return false;
}

static cJSON *serial_auto_baud(void)
{
    static const uint8_t probe[] = {'\r', '\n'};

    for (int idx = 0; idx < NUM_AUTO_BAUD_RATES; idx++) {
        int baud = auto_baud_rates[idx];
        if (serial_set_baud(baud) != ESP_OK) continue;

        uart_flush(SERIAL_UART);
        uart_write_bytes(SERIAL_UART, (const char *)probe, sizeof(probe));

        /* Wait 500 ms for response */
        vTaskDelay(pdMS_TO_TICKS(500));

        uint8_t rx_buf[SERIAL_BUF_SIZE];
        int total = 0;
        int got;
        while ((got = uart_read_bytes(SERIAL_UART,
                                      rx_buf + total,
                                      sizeof(rx_buf) - total,
                                      pdMS_TO_TICKS(10))) > 0) {
            total += got;
            if (total >= (int)sizeof(rx_buf)) break;
        }

        if (total > 0 && response_has_printable(rx_buf, total)) {
            /* Found a responsive baud rate */
            char *hex_resp = NULL;
            size_t hex_len = (size_t)total * 2 + 1;
            hex_resp = malloc(hex_len);
            if (hex_resp) hex_encode(rx_buf, total, hex_resp);

            cJSON *data = cJSON_CreateObject();
            cJSON_AddNumberToObject(data, "detected_baud", baud);
            cJSON_AddNumberToObject(data, "rx_bytes",      total);
            cJSON_AddStringToObject(data, "response",
                                    hex_resp ? hex_resp : "");
            if (hex_resp) free(hex_resp);

            ESP_LOGI(TAG, "Auto-baud detected: %d baud (%d bytes)", baud, total);
            return serial_ok(data);
        }

        ESP_LOGD(TAG, "No response at %d baud", baud);
    }

    /* Restore default baud after failed detection */
    serial_set_baud(RS232_BAUD_DEFAULT);
    return serial_error("Auto-baud failed: no printable response at any tested baud rate");
}

/* -------------------------------------------------------------------------
 * Public command dispatcher
 * ------------------------------------------------------------------------- */
bool serial_is_ready(void) { return s_initialized; }

cJSON *serial_handle_command(const char *action, cJSON *params)
{
    if (!action) {
        return serial_error("action is required");
    }

    if (!s_initialized) {
        return serial_error("RS-232 handler not initialized (no MAX3232 hardware?)");
    }

    if (strcmp(action, "send") == 0) {
        if (!params) return serial_error("params required for send");
        return serial_send(params);
    } else if (strcmp(action, "passthrough") == 0) {
        if (s_passthrough_active) {
            return serial_error("Passthrough already active");
        }
        cJSON *empty = cJSON_CreateObject();
        cJSON *result = serial_passthrough(params ? params : empty);
        if (!params) cJSON_Delete(empty);
        return result;
    } else if (strcmp(action, "auto_baud") == 0) {
        return serial_auto_baud();
    }

    char msg[80];
    snprintf(msg, sizeof(msg), "Unknown action: %s", action);
    return serial_error(msg);
}
