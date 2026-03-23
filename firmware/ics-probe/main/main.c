/*
 * main.c — ICS Probe firmware entry point
 *
 * Receives newline-terminated JSON commands over the built-in USB
 * Serial/JTAG interface, dispatches them to protocol handlers, and
 * returns JSON responses on the same port.
 *
 * Uses usb_serial_jtag driver (shares the S3's built-in USB port
 * with JTAG — no external USB-UART chip needed, works on any S3
 * dev board out of the box).
 */

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "driver/usb_serial_jtag.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char* TAG = "ics-probe";

#define FIRMWARE_VERSION "1.0.0"

// Global stop flag — set by a "stop" command to abort streaming operations
volatile bool g_stop_requested = false;

// -----------------------------------------------------------------------
// USB Serial/JTAG helpers
// -----------------------------------------------------------------------

static void usj_send(const char* str)
{
    if (!str) return;
    size_t len = strlen(str);
    size_t written = 0;
    while (written < len) {
        int ret = usb_serial_jtag_write_bytes(
            (const char*)str + written, len - written, pdMS_TO_TICKS(100));
        if (ret > 0) written += ret;
        else break;
    }
    usb_serial_jtag_write_bytes("\n", 1, pdMS_TO_TICKS(100));
}

static void usj_send_json(cJSON* obj)
{
    if (!obj) return;
    char* str = cJSON_PrintUnformatted(obj);
    if (str) {
        usj_send(str);
        cJSON_free(str);
    }
    cJSON_Delete(obj);
}

// -----------------------------------------------------------------------
// Response builders
// -----------------------------------------------------------------------

static cJSON* make_error(const char* id, const char* msg)
{
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", msg);
    if (id) cJSON_AddStringToObject(resp, "id", id);
    return resp;
}

static cJSON* make_ok(const char* id)
{
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    if (id) cJSON_AddStringToObject(resp, "id", id);
    return resp;
}

// -----------------------------------------------------------------------
// Built-in "probe.*" commands
// -----------------------------------------------------------------------

static cJSON* handle_probe_info(const char* id)
{
    cJSON* resp = make_ok(id);
    cJSON_AddStringToObject(resp, "fw_version", FIRMWARE_VERSION);

    cJSON* caps = cJSON_CreateArray();
    cJSON_AddItemToArray(caps, cJSON_CreateString("modbus"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("serial"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("can"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("adc"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("ble"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("log"));
    cJSON_AddItemToObject(resp, "capabilities", caps);

    return resp;
}

static cJSON* handle_probe_selftest(const char* id)
{
    cJSON* results = cJSON_CreateObject();
    bool all_pass = true;

    struct {
        const char* name;
        cJSON* (*handler)(const char*, cJSON*);
    } modules[] = {
        { "modbus", modbus_handle_command },
        { "serial", serial_handle_command },
        { "can",    can_handle_command    },
        { "adc",    adc_handle_command    },
        { "ble",    ble_handle_command    },
    };

    for (int i = 0; i < (int)(sizeof(modules) / sizeof(modules[0])); i++) {
        cJSON* r = modules[i].handler("selftest", NULL);
        bool pass = false;
        if (r) {
            cJSON* st = cJSON_GetObjectItemCaseSensitive(r, "status");
            pass = st && cJSON_IsString(st) && strcmp(st->valuestring, "ok") == 0;
            cJSON_Delete(r);
        }
        cJSON_AddBoolToObject(results, modules[i].name, pass);
        if (!pass) all_pass = false;
    }

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", all_pass ? "ok" : "error");
    if (id) cJSON_AddStringToObject(resp, "id", id);
    cJSON_AddItemToObject(resp, "results", results);
    return resp;
}

static cJSON* handle_probe_log(const char* id)
{
    cJSON* resp = make_ok(id);
    cJSON* entries = log_get_entries();
    cJSON_AddItemToObject(resp, "entries", entries);
    return resp;
}

// -----------------------------------------------------------------------
// Command dispatcher
// -----------------------------------------------------------------------

static cJSON* dispatch(const char* json_str)
{
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        return make_error(NULL, "json_parse_error");
    }

    const char* id = NULL;
    cJSON* id_item = cJSON_GetObjectItemCaseSensitive(root, "id");
    if (id_item && cJSON_IsString(id_item)) {
        id = id_item->valuestring;
    }

    cJSON* cmd_item = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (!cmd_item || !cJSON_IsString(cmd_item)) {
        cJSON_Delete(root);
        return make_error(id, "missing_cmd");
    }
    const char* cmd = cmd_item->valuestring;

    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");

    // "stop" — abort any running streaming operation
    if (strcmp(cmd, "stop") == 0) {
        g_stop_requested = true;
        log_entry("info", "stop flag set");
        cJSON* resp = make_ok(id);
        cJSON_Delete(root);
        return resp;
    }

    // Split "module.action" on the first '.'
    char module[64] = {0};
    const char* dot = strchr(cmd, '.');
    if (!dot) {
        cJSON_Delete(root);
        return make_error(id, "invalid_cmd_format");
    }
    size_t mod_len = (size_t)(dot - cmd);
    if (mod_len == 0 || mod_len >= sizeof(module)) {
        cJSON_Delete(root);
        return make_error(id, "invalid_module");
    }
    memcpy(module, cmd, mod_len);
    module[mod_len] = '\0';
    const char* action = dot + 1;

    ESP_LOGI(TAG, "cmd: module=%s action=%s", module, action);

    cJSON* result = NULL;

    if (strcmp(module, "probe") == 0) {
        if (strcmp(action, "info") == 0) {
            result = handle_probe_info(id);
        } else if (strcmp(action, "selftest") == 0) {
            result = handle_probe_selftest(id);
        } else if (strcmp(action, "log") == 0) {
            result = handle_probe_log(id);
        } else {
            result = make_error(id, "unknown_probe_action");
        }
    } else {
        if (!safety_rate_limit(module)) {
            cJSON_Delete(root);
            log_entry("warn", "rate limit exceeded");
            return make_error(id, "rate_limited");
        }

        if (strcmp(module, "modbus") == 0) {
            result = modbus_handle_command(action, params);
        } else if (strcmp(module, "serial") == 0) {
            result = serial_handle_command(action, params);
        } else if (strcmp(module, "can") == 0) {
            result = can_handle_command(action, params);
        } else if (strcmp(module, "adc") == 0) {
            result = adc_handle_command(action, params);
        } else if (strcmp(module, "ble") == 0) {
            result = ble_handle_command(action, params);
        } else {
            result = make_error(id, "unknown_module");
        }

        if (result && id && !cJSON_GetObjectItemCaseSensitive(result, "id")) {
            cJSON_AddStringToObject(result, "id", id);
        }
    }

    cJSON_Delete(root);

    if (!result) {
        result = make_error(id, "handler_returned_null");
    }

    return result;
}

// -----------------------------------------------------------------------
// app_main
// -----------------------------------------------------------------------

void app_main(void)
{
    ESP_LOGI(TAG, "ICS Probe v" FIRMWARE_VERSION " starting");

    // ---- Initialise all handlers ----------------------------------------
    log_init();
    safety_init();
    // Peripheral inits disabled until hardware is wired up.
    // Each crashes in esp_intr_alloc when the physical IC isn't connected.
    // Uncomment one at a time as you add peripherals:
    // Peripheral inits — uncomment as hardware is wired:
    // modbus_init();   // MAX3485 + RS-485
    // serial_init();   // MAX3232
    // can_init();      // MCP2515 + SN65HVD230
    // adc_init();      // INA219
    ble_init();         // On-chip BLE radio (8K main stack required)

    log_entry("info", "all handlers initialised");

    // ---- USB Serial/JTAG driver setup -----------------------------------
    usb_serial_jtag_driver_config_t usj_cfg = {
        .tx_buffer_size = JSON_BUFFER_SIZE,
        .rx_buffer_size = JSON_BUFFER_SIZE,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usj_cfg));

    ESP_LOGI(TAG, "USB Serial/JTAG ready");
    log_entry("info", "USB Serial/JTAG ready");

    // ---- Watchdog -------------------------------------------------------
    esp_task_wdt_config_t wdt_cfg = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    ESP_ERROR_CHECK(esp_task_wdt_reconfigure(&wdt_cfg));
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));

    // ---- Main command loop ----------------------------------------------
    char rx_buf[JSON_BUFFER_SIZE];
    size_t rx_len = 0;

    while (true) {
        esp_task_wdt_reset();

        // Read available bytes from USB Serial/JTAG
        char tmp[64];
        int bytes_read = usb_serial_jtag_read_bytes(tmp, sizeof(tmp), pdMS_TO_TICKS(10));

        if (bytes_read > 0) {
            for (int i = 0; i < bytes_read; i++) {
                char c = tmp[i];

                if (c == '\n' || c == '\r') {
                    if (rx_len > 0) {
                        rx_buf[rx_len] = '\0';

                        ESP_LOGI(TAG, "RX: %s", rx_buf);
                        log_entry("info", rx_buf);

                        // Clear stop flag at the start of each new command
                        g_stop_requested = false;

                        cJSON* response = dispatch(rx_buf);
                        esp_task_wdt_reset();

                        char* resp_str = cJSON_PrintUnformatted(response);
                        if (resp_str) {
                            ESP_LOGI(TAG, "TX: %.200s", resp_str);
                            usj_send(resp_str);
                            cJSON_free(resp_str);
                        }
                        cJSON_Delete(response);

                        rx_len = 0;
                    }
                } else if (rx_len + 1 < sizeof(rx_buf)) {
                    rx_buf[rx_len++] = c;
                } else {
                    ESP_LOGW(TAG, "RX buffer overflow, discarding");
                    rx_len = 0;
                }
            }
        }

        esp_task_wdt_reset();
    }
}
