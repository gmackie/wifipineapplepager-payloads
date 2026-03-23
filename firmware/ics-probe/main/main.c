/*
 * main.c — ICS Probe firmware entry point
 *
 * Receives newline-terminated JSON commands over USB CDC serial,
 * dispatches them to protocol handlers, and returns JSON responses.
 *
 * ESP-IDF / TinyUSB CDC (NOT Arduino)
 */

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char* TAG = "ics-probe";

#define FIRMWARE_VERSION "1.0.0"

// Global stop flag — set by a "stop" command to abort streaming operations
volatile bool g_stop_requested = false;

// -----------------------------------------------------------------------
// USB CDC helpers
// -----------------------------------------------------------------------

/*
 * Send a null-terminated string over the TinyUSB CDC interface followed
 * by a newline.  Blocks until all bytes are queued.
 */
static void cdc_send(const char* str)
{
    if (!str) return;
    size_t len = strlen(str);
    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, (const uint8_t*)str, len);
    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, (const uint8_t*)"\n", 1);
    tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(100));
}

/*
 * Serialise a cJSON object to a string, send it over CDC, then free
 * both the string and the cJSON object.
 */
static void cdc_send_json(cJSON* obj)
{
    if (!obj) return;
    char* str = cJSON_PrintUnformatted(obj);
    if (str) {
        cdc_send(str);
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
    cJSON_AddStringToObject(resp, "version", FIRMWARE_VERSION);

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
    /*
     * Each handler exposes its self-test through its handle_command
     * interface via action == "selftest".  We collect pass/fail per
     * module and report an aggregate result.
     */
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

/*
 * Process one JSON command string.  Returns a heap-allocated cJSON
 * response object (caller must cdc_send_json / cJSON_Delete it).
 */
static cJSON* dispatch(const char* json_str)
{
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        return make_error(NULL, "json_parse_error");
    }

    // Extract "id" (optional, echoed back for request/response matching)
    const char* id = NULL;
    cJSON* id_item = cJSON_GetObjectItemCaseSensitive(root, "id");
    if (id_item && cJSON_IsString(id_item)) {
        id = id_item->valuestring;
    }

    // Extract "cmd" (required, format: "module.action")
    cJSON* cmd_item = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (!cmd_item || !cJSON_IsString(cmd_item)) {
        cJSON_Delete(root);
        return make_error(id, "missing_cmd");
    }
    const char* cmd = cmd_item->valuestring;

    // Extract "params" (optional object)
    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");

    // ---- Special top-level commands -----------------------------------

    // "stop" — abort any running streaming operation
    if (strcmp(cmd, "stop") == 0) {
        g_stop_requested = true;
        log_entry("info", "stop flag set");
        cJSON* resp = make_ok(id);
        cJSON_Delete(root);
        return resp;
    }

    // ---- Module.action routing ----------------------------------------

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
        // Built-in probe commands — no rate limiting
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
        // All other modules go through the rate limiter
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

        // If the handler returned a bare result object without an "id",
        // inject the request id now.
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
// TinyUSB CDC line-receive callback
// -----------------------------------------------------------------------

/*
 * Accumulation buffer shared between the CDC RX callback and the main
 * loop task.  Protected here by the fact that TinyUSB delivers data on
 * the same core as the main loop in a cooperative fashion; if you move
 * to a multi-core design, add a mutex.
 */
static char    s_rx_buf[JSON_BUFFER_SIZE];
static size_t  s_rx_len = 0;
static bool    s_line_ready = false;

static void cdc_rx_callback(int itf, cdcacm_event_t* event)
{
    (void)itf;
    if (event->type != CDC_EVENT_RX) return;

    uint8_t tmp[64];
    size_t rx_size = 0;

    esp_err_t ret = tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0, tmp, sizeof(tmp), &rx_size);
    if (ret != ESP_OK || rx_size == 0) return;

    for (size_t i = 0; i < rx_size; i++) {
        char c = (char)tmp[i];

        // Newline terminates a command
        if (c == '\n' || c == '\r') {
            if (s_rx_len > 0) {
                s_rx_buf[s_rx_len] = '\0';
                s_line_ready = true;
                // Reset for next command; note we do NOT clear s_rx_buf
                // here — main loop consumes it before the next callback.
            }
            return;
        }

        // Discard if buffer would overflow
        if (s_rx_len + 1 >= sizeof(s_rx_buf)) {
            ESP_LOGW(TAG, "RX buffer overflow, discarding line");
            s_rx_len = 0;
            s_line_ready = false;
            return;
        }

        s_rx_buf[s_rx_len++] = c;
    }
}

// -----------------------------------------------------------------------
// app_main
// -----------------------------------------------------------------------

void app_main(void)
{
    ESP_LOGI(TAG, "ICS Probe v" FIRMWARE_VERSION " starting");

    // ---- Initialise all handlers --------------------------------------
    log_init();
    safety_init();
    modbus_init();
    serial_init();
    can_init();
    adc_init();
    ble_init();

    log_entry("info", "all handlers initialised");

    // ---- TinyUSB CDC setup -------------------------------------------
    tinyusb_config_t tusb_cfg = {
        .device_descriptor = NULL,  // use default ESP-IDF descriptor
        .string_descriptor = NULL,
        .external_phy = false,
    };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 64,
        .callback_rx = &cdc_rx_callback,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL,
    };
    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm_cfg));

    ESP_LOGI(TAG, "USB CDC ready");
    log_entry("info", "USB CDC ready");

    // ---- Watchdog ----------------------------------------------------
    // Use the legacy task WDT API available in ESP-IDF v5.x
    esp_task_wdt_config_t wdt_cfg = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    ESP_ERROR_CHECK(esp_task_wdt_reconfigure(&wdt_cfg));
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));   // register current task

    // ---- Main command loop -------------------------------------------
    while (true) {
        esp_task_wdt_reset();

        if (!s_line_ready) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }

        // Copy the received line and release the buffer immediately so
        // the CDC callback can start accumulating the next command.
        char line[JSON_BUFFER_SIZE];
        memcpy(line, s_rx_buf, s_rx_len + 1);  // includes null terminator
        s_rx_len = 0;
        s_line_ready = false;

        // Clear stop flag at the start of each new command cycle
        g_stop_requested = false;

        ESP_LOGI(TAG, "RX: %s", line);
        log_entry("info", line);

        cJSON* response = dispatch(line);
        cdc_send_json(response);   // frees response internally

        esp_task_wdt_reset();
    }
}
