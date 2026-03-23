// ble_scanner.c — BLE device discovery using NimBLE (ESP-IDF built-in)
//
// Scans for BLE advertisements and optionally filters for known ICS/OT vendor
// manufacturer IDs and device name keywords.

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

// NimBLE headers (ESP-IDF component: bt -> NimBLE)
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"

#include "config.h"
#include "handlers.h"

static const char *TAG = "ble_scanner";

// ─── Known ICS BLE manufacturer IDs ─────────────────────────────────────────
//
// Source: Bluetooth SIG assigned company identifiers (partial list for ICS vendors).

typedef struct {
    uint16_t    id;
    const char *name;
} mfr_entry_t;

static const mfr_entry_t s_ics_manufacturers[] = {
    { 0x0059, "Emerson"           },
    { 0x0167, "Honeywell"         },
    { 0x0117, "ABB"               },
    { 0x01C1, "Endress+Hauser"    },
    { 0x006A, "Siemens"           },
};
#define ICS_MFR_COUNT (sizeof(s_ics_manufacturers) / sizeof(s_ics_manufacturers[0]))

// ─── ICS-related name keywords ───────────────────────────────────────────────

static const char *s_ics_name_keywords[] = {
    "WirelessHART",
    "wirelesshart",
    "ISA100",
    "isa100",
    "Rosemount",
    "rosemount",
    "Prowirl",
    "prowirl",
    "HART",
    "hart",
    "FieldComm",
    "fieldcomm",
    "Profibus",
    "profibus",
    "Foundation",   // Foundation Fieldbus
    "Yokogawa",
    "EtherNet/IP",
    "ethernet/ip",
    "PROFINET",
    "profinet",
};
#define ICS_KW_COUNT (sizeof(s_ics_name_keywords) / sizeof(s_ics_name_keywords[0]))

// ─── Scan result storage ─────────────────────────────────────────────────────

#define MAX_SCAN_RESULTS 128

typedef struct {
    char     addr[18];      // "AA:BB:CC:DD:EE:FF"
    char     name[64];
    int8_t   rssi;
    uint16_t manufacturer_id;  // 0xFFFF = not present
    bool     ics_match;
} scan_result_t;

static scan_result_t  s_results[MAX_SCAN_RESULTS];
static int            s_result_count = 0;
static SemaphoreHandle_t s_results_mutex = NULL;

// Filter state set at scan start
static bool s_filter_ics = false;

// ─── Module init state ───────────────────────────────────────────────────────

static bool s_initialized = false;

extern volatile bool g_stop_requested;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static void addr_to_str(const ble_addr_t *addr, char *out)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr->val[5], addr->val[4], addr->val[3],
             addr->val[2], addr->val[1], addr->val[0]);
}

static bool is_ics_manufacturer(uint16_t id)
{
    for (size_t i = 0; i < ICS_MFR_COUNT; i++) {
        if (s_ics_manufacturers[i].id == id) return true;
    }
    return false;
}

static bool name_contains_ics_keyword(const char *name)
{
    if (!name || name[0] == '\0') return false;
    for (size_t i = 0; i < ICS_KW_COUNT; i++) {
        if (strcasestr(name, s_ics_name_keywords[i]) != NULL) return true;
    }
    return false;
}

// Parse manufacturer-specific data from an ADV data blob.
// Returns the first manufacturer ID found, or 0xFFFF if absent.
static uint16_t parse_manufacturer_id(const uint8_t *data, uint8_t data_len)
{
    uint8_t i = 0;
    while (i + 1 < data_len) {
        uint8_t len  = data[i];
        if (len == 0 || i + len >= data_len) break;
        uint8_t type = data[i + 1];
        if (type == 0xFF && len >= 3) {  // AD type 0xFF = Manufacturer Specific
            return (uint16_t)(data[i + 2] | ((uint16_t)data[i + 3] << 8));
        }
        i += 1 + len;
    }
    return 0xFFFF;
}

// Parse complete or shortened local name from ADV data.
static void parse_name(const uint8_t *data, uint8_t data_len, char *out, size_t out_size)
{
    out[0] = '\0';
    uint8_t i = 0;
    while (i + 1 < data_len) {
        uint8_t len  = data[i];
        if (len == 0 || i + len >= data_len) break;
        uint8_t type = data[i + 1];
        // AD type 0x08 = Shortened Local Name, 0x09 = Complete Local Name
        if (type == 0x08 || type == 0x09) {
            size_t name_len = len - 1;
            if (name_len >= out_size) name_len = out_size - 1;
            memcpy(out, &data[i + 2], name_len);
            out[name_len] = '\0';
            // Prefer complete name (0x09) over shortened (0x08)
            if (type == 0x09) return;
        }
        i += 1 + len;
    }
}

// ─── NimBLE GAP event callback ───────────────────────────────────────────────

static int gap_event_handler(struct ble_gap_event *event, void *arg)
{
    if (event->type != BLE_GAP_EVENT_DISC) return 0;

    struct ble_hs_adv_fields fields;
    const struct ble_gap_disc_desc *desc = &event->disc;

    char addr_str[18];
    addr_to_str(&desc->addr, addr_str);

    // Parse raw ADV data for name and manufacturer ID
    char     name[64]       = "";
    uint16_t mfr_id         = 0xFFFF;

    if (desc->length_data > 0 && desc->data) {
        parse_name(desc->data, desc->length_data, name, sizeof(name));
        mfr_id = parse_manufacturer_id(desc->data, desc->length_data);

        // Fallback: try NimBLE's field parser for the name if we got nothing
        if (name[0] == '\0') {
            int rc = ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data);
            if (rc == 0 && fields.name && fields.name_len > 0) {
                size_t copy = fields.name_len < sizeof(name) - 1 ? fields.name_len : sizeof(name) - 1;
                memcpy(name, fields.name, copy);
                name[copy] = '\0';
            }
        }
    }

    bool ics_match = is_ics_manufacturer(mfr_id) || name_contains_ics_keyword(name);

    // Apply filter
    if (s_filter_ics && !ics_match) return 0;

    if (xSemaphoreTake(s_results_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        // Deduplicate by address
        bool found = false;
        for (int i = 0; i < s_result_count; i++) {
            if (strcmp(s_results[i].addr, addr_str) == 0) {
                // Update RSSI and name if we now have more info
                s_results[i].rssi = desc->rssi;
                if (name[0] != '\0' && s_results[i].name[0] == '\0') {
                    strncpy(s_results[i].name, name, sizeof(s_results[i].name) - 1);
                }
                if (mfr_id != 0xFFFF) {
                    s_results[i].manufacturer_id = mfr_id;
                    s_results[i].ics_match       = ics_match;
                }
                found = true;
                break;
            }
        }
        if (!found && s_result_count < MAX_SCAN_RESULTS) {
            scan_result_t *r = &s_results[s_result_count++];
            strncpy(r->addr, addr_str, sizeof(r->addr) - 1);
            strncpy(r->name, name,     sizeof(r->name) - 1);
            r->rssi            = desc->rssi;
            r->manufacturer_id = mfr_id;
            r->ics_match       = ics_match;
        }
        xSemaphoreGive(s_results_mutex);
    }

    return 0;
}

// ─── NimBLE host task ────────────────────────────────────────────────────────

static void nimble_host_task(void *param)
{
    nimble_port_run();  // blocks until nimble_port_stop() is called
    nimble_port_freertos_deinit();
}

// Called by NimBLE when the host stack is synced and ready.
static void on_sync(void)
{
    ESP_LOGI(TAG, "NimBLE host synced");
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE host reset: %d", reason);
}

// ─── Public init ────────────────────────────────────────────────────────────

void ble_init(void)
{
    if (s_initialized) return;

    s_results_mutex = xSemaphoreCreateMutex();
    if (!s_results_mutex) {
        ESP_LOGE(TAG, "failed to create results mutex");
        return;
    }

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return;
    }

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();

    nimble_port_freertos_init(nimble_host_task);

    // Give NimBLE host time to sync
    vTaskDelay(pdMS_TO_TICKS(500));

    s_initialized = true;
    ESP_LOGI(TAG, "BLE (NimBLE) initialized");
}

// ─── Action: "scan" ─────────────────────────────────────────────────────────
//
// params: { "duration_s": <int>, "filter": "ics" | absent }
// Returns: array of { addr, name, rssi, manufacturer_id, ics_match }

static cJSON *action_scan(cJSON *params)
{
    cJSON *dur_item    = cJSON_GetObjectItemCaseSensitive(params, "duration_s");
    cJSON *filter_item = cJSON_GetObjectItemCaseSensitive(params, "filter");

    uint32_t duration = (dur_item && cJSON_IsNumber(dur_item))
                        ? (uint32_t)dur_item->valuedouble : 10;

    s_filter_ics = false;
    if (filter_item && cJSON_IsString(filter_item)) {
        if (strcasecmp(filter_item->valuestring, "ics") == 0) {
            s_filter_ics = true;
        }
    }

    // Reset results
    if (xSemaphoreTake(s_results_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        memset(s_results, 0, sizeof(s_results));
        s_result_count = 0;
        xSemaphoreGive(s_results_mutex);
    }

    // Configure passive scan (listen-only) for maximum compatibility with ICS devices.
    // Active scan (sending SCAN_REQ) may alarm IDS on OT networks.
    struct ble_gap_disc_params disc_params = {
        .passive      = 1,
        .itvl         = BLE_GAP_SCAN_ITVL_MS(100),
        .window       = BLE_GAP_SCAN_WIN_MS(50),
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
        .limited      = 0,
        .filter_duplicates = 0,  // we handle dedup ourselves to update RSSI
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params,
                          gap_event_handler, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "scan start failed");
        char code_str[16];
        snprintf(code_str, sizeof(code_str), "%d", rc);
        cJSON_AddStringToObject(err, "rc", code_str);
        return err;
    }

    // Wait for duration or stop flag
    uint64_t deadline = (uint64_t)esp_timer_get_time() + (uint64_t)duration * 1000000ULL;
    while (esp_timer_get_time() < deadline && !g_stop_requested) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ble_gap_disc_cancel();

    // Build JSON result array
    cJSON *result = cJSON_CreateObject();
    cJSON *arr    = cJSON_CreateArray();

    if (xSemaphoreTake(s_results_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        for (int i = 0; i < s_result_count; i++) {
            scan_result_t *r = &s_results[i];
            cJSON *entry = cJSON_CreateObject();

            cJSON_AddStringToObject(entry, "addr", r->addr);
            cJSON_AddStringToObject(entry, "name", r->name[0] ? r->name : "(unknown)");
            cJSON_AddNumberToObject(entry, "rssi", r->rssi);

            if (r->manufacturer_id != 0xFFFF) {
                char mfr_hex[8];
                snprintf(mfr_hex, sizeof(mfr_hex), "0x%04X", r->manufacturer_id);
                cJSON_AddStringToObject(entry, "manufacturer_id", mfr_hex);

                // Also include vendor name if known
                for (size_t m = 0; m < ICS_MFR_COUNT; m++) {
                    if (s_ics_manufacturers[m].id == r->manufacturer_id) {
                        cJSON_AddStringToObject(entry, "manufacturer_name",
                                               s_ics_manufacturers[m].name);
                        break;
                    }
                }
            } else {
                cJSON_AddNullToObject(entry, "manufacturer_id");
            }

            cJSON_AddBoolToObject(entry, "ics_match", r->ics_match);
            cJSON_AddItemToArray(arr, entry);
        }
        xSemaphoreGive(s_results_mutex);
    }

    cJSON_AddItemToObject(result, "devices", arr);
    cJSON_AddNumberToObject(result, "count",      s_result_count);
    cJSON_AddNumberToObject(result, "duration_s", duration);
    cJSON_AddStringToObject(result, "filter",     s_filter_ics ? "ics" : "none");
    return result;
}

// ─── Public command dispatcher ───────────────────────────────────────────────

bool ble_is_ready(void) { return s_initialized; }

cJSON *ble_handle_command(const char *action, cJSON *params)
{
    if (!s_initialized) {
        return cJSON_CreateString("error: BLE handler not initialized");
    }
    // Rate limiting is handled by dispatch() in main.c — don't double-check here
    if (strcmp(action, "scan") == 0) return action_scan(params);

    cJSON *err = cJSON_CreateObject();
    cJSON_AddStringToObject(err, "error", "unknown action");
    cJSON_AddStringToObject(err, "available", "scan");
    return err;
}
