// dio_handler.c — MAX14906 4-channel 24V digital I/O handler
// Exposes digital input/output operations over the 24V field domain.

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"
#include "max14906.h"

// Set by main.c's "stop" command — aborts streaming operations early.
extern volatile bool g_stop_requested;

static const char* TAG = "dio_handler";
static bool s_initialized = false;

// Per-channel mode shadow. The MAX14906 DoiLvl register encodes Type 1/2/3
// thresholds but v1.1 leaves it at default — we just remember the requested
// type here and replay it in read responses. Full threshold programming is
// a v1.2 concern.
static dio_mode_t s_ch_mode[DIO_CHANNELS] = {
    DIO_MODE_INPUT_T3, DIO_MODE_INPUT_T3, DIO_MODE_INPUT_T3, DIO_MODE_INPUT_T3,
};

// ─── Mode name helpers ──────────────────────────────────────────────────────
static const char* mode_to_str(dio_mode_t m)
{
    switch (m) {
        case DIO_MODE_INPUT_T1:  return "input_t1";
        case DIO_MODE_INPUT_T2:  return "input_t2";
        case DIO_MODE_INPUT_T3:  return "input_t3";
        case DIO_MODE_OUTPUT_HS: return "output";
    }
    return "unknown";
}

static bool str_to_mode(const char* s, dio_mode_t* out)
{
    if (!s || !out) return false;
    if (strcmp(s, "input_t1") == 0) { *out = DIO_MODE_INPUT_T1;  return true; }
    if (strcmp(s, "input_t2") == 0) { *out = DIO_MODE_INPUT_T2;  return true; }
    if (strcmp(s, "input_t3") == 0) { *out = DIO_MODE_INPUT_T3;  return true; }
    if (strcmp(s, "output")   == 0) { *out = DIO_MODE_OUTPUT_HS; return true; }
    return false;
}

// ─── Response helpers ───────────────────────────────────────────────────────
static cJSON* err_obj(const char* msg)
{
    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", msg);
    return r;
}

// ─── Init / ready ───────────────────────────────────────────────────────────
void dio_init(void)
{
    if (max14906_init()) {
        s_initialized = true;
        ESP_LOGI(TAG, "DIO handler ready (MAX14906 detected)");
    } else {
        s_initialized = false;
        ESP_LOGW(TAG, "DIO handler disabled (MAX14906 absent)");
    }
}

bool dio_is_ready(void)
{
    return s_initialized;
}

// ─── Action: configure ──────────────────────────────────────────────────────
// params: {"ch": 0..3, "mode": "input_t1"|"input_t2"|"input_t3"|"output"}
static cJSON* cmd_configure(cJSON* params)
{
    if (!params) return err_obj("missing_params");

    cJSON* ch_item   = cJSON_GetObjectItemCaseSensitive(params, "ch");
    cJSON* mode_item = cJSON_GetObjectItemCaseSensitive(params, "mode");

    if (!ch_item || !cJSON_IsNumber(ch_item))       return err_obj("missing_ch");
    if (!mode_item || !cJSON_IsString(mode_item))   return err_obj("missing_mode");

    int ch = (int)ch_item->valuedouble;
    if (ch < 0 || ch >= DIO_CHANNELS) return err_obj("invalid_ch");

    dio_mode_t mode;
    if (!str_to_mode(mode_item->valuestring, &mode)) return err_obj("invalid_mode");

    if (!max14906_set_mode(ch, mode)) return err_obj("spi_failure");

    s_ch_mode[ch] = mode;

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON_AddNumberToObject(r, "ch", ch);
    cJSON_AddStringToObject(r, "mode", mode_to_str(mode));
    return r;
}

// ─── Action: read ───────────────────────────────────────────────────────────
// Returns per-channel state:
//   {"status":"ok","channels":[{"ch":0,"mode":"input_t3","value":1},...]}
static cJSON* cmd_read(void)
{
    uint8_t mask = 0;
    if (!max14906_read_inputs(&mask)) return err_obj("spi_failure");

    cJSON* r   = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON* arr = cJSON_CreateArray();
    for (int ch = 0; ch < DIO_CHANNELS; ch++) {
        cJSON* entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "ch", ch);
        cJSON_AddStringToObject(entry, "mode", mode_to_str(s_ch_mode[ch]));
        cJSON_AddNumberToObject(entry, "value", (mask >> ch) & 0x01);
        cJSON_AddItemToArray(arr, entry);
    }
    cJSON_AddItemToObject(r, "channels", arr);
    return r;
}

// ─── Action: write ──────────────────────────────────────────────────────────
// params: {"ch": 0..3, "value": 0|1, "confirm": true}
// Driving 24V outputs is destructive (can back-feed a live field wire), so
// safety_check_confirm is required — missing/false confirm returns an error.
static cJSON* cmd_write(cJSON* params)
{
    if (!params) return err_obj("missing_params");

    if (!safety_check_confirm(params)) return err_obj("confirm_required");

    cJSON* ch_item  = cJSON_GetObjectItemCaseSensitive(params, "ch");
    cJSON* val_item = cJSON_GetObjectItemCaseSensitive(params, "value");

    if (!ch_item || !cJSON_IsNumber(ch_item))   return err_obj("missing_ch");
    if (!val_item || !cJSON_IsNumber(val_item)) return err_obj("missing_value");

    int ch = (int)ch_item->valuedouble;
    if (ch < 0 || ch >= DIO_CHANNELS) return err_obj("invalid_ch");

    bool high = ((int)val_item->valuedouble) != 0;

    if (!max14906_write_output(ch, high)) return err_obj("spi_failure");

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON_AddNumberToObject(r, "ch", ch);
    cJSON_AddNumberToObject(r, "value", high ? 1 : 0);
    return r;
}

// ─── Action: monitor ────────────────────────────────────────────────────────
// params: {"interval_ms": N, "duration_s": N}
//
// Mirrors the can.listen / adc.stream pattern: emits one JSON line per
// state-change event via printf (buffered to USB Serial/JTAG by the ROM
// console driver — same pipe main.c's usj_send writes to), and returns a
// summary cJSON on normal completion. g_stop_requested is checked every
// iteration to allow early abort via a "stop" command.
static cJSON* cmd_monitor(cJSON* params)
{
    cJSON* iv_item  = params ? cJSON_GetObjectItemCaseSensitive(params, "interval_ms") : NULL;
    cJSON* dur_item = params ? cJSON_GetObjectItemCaseSensitive(params, "duration_s")  : NULL;

    uint32_t interval_ms = (iv_item  && cJSON_IsNumber(iv_item))
                           ? (uint32_t)iv_item->valuedouble : 100;
    uint32_t duration_s  = (dur_item && cJSON_IsNumber(dur_item))
                           ? (uint32_t)dur_item->valuedouble : 10;
    if (interval_ms < 1) interval_ms = 1;
    if (duration_s  < 1) duration_s  = 1;

    uint64_t deadline = (uint64_t)esp_timer_get_time() + (uint64_t)duration_s * 1000000ULL;

    uint8_t prev_mask = 0;
    bool    have_prev = false;
    uint32_t change_count = 0;

    while (esp_timer_get_time() < deadline && !g_stop_requested) {
        uint8_t mask = 0;
        uint64_t ts_ms = (uint64_t)esp_timer_get_time() / 1000ULL;

        if (max14906_read_inputs(&mask)) {
            if (!have_prev || mask != prev_mask) {
                printf("{\"mask\":%u,\"ch0\":%u,\"ch1\":%u,\"ch2\":%u,\"ch3\":%u,\"ts\":%llu}\n",
                       (unsigned)mask,
                       (unsigned)((mask >> 0) & 1),
                       (unsigned)((mask >> 1) & 1),
                       (unsigned)((mask >> 2) & 1),
                       (unsigned)((mask >> 3) & 1),
                       (unsigned long long)ts_ms);
                if (have_prev) change_count++;
                prev_mask = mask;
                have_prev = true;
            }
        } else {
            printf("{\"error\":\"read_failed\",\"ts\":%llu}\n",
                   (unsigned long long)ts_ms);
        }

        vTaskDelay(pdMS_TO_TICKS(interval_ms));
    }

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON_AddStringToObject(r, "stream", "end");
    cJSON_AddNumberToObject(r, "changes",     change_count);
    cJSON_AddNumberToObject(r, "interval_ms", interval_ms);
    cJSON_AddNumberToObject(r, "duration_s",  duration_s);
    return r;
}

// ─── Command dispatcher ─────────────────────────────────────────────────────
cJSON* dio_handle_command(const char* action, cJSON* params)
{
    if (!s_initialized) return err_obj("not_initialized");
    if (!action)        return err_obj("missing_action");

    if (strcmp(action, "configure") == 0) return cmd_configure(params);
    if (strcmp(action, "read")      == 0) return cmd_read();
    if (strcmp(action, "write")     == 0) return cmd_write(params);
    if (strcmp(action, "monitor")   == 0) return cmd_monitor(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    cJSON_AddStringToObject(r, "action", action);
    return r;
}
