// dio_handler.c — MAX14906 4-channel 24V digital I/O handler
// Exposes digital input/output operations over the 24V field domain.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"
#include "max14906.h"

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

// ─── Command dispatcher ─────────────────────────────────────────────────────
cJSON* dio_handle_command(const char* action, cJSON* params)
{
    if (!s_initialized) return err_obj("not_initialized");
    if (!action)        return err_obj("missing_action");

    if (strcmp(action, "configure") == 0) return cmd_configure(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    cJSON_AddStringToObject(r, "action", action);
    return r;
}
