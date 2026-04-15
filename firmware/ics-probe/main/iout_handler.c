// iout_handler.c — AD5420 4-20mA current output DAC handler
// Exposes analog current output operations over the 24V field domain.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"
#include "ad5420.h"

static const char* TAG = "iout_handler";
static bool  s_initialized = false;
static float s_setpoint_ma = 4.0f;

// ─── Response helper ────────────────────────────────────────────────────────
static cJSON* err_obj(const char* msg)
{
    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", msg);
    return r;
}

// ─── Init / ready ───────────────────────────────────────────────────────────
void iout_init(void)
{
    if (ad5420_init()) {
        s_initialized = true;
        ESP_LOGI(TAG, "IOUT handler ready (AD5420 detected)");
    } else {
        s_initialized = false;
        ESP_LOGW(TAG, "IOUT handler disabled (AD5420 absent)");
    }
}

bool iout_is_ready(void)
{
    return s_initialized;
}

// ─── Action: set_ma ─────────────────────────────────────────────────────────
// params: {"ma": 0.0-24.0, "confirm": true}
// Driving a live 4-20mA loop can disturb a real process input, so
// safety_check_confirm is required — missing/false confirm returns an error.
static cJSON* cmd_set_ma(cJSON* params)
{
    if (!params) return err_obj("missing_params");

    if (!safety_check_confirm(params)) return err_obj("confirm_required");

    cJSON* ma_item = cJSON_GetObjectItemCaseSensitive(params, "ma");
    if (!ma_item || !cJSON_IsNumber(ma_item)) return err_obj("missing_ma");

    float ma = (float)ma_item->valuedouble;
    if (ma < IOUT_MIN_MA) ma = IOUT_MIN_MA;
    if (ma > IOUT_MAX_MA) ma = IOUT_MAX_MA;

    if (!ad5420_set_ma(ma)) return err_obj("spi_failure");
    s_setpoint_ma = ma;

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON_AddNumberToObject(r, "ma", ma);
    return r;
}

// ─── Command dispatcher ─────────────────────────────────────────────────────
cJSON* iout_handle_command(const char* action, cJSON* params)
{
    if (!s_initialized) return err_obj("not_initialized");
    if (!action)        return err_obj("missing_action");

    if (strcmp(action, "set_ma") == 0) return cmd_set_ma(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    cJSON_AddStringToObject(r, "action", action);
    return r;
}
