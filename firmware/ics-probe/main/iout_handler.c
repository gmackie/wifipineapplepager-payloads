// iout_handler.c — AD5420 4-20mA current output DAC handler
// Exposes analog current output operations over the 24V field domain.

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"
#include "ad5420.h"

// Set by main.c's "stop" command — aborts streaming operations early.
extern volatile bool g_stop_requested;

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

// ─── Action: ramp ───────────────────────────────────────────────────────────
// params: {"from_ma","to_ma","duration_s","confirm":true}
//
// Confirm-gated. Breaks the ramp into 100ms steps (matches dio.monitor
// cadence) and writes the DAC on each step. g_stop_requested is checked
// every iteration to allow early abort via the "stop" command. No
// streaming progress lines for v1.1 — just the final summary.
static cJSON* cmd_ramp(cJSON* params)
{
    if (!params) return err_obj("missing_params");

    if (!safety_check_confirm(params)) return err_obj("confirm_required");

    cJSON* from_item = cJSON_GetObjectItemCaseSensitive(params, "from_ma");
    cJSON* to_item   = cJSON_GetObjectItemCaseSensitive(params, "to_ma");
    cJSON* dur_item  = cJSON_GetObjectItemCaseSensitive(params, "duration_s");

    if (!from_item || !cJSON_IsNumber(from_item)) return err_obj("missing_from_ma");
    if (!to_item   || !cJSON_IsNumber(to_item))   return err_obj("missing_to_ma");
    if (!dur_item  || !cJSON_IsNumber(dur_item))  return err_obj("missing_duration_s");

    float    from_ma    = (float)from_item->valuedouble;
    float    to_ma      = (float)to_item->valuedouble;
    uint32_t duration_s = (uint32_t)dur_item->valuedouble;
    if (duration_s < 1) duration_s = 1;

    uint32_t steps = duration_s * 10;  // 100ms step period
    if (steps < 1) steps = 1;
    float step_delta = (to_ma - from_ma) / (float)steps;

    float current = from_ma;
    uint32_t i;
    for (i = 0; i < steps; i++) {
        if (g_stop_requested) break;
        (void)ad5420_set_ma(current);
        s_setpoint_ma = current;
        vTaskDelay(pdMS_TO_TICKS(100));
        current += step_delta;
    }

    // Ensure we land exactly on to_ma on clean completion.
    if (!g_stop_requested) {
        (void)ad5420_set_ma(to_ma);
        s_setpoint_ma = to_ma;
    }

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "ok");
    cJSON_AddNumberToObject(r, "final_ma", s_setpoint_ma);
    cJSON_AddNumberToObject(r, "steps", i);
    if (g_stop_requested) cJSON_AddStringToObject(r, "stopped", "early");
    return r;
}

// ─── Command dispatcher ─────────────────────────────────────────────────────
cJSON* iout_handle_command(const char* action, cJSON* params)
{
    if (!s_initialized) return err_obj("not_initialized");
    if (!action)        return err_obj("missing_action");

    if (strcmp(action, "set_ma") == 0) return cmd_set_ma(params);
    if (strcmp(action, "ramp")   == 0) return cmd_ramp(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    cJSON_AddStringToObject(r, "action", action);
    return r;
}
