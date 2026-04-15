// iout_handler.c — AD5420 4-20mA current output DAC handler
// Exposes analog current output operations over the 24V field domain.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"

static const char* TAG = "iout_handler";
static bool s_initialized = false;

void iout_init(void)
{
    // Full init in Phase 2. Stub: leave uninitialized so probe.info reports
    // "iout": false until the real driver lands.
    ESP_LOGI(TAG, "iout_init: stub (Phase 2 not yet implemented)");
    s_initialized = false;
}

bool iout_is_ready(void)
{
    return s_initialized;
}

cJSON* iout_handle_command(const char* action, cJSON* params)
{
    (void)params;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "iout_not_implemented");
    cJSON_AddStringToObject(resp, "action", action ? action : "");
    return resp;
}
