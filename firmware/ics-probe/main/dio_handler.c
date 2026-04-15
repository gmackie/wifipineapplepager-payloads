// dio_handler.c — MAX14906 4-channel 24V digital I/O handler
// Exposes digital input/output operations over the 24V field domain.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"

static const char* TAG = "dio_handler";
static bool s_initialized = false;

void dio_init(void)
{
    // Full init in Phase 2. Stub: leave uninitialized so probe.info reports
    // "dio": false until the real driver lands.
    ESP_LOGI(TAG, "dio_init: stub (Phase 2 not yet implemented)");
    s_initialized = false;
}

bool dio_is_ready(void)
{
    return s_initialized;
}

cJSON* dio_handle_command(const char* action, cJSON* params)
{
    (void)params;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "dio_not_implemented");
    cJSON_AddStringToObject(resp, "action", action ? action : "");
    return resp;
}
