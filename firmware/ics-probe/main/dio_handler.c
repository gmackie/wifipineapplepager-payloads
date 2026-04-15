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

cJSON* dio_handle_command(const char* action, cJSON* params)
{
    (void)params;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "dio_not_implemented");
    cJSON_AddStringToObject(resp, "action", action ? action : "");
    return resp;
}
