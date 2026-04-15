// iout_handler.c — AD5420 4-20mA current output DAC handler
// Exposes analog current output operations over the 24V field domain.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"
#include "ad5420.h"

static const char* TAG = "iout_handler";
static bool s_initialized = false;

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

cJSON* iout_handle_command(const char* action, cJSON* params)
{
    (void)params;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "iout_not_implemented");
    cJSON_AddStringToObject(resp, "action", action ? action : "");
    return resp;
}
