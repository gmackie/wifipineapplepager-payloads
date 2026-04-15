// net_handler.c — W5500 Ethernet controller handler
// Exposes TCP/UDP socket operations over the probe's SPI Ethernet NIC.

#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "config.h"
#include "handlers.h"

static const char* TAG = "net_handler";
static bool s_initialized = false;

void net_init(void)
{
    // Full init in Phase 2. Stub: leave uninitialized so probe.info reports
    // "net": false until the real driver lands.
    ESP_LOGI(TAG, "net_init: stub (Phase 2 not yet implemented)");
    s_initialized = false;
}

bool net_is_ready(void)
{
    return s_initialized;
}

cJSON* net_handle_command(const char* action, cJSON* params)
{
    (void)params;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "net_not_implemented");
    cJSON_AddStringToObject(resp, "action", action ? action : "");
    return resp;
}
