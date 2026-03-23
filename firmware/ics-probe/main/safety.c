/*
 * safety.c — Safety enforcement for ICS Probe
 *
 * Responsibilities:
 *  - Confirm-flag gating for destructive commands
 *  - Per-handler rate limiting
 *  - Brownout detection with graceful CDC error response
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char* TAG = "safety";

// -----------------------------------------------------------------------
// Rate-limit table
// -----------------------------------------------------------------------

#define MAX_TRACKED_HANDLERS 16

typedef struct {
    char     name[32];
    uint32_t last_cmd_ms;
} rate_entry_t;

static rate_entry_t s_rate_table[MAX_TRACKED_HANDLERS];
static int          s_rate_count = 0;

// -----------------------------------------------------------------------
// Brownout handler
// -----------------------------------------------------------------------

/*
 * Called by the brownout detector interrupt before the chip resets.
 * We send a minimal JSON error over CDC so the host can detect the
 * unexpected disconnection and clean up state.
 *
 * Note: this runs in ISR context — keep it minimal and use only
 * ISR-safe CDC operations.  tinyusb_cdcacm_write_queue is safe here
 * because it only copies data into a ring buffer.
 */
static void brownout_handler(void)
{
    const char* msg = "{\"status\":\"error\",\"error\":\"brownout\"}\n";
    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                               (const uint8_t*)msg,
                               strlen(msg));
    // Best-effort flush — ignore return value in ISR context
    tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, 0);
}

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

void safety_init(void)
{
    memset(s_rate_table, 0, sizeof(s_rate_table));
    s_rate_count = 0;

    /*
     * Register shutdown handler for best-effort brownout notification.
     * The brownout detector itself is configured via sdkconfig (Kconfig).
     * When brownout triggers a reset, the shutdown handler chain runs
     * and we try to push a JSON error over CDC before the chip resets.
     */
    esp_err_t err = esp_register_shutdown_handler(brownout_handler);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "shutdown handler registration failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "shutdown handler registered (brownout notification)");
    }
}

/*
 * safety_check_confirm — returns true only if params contains
 * "confirm": true.  Logs a warning and returns false otherwise.
 */
bool safety_check_confirm(cJSON* params)
{
    if (!params) {
        ESP_LOGW(TAG, "safety_check_confirm: no params supplied");
        return false;
    }

    cJSON* confirm = cJSON_GetObjectItemCaseSensitive(params, "confirm");
    if (!confirm || !cJSON_IsBool(confirm) || !cJSON_IsTrue(confirm)) {
        ESP_LOGW(TAG, "safety_check_confirm: 'confirm':true missing from params");
        return false;
    }

    return true;
}

/*
 * safety_rate_limit — returns true if the command is allowed (sufficient
 * time has elapsed since the last command to this handler), false if it
 * should be rejected.
 *
 * Uses esp_log_timestamp() which returns milliseconds since boot — the
 * same source used throughout the log module for consistency.
 */
bool safety_rate_limit(const char* handler_name)
{
    if (!handler_name) return false;

    uint32_t now_ms = esp_log_timestamp();

    // Search for an existing entry
    for (int i = 0; i < s_rate_count; i++) {
        if (strncmp(s_rate_table[i].name, handler_name,
                    sizeof(s_rate_table[i].name) - 1) == 0) {
            uint32_t elapsed = now_ms - s_rate_table[i].last_cmd_ms;
            if (elapsed < RATE_LIMIT_MS) {
                ESP_LOGW(TAG, "rate limit: handler '%s' called too soon "
                         "(elapsed %"PRIu32" ms, min %d ms)",
                         handler_name, elapsed, RATE_LIMIT_MS);
                return false;
            }
            s_rate_table[i].last_cmd_ms = now_ms;
            return true;
        }
    }

    // New handler — add to table if there is room
    if (s_rate_count < MAX_TRACKED_HANDLERS) {
        strncpy(s_rate_table[s_rate_count].name, handler_name,
                sizeof(s_rate_table[s_rate_count].name) - 1);
        s_rate_table[s_rate_count].name[sizeof(s_rate_table[s_rate_count].name) - 1] = '\0';
        s_rate_table[s_rate_count].last_cmd_ms = now_ms;
        s_rate_count++;
    } else {
        // Table full — allow the command but log a warning
        ESP_LOGW(TAG, "rate limit table full, allowing '%s' unchecked",
                 handler_name);
    }

    return true;
}
