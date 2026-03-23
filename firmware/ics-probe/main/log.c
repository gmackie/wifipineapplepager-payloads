/*
 * log.c — Ring-buffer logging for ICS Probe
 *
 * Stores up to MAX_LOG_ENTRIES entries in a circular buffer.  When the
 * buffer is full, the oldest entry is overwritten.  Thread-safe through
 * a FreeRTOS spinlock (portMUX_TYPE); suitable for calls from both task
 * and ISR context.
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char* TAG = "log";

// -----------------------------------------------------------------------
// Ring buffer definition
// -----------------------------------------------------------------------

#define LOG_MSG_MAX 128   // Maximum characters per log message

typedef struct {
    uint32_t timestamp_ms;
    char     level[8];           // "info", "warn", or "error"
    char     msg[LOG_MSG_MAX];
} log_record_t;

static log_record_t s_ring[MAX_LOG_ENTRIES];
static int          s_head  = 0;   // index of the next write slot
static int          s_count = 0;   // number of valid entries (≤ MAX_LOG_ENTRIES)

// Spinlock for ISR-safe access
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/*
 * log_init — clear the ring buffer.  Must be called once from app_main
 * before any other log_* function.
 */
void log_init(void)
{
    portENTER_CRITICAL(&s_mux);
    memset(s_ring, 0, sizeof(s_ring));
    s_head  = 0;
    s_count = 0;
    portEXIT_CRITICAL(&s_mux);

    ESP_LOGI(TAG, "ring buffer initialised (%d slots)", MAX_LOG_ENTRIES);
}

/*
 * log_entry — append a new log record, overwriting the oldest entry when
 * the buffer is full.
 *
 *  level  — "info", "warn", or "error"
 *  msg    — message string (truncated to LOG_MSG_MAX-1 characters)
 */
void log_entry(const char* level, const char* msg)
{
    if (!level || !msg) return;

    uint32_t now_ms = esp_log_timestamp();

    portENTER_CRITICAL(&s_mux);

    log_record_t* rec = &s_ring[s_head];
    rec->timestamp_ms = now_ms;

    strncpy(rec->level, level, sizeof(rec->level) - 1);
    rec->level[sizeof(rec->level) - 1] = '\0';

    strncpy(rec->msg, msg, sizeof(rec->msg) - 1);
    rec->msg[sizeof(rec->msg) - 1] = '\0';

    s_head = (s_head + 1) % MAX_LOG_ENTRIES;
    if (s_count < MAX_LOG_ENTRIES) {
        s_count++;
    }

    portEXIT_CRITICAL(&s_mux);

    // Mirror to the ESP-IDF serial log so entries appear in the monitor
    if (strcmp(level, "error") == 0) {
        ESP_LOGE(TAG, "%s", msg);
    } else if (strcmp(level, "warn") == 0) {
        ESP_LOGW(TAG, "%s", msg);
    } else {
        ESP_LOGI(TAG, "%s", msg);
    }
}

/*
 * log_get_entries — return a cJSON array containing all buffered log
 * entries in chronological order (oldest first).
 *
 * Each element is an object:
 *   { "ts": <uint32 ms>, "level": "<str>", "msg": "<str>" }
 *
 * The caller is responsible for calling cJSON_Delete() on the returned
 * array when it is no longer needed.
 */
cJSON* log_get_entries(void)
{
    cJSON* arr = cJSON_CreateArray();
    if (!arr) return NULL;

    portENTER_CRITICAL(&s_mux);

    /*
     * Calculate the index of the oldest entry.  When the buffer has not
     * yet wrapped, the oldest entry is at index 0.  Once it wraps,
     * s_head points to the slot that will be written next, which is also
     * the oldest slot.
     */
    int oldest;
    int count = s_count;

    if (count < MAX_LOG_ENTRIES) {
        oldest = 0;
    } else {
        oldest = s_head;  // buffer is full; s_head == oldest slot
    }

    // Take a local snapshot so we can release the lock quickly
    log_record_t snapshot[MAX_LOG_ENTRIES];
    memcpy(snapshot, s_ring, sizeof(s_ring));

    portEXIT_CRITICAL(&s_mux);

    // Build the JSON array from the snapshot
    for (int i = 0; i < count; i++) {
        int idx = (oldest + i) % MAX_LOG_ENTRIES;
        const log_record_t* rec = &snapshot[idx];

        cJSON* entry = cJSON_CreateObject();
        if (!entry) continue;

        cJSON_AddNumberToObject(entry, "ts",    (double)rec->timestamp_ms);
        cJSON_AddStringToObject(entry, "level", rec->level);
        cJSON_AddStringToObject(entry, "msg",   rec->msg);

        cJSON_AddItemToArray(arr, entry);
    }

    return arr;
}
