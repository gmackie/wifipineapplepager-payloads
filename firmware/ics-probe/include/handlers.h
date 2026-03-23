#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

// Handler state machine
typedef enum {
    HANDLER_IDLE,
    HANDLER_BUSY,
    HANDLER_RESPONSE_READY
} handler_state_t;

// --- Modbus Handler ---
void modbus_init(void);
cJSON* modbus_handle_command(const char* action, cJSON* params);

// --- Serial Handler ---
void serial_init(void);
cJSON* serial_handle_command(const char* action, cJSON* params);

// --- CAN Handler ---
void can_init(void);
cJSON* can_handle_command(const char* action, cJSON* params);

// --- ADC Handler ---
void adc_init(void);
cJSON* adc_handle_command(const char* action, cJSON* params);

// --- BLE Scanner ---
void ble_init(void);
cJSON* ble_handle_command(const char* action, cJSON* params);

// --- Safety ---
void safety_init(void);
bool safety_check_confirm(cJSON* params);
bool safety_rate_limit(const char* handler_name);

// --- Logging ---
void log_init(void);
void log_entry(const char* level, const char* msg);
cJSON* log_get_entries(void);
