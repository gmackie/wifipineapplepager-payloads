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
bool modbus_is_ready(void);
cJSON* modbus_handle_command(const char* action, cJSON* params);

// --- Serial Handler ---
void serial_init(void);
bool serial_is_ready(void);
cJSON* serial_handle_command(const char* action, cJSON* params);

// --- CAN Handler ---
void can_init(void);
bool can_is_ready(void);
cJSON* can_handle_command(const char* action, cJSON* params);

// --- ADC Handler ---
void adc_init(void);
bool adc_is_ready(void);
cJSON* adc_handle_command(const char* action, cJSON* params);

// --- BLE Scanner ---
void ble_init(void);
bool ble_is_ready(void);
cJSON* ble_handle_command(const char* action, cJSON* params);

// --- Network Handler (W5500 Ethernet) ---
void net_init(void);
bool net_is_ready(void);
cJSON* net_handle_command(const char* action, cJSON* params);

// --- Digital I/O Handler (MAX14906) ---
void dio_init(void);
bool dio_is_ready(void);
cJSON* dio_handle_command(const char* action, cJSON* params);

// --- Current Output Handler (AD5420) ---
void iout_init(void);
bool iout_is_ready(void);
cJSON* iout_handle_command(const char* action, cJSON* params);

// --- Safety ---
void safety_init(void);
bool safety_check_confirm(cJSON* params);
bool safety_rate_limit(const char* handler_name);

// --- Logging ---
void log_init(void);
void log_entry(const char* level, const char* msg);
cJSON* log_get_entries(void);
