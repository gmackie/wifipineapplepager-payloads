// adc_handler.c — 4-20 mA current measurement via INA219 over I2C
// Uses ESP-IDF I2C master driver + cJSON for structured output.

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char *TAG = "adc_handler";

// ─── INA219 register addresses ───────────────────────────────────────────────

#define INA219_REG_CONFIG       0x00
#define INA219_REG_SHUNT_V      0x01
#define INA219_REG_BUS_V        0x02
#define INA219_REG_POWER        0x03
#define INA219_REG_CURRENT      0x04
#define INA219_REG_CALIBRATION  0x05

// ─── INA219 CONFIG register bit fields ──────────────────────────────────────
//
// [15]    RST           software reset
// [13]    BRNG          bus voltage range: 0=16V, 1=32V
// [12:11] PGA           shunt PGA gain:    00=/1(±40mV), 01=/2(±80mV),
//                                          10=/4(±160mV), 11=/8(±320mV)
// [10:7]  BADC          bus ADC resolution / averaging
// [6:3]   SADC          shunt ADC resolution / averaging
// [2:0]   MODE          operating mode
//
// For 4-20 mA on a 250 Ω sense resistor:
//   Vshunt_max = 20 mA × 250 Ω = 5 V → exceeds INA219 shunt input range!
//
// Practical note: 250 Ω is an unusually large sense resistor for INA219.
// The INA219 shunt input maximum differential is ±320 mV (PGA = /8).
// At 20 mA → 250 Ω × 20 mA = 5 000 mV — far out of range.
//
// The SENSE_RESISTOR_OHMS define in config.h is therefore treated as a
// documentation value (actual board may use a different value or an external
// op-amp stage). The calibration constant below is calculated for the
// INA219 shunt voltage range:
//
//   Current_LSB = MaxExpectedCurrent / 32768
//   For this driver we target Max_I = 25 mA (slightly above 20 mA):
//     Current_LSB = 25e-3 / 32768 ≈ 0.7629 µA  → round to 1 µA for simplicity
//   Cal = trunc(0.04096 / (Current_LSB × R_shunt))
//
// Users on real hardware should adjust CURRENT_LSB_UA and recalculate.

#define CURRENT_LSB_UA      1UL        // 1 µA per LSB
#define CURRENT_LSB_A       (CURRENT_LSB_UA * 1e-6f)

// Calibration = 0.04096 / (Current_LSB_A × R_shunt_ohms)
// With R=250 this gives a very small cal value; kept as runtime calculation.

// CONFIG value:
//   BRNG=0 (16V bus), PGA=/8 (±320mV), BADC=12-bit, SADC=12-bit, MODE=continuous
//   Bit pattern: 0 0 0 | BRNG=0 | PGA=11 | BADC=0011 | SADC=0011 | MODE=111
//   = 0x0000 | (0<<13) | (3<<11) | (3<<7) | (3<<3) | 7
//   = 0x1E1F  (no BRNG, PGA=/8, 12-bit continuous)
#define INA219_CONFIG_VAL   0x1E1F

#define I2C_PORT            I2C_NUM_0
#define I2C_TIMEOUT_MS      100

// ─── Module state ───────────────────────────────────────────────────────────

static bool    s_initialized = false;
static uint16_t s_calibration = 0;

extern volatile bool g_stop_requested;

// ─── Low-level I2C helpers ───────────────────────────────────────────────────

// Write a 16-bit value to an INA219 register (big-endian on wire).
static esp_err_t ina219_write_reg(uint8_t reg, uint16_t val)
{
    uint8_t data[3] = {
        reg,
        (uint8_t)(val >> 8),
        (uint8_t)(val & 0xFF),
    };
    return i2c_master_write_to_device(I2C_PORT, INA219_ADDR, data, sizeof(data),
                                      pdMS_TO_TICKS(I2C_TIMEOUT_MS));
}

// Read a 16-bit signed register from INA219.
static esp_err_t ina219_read_reg(uint8_t reg, int16_t *out)
{
    uint8_t reg_buf[1] = { reg };
    uint8_t rx[2]      = { 0 };

    esp_err_t err = i2c_master_write_read_device(
        I2C_PORT, INA219_ADDR,
        reg_buf, 1,
        rx, 2,
        pdMS_TO_TICKS(I2C_TIMEOUT_MS));

    if (err == ESP_OK) {
        *out = (int16_t)((rx[0] << 8) | rx[1]);
    }
    return err;
}

// ─── Calibration calculation ─────────────────────────────────────────────────

static uint16_t calc_calibration(void)
{
    // Cal = 0.04096 / (Current_LSB_A × R_shunt)
    // With CURRENT_LSB_UA = 1 → Current_LSB_A = 1e-6
    // R_shunt = SENSE_RESISTOR_OHMS
    float cal_f = 0.04096f / (CURRENT_LSB_A * (float)SENSE_RESISTOR_OHMS);
    if (cal_f < 1.0f)  cal_f = 1.0f;
    if (cal_f > 65535.0f) cal_f = 65535.0f;
    return (uint16_t)cal_f;
}

// ─── Public init ────────────────────────────────────────────────────────────

void adc_init(void)
{
    if (s_initialized) return;

    i2c_config_t conf = {
        .mode             = I2C_MODE_MASTER,
        .sda_io_num       = I2C_SDA_PIN,
        .scl_io_num       = I2C_SCL_PIN,
        .sda_pullup_en    = GPIO_PULLUP_ENABLE,
        .scl_pullup_en    = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 100000,  // 100 kHz standard mode
    };
    ESP_ERROR_CHECK(i2c_param_config(I2C_PORT, &conf));
    ESP_ERROR_CHECK(i2c_driver_install(I2C_PORT, I2C_MODE_MASTER, 0, 0, 0));

    // INA219 configuration register
    esp_err_t err = ina219_write_reg(INA219_REG_CONFIG, INA219_CONFIG_VAL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "INA219 config write failed: %s", esp_err_to_name(err));
        return;
    }

    // Calibration register
    s_calibration = calc_calibration();
    err = ina219_write_reg(INA219_REG_CALIBRATION, s_calibration);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "INA219 calibration write failed: %s", esp_err_to_name(err));
        return;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "INA219 initialized (addr=0x%02X, cal=%u, R_sense=%d Ω)",
             INA219_ADDR, s_calibration, SENSE_RESISTOR_OHMS);
}

// ─── Current reading ─────────────────────────────────────────────────────────

// Returns current in milliamps, or NAN on error.
static float ina219_read_milliamps(void)
{
    int16_t raw = 0;
    esp_err_t err = ina219_read_reg(INA219_REG_CURRENT, &raw);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "INA219 current read failed: %s", esp_err_to_name(err));
        return NAN;
    }
    // raw = current / Current_LSB  → current_µA = raw × CURRENT_LSB_UA
    // milliamps = raw × CURRENT_LSB_UA / 1000.0
    float milliamps = (float)raw * (float)CURRENT_LSB_UA / 1000.0f;
    return milliamps;
}

// ─── Action: "read" ─────────────────────────────────────────────────────────
//
// params: {} (none required)
// Returns: { "milliamps": <float> }

static cJSON *action_read(cJSON *params)
{
    (void)params;

    float ma = ina219_read_milliamps();

    cJSON *result = cJSON_CreateObject();
    if (isnan(ma)) {
        cJSON_AddStringToObject(result, "error", "I2C read failed");
    } else {
        cJSON_AddNumberToObject(result, "milliamps", (double)ma);

        // Annotate loop status for convenience
        if (ma >= 3.8f && ma <= 4.2f) {
            cJSON_AddStringToObject(result, "loop_status", "live_zero");
        } else if (ma >= 3.5f && ma < 3.8f) {
            cJSON_AddStringToObject(result, "loop_status", "below_range");
        } else if (ma > 20.5f) {
            cJSON_AddStringToObject(result, "loop_status", "over_range");
        } else if (ma < 1.0f) {
            cJSON_AddStringToObject(result, "loop_status", "open_circuit");
        } else {
            cJSON_AddStringToObject(result, "loop_status", "normal");
        }
    }
    return result;
}

// ─── Action: "stream" ───────────────────────────────────────────────────────
//
// params: { "interval_ms": <int>, "duration_s": <int> }
// Outputs one JSON line per reading to stdout, then returns summary.

static cJSON *action_stream(cJSON *params)
{
    cJSON *iv_item  = cJSON_GetObjectItemCaseSensitive(params, "interval_ms");
    cJSON *dur_item = cJSON_GetObjectItemCaseSensitive(params, "duration_s");

    uint32_t interval_ms = (iv_item && cJSON_IsNumber(iv_item))
                           ? (uint32_t)iv_item->valuedouble : 1000;
    uint32_t duration_s  = (dur_item && cJSON_IsNumber(dur_item))
                           ? (uint32_t)dur_item->valuedouble : 10;

    if (interval_ms < 1)   interval_ms = 1;
    if (duration_s  < 1)   duration_s  = 1;

    uint64_t deadline   = (uint64_t)esp_timer_get_time() + (uint64_t)duration_s * 1000000ULL;
    uint32_t sample_cnt = 0;
    float    sum_ma     = 0.0f;
    float    min_ma     =  1e9f;
    float    max_ma     = -1e9f;

    while (esp_timer_get_time() < deadline && !g_stop_requested) {
        uint64_t loop_start = (uint64_t)esp_timer_get_time();

        float ma = ina219_read_milliamps();
        uint64_t ts_ms = loop_start / 1000ULL;

        if (!isnan(ma)) {
            printf("{\"milliamps\":%.4f,\"ts\":%llu}\n",
                   (double)ma, (unsigned long long)ts_ms);
            sample_cnt++;
            sum_ma += ma;
            if (ma < min_ma) min_ma = ma;
            if (ma > max_ma) max_ma = ma;
        } else {
            printf("{\"error\":\"read_failed\",\"ts\":%llu}\n",
                   (unsigned long long)ts_ms);
        }

        // Sleep for the remainder of the interval
        uint64_t elapsed_us = (uint64_t)esp_timer_get_time() - loop_start;
        int32_t  sleep_ms   = (int32_t)interval_ms - (int32_t)(elapsed_us / 1000ULL);
        if (sleep_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS((uint32_t)sleep_ms));
        }
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "status", "done");
    cJSON_AddNumberToObject(result, "samples",     sample_cnt);
    cJSON_AddNumberToObject(result, "duration_s",  duration_s);
    cJSON_AddNumberToObject(result, "interval_ms", interval_ms);
    if (sample_cnt > 0) {
        cJSON_AddNumberToObject(result, "avg_milliamps", (double)(sum_ma / (float)sample_cnt));
        cJSON_AddNumberToObject(result, "min_milliamps", (double)min_ma);
        cJSON_AddNumberToObject(result, "max_milliamps", (double)max_ma);
    }
    return result;
}

// ─── Public command dispatcher ───────────────────────────────────────────────

cJSON *adc_handle_command(const char *action, cJSON *params)
{
    if (!s_initialized) {
        return cJSON_CreateString("error: ADC handler not initialized");
    }
    if (!safety_rate_limit("adc")) {
        return cJSON_CreateString("error: rate limit exceeded");
    }

    if (strcmp(action, "read")   == 0) return action_read(params);
    if (strcmp(action, "stream") == 0) return action_stream(params);

    cJSON *err = cJSON_CreateObject();
    cJSON_AddStringToObject(err, "error", "unknown action");
    cJSON_AddStringToObject(err, "available", "read | stream");
    return err;
}
