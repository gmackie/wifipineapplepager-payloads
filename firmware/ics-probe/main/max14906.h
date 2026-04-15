// max14906.h — MAX14906 4-channel 24V industrial DIO SPI driver
//
// The MAX14906 is a quad high-side switch / digital input with per-channel
// mode select. It sits on the shared SPI3 bus behind the ADUM1401 digital
// isolator in the 24V field domain.
//
// v1.1 simplification: Type 1/2/3 input threshold differentiation is
// recorded in a module-static array but not actually programmed into the
// DoiLvl register — the chip runs at its default threshold for POC use.
// Full Type differentiation is a v1.2 concern.

#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    DIO_MODE_INPUT_T1  = 0,  // IEC 61131-2 Type 1 (~15 V threshold) — POC: default
    DIO_MODE_INPUT_T2  = 1,  // Type 2 (~11 V) — POC: default
    DIO_MODE_INPUT_T3  = 2,  // Type 3 (~5 V)  — POC: default
    DIO_MODE_OUTPUT_HS = 3,  // High-side switch, active-high
} dio_mode_t;

// Initialise the MAX14906 on SPI3. Returns true if the chip responded to a
// probe read, false on any failure (absent hardware is handled gracefully).
bool max14906_init(void);

// Set channel mode (input T1/T2/T3 or high-side output).
bool max14906_set_mode(int ch, dio_mode_t mode);

// Drive a high-side output channel on/off.
bool max14906_write_output(int ch, bool high);

// Read the 4-channel input level mask into *out_mask (bits [3:0]).
bool max14906_read_inputs(uint8_t* out_mask);

// Read Interrupt (low byte) + OvrLdChF (high byte) combined into a 16-bit
// status word. Returns 0 if the driver is not initialised.
uint16_t max14906_read_faults(void);
