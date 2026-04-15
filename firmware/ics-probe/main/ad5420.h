// ad5420.h — AD5420 16-bit 4-20mA current output DAC SPI driver
//
// The AD5420 is a single-channel 16-bit current-output DAC that sources a
// programmable 4-20mA loop. It sits on the shared SPI3 bus behind the
// ADUM1401 digital isolator in the 24V field domain alongside the MAX14906.
//
// v1.1 simplification: the status-register read-back frame is stubbed —
// ad5420_read_status() returns 0x0000 until v1.2. The priority surface is
// set_ma / ramp / off, which is sufficient for bring-up.

#pragma once
#include <stdint.h>
#include <stdbool.h>

// Initialise the AD5420 on SPI3. Returns true if the chip was programmed
// into 4-20mA source mode, false on any failure (absent hardware is
// handled gracefully — the shared bus is left in a usable state).
bool ad5420_init(void);

// Set the loop current. Input is clamped to [IOUT_MIN_MA, IOUT_MAX_MA] and
// values below IOUT_OPERATING_MIN are further clamped to 4mA before the
// DAC-code conversion (the 4-20mA range has no code below 4mA).
bool ad5420_set_ma(float ma);

// Drive the DAC back to its minimum code (4mA in source mode). Note that
// this does not open the loop — a hardware relay would be needed for that.
bool ad5420_off(void);

// Read the status register. v1.1 stub: always returns 0x0000.
uint16_t ad5420_read_status(void);
