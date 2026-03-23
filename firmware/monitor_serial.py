#!/usr/bin/env python3
import serial, sys, time

def monitor_serial(port='/dev/cu.usbmodem101', timeout=30):
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        print(f'Connected to {port}. Reading for {timeout}s...')
        print('=' * 70)

        start_time = time.time()
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='replace').rstrip()
                if line:
                    print(line)
                    sys.stdout.flush()

        print('=' * 70)
        ser.close()
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    port = sys.argv[1] if len(sys.argv) > 1 else '/dev/cu.usbmodem101'
    monitor_serial(port=port)
