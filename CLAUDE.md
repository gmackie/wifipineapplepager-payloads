# CLAUDE.md

This file provides context for Claude Code when working on the WiFi Pineapple Pager payloads repository.

## Build & Test Commands

```bash
# Syntax check a payload
bash -n payload.sh

# Lint with shellcheck (if available)
shellcheck payload.sh

# Lint all payloads in a directory
find library -name "payload.sh" -exec shellcheck {} \;
```

No compilation required - payloads run directly on the device.

## Project Structure

```
library/
  alerts/                    # Alert-triggered payloads (fired by system events)
    deauth_flood_detected/
    handshake_captured/
    pineapple_auth_captured/
    pineapple_client_connected/
  recon/                     # Reconnaissance payloads (target selection)
    access_point/
    client/
  user/                      # User-initiated payloads
    examples/                # DuckyScript command examples (ALERT, SPINNER, etc.)
    exfiltration/
    general/
    incident_response/
    interception/
    prank/
    reconnaissance/
    remote_access/
```

- Each payload lives in its own directory with a `payload.sh` entry file
- Complex payloads may include `scripts/` subdirectories and a `README.md`

## Code Style & Conventions

### File Structure
- Indentation: 2 spaces (no tabs)
- File naming: `kebab-case` or `snake_case` (no spaces)
- Entry file: always named `payload.sh`

### Payload Header (Required)
```bash
#!/bin/bash
# Title: Descriptive Name
# Description: Brief explanation
# Author: YourName
# Version: 1.0
# Category: general|reconnaissance|exfiltration|...
# Net Mode: NAT|BRIDGE|OFF
#
# LED States (optional, for complex payloads)
# - Blue: Idle/Menu
# - Amber: Working
# - Green: Success
# - Red: Error
```

### DuckyScript Commands
DuckyScript commands are ALWAYS UPPERCASE. They integrate with Bash:

| Command | Usage |
|---------|-------|
| `LOG [color] "msg"` | Log message (colors: red, green, blue) |
| `ALERT "msg"` | Show popup alert |
| `PROMPT "msg"` | Show message, wait for button |
| `ERROR_DIALOG "msg"` | Show error dialog |
| `WAIT_FOR_BUTTON_PRESS [btn]` | Wait for button (UP, DOWN, etc.) |
| `WAIT_FOR_INPUT` | Wait and return button pressed |
| `START_SPINNER "msg"` | Start spinner, returns ID |
| `STOP_SPINNER $id` | Stop spinner by ID |
| `CONFIRMATION_DIALOG "msg"` | Yes/No dialog |
| `TEXT_PICKER "label" "default"` | Text input |
| `NUMBER_PICKER "label" default` | Number input |
| `IP_PICKER "label" "default"` | IP address input |
| `MAC_PICKER "label" "default"` | MAC address input |

### Picker Return Code Handling
```bash
resp=$(NUMBER_PICKER "Enter value" 42)
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; exit 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Error"; exit 1 ;;
esac
LOG "User picked: $resp"
```

### Confirmation Dialog Handling
```bash
resp=$(CONFIRMATION_DIALOG "Continue?")
case "$resp" in
    $DUCKYSCRIPT_USER_CONFIRMED) LOG "Yes" ;;
    $DUCKYSCRIPT_USER_DENIED)    LOG "No" ;;
esac
```

## Environment Variables

### Alert Payloads
System-provided variables for alert-triggered payloads:

**Handshake Captured:**
- `$_ALERT_HANDSHAKE_SUMMARY` - Human-readable summary
- `$_ALERT_HANDSHAKE_AP_MAC_ADDRESS` - AP/BSSID MAC
- `$_ALERT_HANDSHAKE_CLIENT_MAC_ADDRESS` - Client MAC
- `$_ALERT_HANDSHAKE_TYPE` - eapol | pmkid
- `$_ALERT_HANDSHAKE_PCAP_PATH` - Path to pcap file
- `$_ALERT_HANDSHAKE_HASHCAT_PATH` - Path to hashcat file

**Client Connected:**
- `$_ALERT_CLIENT_CONNECTED_SUMMARY` - Human-readable summary
- `$_ALERT_CLIENT_CONNECTED_AP_MAC_ADDRESS` - AP/BSSID
- `$_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS` - Client MAC
- `$_ALERT_CLIENT_CONNECTED_SSID` - SSID (UTF-8 sanitized)

### Recon Payloads
System-provided variables for selected targets:

**Access Point:**
- `$_RECON_SELECTED_AP_BSSID` - AP BSSID
- `$_RECON_SELECTED_AP_SSID` - AP SSID
- `$_RECON_SELECTED_AP_CHANNEL` - Channel
- `$_RECON_SELECTED_AP_ENCRYPTION_TYPE` - Encryption type
- `$_RECON_SELECTED_AP_RSSI` - Signal strength
- `$_RECON_SELECTED_AP_CLIENT_COUNT` - Connected clients
- `$_RECON_SELECTED_AP_OUI` - Vendor OUI

## Security Rules

- NEVER commit credentials, API keys, or live endpoints
- Use `example.com` and placeholder values for configuration
- Avoid purely destructive payloads
- Payloads must be educational and safe

## Workflow

- Branch naming: `feature/payload-name` or `fix/issue-description`
- Commits: imperative mood ("add recon payload", "fix alert handler")
- PRs: include purpose, category path, configuration notes, test results
