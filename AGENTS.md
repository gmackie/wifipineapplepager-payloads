# Repository Guidelines

> Agent instructions for AI coding assistants (Copilot, Cursor, Claude, etc.)

## Project Structure & Module Organization

```
library/
  alerts/                    # Alert-triggered payloads (system events)
    deauth_flood_detected/
    handshake_captured/
    pineapple_auth_captured/
    pineapple_client_connected/
  recon/                     # Reconnaissance payloads (target selection)
    access_point/
    client/
  user/                      # User-initiated payloads
    examples/                # DuckyScript command examples
    exfiltration/
    general/
    incident_response/
    interception/
    prank/
    reconnaissance/
    remote_access/
```

- `library/alerts/*/example/payload.sh`: Alert-driven examples (e.g., client connected, handshake captured)
- `library/recon/*/example/payload.sh`: Reconnaissance examples (AP/client)
- `library/user/**`: User payload categories with examples and placeholders
- Add new payloads under the most relevant category in `library/.../<your_payload_name>/` with a `payload.sh` file

## Build, Test, and Development Commands

```bash
# Syntax check for bash
bash -n payload.sh

# Lint common shell pitfalls
shellcheck payload.sh

# Lint all payloads
find library -name "payload.sh" -exec shellcheck {} \;
```

- No compilation required - payloads run directly on-device
- Deploy payload folder to the Pager and execute from UI or CLI
- Verify LED/ringtone behavior during testing

## Coding Style & Naming Conventions

- **Indentation**: 2 spaces; avoid tabs
- **File naming**: no spaces; use `kebab-case` or `snake_case`
- **Entry file**: always name your script `payload.sh`
- **DuckyScript**: commands in UPPERCASE; combine with Bash for logic

### Required Payload Header

```bash
#!/bin/bash
# Title: Descriptive Payload Name
# Description: Brief explanation of what it does
# Author: YourName
# Version: 1.0
# Category: general|reconnaissance|exfiltration|interception|...
# Net Mode: NAT|BRIDGE|OFF
#
# LED States (optional)
# - Blue: Idle/Menu
# - Amber: Working
# - Green: Success
# - Red: Error
```

## DuckyScript Command Reference

DuckyScript commands are ALWAYS UPPERCASE and integrate directly with Bash.

### Output & Logging

| Command | Description | Example |
|---------|-------------|---------|
| `LOG [color] "msg"` | Log to payload output (red/green/blue) | `LOG green "Success!"` |
| `ALERT "msg"` | Show popup alert | `ALERT "Handshake captured!"` |
| `PROMPT "msg"` | Show message, wait for button | `PROMPT "Press to continue"` |
| `ERROR_DIALOG "msg"` | Show error dialog | `ERROR_DIALOG "Failed!"` |

### User Input

| Command | Description | Example |
|---------|-------------|---------|
| `WAIT_FOR_BUTTON_PRESS [btn]` | Wait for button (UP/DOWN/etc.) | `WAIT_FOR_BUTTON_PRESS UP` |
| `WAIT_FOR_INPUT` | Wait and return button pressed | `btn=$(WAIT_FOR_INPUT)` |
| `CONFIRMATION_DIALOG "msg"` | Yes/No dialog | `resp=$(CONFIRMATION_DIALOG "Continue?")` |
| `TEXT_PICKER "label" "default"` | Text input | `name=$(TEXT_PICKER "Name?" "")` |
| `NUMBER_PICKER "label" default` | Number input | `ch=$(NUMBER_PICKER "Channel" 6)` |
| `IP_PICKER "label" "default"` | IP address input | `ip=$(IP_PICKER "Target" "10.0.0.1")` |
| `MAC_PICKER "label" "default"` | MAC address input | `mac=$(MAC_PICKER "Target" "AA:BB:CC:DD:EE:FF")` |

### Progress Indicators

| Command | Description | Example |
|---------|-------------|---------|
| `START_SPINNER "msg"` | Start spinner, returns ID | `id=$(START_SPINNER "Working...")` |
| `STOP_SPINNER $id` | Stop spinner by ID | `STOP_SPINNER $id` |

### Return Code Constants

```bash
$DUCKYSCRIPT_CANCELLED      # User cancelled/backed out
$DUCKYSCRIPT_REJECTED       # Dialog was dismissed
$DUCKYSCRIPT_ERROR          # System error occurred
$DUCKYSCRIPT_USER_CONFIRMED # User selected "Yes"
$DUCKYSCRIPT_USER_DENIED    # User selected "No"
```

### Standard Picker Pattern

```bash
resp=$(NUMBER_PICKER "Enter channel" 6)
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; exit 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Error"; exit 1 ;;
esac
LOG "Selected: $resp"
```

## Environment Variables

### Alert Payload Variables

System-provided when alert payloads are triggered:

**Handshake Captured (`$_ALERT_HANDSHAKE_*`):**
- `$_ALERT_HANDSHAKE_SUMMARY` - Human-readable summary
- `$_ALERT_HANDSHAKE_AP_MAC_ADDRESS` - AP BSSID
- `$_ALERT_HANDSHAKE_CLIENT_MAC_ADDRESS` - Client MAC
- `$_ALERT_HANDSHAKE_TYPE` - `eapol` or `pmkid`
- `$_ALERT_HANDSHAKE_COMPLETE` - Full 4-way + beacon (eapol only)
- `$_ALERT_HANDSHAKE_CRACKABLE` - Potentially crackable (eapol only)
- `$_ALERT_HANDSHAKE_PCAP_PATH` - Path to pcap
- `$_ALERT_HANDSHAKE_HASHCAT_PATH` - Path to hashcat file

**Client Connected (`$_ALERT_CLIENT_CONNECTED_*`):**
- `$_ALERT_CLIENT_CONNECTED_SUMMARY` - Human-readable summary
- `$_ALERT_CLIENT_CONNECTED_AP_MAC_ADDRESS` - AP BSSID
- `$_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS` - Client MAC
- `$_ALERT_CLIENT_CONNECTED_SSID` - SSID (UTF-8 sanitized)
- `$_ALERT_CLIENT_CONNECTED_SSID_LENGTH` - Original SSID length

### Recon Payload Variables

System-provided when target is selected:

**Access Point (`$_RECON_SELECTED_AP_*`):**
- `$_RECON_SELECTED_AP_BSSID` - AP BSSID
- `$_RECON_SELECTED_AP_SSID` - AP SSID
- `$_RECON_SELECTED_AP_CHANNEL` - Channel
- `$_RECON_SELECTED_AP_ENCRYPTION_TYPE` - Encryption type
- `$_RECON_SELECTED_AP_RSSI` - Signal strength
- `$_RECON_SELECTED_AP_CLIENT_COUNT` - Connected clients
- `$_RECON_SELECTED_AP_OUI` - Vendor OUI
- `$_RECON_SELECTED_AP_HIDDEN` - Hidden network flag
- `$_RECON_SELECTED_AP_TIMESTAMP` - Discovery timestamp
- `$_RECON_SELECTED_AP_FREQ` - Frequency
- `$_RECON_SELECTED_AP_PACKETS` - Packet count

## Testing Guidelines

- **Manual tests**: verify on a WiFi Pineapple Pager with safe, non-production targets
- **Configuration**: use placeholders (e.g., `example.com`, dummy keys). Do not commit secrets
- **Staged code**: include scripts alongside the payload and instruct users to host them; do not hardcode live URLs

## Commit & Pull Request Guidelines

- **Commits**: concise, imperative (e.g., "add recon payload", "fix directory name for alerts")
- **PRs must include**: purpose/summary, category path, configuration notes, test steps/results
- Keep changes scoped to one payload/folder when possible; include any required assets

## Security & Configuration Rules

- **Never** commit credentials or live endpoints; use `DEFINE`-style variables and placeholders
- **Avoid** purely destructive behavior; payloads must be educational and safe
- **Always** use `example.com` for URLs and dummy values for sensitive config

## Good vs Bad Examples

### Good: Proper picker handling
```bash
resp=$(IP_PICKER "Target IP" "192.168.1.1")
case $? in
    $DUCKYSCRIPT_CANCELLED) LOG "Cancelled"; exit 1 ;;
    $DUCKYSCRIPT_REJECTED)  LOG "Rejected"; exit 1 ;;
    $DUCKYSCRIPT_ERROR)     LOG "Error"; exit 1 ;;
esac
LOG "Scanning $resp"
```

### Bad: Ignoring return codes
```bash
# Don't do this - ignores user cancellation
resp=$(IP_PICKER "Target IP" "192.168.1.1")
LOG "Scanning $resp"  # Will proceed even if cancelled
```

### Good: Modular payload structure
```bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/scripts/common.sh"
```

### Bad: Hardcoded paths and no error handling
```bash
# Don't do this
source /root/myscript.sh
```
