#!/bin/bash
# Title: EdgeOps Enrollment
# Description: One-time enrollment of this pager as an EdgeOps edge node
# Author: ICS Toolkit
# Version: 0.1
# Category: remote_access
# Net Mode: NAT
#
# LED States
# - Blue:  Awaiting input
# - Green: Enrolled
# - Red:   Error

set -euo pipefail

ENROLLMENT_DIR="/root/edgeops"
ENROLLMENT_FILE="$ENROLLMENT_DIR/enrollment.json"
CONFIG_FILE="$ENROLLMENT_DIR/agent-config.json"

main() {
  LOG blue "=== EdgeOps Device Enrollment ==="
  LOG ""
  LOG blue "This enrolls the pager as an EdgeOps edge node."
  LOG blue "You need your Controls Foundry API base URL and an API key."
  LOG ""

  mkdir -p "$ENROLLMENT_DIR"

  # API base URL
  local api_base
  api_base=$(TEXT_PICKER "Controls Foundry API URL" "https://api.edgeops.cloud")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  # Device ID
  local device_id
  device_id=$(TEXT_PICKER "Device ID (e.g., org-123-pager-001)" "pager-001")
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac

  # Auth method
  local auth_resp
  auth_resp=$(CONFIRMATION_DIALOG "Use API Key auth? (No = Certificate auth)")

  local auth_type api_key cert_path key_path ca_path iot_endpoint

  case "$auth_resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED")
      auth_type="api_key"
      api_key=$(TEXT_PICKER "API Key" "ek_...")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      ;;
    *)
      auth_type="certificate"
      cert_path=$(TEXT_PICKER "Certificate path" "/root/edgeops/certs/device.cert.pem")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      key_path=$(TEXT_PICKER "Private key path" "/root/edgeops/certs/device.private.key")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      ca_path=$(TEXT_PICKER "Root CA path" "/root/edgeops/certs/root-CA.crt")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      iot_endpoint=$(TEXT_PICKER "IoT endpoint" "xxxxx-ats.iot.us-west-2.amazonaws.com")
      case $? in
        "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
          LOG "Cancelled"; exit 1 ;;
      esac
      ;;
  esac

  # Write enrollment record
  LOG blue "Saving enrollment..."

  if [[ "$auth_type" == "api_key" ]]; then
    cat > "$ENROLLMENT_FILE" <<ENROLL_EOF
{
  "device_id": "$device_id",
  "api_base_url": "$api_base",
  "auth_type": "api_key",
  "enrolled_at": "$(date -Iseconds)"
}
ENROLL_EOF

    cat > "$CONFIG_FILE" <<CONFIG_EOF
{
  "device_id": "$device_id",
  "api_base_url": "$api_base",
  "auth": {
    "type": "api_key",
    "api_key": "$api_key"
  },
  "poll_interval_ms": 5000,
  "buffer_max_mb": 50,
  "adapters": [
    {"type": "modbus-rtu", "connection_params": {}, "signals": []},
    {"type": "digital-io", "connection_params": {}, "signals": []},
    {"type": "analog-output", "connection_params": {}, "signals": []}
  ]
}
CONFIG_EOF
  else
    cat > "$ENROLLMENT_FILE" <<ENROLL_EOF
{
  "device_id": "$device_id",
  "api_base_url": "$api_base",
  "auth_type": "certificate",
  "enrolled_at": "$(date -Iseconds)"
}
ENROLL_EOF

    cat > "$CONFIG_FILE" <<CONFIG_EOF
{
  "device_id": "$device_id",
  "api_base_url": "$api_base",
  "auth": {
    "type": "certificate",
    "certificate": "$cert_path",
    "private_key": "$key_path",
    "root_ca": "$ca_path",
    "iot_endpoint": "$iot_endpoint"
  },
  "poll_interval_ms": 5000,
  "buffer_max_mb": 50,
  "adapters": [
    {"type": "modbus-rtu", "connection_params": {}, "signals": []},
    {"type": "digital-io", "connection_params": {}, "signals": []},
    {"type": "analog-output", "connection_params": {}, "signals": []}
  ]
}
CONFIG_EOF
  fi

  chmod 600 "$CONFIG_FILE"

  LOG green "Enrollment complete!"
  LOG green "Device: $device_id"
  LOG green "API: $api_base"
  LOG green "Auth: $auth_type"
  LOG ""
  LOG blue "Config saved to $CONFIG_FILE"
  LOG blue "Start the EdgeOps Agent payload to begin streaming data."

  ALERT "EdgeOps enrollment complete: $device_id"
}

main "$@"
