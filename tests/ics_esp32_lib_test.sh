#!/usr/bin/env bash
set -euo pipefail

# --- Test harness for v1.1 esp32.sh wrappers ---

PASS_COUNT=0
FAIL_COUNT=0
CONFIRM_RESPONSE=0  # 0 = confirmed, 1 = denied

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# State files (avoid subshell variable scoping)
SEND_CMD_FILE="$tmp_dir/send_cmd"
SEND_PARAMS_FILE="$tmp_dir/send_params"
CONFIRM_FLAG_FILE="$tmp_dir/confirm_prompted"

# --- DuckyScript constants (on the real pager these are provided by the runtime) ---
DUCKYSCRIPT_USER_CONFIRMED=0
DUCKYSCRIPT_USER_DENIED=1
DUCKYSCRIPT_CANCELLED=2
DUCKYSCRIPT_REJECTED=3
DUCKYSCRIPT_ERROR=4

# --- Mocks ---

esp32_send() {
  printf '%s' "$1" > "$SEND_CMD_FILE"
  printf '%s' "${2:-{}}" > "$SEND_PARAMS_FILE"
  echo '{"status":"ok"}'
}

CONFIRMATION_DIALOG() {
  printf '1' > "$CONFIRM_FLAG_FILE"
  echo "$CONFIRM_RESPONSE"
}

LOG() { :; }
ERROR_DIALOG() { :; }
ALERT() { :; }

# Preload ESP32_DEV so esp32_send doesn't bail on the empty-check
ESP32_DEV="/tmp/fake_tty"

# --- Source the library under test ---
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
source "$repo_root/library/user/ics/lib/esp32.sh"

# Re-override esp32_send because sourcing the lib replaces our mock.
esp32_send() {
  printf '%s' "$1" > "$SEND_CMD_FILE"
  printf '%s' "${2:-{}}" > "$SEND_PARAMS_FILE"
  echo '{"status":"ok"}'
}

# --- Assertion helpers ---

reset_state() {
  rm -f "$SEND_CMD_FILE" "$SEND_PARAMS_FILE" "$CONFIRM_FLAG_FILE"
  CONFIRM_RESPONSE=0
}

_read_file() { [[ -f "$1" ]] && cat "$1" || echo ""; }

assert_cmd() {
  local expected="$1"
  local actual
  actual=$(_read_file "$SEND_CMD_FILE")
  if [[ "$actual" != "$expected" ]]; then
    echo "  expected cmd='$expected', got cmd='$actual'" >&2
    return 1
  fi
}

assert_params_contain() {
  local needle="$1"
  local actual
  actual=$(_read_file "$SEND_PARAMS_FILE")
  if [[ "$actual" != *"$needle"* ]]; then
    echo "  expected params to contain '$needle', got '$actual'" >&2
    return 1
  fi
}

assert_no_send() {
  local actual
  actual=$(_read_file "$SEND_CMD_FILE")
  if [[ -n "$actual" ]]; then
    echo "  expected no send, but got cmd='$actual'" >&2
    return 1
  fi
}

assert_confirmed() {
  if [[ ! -f "$CONFIRM_FLAG_FILE" ]]; then
    echo "  expected confirmation prompt, but none issued" >&2
    return 1
  fi
}

assert_not_confirmed() {
  if [[ -f "$CONFIRM_FLAG_FILE" ]]; then
    echo "  expected no confirmation prompt, but one was issued" >&2
    return 1
  fi
}

run_test() {
  local name="$1"
  reset_state
  if "$name"; then
    echo "  PASS: $name"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "  FAIL: $name" >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# --- Tests ---

test_net_dhcp_sends_correct_command() {
  esp32_net_dhcp 15 >/dev/null
  assert_cmd "net.dhcp" && assert_params_contain '"timeout_s":15'
}

test_net_tcp_connect() {
  esp32_net_tcp_connect "10.0.0.1" 502 >/dev/null
  assert_cmd "net.tcp_connect" && assert_params_contain '"host":"10.0.0.1"' && assert_params_contain '"port":502'
}

test_net_udp_send() {
  esp32_net_udp_send "255.255.255.255" 47808 "deadbeef" >/dev/null
  assert_cmd "net.udp_send" && assert_params_contain '"port":47808' && assert_params_contain '"data":"deadbeef"'
}

test_dio_read_no_confirm() {
  esp32_dio_read >/dev/null
  assert_cmd "dio.read" && assert_not_confirmed
}

test_dio_write_confirm_accepted() {
  CONFIRM_RESPONSE=0
  esp32_dio_write 0 1 >/dev/null
  assert_confirmed && assert_cmd "dio.write" && assert_params_contain '"confirm":true'
}

test_dio_write_confirm_denied() {
  CONFIRM_RESPONSE=1
  esp32_dio_write 0 1 >/dev/null 2>/dev/null || true
  assert_confirmed && assert_no_send
}

test_iout_set_ma_confirmed() {
  CONFIRM_RESPONSE=0
  esp32_iout_set_ma 12.0 >/dev/null
  assert_confirmed && assert_cmd "iout.set_ma" && assert_params_contain '"confirm":true' && assert_params_contain '"ma":12.0'
}

test_iout_set_ma_denied() {
  CONFIRM_RESPONSE=1
  esp32_iout_set_ma 12.0 >/dev/null 2>/dev/null || true
  assert_confirmed && assert_no_send
}

test_iout_off_no_confirm() {
  esp32_iout_off >/dev/null
  assert_cmd "iout.off" && assert_not_confirmed
}

test_dio_configure_no_confirm() {
  esp32_dio_configure 0 "input_t3" >/dev/null
  assert_cmd "dio.configure" && assert_not_confirmed && assert_params_contain '"mode":"input_t3"'
}

# --- Run all tests ---

echo "Running v1.1 esp32.sh wrapper tests..."
run_test test_net_dhcp_sends_correct_command
run_test test_net_tcp_connect
run_test test_net_udp_send
run_test test_dio_read_no_confirm
run_test test_dio_write_confirm_accepted
run_test test_dio_write_confirm_denied
run_test test_iout_set_ma_confirmed
run_test test_iout_set_ma_denied
run_test test_iout_off_no_confirm
run_test test_dio_configure_no_confirm

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "FAIL"
  exit 1
else
  echo "PASS"
  exit 0
fi
