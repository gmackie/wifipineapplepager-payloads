#!/bin/bash
# shellcheck disable=SC1090,SC1091,SC2034,SC2329

set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

payload="library/user/remote_access/agent_console/payload.sh"
tmp_source="$(mktemp)"
trap 'rm -f "$tmp_source"' EXIT
sed '$d' "$payload" >"$tmp_source"

DUCKYSCRIPT_CANCELLED=1
DUCKYSCRIPT_REJECTED=2
DUCKYSCRIPT_ERROR=3
SESSION_NAME="test"
CURRENT_PROFILE_PATH="/tmp/bundled.json"
CURRENT_SESSION_ID="session-1"
CURRENT_SESSION_TITLE=""
CURRENT_SESSION_BACKEND=""
CURRENT_JOB_ID=""
CURRENT_JOB_JSON=""
LAST_STATUS_JSON=""
LAST_JOB_JSON=""
NO_SESSION_GUIDANCE=0
LOG_LINES=()

source "$tmp_source"

LOG() {
  local color="$1"
  shift
  LOG_LINES+=("$color|$*")
}

ERROR_DIALOG() {
  fail "unexpected error dialog: $*"
}

PROMPT() {
  :
}

NUMBER_PICKER() {
  fail "unexpected NUMBER_PICKER call"
}

TEXT_PICKER() {
  fail "unexpected TEXT_PICKER call"
}

CONFIRMATION_DIALOG() {
  fail "unexpected CONFIRMATION_DIALOG call"
}

WAIT_FOR_INPUT() {
  fail "unexpected WAIT_FOR_INPUT call"
}

show_no_session_guidance() {
  NO_SESSION_GUIDANCE=1
}

picker_failed() {
  return 1
}

load_session_status() {
  printf '%s\n' "$LAST_STATUS_JSON"
}

load_job_json_file() {
  printf '%s\n' "$LAST_JOB_JSON"
}

profile_label_for_path() {
  printf '%s\n' "bundled.json"
}

json_field() {
  local json="$1"
  local key="$2"

  JSON_INPUT="$json" JSON_KEY="$key" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
value = data.get(os.environ["JSON_KEY"], "")
if value is None:
    print("")
elif isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
PY
}

reset_logs() {
  LOG_LINES=()
  CURRENT_SESSION_ID="session-1"
}

assert_log_contains() {
  local needle="$1"
  local line

  for line in "${LOG_LINES[@]-}"; do
    if [[ "$line" == *"$needle"* ]]; then
      return 0
    fi
  done

  fail "expected log to contain: $needle"
}

assert_log_not_contains() {
  local needle="$1"
  local line

  for line in "${LOG_LINES[@]-}"; do
    if [[ "$line" == *"$needle"* ]]; then
      fail "did not expect log to contain: $needle"
    fi
  done
}

test_failed_job_without_error_still_shows_reply_preview() {
  reset_logs
  LAST_STATUS_JSON='{"title":"Session Alpha","backend":"command","last_job_state":"failed","last_job_id":"job-7","last_response_preview":"assistant fallback preview"}'
  LAST_JOB_JSON='{"id":"job-7","state":"failed","error":""}'

  render_dashboard

  assert_log_contains "Reply: assistant fallback preview"
  assert_log_not_contains "Error: "
}

test_compact_dashboard_preserves_backend_and_profile() {
  local long_title="This is a deliberately long session title that would normally push metadata off screen"
  local long_job="completed (job-1234567890-abcdefghijklmnopqrstuvwxyz)"
  local long_profile="very-long-profile-name-that-should-still-keep-its-label-visible.json"

  reset_logs
  LAST_STATUS_JSON="{\"title\":\"$long_title\",\"backend\":\"command\",\"last_job_state\":\"$long_job\",\"last_job_id\":\"\",\"last_response_preview\":\"\"}"

  profile_label_for_path() {
    printf '%s\n' "$long_profile"
  }

  render_dashboard

  assert_log_contains "Backend: command"
  assert_log_contains "Profile:"
}

test_failed_job_without_error_still_shows_reply_preview
test_compact_dashboard_preserves_backend_and_profile

echo OK
