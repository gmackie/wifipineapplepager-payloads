#!/bin/bash
# Title: Agent Console
# Description: Persistent pager chat sessions for local coding agents
# Author: OpenAI
# Version: 1.0
# Category: remote_access
# Net Mode: NAT
#
# LED States (optional)
# - Blue: Menu
# - Amber: Waiting for agent
# - Green: Response ready
# - Red: Error

set -euo pipefail

PAYLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$PAYLOAD_DIR/agent_console.py"
LOOT_DIR="/root/loot/agent-console"
SESSION_NAME="agent-console"
REQUIRED_PACKAGES=(python3)
DEFAULT_PROFILE_PATH="$PAYLOAD_DIR/profiles/command.example.json"
CURRENT_SESSION_ID=""
CURRENT_SESSION_TITLE=""
CURRENT_SESSION_BACKEND=""
CURRENT_PROFILE_PATH="$DEFAULT_PROFILE_PATH"
CURRENT_PROFILE_TYPE="command"
CURRENT_JOB_ID=""
CURRENT_JOB_JSON=""
LAST_PROMPT=""
SHORT_REPLY_LIMIT=160
ERROR_SUMMARY_LIMIT=120

require_package() {
  local pkg="$1"
  if ! opkg list-installed | grep -q "^${pkg} "; then
    ERROR_DIALOG "${pkg} is required for Agent Console"
    exit 1
  fi
}

require_dependencies() {
  local pkg
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    require_package "$pkg"
  done
}

run_helper() {
  python3 "$HELPER" "$@"
}

ensure_loot_dir() {
  mkdir -p "$LOOT_DIR"
}

is_short_reply() {
  local text="$1"
  [[ ${#text} -le $SHORT_REPLY_LIMIT ]]
}

summarize_error() {
  local text="$1"
  text="${text//$'\n'/ }"
  text="${text//$'\r'/ }"

  if [[ ${#text} -le $ERROR_SUMMARY_LIMIT ]]; then
    printf '%s\n' "$text"
    return 0
  fi

  if [[ $ERROR_SUMMARY_LIMIT -le 3 ]]; then
    printf '%s\n' "${text:0:$ERROR_SUMMARY_LIMIT}"
    return 0
  fi

  printf '%s...\n' "${text:0:$((ERROR_SUMMARY_LIMIT - 3))}"
}

dashboard_normalize_text() {
  local text="$1"

  text="${text//$'\r'/ }"
  text="${text//$'\n'/ }"
  text="${text//$'\t'/ }"
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"

  while [[ "$text" == *"  "* ]]; do
    text="${text//  / }"
  done

  printf '%s\n' "$text"
}

dashboard_truncate_text() {
  local text="$1"
  local limit="$2"

  if [[ -z "$text" ]]; then
    printf '\n'
    return 0
  fi

  if [[ ${#text} -le $limit ]]; then
    printf '%s\n' "$text"
    return 0
  fi

  if [[ $limit -le 3 ]]; then
    printf '%s\n' "${text:0:$limit}"
    return 0
  fi

  printf '%s...\n' "${text:0:$((limit - 3))}"
}

dashboard_compact_pair_line() {
  local left_label="$1"
  local left_value="$2"
  local right_label="$3"
  local right_value="$4"
  local limit="${5:-72}"
  local left
  local right
  local left_limit
  local right_limit
  local min_left
  local min_right

  left_label="$(dashboard_normalize_text "$left_label")"
  left_value="$(dashboard_normalize_text "$left_value")"
  right_label="$(dashboard_normalize_text "$right_label")"
  right_value="$(dashboard_normalize_text "$right_value")"

  if [[ -n "$left_value" ]]; then
    left="${left_label}: $left_value"
  fi

  if [[ -n "$right_value" ]]; then
    right="${right_label}: $right_value"
  fi

  if [[ -n "$left" && -n "$right" ]]; then
    if [[ $(( ${#left} + 3 + ${#right} )) -le $limit ]]; then
      printf '%s | %s\n' "$left" "$right"
      return 0
    fi

    min_left=$(( ${#left_label} + 3 ))
    min_right=$(( ${#right_label} + 3 ))
    right_limit=${#right}
    left_limit=$(( limit - 3 - right_limit ))

    if [[ $left_limit -lt $min_left ]]; then
      left_limit=$min_left
      right_limit=$(( limit - 3 - left_limit ))
    fi

    if [[ $right_limit -lt $min_right ]]; then
      right_limit=$min_right
      left_limit=$(( limit - 3 - right_limit ))
    fi

    if [[ $left_limit -lt $min_left || $right_limit -lt $min_right ]]; then
      dashboard_truncate_text "${left} | ${right}" "$limit"
      return 0
    fi

    left="$(dashboard_truncate_text "$left" "$left_limit")"
    right="$(dashboard_truncate_text "$right" "$right_limit")"
    left="${left%$'\n'}"
    right="${right%$'\n'}"
    printf '%s | %s\n' "$left" "$right"
    return 0
  fi

  dashboard_truncate_text "${left}${right}" "$limit"
}

dashboard_summary_line() {
  dashboard_compact_pair_line "Session" "$1" "Backend" "$2"
}

dashboard_meta_line() {
  dashboard_compact_pair_line "Job" "$1" "Profile" "$2"
}

picker_failed() {
  local code="$1"
  case "$code" in
    "$DUCKYSCRIPT_CANCELLED")
      LOG blue "Cancelled"
      return 1
      ;;
    "$DUCKYSCRIPT_REJECTED")
      LOG blue "Rejected"
      return 1
      ;;
    "$DUCKYSCRIPT_ERROR")
      ERROR_DIALOG "Input error"
      return 1
      ;;
  esac
  return 0
}

helper_json() {
  run_helper "$@"
}

json_field() {
  local json="$1"
  local key="$2"
  JSON_INPUT="$json" JSON_KEY="$key" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
value = data.get(os.environ["JSON_KEY"])
if isinstance(value, (dict, list)):
    print(json.dumps(value))
elif value is None:
    print("")
else:
    print(value)
PY
}

json_length() {
  local json="$1"
  JSON_INPUT="$json" python3 - <<'PY'
import json
import os

value = json.loads(os.environ["JSON_INPUT"])
print(len(value))
PY
}

json_item_field() {
  local json="$1"
  local index="$2"
  local key="$3"
  JSON_INPUT="$json" JSON_INDEX="$index" JSON_KEY="$key" python3 - <<'PY'
import json
import os

items = json.loads(os.environ["JSON_INPUT"])
idx = int(os.environ["JSON_INDEX"]) - 1
if idx < 0 or idx >= len(items):
    raise SystemExit(1)
value = items[idx].get(os.environ["JSON_KEY"])
if isinstance(value, (dict, list)):
    print(json.dumps(value))
elif value is None:
    print("")
else:
    print(value)
PY
}

print_session_list() {
  local sessions_json="$1"
  JSON_INPUT="$sessions_json" python3 - <<'PY' | while IFS= read -r line; do
import json
import os

sessions = json.loads(os.environ["JSON_INPUT"])
if not sessions:
    print("  (no existing sessions)")
else:
    for idx, session in enumerate(sessions, 1):
        title = session.get("title") or "(untitled)"
        backend = session.get("backend") or "unknown"
        session_id = session.get("id") or ""
        print(f"  {idx}. {title} [{backend}] {session_id}")
PY
    LOG blue "$line"
  done
}

session_summary_line() {
  local index="$1"
  local title="$2"
  local backend="$3"
  local state="$4"
  local preview="$5"
  local max_width="${6:-88}"

  SUMMARY_INDEX="$index" \
  SUMMARY_TITLE="$title" \
  SUMMARY_BACKEND="$backend" \
  SUMMARY_STATE="$state" \
  SUMMARY_PREVIEW="$preview" \
  SUMMARY_MAX_WIDTH="$max_width" \
    python3 - <<'PY'
import os


def normalize(text: str) -> str:
    return " ".join(str(text).split())


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


index = normalize(os.environ["SUMMARY_INDEX"])
title = normalize(os.environ["SUMMARY_TITLE"])
backend = normalize(os.environ["SUMMARY_BACKEND"])
state = normalize(os.environ["SUMMARY_STATE"])
preview = normalize(os.environ["SUMMARY_PREVIEW"])
max_width = int(os.environ["SUMMARY_MAX_WIDTH"])

prefix = f"  {index}. "
suffix = f" [{backend}] {state}"
title_budget = max_width - len(prefix) - len(suffix)
if title_budget < 0:
    title_budget = 0

title = truncate(title, title_budget)
summary = f"{prefix}{title}{suffix}"

if preview:
    separator = " | "
    preview_budget = max_width - len(summary) - len(separator)
    if preview_budget > 0:
        preview = truncate(preview, preview_budget)
        if preview:
            summary = f"{summary}{separator}{preview}"

print(summary)
PY
}

print_session_picker_list() {
  local sessions_json="$1"
  local status_json
  local index
  local title
  local backend
  local state
  local preview

  JSON_INPUT="$sessions_json" python3 - <<'PY' | while IFS= read -r session_line; do
import json
import os

sessions = json.loads(os.environ["JSON_INPUT"])
if not sessions:
    print("")
else:
    for idx, session in enumerate(sessions, 1):
        print(f"{idx}\t{session.get('id') or ''}\t{session.get('title') or '(untitled)'}\t{session.get('backend') or 'unknown'}")
PY
    [[ -n "$session_line" ]] || continue
    IFS=$'\t' read -r index session_id title backend <<EOF
$session_line
EOF

    state="none"
    preview=""
    if status_json="$(load_session_status "$session_id" 2>/dev/null)"; then
      state="$(json_field "$status_json" last_job_state)"
      preview="$(json_field "$status_json" last_response_preview)"
    fi

    session_summary_line "$index" "$title" "$backend" "${state:-none}" "$preview"
  done
}

profile_type_for_path() {
  local profile_path="$1"
  PROFILE_PATH="$profile_path" python3 - <<'PY'
import json
import os
import pathlib

path = pathlib.Path(os.environ["PROFILE_PATH"])
if not path.is_file():
    raise SystemExit(1)
with path.open(encoding="utf-8") as handle:
    data = json.load(handle)
profile_type = data.get("type")
if not isinstance(profile_type, str) or not profile_type:
    raise SystemExit(1)
print(profile_type)
PY
}

default_profile_path_for_backend() {
  local backend="$1"
  case "$backend" in
    http)
      printf '%s\n' "$PAYLOAD_DIR/profiles/http.example.json"
      ;;
    command|*)
      printf '%s\n' "$PAYLOAD_DIR/profiles/command.example.json"
      ;;
  esac
}

profile_label_for_path() {
  local profile_path="$1"
  basename "$profile_path"
}

profile_paths_sorted() {
  find "$PAYLOAD_DIR/profiles" -maxdepth 1 -type f -name '*.json' | sort
}

profile_matches_backend() {
  local profile_path="$1"
  local backend_filter="${2:-}"
  local profile_type

  if [[ -z "$backend_filter" ]]; then
    return 0
  fi

  if ! profile_type="$(profile_type_for_path "$profile_path")"; then
    return 1
  fi

  [[ "$profile_type" == "$backend_filter" ]]
}

list_profile_paths() {
  local backend_filter="${1:-${CURRENT_SESSION_BACKEND:-}}"
  local profile_path

  while IFS= read -r profile_path; do
    [[ -n "$profile_path" ]] || continue

    if ! profile_matches_backend "$profile_path" "$backend_filter"; then
      continue
    fi

    printf '%s\n' "$profile_path"
  done < <(profile_paths_sorted)
}

list_profile_options() {
  local profile_path
  local profile_label

  while IFS= read -r profile_path; do
    [[ -n "$profile_path" ]] || continue
    profile_label="$(profile_label_for_path "$profile_path")"
    printf '%s\t%s\n' "$profile_label" "$profile_path"
  done < <(list_profile_paths)
}

choose_manual_profile_path() {
  local default_path="$1"
  local profile_path

  profile_path=$(TEXT_PICKER "Manual profile path" "$default_path")
  picker_failed $? || return 1

  if [[ ! -f "$profile_path" ]]; then
    ERROR_DIALOG "Profile not found: $profile_path"
    return 1
  fi

  local profile_type
  if ! profile_type="$(profile_type_for_path "$profile_path")"; then
    ERROR_DIALOG "Invalid profile: $profile_path"
    return 1
  fi

  case "$profile_type" in
    command|http)
      ;;
    *)
      ERROR_DIALOG "Unsupported profile type: $profile_type"
      return 1
      ;;
  esac

  if [[ -n "$CURRENT_SESSION_BACKEND" && "$CURRENT_SESSION_BACKEND" != "$profile_type" ]]; then
    ERROR_DIALOG "Profile type must match session backend: $CURRENT_SESSION_BACKEND"
    return 1
  fi

  CURRENT_PROFILE_PATH="$profile_path"
  CURRENT_PROFILE_TYPE="$profile_type"
}

choose_bundled_profile_path() {
  local default_path="$1"
  local profile_lines=()
  local profile_count=0
  local profile_line
  local profile_label
  local profile_path
  local choice
  local default_choice=1
  local selected_index=0
  local selected_label
  local selected_profile_path
  local profile_type

  mapfile -t profile_lines < <(list_profile_options)
  profile_count="${#profile_lines[@]}"
  if [[ "$profile_count" -eq 0 ]]; then
    ERROR_DIALOG "No bundled profiles available"
    return 1
  fi

  for profile_line in "${profile_lines[@]}"; do
    selected_index=$((selected_index + 1))
    profile_label="${profile_line%%$'\t'*}"
    profile_path="${profile_line#*$'\t'}"
    if [[ "$profile_path" == "$default_path" ]]; then
      default_choice="$selected_index"
    fi
  done

  LOG blue "Bundled profiles:"
  selected_index=0
  for profile_line in "${profile_lines[@]}"; do
    selected_index=$((selected_index + 1))
    profile_label="${profile_line%%$'\t'*}"
    profile_path="${profile_line#*$'\t'}"
    if [[ "$profile_path" == "$CURRENT_PROFILE_PATH" ]]; then
      LOG blue "  ${selected_index}. ${profile_label} (current)"
    else
      LOG blue "  ${selected_index}. ${profile_label}"
    fi
  done

  choice=$(NUMBER_PICKER "Profile number" "$default_choice")
  picker_failed $? || return 1

  if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
    ERROR_DIALOG "Invalid profile selection"
    return 1
  fi

  if [[ "$choice" -lt 1 || "$choice" -gt "$profile_count" ]]; then
    ERROR_DIALOG "Profile selection out of range"
    return 1
  fi

  profile_line="${profile_lines[$((choice - 1))]}"
  selected_label="${profile_line%%$'\t'*}"
  selected_profile_path="${profile_line#*$'\t'}"

  if ! profile_type="$(profile_type_for_path "$selected_profile_path")"; then
    ERROR_DIALOG "Invalid profile: $selected_profile_path"
    return 1
  fi

  if [[ -n "$CURRENT_SESSION_BACKEND" && "$CURRENT_SESSION_BACKEND" != "$profile_type" ]]; then
    ERROR_DIALOG "Profile type must match session backend: $CURRENT_SESSION_BACKEND"
    return 1
  fi

  CURRENT_PROFILE_PATH="$selected_profile_path"
  CURRENT_PROFILE_TYPE="$profile_type"
  LOG green "Selected profile: ${selected_label}"
}

load_session_status() {
  local session_id="$1"
  helper_json show-session-status --session-id "$session_id"
}

restore_profile_path_from_jobs() {
  local session_id="$1"
  local jobs_json
  local latest_profile_path

  if ! jobs_json="$(helper_json list-jobs --session-id "$session_id" 2>/dev/null)"; then
    return 1
  fi

  latest_profile_path="$(JSON_INPUT="$jobs_json" python3 - <<'PY'
import json
import os

jobs = json.loads(os.environ["JSON_INPUT"])
profile_path = ""
for job in jobs:
    value = job.get("profile_path")
    if isinstance(value, str) and value:
        profile_path = value
print(profile_path)
PY
)"

  if [[ -n "$latest_profile_path" && -f "$latest_profile_path" ]]; then
    CURRENT_PROFILE_PATH="$latest_profile_path"
    CURRENT_PROFILE_TYPE="$(profile_type_for_path "$latest_profile_path")"
    return 0
  fi

  return 1
}

restore_recent_session() {
  local sessions_json
  local latest_json
  local latest_session_id
  local latest_session_title
  local latest_session_backend
  local status_json

  if ! sessions_json="$(helper_json list-sessions)"; then
    return 1
  fi

  if [[ "$(json_length "$sessions_json")" -eq 0 ]]; then
    return 1
  fi

  latest_json="$(JSON_INPUT="$sessions_json" python3 - <<'PY'
import json
import os

sessions = json.loads(os.environ["JSON_INPUT"])
if not sessions:
    raise SystemExit(1)

def session_key(item):
    return (item.get("updated_at") or item.get("created_at") or "", item.get("id") or "")

latest = max(sessions, key=session_key)
print(json.dumps(latest))
PY
)"

  latest_session_id="$(json_field "$latest_json" id)"
  latest_session_title="$(json_field "$latest_json" title)"
  latest_session_backend="$(json_field "$latest_json" backend)"

  if ! status_json="$(load_session_status "$latest_session_id" 2>/dev/null)"; then
    return 1
  fi

  CURRENT_SESSION_ID="$latest_session_id"
  CURRENT_SESSION_TITLE="$latest_session_title"
  CURRENT_SESSION_BACKEND="$latest_session_backend"
  CURRENT_PROFILE_PATH="$(default_profile_path_for_backend "$CURRENT_SESSION_BACKEND")"
  CURRENT_PROFILE_TYPE="$CURRENT_SESSION_BACKEND"
  restore_profile_path_from_jobs "$CURRENT_SESSION_ID" || true
  LAST_PROMPT=""
  CURRENT_JOB_ID=""
  CURRENT_JOB_JSON=""
  CURRENT_JOB_ID="$(json_field "$status_json" last_job_id)"
  return 0
}

choose_profile_path() {
  local default_path="$1"
  local choice

  while true; do
    LOG blue "Profile"
    choice=$(NUMBER_PICKER "1 Bundled profile, 2 Manual path, 3 Back" 1)
    picker_failed $? || return 1

    case "$choice" in
      1)
        choose_bundled_profile_path "$default_path" && return 0
        ;;
      2)
        choose_manual_profile_path "$default_path" && return 0
        ;;
      3)
        return 1
        ;;
      *)
        ERROR_DIALOG "Invalid choice"
        ;;
    esac
  done
}

create_session_for_profile() {
  local title="$1"
  local profile_type="$2"
  local create_json

  if ! create_json="$(helper_json create-session --title "$title" --backend "$profile_type")"; then
    ERROR_DIALOG "Failed to create session"
    return 1
  fi

  CURRENT_SESSION_ID="$(json_field "$create_json" id)"
  CURRENT_SESSION_TITLE="$(json_field "$create_json" title)"
  CURRENT_SESSION_BACKEND="$(json_field "$create_json" backend)"
  LAST_PROMPT=""
  CURRENT_JOB_ID=""
  CURRENT_JOB_JSON=""
}

choose_existing_session() {
  local sessions_json
  local choice
  local session_count
  local selected_session_backend=""

  if ! sessions_json="$(helper_json list-sessions)"; then
    ERROR_DIALOG "Failed to list existing sessions"
    return 1
  fi

  session_count="$(json_length "$sessions_json")"
  if [[ "$session_count" -eq 0 ]]; then
    ERROR_DIALOG "No existing sessions available"
    return 1
  fi

  LOG blue "Existing sessions:"
  print_session_picker_list "$sessions_json"

  choice=$(NUMBER_PICKER "Session number" 1)
  picker_failed $? || return 1

  if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
    ERROR_DIALOG "Invalid session selection"
    return 1
  fi

  if [[ "$choice" -lt 1 ]]; then
    ERROR_DIALOG "Session selection out of range"
    return 1
  fi

  if [[ "$choice" -gt "$session_count" ]]; then
    ERROR_DIALOG "Session selection out of range"
    return 1
  fi

  selected_session_backend="$(json_item_field "$sessions_json" "$choice" backend)"
  if [[ -z "$selected_session_backend" ]]; then
    ERROR_DIALOG "Selected session is missing backend metadata"
    return 1
  fi

  CURRENT_SESSION_BACKEND="$selected_session_backend"
  CURRENT_SESSION_ID="$(json_item_field "$sessions_json" "$choice" id)"
  CURRENT_SESSION_TITLE="$(json_item_field "$sessions_json" "$choice" title)"
  CURRENT_PROFILE_PATH="$(default_profile_path_for_backend "$CURRENT_SESSION_BACKEND")"
  CURRENT_PROFILE_TYPE="$CURRENT_SESSION_BACKEND"
  restore_profile_path_from_jobs "$CURRENT_SESSION_ID" || true
  LAST_PROMPT=""
  CURRENT_JOB_ID="$(json_field "$(load_session_status "$CURRENT_SESSION_ID")" last_job_id)"
  CURRENT_JOB_JSON=""
  if [[ -n "$CURRENT_JOB_ID" ]]; then
    CURRENT_JOB_JSON="$(load_job_json_file "$CURRENT_SESSION_ID" "$CURRENT_JOB_ID" 2>/dev/null || true)"
  fi
  LOG green "Selected session: ${CURRENT_SESSION_TITLE:-$CURRENT_SESSION_ID}"
}

create_new_session() {
  local title

  CURRENT_SESSION_BACKEND=""
  choose_profile_path "$DEFAULT_PROFILE_PATH" || return 1

  title=$(TEXT_PICKER "New session title" "Agent Console")
  picker_failed $? || return 1

  create_session_for_profile "$title" "$CURRENT_PROFILE_TYPE" || return 1
  LOG green "Created session: ${CURRENT_SESSION_TITLE:-$CURRENT_SESSION_ID}"
}

rename_session_flow() {
  local title
  local renamed_json

  if [[ -z "$CURRENT_SESSION_ID" ]]; then
    show_no_session_guidance
    return 1
  fi

  title=$(TEXT_PICKER "Rename session" "${CURRENT_SESSION_TITLE:-Agent Console}")
  picker_failed $? || return 1

  if ! renamed_json="$(helper_json rename-session --session-id "$CURRENT_SESSION_ID" --title "$title")"; then
    ERROR_DIALOG "Failed to rename session"
    return 1
  fi

  CURRENT_SESSION_TITLE="$(json_field "$renamed_json" title)"
  LOG green "Renamed session: ${CURRENT_SESSION_TITLE:-$CURRENT_SESSION_ID}"
}

sessions_menu() {
  local choice
  local back_label="${1:-Back}"

  while true; do
    LOG blue "Sessions"
    choice=$(NUMBER_PICKER "1 Resume recent, 2 Choose session, 3 New session, 4 Rename session, 5 ${back_label}" 1)
    picker_failed $? || return 1

    case "$choice" in
      1)
        if restore_recent_session; then
          LOG green "Resumed session: ${CURRENT_SESSION_TITLE:-$CURRENT_SESSION_ID}"
          return 0
        fi
        ERROR_DIALOG "No valid recent session to resume"
        ;;
      2)
        if choose_existing_session; then
          return 0
        fi
        ;;
      3)
        if create_new_session; then
          return 0
        fi
        ;;
      4)
        rename_session_flow || true
        ;;
      5)
        return 1
        ;;
      *)
        ERROR_DIALOG "Invalid choice"
        ;;
    esac
  done
}

select_session_context() {
  sessions_menu
}

show_job_result() {
  local job_json="$1"
  local state
  local response
  local error
  local job_id

  job_id="$(json_field "$job_json" id)"
  state="$(json_field "$job_json" state)"
  response="$(json_field "$job_json" response)"
  error="$(json_field "$job_json" error)"

  if [[ "$state" == "completed" ]]; then
    LOG green "Job $job_id completed"
    return 0
  fi

  if [[ "$state" == "running" ]]; then
    LOG blue "Job $job_id is still running"
    return 0
  fi

  if [[ "$state" == "failed" ]]; then
    LOG blue "Job $job_id failed"
    if [[ -n "$error" ]]; then
      ERROR_DIALOG "$(summarize_error "$error")"
    fi
    return 0
  fi

  LOG blue "Job $job_id state: $state"
  show_no_result_guidance
  return 0
}

show_completed_reply_if_available() {
  local job_json="$1"
  local state
  local response

  state="$(json_field "$job_json" state)"
  response="$(json_field "$job_json" response)"

  if [[ "$state" == "completed" && -n "$response" ]]; then
    if ! is_short_reply "$response"; then
      LOG blue "Long reply ready. Use Last reply to open it."
      return 0
    fi

    PROMPT "$response"
  fi
}

load_job_json_file() {
  local session_id="$1"
  local job_id="$2"
  local job_file="$LOOT_DIR/sessions/$session_id/jobs/$job_id.json"

  if [[ -f "$job_file" ]]; then
    cat "$job_file"
    return 0
  fi

  return 1
}

render_dashboard() {
  local status_json
  local title
  local backend
  local profile_name
  local last_job_state
  local last_job_id
  local preview
  local last_job_json
  local error_preview

  if [[ -z "$CURRENT_SESSION_ID" ]]; then
    show_no_session_guidance
    return 0
  fi

  if ! status_json="$(load_session_status "$CURRENT_SESSION_ID")"; then
    ERROR_DIALOG "Failed to load session dashboard"
    return 1
  fi

  title="$(json_field "$status_json" title)"
  backend="$(json_field "$status_json" backend)"
  last_job_state="$(json_field "$status_json" last_job_state)"
  last_job_id="$(json_field "$status_json" last_job_id)"
  preview="$(json_field "$status_json" last_response_preview)"
  profile_name="$(profile_label_for_path "$CURRENT_PROFILE_PATH")"
  CURRENT_SESSION_TITLE="${title:-$CURRENT_SESSION_TITLE}"

  LOG blue "=== Agent Console ==="
  LOG blue "$(dashboard_summary_line "${title:-$CURRENT_SESSION_ID}" "${backend:-unknown}")"

  if [[ -n "$last_job_id" ]]; then
    LOG blue "$(dashboard_meta_line "${last_job_state:-unknown} ($last_job_id)" "${profile_name:-unknown}")"
  else
    LOG blue "$(dashboard_meta_line "${last_job_state:-none}" "${profile_name:-unknown}")"
  fi

  if [[ "$last_job_state" == "failed" && -n "$last_job_id" ]]; then
    if last_job_json="$(load_job_json_file "$CURRENT_SESSION_ID" "$last_job_id" 2>/dev/null)"; then
      error_preview="$(json_field "$last_job_json" error)"
      if [[ -n "$error_preview" ]]; then
        LOG blue "Error: $(summarize_error "$error_preview")"
        return 0
      fi
    fi
  fi

  if [[ -n "$preview" ]]; then
    LOG blue "Reply: $preview"
  fi
}

read_last_transcript_response() {
  local transcript_file="$LOOT_DIR/sessions/$CURRENT_SESSION_ID/transcript.jsonl"

  if [[ ! -f "$transcript_file" ]]; then
    return 1
  fi

  TRANSCRIPT_FILE="$transcript_file" python3 - <<'PY'
import json
import os

path = os.environ["TRANSCRIPT_FILE"]
last = ""
with open(path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("role") == "assistant":
            content = event.get("content")
            if isinstance(content, str):
                last = content
print(last)
PY
}

send_message_flow() {
  local message
  local queued_json
  local job_json

  if [[ -z "$CURRENT_SESSION_ID" ]]; then
    show_no_session_guidance
    return 1
  fi

  message=$(TEXT_PICKER "Send message" "$LAST_PROMPT")
  picker_failed $? || return 1

  if [[ -n "$message" ]]; then
    LAST_PROMPT="$message"
  fi

  if ! queued_json="$(helper_json send-message --session-id "$CURRENT_SESSION_ID" --message "$message")"; then
    ERROR_DIALOG "$(summarize_error "Failed to queue message")"
    return 1
  fi

  CURRENT_JOB_ID="$(json_field "$queued_json" id)"
  CURRENT_JOB_JSON="$queued_json"
  LOG blue "Queued job: $CURRENT_JOB_ID"

  if ! job_json="$(helper_json run-job --session-id "$CURRENT_SESSION_ID" --job-id "$CURRENT_JOB_ID" --profile "$CURRENT_PROFILE_PATH")"; then
    ERROR_DIALOG "$(summarize_error "Failed to start job")"
    return 1
  fi

  CURRENT_JOB_JSON="$job_json"
  CURRENT_JOB_ID="$(json_field "$job_json" id)"
  show_job_result "$job_json"
  show_completed_reply_if_available "$job_json"
}

refresh_last_job_flow() {
  local job_json
  local job_file
  local job_profile_path
  local job_profile_type

  if [[ -z "$CURRENT_SESSION_ID" || -z "$CURRENT_JOB_ID" ]]; then
    show_no_job_guidance
    return 0
  fi

  if [[ -n "$CURRENT_JOB_JSON" ]]; then
    job_profile_path="$(json_field "$CURRENT_JOB_JSON" profile_path)"
  fi
  if [[ -z "$job_profile_path" ]]; then
    job_profile_path="$CURRENT_PROFILE_PATH"
  fi

  if ! job_profile_type="$(profile_type_for_path "$job_profile_path" 2>/dev/null)"; then
    job_profile_type="$CURRENT_PROFILE_TYPE"
  fi

  if [[ "$job_profile_type" == "http" ]]; then
    if ! job_json="$(helper_json poll-job --session-id "$CURRENT_SESSION_ID" --job-id "$CURRENT_JOB_ID" --profile "$job_profile_path")"; then
      ERROR_DIALOG "$(summarize_error "Failed to refresh job")"
      return 1
    fi
    CURRENT_JOB_JSON="$job_json"
    show_job_result "$job_json"
    return 0
  fi

  job_file="$LOOT_DIR/sessions/$CURRENT_SESSION_ID/jobs/$CURRENT_JOB_ID.json"
  if [[ ! -f "$job_file" ]]; then
    ERROR_DIALOG "$(summarize_error "Job file not found")"
    return 1
  fi

  CURRENT_JOB_JSON="$(<"$job_file")"
  show_job_result "$CURRENT_JOB_JSON"
}

view_last_response_flow() {
  local state

  state="$(current_job_state)"
  case "$state" in
    completed)
      show_last_reply_flow
      ;;
    failed)
      show_last_error_flow
      ;;
    *)
      show_last_result_flow
      ;;
  esac
}

show_recent_turns_flow() {
  local recent_turns_json
  local formatted_turns

  if [[ -z "$CURRENT_SESSION_ID" ]]; then
    show_no_session_guidance
    return 1
  fi

  if ! recent_turns_json="$(helper_json show-recent-turns --session-id "$CURRENT_SESSION_ID" --limit 4)"; then
    ERROR_DIALOG "$(summarize_error "Failed to load recent turns")"
    return 1
  fi

  if [[ "$(json_length "$recent_turns_json")" -eq 0 ]]; then
    show_no_recent_turns_guidance
    return 0
  fi

  formatted_turns="$(JSON_INPUT="$recent_turns_json" python3 - <<'PY'
import json
import os

items = json.loads(os.environ["JSON_INPUT"])


def label_for(role: str) -> str:
    if role == "user":
        return "You"
    if role == "assistant":
        return "Agent"
    if not role:
        return "Entry"
    return role[:1].upper() + role[1:]


def preview(content: object, limit: int = 72) -> str:
    text = " ".join(str(content).split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


for item in items:
    role = label_for(str(item.get("role", "")))
    content = preview(item.get("content", ""))
    print(f"{role}\t{content}")
PY
)"

  LOG blue "Recent turns"
  while IFS=$'\t' read -r role content; do
    if [[ -n "$content" ]]; then
      LOG blue "${role}: ${content}"
    else
      LOG blue "${role}:"
    fi
  done <<< "$formatted_turns"
}

load_current_job_json() {
  if [[ -n "$CURRENT_JOB_JSON" ]]; then
    printf '%s\n' "$CURRENT_JOB_JSON"
    return 0
  fi

  if [[ -n "$CURRENT_SESSION_ID" && -n "$CURRENT_JOB_ID" ]]; then
    if CURRENT_JOB_JSON="$(load_job_json_file "$CURRENT_SESSION_ID" "$CURRENT_JOB_ID" 2>/dev/null)"; then
      printf '%s\n' "$CURRENT_JOB_JSON"
      return 0
    fi
  fi

  return 1
}

show_last_reply_flow() {
  local job_json
  local response

  if job_json="$(load_current_job_json 2>/dev/null)"; then
    response="$(json_field "$job_json" response)"
    if [[ -n "$response" ]]; then
      PROMPT "$response"
      return 0
    fi
  fi

  if [[ -n "$CURRENT_SESSION_ID" ]]; then
    response="$(read_last_transcript_response || true)"
    if [[ -n "$response" ]]; then
      PROMPT "$response"
      return 0
    fi
  fi

  show_no_reply_guidance
}

show_last_error_flow() {
  local job_json
  local error

  if job_json="$(load_current_job_json 2>/dev/null)"; then
    error="$(json_field "$job_json" error)"
    if [[ -n "$error" ]]; then
      PROMPT "$error"
      return 0
    fi
  fi

  show_no_error_guidance
}

show_last_result_flow() {
  local job_json
  local response
  local error

  if job_json="$(load_current_job_json 2>/dev/null)"; then
    response="$(json_field "$job_json" response)"
    if [[ -n "$response" ]]; then
      PROMPT "$response"
      return 0
    fi

    error="$(json_field "$job_json" error)"
    if [[ -n "$error" ]]; then
      PROMPT "$error"
      return 0
    fi
  fi

  if [[ -n "$CURRENT_SESSION_ID" ]]; then
    response="$(read_last_transcript_response || true)"
    if [[ -n "$response" ]]; then
      PROMPT "$response"
      return 0
    fi
  fi

  show_no_result_guidance
}

current_job_state() {
  local job_file="$LOOT_DIR/sessions/$CURRENT_SESSION_ID/jobs/$CURRENT_JOB_ID.json"
  local state

  if [[ -n "$CURRENT_JOB_JSON" ]]; then
    state="$(json_field "$CURRENT_JOB_JSON" state)"
    if [[ -n "$state" ]]; then
      printf '%s\n' "$state"
      return 0
    fi
  fi

  if [[ -f "$job_file" ]]; then
    state="$(JSON_INPUT="$(<"$job_file")" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
print(data.get("state", ""))
PY
)"
    if [[ -n "$state" ]]; then
      printf '%s\n' "$state"
      return 0
    fi
  fi

  printf '%s\n' ""
}

show_no_session_guidance() {
  LOG blue "Choose or create a session from Sessions."
}

show_no_job_guidance() {
  LOG blue "Send a prompt first, or choose a different session."
}

show_no_reply_guidance() {
  LOG blue "Send a prompt first, or refresh the current job."
}

show_no_error_guidance() {
  LOG blue "Run a failing job first, or choose a different session."
}

show_no_result_guidance() {
  LOG blue "Send a prompt, refresh the job, or choose a session."
}

show_no_recent_turns_guidance() {
  LOG blue "Send a prompt first, then reopen Recent turns."
}

result_menu_label_for_state() {
  local state="$1"

  case "$state" in
    completed)
      printf '%s\n' "3 Last reply"
      ;;
    failed)
      printf '%s\n' "3 Last error"
      ;;
    *)
      printf '%s\n' "3 Last result"
      ;;
  esac
}

main_menu_result_label() {
  result_menu_label_for_state "$(current_job_state)"
}

main_menu_refresh_label() {
  local state

  state="$(current_job_state)"
  case "$state" in
    running)
      printf '%s\n' "2 Refresh running job"
      ;;
    completed|failed)
      printf '%s\n' "2 Check last job"
      ;;
    *)
      printf '%s\n' "2 Refresh"
      ;;
  esac
}

switch_profile_flow() {
  local profile_name
  local backend_name

  choose_profile_path "$CURRENT_PROFILE_PATH" || return 1
  profile_name="$(profile_label_for_path "$CURRENT_PROFILE_PATH")"
  backend_name="${CURRENT_SESSION_BACKEND:-$CURRENT_PROFILE_TYPE}"
  LOG green "Using ${backend_name:-unknown} profile: ${profile_name:-unknown}"
}

show_current_profile_flow() {
  local profile_name
  local backend_name
  local profile_path

  profile_name="$(profile_label_for_path "$CURRENT_PROFILE_PATH")"
  backend_name="${CURRENT_SESSION_BACKEND:-$CURRENT_PROFILE_TYPE}"

  LOG blue "Current profile: ${profile_name:-unknown}"
  LOG blue "Backend: ${backend_name:-unknown}"
  profile_path="$CURRENT_PROFILE_PATH"
  if [[ -n "$profile_path" && "$profile_path" != "$PAYLOAD_DIR/profiles/${profile_name}" ]]; then
    LOG blue "Path: $profile_path"
  fi
}

profile_menu() {
  local choice

  while true; do
    LOG blue "Profile"
    choice=$(NUMBER_PICKER "1 Show current profile, 2 Switch profile, 3 Back" 1)
    picker_failed $? || return 1

    case "$choice" in
      1)
        show_current_profile_flow
        ;;
      2)
        if switch_profile_flow; then
          return 0
        fi
        ;;
      3)
        return 0
        ;;
      *)
        ERROR_DIALOG "Invalid choice"
        ;;
    esac
  done
}

ensure_session_context() {
  if restore_recent_session; then
    LOG green "Resumed session: ${CURRENT_SESSION_TITLE:-$CURRENT_SESSION_ID}"
    return 0
  fi

  sessions_menu "Exit"
}

main() {
  ensure_loot_dir
  require_dependencies

  LOG blue "Agent Console ($SESSION_NAME)"
  ensure_session_context || exit 1

  while true; do
    local choice
    local result_label
    local refresh_label

    render_dashboard || {
      CURRENT_SESSION_ID=""
      CURRENT_SESSION_TITLE=""
      CURRENT_SESSION_BACKEND=""
      CURRENT_JOB_ID=""
      CURRENT_JOB_JSON=""
      select_session_context || exit 1
      continue
    }

    refresh_label="$(main_menu_refresh_label)"
    result_label="$(main_menu_result_label)"
    choice=$(NUMBER_PICKER "1 Send, ${refresh_label}, ${result_label}, 4 Recent turns, 5 Sessions, 6 Profile, 7 Exit" 1)
    picker_failed $? || break

    case "$choice" in
      1) send_message_flow || true ;;
      2) refresh_last_job_flow || true ;;
      3) view_last_response_flow || true ;;
      4) show_recent_turns_flow || true ;;
      5) sessions_menu || true ;;
      6) profile_menu || true ;;
      7) LOG blue "Exiting Agent Console"; break ;;
      *) ERROR_DIALOG "Invalid choice" ;;
    esac
  done
}

main "$@"
