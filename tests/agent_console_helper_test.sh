#!/bin/bash

set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'if [[ -n "${http_pid:-}" ]]; then kill "$http_pid" 2>/dev/null || true; wait "$http_pid" 2>/dev/null || true; fi; rm -rf "$tmp_dir"' EXIT

helper="library/user/remote_access/agent_console/agent_console.py"
command_profile="library/user/remote_access/agent_console/profiles/command.example.json"
long_command_profile="$tmp_dir/long-command-profile.json"
http_profile="$tmp_dir/http-profile.json"
http_server_script="$tmp_dir/http_dummy_server.py"
http_port_file="$tmp_dir/http-port"
http_log="$tmp_dir/http-server.log"
http_pid=""

extract_json_field() {
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

export AGENT_CONSOLE_ROOT="$tmp_dir/root"

cat >"$http_server_script" <<'PY'
#!/usr/bin/env python3
import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port_file = pathlib.Path(sys.argv[1])
state_file = pathlib.Path(sys.argv[2])
state_file.write_text(json.dumps({"poll_count": 0}), encoding="utf-8")


def load_state():
    return json.loads(state_file.read_text(encoding="utf-8"))


def save_state(state):
    state_file.write_text(json.dumps(state), encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        data = json.loads(raw) if raw else {}
        message = data.get("message", "")
        if message == "immediate":
            self._send_json({"response": "http immediate ok"})
            return
        if message == "async":
            self._send_json({"status": "queued", "job_id": "remote-async-1", "message": "accepted"})
            return
        self._send_json({"status": "failed", "error": "unknown message"}, status=400)

    def do_GET(self):
        if self.path != "/jobs/remote-async-1":
            self._send_json({"status": "failed", "error": "unknown job"}, status=404)
            return
        state = load_state()
        state["poll_count"] += 1
        save_state(state)
        if state["poll_count"] < 2:
            self._send_json({"status": "running", "job_id": "remote-async-1"})
            return
        self._send_json({"status": "completed", "response": "http async ok", "job_id": "remote-async-1"})


server = HTTPServer(("127.0.0.1", 0), Handler)
port_file.write_text(str(server.server_port), encoding="utf-8")
server.serve_forever()
PY

python3 "$http_server_script" "$http_port_file" "$tmp_dir/http-state.json" >"$http_log" 2>&1 &
http_pid="$!"

for _ in $(seq 1 50); do
  if [[ -s "$http_port_file" ]]; then
    break
  fi
  sleep 0.1
done

[[ -s "$http_port_file" ]] || fail "dummy HTTP server did not start"
http_port="$(cat "$http_port_file")"

cat >"$http_profile" <<EOF
{
  "type": "http",
  "submit_url": "http://127.0.0.1:${http_port}/jobs",
  "status_url": "http://127.0.0.1:${http_port}/jobs/{remote_job_id}",
  "method": "POST",
  "poll_method": "GET",
  "timeout_seconds": 5
}
EOF

cat >"$long_command_profile" <<'EOF'
{
  "type": "command",
  "command": [
    "/bin/sh",
    "-lc",
    "printf 'this is a deliberately long assistant response for dashboard preview truncation verification'\n"
  ],
  "timeout_seconds": 5
}
EOF

session_json="$(python3 "$helper" create-session --title "Smoke Test" --backend command)"
session_id="$(extract_json_field "$session_json" id)"

job_json="$(python3 "$helper" send-message --session-id "$session_id" --message "ping")"
job_id="$(extract_json_field "$job_json" id)"

run_json="$(python3 "$helper" run-job --session-id "$session_id" --job-id "$job_id" --profile "$command_profile")"
run_state="$(extract_json_field "$run_json" state)"
run_response="$(extract_json_field "$run_json" response)"

[[ "$run_state" == "completed" ]] || fail "command adapter job should complete"
[[ "$run_response" == "echo: ping" ]] || fail "unexpected command adapter response"

second_job_json="$(python3 "$helper" send-message --session-id "$session_id" --message "second turn")"
second_job_id="$(extract_json_field "$second_job_json" id)"
second_run_json="$(python3 "$helper" run-job --session-id "$session_id" --job-id "$second_job_id" --profile "$command_profile")"
second_run_state="$(extract_json_field "$second_run_json" state)"
second_run_response="$(extract_json_field "$second_run_json" response)"

[[ "$second_run_state" == "completed" ]] || fail "second command adapter job should complete"
[[ "$second_run_response" == "echo: second turn" ]] || fail "unexpected second command adapter response"

last_response="$(python3 "$helper" show-last-response --session-id "$session_id")"
[[ "$last_response" == "echo: second turn" ]] || fail "last response should match latest command adapter output"

transcript_before_recent="$(cat "$AGENT_CONSOLE_ROOT/sessions/$session_id/transcript.jsonl")"
recent_turns="$(python3 "$helper" show-recent-turns --session-id "$session_id" --limit 2)"
echo "$recent_turns" | grep -q '"role": "user"' || fail "recent turns should include user entries"
echo "$recent_turns" | grep -q '"role": "assistant"' || fail "recent turns should include assistant entries"
echo "$recent_turns" | grep -q '"content": "second turn"' || fail "recent turns should include latest user entry"
echo "$recent_turns" | grep -q '"content": "echo: second turn"' || fail "recent turns should include latest assistant entry"
JSON_INPUT="$recent_turns" python3 - <<'PY'
import json
import os
items = json.loads(os.environ["JSON_INPUT"])
assert len(items) == 2
assert items[0]["role"] == "user"
assert items[0]["content"] == "second turn"
assert items[1]["role"] == "assistant"
assert items[1]["content"] == "echo: second turn"
PY
transcript_after_recent="$(cat "$AGENT_CONSOLE_ROOT/sessions/$session_id/transcript.jsonl")"
[[ "$transcript_before_recent" == "$transcript_after_recent" ]] || fail "show-recent-turns should not modify transcript"

job_list="$(python3 "$helper" list-jobs --session-id "$session_id")"
echo "$job_list" | grep -q "\"state\": \"completed\"" || fail "job list should include completed job"

session_view="$(python3 "$helper" show-session --session-id "$session_id")"
echo "$session_view" | grep -q "\"title\": \"Smoke Test\"" || fail "show-session should return session metadata"

status_json="$(python3 "$helper" show-session-status --session-id "$session_id")"
echo "$status_json" | grep -q "\"title\": \"Smoke Test\"" || fail "session status should include title"
echo "$status_json" | grep -q "\"backend\": \"command\"" || fail "session status should include backend"
echo "$status_json" | grep -q "\"last_job_id\": \"$second_job_id\"" || fail "session status should include last job id"
echo "$status_json" | grep -q "\"last_job_state\": \"completed\"" || fail "session status should include last job state"
echo "$status_json" | grep -q "\"last_response_preview\": \"echo: second turn\"" || fail "session status should include preview"

long_job_json="$(python3 "$helper" send-message --session-id "$session_id" --message "long preview")"
long_job_id="$(extract_json_field "$long_job_json" id)"
python3 "$helper" run-job --session-id "$session_id" --job-id "$long_job_id" --profile "$long_command_profile" >/dev/null
long_status_json="$(python3 "$helper" show-session-status --session-id "$session_id")"
echo "$long_status_json" | grep -q '"last_response_preview": "this is a deliberately long assistant response for dashbo...' || fail "session status should truncate long previews"

missing_json="$(python3 "$helper" send-message --session-id "$session_id" --message "bad profile")"
missing_job_id="$(extract_json_field "$missing_json" id)"
missing_run_json="$(python3 "$helper" run-job --session-id "$session_id" --job-id "$missing_job_id" --profile /no/such/profile.json)"
missing_state="$(extract_json_field "$missing_run_json" state)"
missing_error="$(extract_json_field "$missing_run_json" error)"

[[ "$missing_state" == "failed" ]] || fail "missing profile should produce failed job state"
[[ "$missing_error" == "unknown profile: /no/such/profile.json" ]] || fail "missing profile should surface the profile error"

missing_job_list="$(python3 "$helper" list-jobs --session-id "$session_id")"
echo "$missing_job_list" | grep -q "\"id\": \"$missing_job_id\"" || fail "missing-profile job should remain persisted"
echo "$missing_job_list" | grep -q "\"state\": \"failed\"" || fail "missing-profile job should be persisted as failed"

http_session_json="$(python3 "$helper" create-session --title "HTTP Test" --backend http)"
http_session_id="$(extract_json_field "$http_session_json" id)"

http_immediate_job_json="$(python3 "$helper" send-message --session-id "$http_session_id" --message "immediate")"
http_immediate_job_id="$(extract_json_field "$http_immediate_job_json" id)"
http_immediate_run_json="$(python3 "$helper" run-job --session-id "$http_session_id" --job-id "$http_immediate_job_id" --profile "$http_profile")"
http_immediate_state="$(extract_json_field "$http_immediate_run_json" state)"
http_immediate_response="$(extract_json_field "$http_immediate_run_json" response)"

[[ "$http_immediate_state" == "completed" ]] || fail "immediate HTTP job should complete"
[[ "$http_immediate_response" == "http immediate ok" ]] || fail "unexpected immediate HTTP response"

http_async_job_json="$(python3 "$helper" send-message --session-id "$http_session_id" --message "async")"
http_async_job_id="$(extract_json_field "$http_async_job_json" id)"
http_async_run_json="$(python3 "$helper" run-job --session-id "$http_session_id" --job-id "$http_async_job_id" --profile "$http_profile")"
http_async_run_state="$(extract_json_field "$http_async_run_json" state)"

[[ "$http_async_run_state" == "running" ]] || fail "async HTTP submit should remain running"

http_async_poll_one="$(python3 "$helper" poll-job --session-id "$http_session_id" --job-id "$http_async_job_id" --profile "$http_profile")"
http_async_poll_one_state="$(extract_json_field "$http_async_poll_one" state)"
[[ "$http_async_poll_one_state" == "running" ]] || fail "first async HTTP poll should remain running"

http_async_poll_two="$(python3 "$helper" poll-job --session-id "$http_session_id" --job-id "$http_async_job_id" --profile "$http_profile")"
http_async_poll_two_state="$(extract_json_field "$http_async_poll_two" state)"
http_async_poll_two_response="$(extract_json_field "$http_async_poll_two" response)"
[[ "$http_async_poll_two_state" == "completed" ]] || fail "second async HTTP poll should complete"
[[ "$http_async_poll_two_response" == "http async ok" ]] || fail "unexpected async HTTP response"

http_last_response="$(python3 "$helper" show-last-response --session-id "$http_session_id")"
[[ "$http_last_response" == "http async ok" ]] || fail "HTTP last response should match async completion"

generic_session_json="$(python3 "$helper" create-session --title "Agent Console" --backend command)"
generic_session_id="$(extract_json_field "$generic_session_json" id)"
python3 "$helper" send-message --session-id "$generic_session_id" --message "   Investigate wlan0 auth failures across the last capture   " >/dev/null
generic_session_view="$(python3 "$helper" show-session --session-id "$generic_session_id")"
echo "$generic_session_view" | grep -q '"title": "Investigate wlan0 auth failures across the last capture"' || fail "generic titles should auto-seed from first prompt"

renamed_session_json="$(python3 "$helper" rename-session --session-id "$generic_session_id" --title "WLAN auth failure review")"
echo "$renamed_session_json" | grep -q '"title": "WLAN auth failure review"' || fail "rename-session should persist explicit titles"
renamed_session_view="$(python3 "$helper" show-session --session-id "$generic_session_id")"
echo "$renamed_session_view" | grep -q '"title": "WLAN auth failure review"' || fail "renamed session title should persist on disk"

explicit_session_json="$(python3 "$helper" create-session --title "Already Named" --backend command)"
explicit_session_id="$(extract_json_field "$explicit_session_json" id)"
python3 "$helper" send-message --session-id "$explicit_session_id" --message "   keep the original title   " >/dev/null
explicit_session_view="$(python3 "$helper" show-session --session-id "$explicit_session_id")"
echo "$explicit_session_view" | grep -q '"title": "Already Named"' || fail "explicit titles should not be auto-seeded"

echo OK
