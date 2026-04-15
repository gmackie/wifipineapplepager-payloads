# Agent Console Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a pager payload that provides persistent agent chat sessions with pluggable `command` and `http` backends for on-device or local agent runtimes.

**Architecture:** Add a new payload at `library/user/remote_access/agent_console/` with a shell UI entrypoint and a Python helper. The shell handles pager-native menus and dependency checks, while Python owns session state, transcripts, jobs, and backend adapter dispatch. Start with durable file-backed sessions and a small CLI surface so the payload can resume safely after exits or backend failures.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, tmux, shellcheck, `bash -n`

### Task 1: Scaffold the payload directory and README

**Files:**
- Create: `library/user/remote_access/agent_console/payload.sh`
- Create: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the minimal payload header and dependency constants**

Create `library/user/remote_access/agent_console/payload.sh` with:

```bash
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
REQUIRED_PACKAGES=(python3 tmux)
```

**Step 2: Add a README with operator-facing purpose and directory layout**

Create `library/user/remote_access/agent_console/README.md` with:

- purpose of the payload
- required packages
- backend types (`command`, `http`)
- where sessions/transcripts are stored
- example profile format

**Step 3: Verify shell syntax**

Run: `bash -n library/user/remote_access/agent_console/payload.sh`

Expected: no output, exit code 0

**Step 4: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh library/user/remote_access/agent_console/README.md
git commit -m "add agent console payload scaffold"
```

### Task 2: Add shell helpers for dependency checks and helper invocation

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Add dependency-check functions**

Add:

```bash
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
```

**Step 2: Add helper wrapper functions**

Add:

```bash
run_helper() {
  python3 "$HELPER" "$@"
}

ensure_loot_dir() {
  mkdir -p "$LOOT_DIR"
}
```

**Step 3: Add a minimal entrypoint**

Add:

```bash
main() {
  ensure_loot_dir
  require_dependencies
  LOG blue "Agent Console"
}

main "$@"
```

**Step 4: Verify**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: no syntax errors; shellcheck warnings resolved or justified

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console shell helpers"
```

### Task 3: Create the Python helper CLI with session creation and listing

**Files:**
- Create: `library/user/remote_access/agent_console/agent_console.py`

**Step 1: Write the failing Python smoke test command manually**

Run:

`python3 library/user/remote_access/agent_console/agent_console.py list-sessions`

Expected: FAIL with file not found before implementation

**Step 2: Create a minimal helper with argparse and session root handling**

Create `library/user/remote_access/agent_console/agent_console.py` with:

```python
#!/usr/bin/env python3
import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("AGENT_CONSOLE_ROOT", "/root/loot/agent-console"))
SESSIONS_DIR = ROOT / "sessions"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_root() -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def session_dir(session_id: str) -> Path:
    return SESSIONS_DIR / session_id


def session_file(session_id: str) -> Path:
    return session_dir(session_id) / "session.json"


def create_session(title: str, backend: str) -> dict:
    ensure_root()
    session_id = uuid.uuid4().hex[:12]
    data = {
        "id": session_id,
        "title": title or f"Session {session_id}",
        "backend": backend,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    path = session_dir(session_id)
    (path / "jobs").mkdir(parents=True, exist_ok=True)
    (path / "artifacts").mkdir(parents=True, exist_ok=True)
    session_file(session_id).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (path / "transcript.jsonl").touch()
    return data


def list_sessions() -> list[dict]:
    ensure_root()
    sessions = []
    for child in sorted(SESSIONS_DIR.iterdir()):
        file_path = child / "session.json"
        if file_path.is_file():
            sessions.append(json.loads(file_path.read_text(encoding="utf-8")))
    return sessions


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    create_parser = sub.add_parser("create-session")
    create_parser.add_argument("--title", default="")
    create_parser.add_argument("--backend", default="command")

    sub.add_parser("list-sessions")

    args = parser.parse_args()

    if args.command == "create-session":
      data = create_session(args.title, args.backend)
      print(json.dumps(data))
      return 0
    if args.command == "list-sessions":
      print(json.dumps(list_sessions()))
      return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

**Step 3: Verify**

Run:

- `python3 library/user/remote_access/agent_console/agent_console.py create-session --title "Test" --backend command`
- `python3 library/user/remote_access/agent_console/agent_console.py list-sessions`

Expected:

- first command prints a JSON session object
- second command prints a JSON array containing that session

**Step 4: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py
git commit -m "add agent console session helper"
```

### Task 4: Add transcript append and job creation primitives

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`

**Step 1: Add the failing command expectation**

Run:

`python3 library/user/remote_access/agent_console/agent_console.py send-message --session-id invalid --message hi`

Expected: FAIL because `send-message` is not implemented yet

**Step 2: Implement transcript and job helpers**

Add:

```python
def transcript_file(session_id: str) -> Path:
    return session_dir(session_id) / "transcript.jsonl"


def jobs_dir(session_id: str) -> Path:
    return session_dir(session_id) / "jobs"


def read_session(session_id: str) -> dict:
    path = session_file(session_id)
    if not path.is_file():
        raise FileNotFoundError(f"unknown session: {session_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_session(session_id: str, data: dict) -> None:
    session_file(session_id).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def append_transcript(session_id: str, role: str, content: str, job_id: str) -> None:
    event = {
        "timestamp": utc_now(),
        "role": role,
        "job_id": job_id,
        "content": content,
    }
    with transcript_file(session_id).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def create_job(session_id: str, message: str) -> dict:
    session = read_session(session_id)
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "session_id": session_id,
        "backend": session["backend"],
        "state": "queued",
        "message": message,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    (jobs_dir(session_id) / f"{job_id}.json").write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    append_transcript(session_id, "user", message, job_id)
    session["updated_at"] = utc_now()
    write_session(session_id, session)
    return job
```

**Step 3: Add CLI support**

Add a `send-message` subcommand that:

- requires `--session-id`
- requires `--message`
- creates a queued job
- prints the job JSON

**Step 4: Verify**

Run:

- `sid=$(python3 library/user/remote_access/agent_console/agent_console.py create-session --title "Test" --backend command | jq -r .id)`
- `python3 library/user/remote_access/agent_console/agent_console.py send-message --session-id "$sid" --message "hello"`

Expected:

- job JSON with `state` equal to `queued`
- transcript file created under the session directory

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py
git commit -m "add agent console job queue primitives"
```

### Task 5: Implement the command adapter

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Create: `library/user/remote_access/agent_console/profiles/command.example.json`

**Step 1: Add the failing execution expectation**

Run:

`python3 library/user/remote_access/agent_console/agent_console.py run-job --session-id "$sid" --job-id "$jid"`

Expected: FAIL because `run-job` is not implemented yet

**Step 2: Add a simple profile contract**

Create `library/user/remote_access/agent_console/profiles/command.example.json`:

```json
{
  "type": "command",
  "command": [
    "/bin/sh",
    "-lc",
    "printf 'echo: %s\n' \"$AGENT_CONSOLE_PROMPT\""
  ]
}
```

**Step 3: Implement adapter execution**

Add code that:

- loads a profile JSON file
- validates `type == "command"`
- executes the configured command with environment variables:
  - `AGENT_CONSOLE_PROMPT`
  - `AGENT_CONSOLE_SESSION_ID`
  - `AGENT_CONSOLE_JOB_ID`
- captures stdout/stderr
- writes the response into transcript as `assistant`
- updates the job state to `completed` or `failed`

Use `subprocess.run(..., capture_output=True, text=True, timeout=...)`.

**Step 4: Add CLI support**

Add `run-job` subcommand arguments:

- `--session-id`
- `--job-id`
- `--profile`

**Step 5: Verify**

Run:

- `sid=$(python3 library/user/remote_access/agent_console/agent_console.py create-session --title "Cmd" --backend command | jq -r .id)`
- `jid=$(python3 library/user/remote_access/agent_console/agent_console.py send-message --session-id "$sid" --message "hello agent" | jq -r .id)`
- `python3 library/user/remote_access/agent_console/agent_console.py run-job --session-id "$sid" --job-id "$jid" --profile library/user/remote_access/agent_console/profiles/command.example.json`

Expected:

- job JSON with `state` equal to `completed`
- transcript contains both `user` and `assistant` lines
- assistant response contains `echo: hello agent`

**Step 6: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py library/user/remote_access/agent_console/profiles/command.example.json
git commit -m "add agent console command adapter"
```

### Task 6: Implement the HTTP adapter

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Create: `library/user/remote_access/agent_console/profiles/http.example.json`

**Step 1: Add the profile format**

Create `library/user/remote_access/agent_console/profiles/http.example.json`:

```json
{
  "type": "http",
  "submit_url": "http://127.0.0.1:8080/jobs",
  "method": "POST",
  "timeout_seconds": 30
}
```

**Step 2: Implement the adapter**

Add code using Python standard library (`urllib.request`) that:

- POSTs JSON containing `session_id`, `job_id`, and `message`
- accepts either immediate response payloads or an async job response
- if immediate response contains `response`, mark complete and append transcript
- if response contains only a remote job id, store it in the job file and leave state as `running`

**Step 3: Add a polling command**

Add `poll-job` subcommand that:

- reloads the job file
- for HTTP jobs with remote job ids, queries a status/result endpoint defined in the profile
- completes the job once a response is returned

**Step 4: Verify**

Run against a local dummy HTTP server and confirm:

- submit succeeds
- immediate response path works
- failed network requests set the job to `failed`

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py library/user/remote_access/agent_console/profiles/http.example.json
git commit -m "add agent console http adapter"
```

### Task 7: Add shell menu flow for session creation and message sending

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Add session picker helpers**

Implement functions that:

- create a new session with `TEXT_PICKER`
- list existing sessions via helper
- choose a session id
- choose a backend profile path

Use return-code handling for every picker and dialog per repo conventions.

**Step 2: Add send/refresh/view actions**

Implement a simple loop with:

- `1 Send message`
- `2 Refresh last job`
- `3 View last response`
- `4 Switch profile`
- `5 Exit`

Each action should call the Python helper and present short results through `LOG`, `PROMPT`, or `ALERT`.

**Step 3: Verify**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: no syntax errors and no unhandled picker return codes

**Step 4: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console pager session flow"
```

### Task 8: Add helper commands for status and transcript viewing

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`

**Step 1: Implement read-only CLI commands**

Add:

- `show-session --session-id`
- `show-last-response --session-id`
- `list-jobs --session-id`

`show-last-response` should scan `transcript.jsonl` in reverse and print the latest `assistant` content.

**Step 2: Verify**

Run:

- `python3 library/user/remote_access/agent_console/agent_console.py show-session --session-id "$sid"`
- `python3 library/user/remote_access/agent_console/agent_console.py show-last-response --session-id "$sid"`

Expected:

- session JSON on the first command
- plain response text or JSON wrapper on the second command

**Step 3: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py
git commit -m "add agent console session status commands"
```

### Task 9: Add failure-path tests and a shell smoke test

**Files:**
- Create: `tests/agent_console_helper_test.sh`

**Step 1: Write a shell test that runs the helper in a temporary root**

Create `tests/agent_console_helper_test.sh` using the existing repo shell-test style:

```bash
#!/bin/bash

set -euo pipefail

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

helper="library/user/remote_access/agent_console/agent_console.py"
export AGENT_CONSOLE_ROOT="$tmp_dir/root"

session_json="$(python3 "$helper" create-session --title "Test" --backend command)"
session_id="$(printf '%s' "$session_json" | jq -r .id)"

job_json="$(python3 "$helper" send-message --session-id "$session_id" --message "ping")"
job_id="$(printf '%s' "$job_json" | jq -r .id)"

python3 "$helper" run-job \
  --session-id "$session_id" \
  --job-id "$job_id" \
  --profile library/user/remote_access/agent_console/profiles/command.example.json \
  >/dev/null

last_response="$(python3 "$helper" show-last-response --session-id "$session_id")"
[[ "$last_response" == *"echo: ping"* ]]

echo OK
```

**Step 2: Add a failure-path check**

Extend the test to run `run-job` with a missing profile and assert non-zero exit.

**Step 3: Verify**

Run:

- `bash tests/agent_console_helper_test.sh`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected:

- helper test prints `OK`
- shell checks pass

**Step 4: Commit**

```bash
git add tests/agent_console_helper_test.sh
git commit -m "add agent console helper smoke tests"
```

### Task 10: Final verification and documentation pass

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`
- Modify: `docs/updated-payloads.md`

**Step 1: Document setup and supported profiles**

Update the README with:

- required packages
- session path
- example invocation flow
- profile examples for Claude Code, Codex, and OpenCode wrappers
- safety notes about sensitive transcripts

**Step 2: Add the payload to the catalog**

Update `docs/updated-payloads.md` with a short entry for `agent_console`.

**Step 3: Run final verification**

Run:

- `bash tests/agent_console_helper_test.sh`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: all commands succeed

**Step 4: Commit**

```bash
git add library/user/remote_access/agent_console/README.md docs/updated-payloads.md
git commit -m "document agent console payload"
```
