# Agent Console Session Titles Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve Agent Console session UX by auto-seeding better session titles from the first prompt and adding a manual rename action in the Sessions menu.

**Architecture:** Extend the Python helper with small session-title utilities so the persisted session metadata can be renamed safely and auto-titled only when the current title is still generic. Then update the pager shell flow to expose `Rename session` under `Sessions` and keep the current dashboard/session restore logic intact.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add helper support for session title updates

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Modify: `tests/agent_console_helper_test.sh`

**Step 1: Write the failing test**

Extend `tests/agent_console_helper_test.sh` with helper coverage that expects:

```bash
auto_session_json="$(python3 "$helper" create-session --title "Agent Console" --backend command)"
auto_session_id="$(extract_json_field "$auto_session_json" id)"
python3 "$helper" send-message --session-id "$auto_session_id" --message "Investigate wlan0 auth failures across the last capture"
auto_session_view="$(python3 "$helper" show-session --session-id "$auto_session_id")"
echo "$auto_session_view" | grep -q '"title": "Investigate wlan0 auth failures across the last capture"' || fail "generic titles should auto-seed from first prompt"

renamed_session_json="$(python3 "$helper" rename-session --session-id "$auto_session_id" --title "WLAN auth failure review")"
echo "$renamed_session_json" | grep -q '"title": "WLAN auth failure review"' || fail "rename-session should persist explicit titles"
```

**Step 2: Run test to verify it fails**

Run: `bash tests/agent_console_helper_test.sh`

Expected: FAIL because `rename-session` does not exist yet and generic titles do not auto-update.

**Step 3: Write minimal implementation**

In `library/user/remote_access/agent_console/agent_console.py`:

- add a helper that detects generic titles such as `Agent Console` or `Session <id>`
- add a small title-normalization helper that trims whitespace and falls back to the existing title rules when empty
- when `send-message` creates the first job for a session with a generic title, update `session.json` with a prompt-derived title
- cap auto-generated titles to a pager-friendly length
- add a new `rename-session --session-id --title` command that persists an explicit title and refreshes `updated_at`

**Step 4: Run verification**

Run:

- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 2: Add session rename to the pager UX

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects a rename action in the Sessions flow:

```bash
rg -n 'Rename session' library/user/remote_access/agent_console/payload.sh >/dev/null || fail "sessions menu should expose rename session"
```

**Step 2: Run verification to confirm failure**

Run the `rg` check above.

Expected: FAIL before implementation.

**Step 3: Write minimal implementation**

Update `library/user/remote_access/agent_console/payload.sh` to:

- add a `rename_session_flow()` that:
  - prompts for a new title using the current session title as the default
  - calls `rename-session`
  - refreshes `CURRENT_SESSION_TITLE`
  - confirms the new human-readable title
- update `sessions_menu()` to include `Rename session`
- keep the existing session selection/create/resume flows intact

Recommended ordering:

- `1 Resume recent`
- `2 Choose session`
- `3 New session`
- `4 Rename session`
- `5 Back`

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for session naming behavior

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'Rename session|first prompt' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that:

- new sessions start with a simple default title
- the first prompt can auto-seed a better session title when the title is still generic
- `Sessions -> Rename session` is the manual override

**Step 3: Run verification**

Run:

- `rg -n 'Rename session|first prompt' library/user/remote_access/agent_console/README.md`

Expected: PASS

### Task 4: Final verification

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Modify: `library/user/remote_access/agent_console/payload.sh`
- Modify: `library/user/remote_access/agent_console/README.md`
- Modify: `tests/agent_console_helper_test.sh`

**Step 1: Run full verification**

Run:

- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`
- `rg -n 'Rename session|first prompt' library/user/remote_access/agent_console/README.md library/user/remote_access/agent_console/payload.sh`

Expected: PASS
