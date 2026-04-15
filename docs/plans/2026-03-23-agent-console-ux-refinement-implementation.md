# Agent Console UX Refinement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refine Agent Console into a dashboard-first pager UX that restores the current session quickly, keeps send/refresh/reply actions primary, and moves session/profile management into secondary submenus.

**Architecture:** Keep the existing shell payload as the pager UI layer and the Python helper as the durable session/job layer. Add a small amount of helper support for “current session” status if needed, but keep most UX work inside `payload.sh`: auto-resume, dashboard rendering, state-aware labels, and session/profile submenus.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add helper support for dashboard-friendly session status

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Test: `tests/agent_console_helper_test.sh`

**Step 1: Write the failing test**

Extend `tests/agent_console_helper_test.sh` with a new assertion that calls a new helper command and expects a compact summary for the current session:

```bash
status_json="$(python3 "$helper" show-session-status --session-id "$session_id")"
echo "$status_json" | grep -q '"title": "Smoke Test"' || fail "status should include title"
echo "$status_json" | grep -q '"last_job_state": "completed"' || fail "status should include last job state"
```

**Step 2: Run test to verify it fails**

Run: `bash tests/agent_console_helper_test.sh`

Expected: FAIL because `show-session-status` does not exist yet.

**Step 3: Write minimal implementation**

Add `show-session-status --session-id` to `library/user/remote_access/agent_console/agent_console.py` that returns JSON with:

- `id`
- `title`
- `backend`
- `last_job_id`
- `last_job_state`
- `last_response_preview`

Build it from the existing `show_session`, `list_jobs`, and `show_last_response` helpers. Keep preview truncation simple, for example 60 characters.

**Step 4: Run test to verify it passes**

Run:

- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py tests/agent_console_helper_test.sh
git commit -m "add agent console session status helper"
```

### Task 2: Replace upfront setup with auto-resume and dashboard render

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing shell expectation**

Add a temporary shell verification flow in your local check sequence that expects a new dashboard render function name to exist:

```bash
grep -q 'render_dashboard()' library/user/remote_access/agent_console/payload.sh || fail "missing dashboard renderer"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: shell still parses, but the grep expectation fails because the function does not exist yet.

**Step 3: Write minimal implementation**

Refactor `payload.sh` so startup does this:

1. Ensure dependencies and loot dir.
2. Attempt to restore the most recent valid session automatically.
3. If no valid session exists, fall back to session selection/creation.
4. Render a dashboard before prompting for an action.

Add helper functions such as:

- `restore_recent_session()`
- `render_dashboard()`
- `load_session_status()`

The dashboard should show:

- session title
- backend
- profile basename
- last job state
- short last-response preview

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console dashboard startup flow"
```

### Task 3: Move session actions into a dedicated Sessions submenu

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects a dedicated `sessions_menu` function:

```bash
grep -q 'sessions_menu()' library/user/remote_access/agent_console/payload.sh || fail "missing sessions menu"
```

**Step 2: Run to verify failure**

Run: `bash -n library/user/remote_access/agent_console/payload.sh`

Expected: syntax passes, grep expectation fails.

**Step 3: Write minimal implementation**

Add a `sessions_menu` with:

- `1 Resume recent`
- `2 Choose session`
- `3 New session`
- `4 Back`

Update the main dashboard menu to call this submenu instead of exposing session selection at launch every time.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console sessions submenu"
```

### Task 4: Move profile actions into a dedicated Profile submenu

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects a dedicated `profile_menu` function:

```bash
grep -q 'profile_menu()' library/user/remote_access/agent_console/payload.sh || fail "missing profile menu"
```

**Step 2: Run to verify failure**

Run: `bash -n library/user/remote_access/agent_console/payload.sh`

Expected: grep expectation fails first.

**Step 3: Write minimal implementation**

Add a `profile_menu` with:

- `1 Show current profile`
- `2 Switch profile`
- `3 Back`

When showing the current profile, present:

- basename label
- backend type
- full path only if needed

When switching, keep the existing backend compatibility enforcement and confirm the active profile in a short log line.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console profile submenu"
```

### Task 5: Simplify the main menu into a dashboard-first action loop

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects the new main menu label ordering:

```bash
grep -q '1 Send, 2 Refresh, 3 Last reply, 4 Sessions, 5 Profile, 6 Exit' \
  library/user/remote_access/agent_console/payload.sh || fail "missing dashboard-first menu"
```

**Step 2: Run to verify failure**

Run: `bash -n library/user/remote_access/agent_console/payload.sh`

Expected: shell parses, label expectation fails.

**Step 3: Write minimal implementation**

Update the action loop to:

- show the dashboard at the top of every iteration
- use the simplified menu order
- rename `View` to `Last reply`
- use state-aware wording for refresh when possible, for example:
  - “Refresh running job”
  - “Check last job”

After `Send`, return directly to the dashboard instead of re-entering session/profile selection.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "refine agent console dashboard menu"
```

### Task 6: Update docs to match the refined UX

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Add a local check that expects “dashboard” language in the README:

```bash
grep -qi 'dashboard' library/user/remote_access/agent_console/README.md || fail "README missing dashboard UX"
```

**Step 2: Run to verify failure**

Run the grep command.

Expected: FAIL if the README still describes the old setup-heavy flow.

**Step 3: Write minimal implementation**

Update the README so it explains:

- auto-resume behavior
- dashboard fields
- Sessions submenu
- Profile submenu
- the simplified action loop

**Step 4: Run verification**

Run:

- `grep -qi 'dashboard' library/user/remote_access/agent_console/README.md`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/README.md
git commit -m "document agent console dashboard ux"
```

### Task 7: Final verification

**Files:**
- Modify: `tests/agent_console_helper_test.sh`
- Modify: `library/user/remote_access/agent_console/payload.sh`
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Run full verification**

Run:

- `bash tests/agent_console_helper_test.sh`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`

Expected: all commands succeed, helper test prints `OK`

**Step 2: Review against UX requirements**

Check manually in code that:

- startup auto-resumes when possible
- dashboard renders before the main menu
- session/profile management is secondary
- menu order matches the approved UX

**Step 3: Commit**

```bash
git add tests/agent_console_helper_test.sh \
  library/user/remote_access/agent_console/payload.sh \
  library/user/remote_access/agent_console/agent_console.py \
  library/user/remote_access/agent_console/README.md
git commit -m "refine agent console pager ux"
```
