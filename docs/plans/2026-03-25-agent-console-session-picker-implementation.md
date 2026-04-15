# Agent Console Session Picker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve `Sessions -> Choose session` by replacing the raw numbered list with a compact session picker that shows title, backend, and last job state at a glance.

**Architecture:** Keep the helper API unchanged and enrich the shell-side session list in `payload.sh`. Build compact one-line summaries from existing `list-sessions` and `show-session-status` data, then use those summaries in the existing choose-session flow without changing how a selected session is restored.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add compact session summary formatting helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'session_summary_line|print_session_picker_list' library/user/remote_access/agent_console/payload.sh
```

Expected: FAIL because the compact summary helpers do not exist yet.

**Step 2: Write minimal implementation**

Add helpers in `payload.sh` that:

- build a compact summary line for one session
- include title, backend, and last job state
- optionally include a short reply preview when available and brief enough
- keep output pager-friendly and single-line

Do not change the choose-session flow yet.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Replace raw session list output in choose-session flow

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'Existing sessions:|Last job:' library/user/remote_access/agent_console/payload.sh
```

Expected: the file still reflects the old generic session-list flow before the new compact picker output is wired.

**Step 2: Write minimal implementation**

Update `choose_existing_session()` so it:

- shows a compact summary list instead of just title/backend/id
- keeps the existing numbered selection model
- leaves the restore logic unchanged after a valid selection
- stays readable when there are many sessions by keeping each entry to one line

Recommended entry shape:

- `1. Review wlan0 auth [command] completed`
- `2. Local HTTP bridge [http] running`

If a short preview fits, append it after a separator.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for the new session picker UX

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'compact session picker|last job state' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that `Sessions -> Choose session` now shows a compact summary with session title, backend, and last job state so operators can identify the right thread faster.

**Step 3: Run verification**

Run:

- `rg -n 'compact session picker|last job state' library/user/remote_access/agent_console/README.md`

Expected: PASS

### Task 4: Final verification

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Run full verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`
- `bash tests/agent_console_helper_test.sh`
- `rg -n 'compact session picker|last job state' library/user/remote_access/agent_console/README.md`

Expected: PASS
