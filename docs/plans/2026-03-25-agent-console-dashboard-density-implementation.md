# Agent Console Dashboard Density Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce dashboard clutter by combining related status fields into fewer lines while preserving the same information hierarchy.

**Architecture:** Keep the current session/job/status data sources unchanged and refactor only the shell-side dashboard rendering in `payload.sh`. Add a small formatting helper for compact dashboard lines, then render session/backend and job/profile information in denser grouped lines with a single preview/error line underneath.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add compact dashboard line helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'dashboard_summary_line|dashboard_meta_line' library/user/remote_access/agent_console/payload.sh
```

Expected: FAIL because the compact dashboard helpers do not exist yet.

**Step 2: Write minimal implementation**

Add shell helpers that:

- combine two related labels into one compact line
- normalize/trim values
- preserve pager readability with light truncation when needed

Do not change `render_dashboard()` yet.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Compress the dashboard rendering

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'Session: .*\\n.*Backend: .*\\n.*Profile:' library/user/remote_access/agent_console/payload.sh
```

Expected: the dashboard still uses the old separate-line layout before the change.

**Step 2: Write minimal implementation**

Update `render_dashboard()` so it uses a denser layout, for example:

- `Session: <title> | <backend>`
- `Job: <state> | <profile>`
- `Reply: <preview>` or `Error: <preview>`

Keep:

- the same dashboard data
- the same state-specific preview/error behavior
- the existing `=== Agent Console ===` heading if it still helps orientation

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for the denser dashboard

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'compact dashboard|session, backend, and profile in fewer lines|denser dashboard' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that the dashboard now compresses session/backend/profile/job information into fewer lines while keeping the same context visible.

**Step 3: Run verification**

Run:

- `rg -n 'compact dashboard|fewer lines|denser dashboard' library/user/remote_access/agent_console/README.md`

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
- `rg -n 'compact dashboard|fewer lines|denser dashboard' library/user/remote_access/agent_console/README.md`

Expected: PASS
