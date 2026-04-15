# Agent Console Result Navigation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make result navigation clearer by replacing the generic `Last reply` wording with state-aware labels that distinguish successful replies from failure details.

**Architecture:** Keep the existing stored job/result behavior and only refine the shell-side wording in `payload.sh` plus the README. Add a small label helper that derives the action text from the current job state, then use it consistently in the main menu and user-facing guidance strings.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add state-aware result label helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'main_menu_result_label|Last error|Last result' library/user/remote_access/agent_console/payload.sh
```

Expected: FAIL because the state-aware result label helper does not exist yet.

**Step 2: Write minimal implementation**

Add shell helpers that:

- inspect the current job state
- return `3 Last reply` for completed jobs
- return `3 Last error` for failed jobs
- return `3 Last result` for other or unknown states

Do not change the main menu or prompts yet.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Wire the state-aware label into the menu and prompts

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'Last reply' library/user/remote_access/agent_console/payload.sh
```

Expected: the file still contains hard-coded `Last reply` strings in the menu/prompts before the change.

**Step 2: Write minimal implementation**

Update `payload.sh` so that:

- the main dashboard loop uses the new result label helper
- long successful replies say `Use Last reply to open it` only when the current result is actually a reply
- error-facing guidance uses `Last error`
- generic wording uses `Last result`
- the underlying `view_last_response_flow()` behavior remains unchanged

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for the new result navigation wording

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'Last error|Last result' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that:

- successful completed output is reached through `Last reply`
- failed jobs surface detail through `Last error`
- when the state is less specific, the payload may show `Last result`

**Step 3: Run verification**

Run:

- `rg -n 'Last error|Last result' library/user/remote_access/agent_console/README.md`

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
- `rg -n 'Last error|Last result' library/user/remote_access/agent_console/README.md library/user/remote_access/agent_console/payload.sh`

Expected: PASS
