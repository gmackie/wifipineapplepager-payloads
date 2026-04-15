# Agent Console Result Targeting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the state-aware result action open the matching kind of data so `Last reply`, `Last error`, and `Last result` behave consistently with their labels.

**Architecture:** Keep the existing persisted job/transcript model and refine only the shell-side lookup logic in `payload.sh`. Add small helpers to load the current job payload and open reply/error/result views according to the current job state, then update the README to explain the narrower targeting behavior.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add targeted result lookup helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'show_last_reply_flow|show_last_error_flow|load_current_job_json' library/user/remote_access/agent_console/payload.sh
```

Expected: FAIL because the targeted result helpers do not exist yet.

**Step 2: Write minimal implementation**

Add shell helpers that:

- load the current job JSON from memory or disk when possible
- open the latest reply view
- open the latest error view
- preserve the existing transcript fallback only for reply/result access, not the explicit error path

Do not wire `view_last_response_flow()` yet.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Make `view_last_response_flow()` follow the current label/state

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
sed -n '957,995p' library/user/remote_access/agent_console/payload.sh
```

Expected: the function still uses the old broad fallback order before the change.

**Step 2: Write minimal implementation**

Update `view_last_response_flow()` so it:

- checks `current_job_state()`
- for `completed`, opens reply-focused data only
- for `failed`, opens error-focused data only
- for all other states, uses the broader `Last result` fallback
- keeps the underlying storage model unchanged

If a targeted view has no matching data, use a concise state-specific message such as `No reply available` or `No error available`.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for the targeted result behavior

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'matching kind of data|No reply available|No error available' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that:

- `Last reply` now targets reply data
- `Last error` now targets failure detail
- `Last result` is the broader fallback when the current state is not specific enough

**Step 3: Run verification**

Run:

- `rg -n 'Last error|Last result|Last reply' library/user/remote_access/agent_console/README.md`

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
- `rg -n 'Last error|Last result|Last reply' library/user/remote_access/agent_console/README.md library/user/remote_access/agent_console/payload.sh`

Expected: PASS
