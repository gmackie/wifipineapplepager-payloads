# Agent Console Empty State Guidance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace terse empty-state messages in Agent Console with actionable guidance that tells the operator what to do next.

**Architecture:** Keep the existing control flow and storage model unchanged, and refine only the shell-side empty-state messaging in `payload.sh` plus the README. Add a small set of focused helper messages for the highest-frequency branches: no session, no job to refresh, no reply/error/result, and no recent turns.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add actionable empty-state guidance helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'show_no_session_guidance|show_no_job_guidance|show_no_result_guidance' library/user/remote_access/agent_console/payload.sh
```

Expected: FAIL because the guidance helpers do not exist yet.

**Step 2: Write minimal implementation**

Add shell helpers that emit concise next-step guidance for:

- no active session
- no job to refresh
- no reply available
- no error available
- no result available
- no recent turns available

Prefer short next-step wording such as:

- `Choose or create a session from Sessions.`
- `Send a prompt first, or choose a different session.`
- `Refresh the job first, or send a new prompt.`

Do not wire the existing branches yet.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Replace the highest-frequency terse empty states

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Run:

```bash
rg -n 'No session selected|No job to refresh|No reply available|No error available|No result available|No recent turns available' library/user/remote_access/agent_console/payload.sh
```

Expected: the file still contains the terse empty-state strings before the guidance helpers are wired.

**Step 2: Write minimal implementation**

Update `payload.sh` so the high-frequency branches use the new guidance helpers instead of bare `LOG blue "No ..."` strings.

Target branches:

- no active session
- no job to refresh
- no reply available
- no error available
- no result available
- no recent turns available

Keep the underlying logic and return codes unchanged.

**Step 3: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

### Task 3: Update README for actionable empty states

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'actionable empty states|what to do next|choose or create a session|send a prompt first' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that the payload now gives next-step guidance in common empty states, especially when there is no active session, no current job, or no reply/error/result to open yet.

**Step 3: Run verification**

Run:

- `rg -n 'actionable empty states|what to do next|choose or create a session|send a prompt first' library/user/remote_access/agent_console/README.md`

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
- `rg -n 'choose or create a session|send a prompt first|refresh the job first|what to do next' library/user/remote_access/agent_console/README.md library/user/remote_access/agent_console/payload.sh`

Expected: PASS
