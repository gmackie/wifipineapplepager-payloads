# Agent Console Conversation UX Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refine Agent Console so sending prompts feels conversational on the Pager by reusing the previous prompt and immediately showing full replies for completed jobs.

**Architecture:** Keep the existing helper mostly unchanged and concentrate the UX refinement inside `payload.sh`. Persist only the minimal extra shell state needed for prompt reuse, and reuse the existing helper commands for message submission and last-response lookup.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Remember the previous prompt in the shell flow

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects a persistent last-prompt variable and send flow usage:

```bash
grep -q 'LAST_PROMPT=' library/user/remote_access/agent_console/payload.sh || fail "missing last prompt state"
grep -q 'TEXT_PICKER "Send message" "$LAST_PROMPT"' library/user/remote_access/agent_console/payload.sh || fail "send flow does not reuse last prompt"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the two grep checks above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Add a shell variable such as:

```bash
LAST_PROMPT=""
```

Update `send_message_flow()` so:

- `TEXT_PICKER` defaults to `"$LAST_PROMPT"`
- after successful text entry, `LAST_PROMPT` is updated to the current prompt
- empty prompt handling stays safe

Do not add helper persistence yet; this is in-session reuse only.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "remember previous agent console prompt"
```

### Task 2: Show full reply immediately for completed jobs

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects completed sends to call the full-reply viewer:

```bash
grep -q 'PROMPT "\$response"' library/user/remote_access/agent_console/payload.sh || fail "completed replies are not shown immediately"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the grep check above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Refactor the reply display flow so:

- if `send_message_flow()` gets a `completed` job with a non-empty response, it opens the full reply immediately with `PROMPT`
- if the job is still `running`, it returns to the dashboard without opening a full reply
- if the job `failed`, keep the existing error behavior

You may extract a helper such as:

- `show_response_prompt()`
- `show_completed_reply_if_available()`

Keep `Last reply` working as a separate explicit action.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "show completed replies immediately"
```

### Task 3: Keep dashboard behavior aligned with immediate reply display

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects `Last reply` terminology and dashboard loop continuity to remain intact:

```bash
grep -q '3 Last reply' library/user/remote_access/agent_console/payload.sh || fail "main loop lost last reply action"
```

**Step 2: Run verification to confirm failure if needed**

Run the grep check and shell syntax check.

Expected: if the label or flow drifted, it fails here.

**Step 3: Write minimal implementation**

Make sure:

- immediate full reply display does not remove the dashboard return path
- dismissing the reply prompt lands back in the dashboard loop
- `Last reply` still reopens the latest assistant response independently of the last send result

This task is mostly cleanup after Task 2, not new behavior.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "stabilize agent console reply loop"
```

### Task 4: Update README to document conversational send behavior

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Add a local check that expects prompt reuse and immediate reply behavior in the README:

```bash
grep -qi 'previous prompt' library/user/remote_access/agent_console/README.md || fail "README missing prompt reuse behavior"
grep -qi 'full reply' library/user/remote_access/agent_console/README.md || fail "README missing immediate reply behavior"
```

**Step 2: Run to verify failure**

Run the grep checks.

Expected: FAIL before implementation if the README does not yet describe the conversational flow.

**Step 3: Write minimal implementation**

Update the README to explain:

- `Send` reuses the previous prompt text for quicker iteration
- completed jobs open the full reply immediately
- running jobs return to the dashboard for refresh

**Step 4: Run verification**

Run:

- `grep -qi 'previous prompt' library/user/remote_access/agent_console/README.md`
- `grep -qi 'full reply' library/user/remote_access/agent_console/README.md`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/README.md
git commit -m "document conversational agent console ux"
```

### Task 5: Final verification

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Run full verification**

Run:

- `bash tests/agent_console_helper_test.sh`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`

Expected: all commands succeed, helper test prints `OK`

**Step 2: Review against the approved UX**

Check manually in code that:

- `Send` defaults to the previous prompt
- completed jobs open the full reply immediately
- running jobs still return to the dashboard
- `Last reply` remains available as a separate action

**Step 3: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh \
  library/user/remote_access/agent_console/README.md
git commit -m "refine agent console conversational flow"
```
