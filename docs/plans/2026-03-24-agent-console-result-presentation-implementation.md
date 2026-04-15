# Agent Console Result Presentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refine Agent Console so long replies and failures are shown with a summary-first UX while short successful replies still open immediately.

**Architecture:** Keep the helper unchanged and implement reply/error presentation policy in `payload.sh`. Add a small shell-side threshold for “short” vs “long” completed replies, and use the existing stored response/error fields to drive dashboard summaries and explicit full-detail views.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add a shell-side reply-length threshold

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add local checks that expect a result-length threshold constant and helper:

```bash
grep -q 'SHORT_REPLY_LIMIT=' library/user/remote_access/agent_console/payload.sh || fail "missing short reply threshold"
grep -q 'is_short_reply()' library/user/remote_access/agent_console/payload.sh || fail "missing short reply helper"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the grep checks above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Add:

```bash
SHORT_REPLY_LIMIT=160
```

and a helper such as:

```bash
is_short_reply() {
  local text="$1"
  [[ ${#text} -le $SHORT_REPLY_LIMIT ]]
}
```

Keep the threshold simple and shell-local.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console reply threshold"
```

### Task 2: Only auto-open short successful replies

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects the completed-reply prompt path to be gated through the short-reply helper:

```bash
grep -q 'is_short_reply "\\$response"' library/user/remote_access/agent_console/payload.sh || fail "short reply gating missing"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the grep check above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Refine the post-send completed-reply behavior so:

- short completed replies still open immediately with `PROMPT`
- long completed replies do not auto-open; instead log a short message such as:
  - `Long reply ready. Use Last reply to open it.`

Do not change `Last reply`; it should remain the explicit full-detail path.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "gate agent console auto-open replies by length"
```

### Task 3: Show failure summaries instead of full raw errors

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects failure handling to use a summary helper:

```bash
grep -q 'summarize_error()' library/user/remote_access/agent_console/payload.sh || fail "missing error summary helper"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the grep check above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Add a helper such as:

```bash
summarize_error() {
  local text="$1"
  text="${text//$'\n'/ }"
  printf '%s' "${text:0:80}"
}
```

Update failure handling so the immediate UI shows a short summary only. Keep the full detail accessible through the existing stored job data and explicit user actions.

Do not introduce a new helper command in this task.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "summarize agent console errors"
```

### Task 4: Update README to document result-presentation rules

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Add local checks that expect the README to describe short vs long replies and summarized failures:

```bash
grep -qi 'long reply' library/user/remote_access/agent_console/README.md || fail "README missing long-reply behavior"
grep -qi 'error summary' library/user/remote_access/agent_console/README.md || fail "README missing error summary behavior"
```

**Step 2: Run to verify failure**

Run the grep checks.

Expected: FAIL before implementation if the README does not yet describe the new policy.

**Step 3: Write minimal implementation**

Update the README to explain:

- short successful replies open immediately
- long successful replies stay in the dashboard with `Last reply` as the full-detail path
- failures surface a short summary first

**Step 4: Run verification**

Run:

- `grep -qi 'long reply' library/user/remote_access/agent_console/README.md`
- `grep -qi 'error summary' library/user/remote_access/agent_console/README.md`

Expected: both pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/README.md
git commit -m "document agent console result presentation"
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

- short completed replies still open immediately
- long replies return to the dashboard with a summary message
- failures show short summaries instead of full raw text
- `Last reply` remains the explicit full-detail path

**Step 3: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh \
  library/user/remote_access/agent_console/README.md
git commit -m "refine agent console result presentation"
```
