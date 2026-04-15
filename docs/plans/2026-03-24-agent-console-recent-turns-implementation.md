# Agent Console Recent Turns Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a compact read-only `Recent turns` view to Agent Console so the operator can quickly recover conversation context without opening the full transcript.

**Architecture:** Keep transcript persistence in the existing helper and add a small helper command for recent-turn extraction. Then wire a new pager action in `payload.sh` that displays the last few user/assistant entries in a compact role-marked format. This remains read-only and does not alter send/reply state.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add helper support for recent turns

**Files:**
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Modify: `tests/agent_console_helper_test.sh`

**Step 1: Write the failing test**

Extend `tests/agent_console_helper_test.sh` with a new helper assertion:

```bash
recent_turns="$(python3 "$helper" show-recent-turns --session-id "$session_id" --limit 4)"
echo "$recent_turns" | grep -q '"role": "user"' || fail "recent turns should include user entries"
echo "$recent_turns" | grep -q '"role": "assistant"' || fail "recent turns should include assistant entries"
```

**Step 2: Run test to verify it fails**

Run: `bash tests/agent_console_helper_test.sh`

Expected: FAIL because `show-recent-turns` does not exist yet.

**Step 3: Write minimal implementation**

Add `show-recent-turns --session-id --limit` to `library/user/remote_access/agent_console/agent_console.py`.

Implementation requirements:

- read from `transcript.jsonl`
- return the last `N` events in chronological order
- keep output as JSON array of transcript objects
- default limit can be small, for example `6`

**Step 4: Run verification**

Run:

- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`
- `bash tests/agent_console_helper_test.sh`

Expected: PASS

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/agent_console.py tests/agent_console_helper_test.sh
git commit -m "add agent console recent turns helper"
```

### Task 2: Add a compact pager-side Recent turns view

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add local checks that expect a `recent_turns_flow` function and a new menu label:

```bash
grep -q 'recent_turns_flow()' library/user/remote_access/agent_console/payload.sh || fail "missing recent turns flow"
grep -q 'Recent turns' library/user/remote_access/agent_console/payload.sh || fail "missing recent turns action"
```

**Step 2: Run verification to confirm failure**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- the grep checks above

Expected: shell parses, grep check fails before implementation.

**Step 3: Write minimal implementation**

Add a read-only `recent_turns_flow` that:

- calls `show-recent-turns`
- formats the last few entries with compact role markers:
  - `You: ...`
  - `Agent: ...`
- truncates long lines for pager readability
- uses `PROMPT` or short `LOG` lines to display the result

Do not add selection or reuse behavior. This is context-only.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "add agent console recent turns view"
```

### Task 3: Add Recent turns to the main dashboard loop

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects the main menu to include `Recent turns`:

```bash
grep -q 'Recent turns' library/user/remote_access/agent_console/payload.sh || fail "main loop missing recent turns"
```

**Step 2: Run verification to confirm failure if needed**

Run the grep check and shell syntax check.

Expected: FAIL if the action is not wired yet.

**Step 3: Write minimal implementation**

Update the dashboard menu to:

- keep the existing action ordering as stable as possible
- insert `Recent turns` as a separate read-only action

Recommended shape:

- `1 Send`
- `2 Refresh`
- `3 Last reply`
- `4 Recent turns`
- `5 Sessions`
- `6 Profile`
- `7 Exit`

Keep state-aware refresh wording if already present.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `bash tests/agent_console_helper_test.sh`

Expected: all pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh
git commit -m "wire agent console recent turns into dashboard"
```

### Task 4: Update README to document Recent turns

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Add a local check that expects `Recent turns` in the README:

```bash
grep -qi 'Recent turns' library/user/remote_access/agent_console/README.md || fail "README missing recent turns"
```

**Step 2: Run to verify failure**

Run the grep check.

Expected: FAIL before implementation if the README does not yet mention the action.

**Step 3: Write minimal implementation**

Update the README to explain:

- `Recent turns` is a compact read-only view of the last few exchanges
- it complements `Last reply`
- it is for context, not editing or reuse

**Step 4: Run verification**

Run:

- `grep -qi 'Recent turns' library/user/remote_access/agent_console/README.md`

Expected: pass

**Step 5: Commit**

```bash
git add library/user/remote_access/agent_console/README.md
git commit -m "document agent console recent turns"
```

### Task 5: Final verification

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`
- Modify: `library/user/remote_access/agent_console/agent_console.py`
- Modify: `tests/agent_console_helper_test.sh`
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Run full verification**

Run:

- `bash tests/agent_console_helper_test.sh`
- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`
- `python3 -m py_compile library/user/remote_access/agent_console/agent_console.py`

Expected: all commands succeed, helper test prints `OK`

**Step 2: Review against approved UX**

Check manually in code that:

- `Recent turns` is read-only
- it shows the most recent few transcript entries
- it uses compact `You` / `Agent` style labeling
- it does not interfere with `Send` or `Last reply`

**Step 3: Commit**

```bash
git add library/user/remote_access/agent_console/payload.sh \
  library/user/remote_access/agent_console/agent_console.py \
  tests/agent_console_helper_test.sh \
  library/user/remote_access/agent_console/README.md
git commit -m "add agent console recent turns view"
```
