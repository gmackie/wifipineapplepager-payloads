# Agent Console Profile Picker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace raw-path-first profile switching with a pager-friendly profile picker that lists bundled profiles first while still allowing a manual custom path fallback.

**Architecture:** Keep the helper unchanged and refactor the shell-side profile flow in `payload.sh`. Add a small profile discovery layer for `profiles/*.json`, present readable labels in a picker flow, preserve backend compatibility validation, and keep manual path entry as an explicit fallback instead of the default UX.

**Tech Stack:** Bash, DuckyScript commands, Python 3 standard library, shellcheck, `bash -n`

### Task 1: Add bundled profile discovery helpers

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects profile discovery helpers:

```bash
rg -n 'list_profile_paths|pick_profile_from_list' library/user/remote_access/agent_console/payload.sh >/dev/null
```

**Step 2: Run verification to confirm failure**

Run the `rg` check above.

Expected: FAIL because the helpers do not exist yet.

**Step 3: Write minimal implementation**

Add shell helpers that:

- enumerate `library/user/remote_access/agent_console/profiles/*.json`
- sort the results
- expose a small readable label for each profile, preferring basename over full path
- support filtering by backend type when `CURRENT_SESSION_BACKEND` is already set

Do not change the user-facing flow yet.

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 2: Replace raw path entry with picker-first profile selection

**Files:**
- Modify: `library/user/remote_access/agent_console/payload.sh`

**Step 1: Write the failing expectation**

Add a local check that expects a manual fallback menu entry and the new picker flow:

```bash
rg -n 'Manual path|Bundled profile|Select profile' library/user/remote_access/agent_console/payload.sh >/dev/null
```

**Step 2: Run verification to confirm failure**

Run the `rg` check above.

Expected: FAIL before implementation.

**Step 3: Write minimal implementation**

Refactor `choose_profile_path()` so it:

- first offers a profile source picker:
  - bundled profile list
  - manual path entry
- for bundled profiles:
  - show numbered choices using basename-style labels
  - preserve current profile as the default when possible
  - validate backend compatibility before selection is accepted
- for manual path entry:
  - keep the current text input path logic
  - keep the same validation and compatibility checks

Use concise pager wording, for example:

- `1 Bundled profile`
- `2 Manual path`
- `3 Back`

**Step 4: Run verification**

Run:

- `bash -n library/user/remote_access/agent_console/payload.sh`
- `shellcheck library/user/remote_access/agent_console/payload.sh`

Expected: PASS

### Task 3: Update README for the new profile UX

**Files:**
- Modify: `library/user/remote_access/agent_console/README.md`

**Step 1: Write the failing doc expectation**

Run:

```bash
rg -n 'Bundled profile|Manual path' library/user/remote_access/agent_console/README.md
```

Expected: FAIL before the docs are updated.

**Step 2: Write minimal documentation**

Document that:

- `Profile -> Switch profile` now defaults to a bundled profile picker
- manual custom paths are still available as a fallback
- backend compatibility checks still apply

**Step 3: Run verification**

Run:

- `rg -n 'Bundled profile|Manual path' library/user/remote_access/agent_console/README.md`

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
- `rg -n 'Bundled profile|Manual path' library/user/remote_access/agent_console/README.md library/user/remote_access/agent_console/payload.sh`

Expected: PASS
