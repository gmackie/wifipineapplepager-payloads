# Agent Console - WiFi Pineapple Pager Design Document

**Date:** 2026-03-23
**Status:** Approved
**Target Platform:** WiFi Pineapple Pager

---

## Executive Summary

Add a pager payload that lets an operator interact with a coding agent running on the pager itself or reachable through a local bridge. The operator experience should look like a persistent chat session, but the implementation should persist all work as jobs and transcripts so sessions can survive payload exits, reconnects, and backend failures.

The feature should ship as a single payload with pluggable backends rather than separate payloads for Claude Code, Codex, and OpenCode. This keeps the pager UI, session management, artifact handling, and verification logic centralized while allowing multiple agent runtimes to be supported through small adapter layers.

The first version may require `python3` and `tmux`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    WiFi Pineapple Pager                 │
│                                                         │
│  library/user/remote_access/agent_console/             │
│  ┌───────────────────────────────────────────────────┐  │
│  │ payload.sh                                        │  │
│  │  - Pager UI flow                                  │  │
│  │  - Dependency checks                              │  │
│  │  - Backend/session pickers                        │  │
│  │  - tmux launcher/attach                           │  │
│  └───────────────────────────────────────────────────┘  │
│                       │                                 │
│                       ▼                                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │ agent_console.py                                  │  │
│  │  - Session store                                  │  │
│  │  - Job queue/state                                │  │
│  │  - Transcript persistence                         │  │
│  │  - Backend adapter dispatch                       │  │
│  └───────────────────────────────────────────────────┘  │
│                       │                                 │
│           ┌───────────┴───────────┐                     │
│           ▼                       ▼                     │
│    HTTP adapter              Command adapter            │
│    - localhost bridge        - wrapper script          │
│    - request/result API      - mailbox/tmux flow       │
└─────────────────────────────────────────────────────────┘
```

### Design Principles

- One payload, many adapters.
- Session state lives on disk, not in shell variables.
- Pager UI remains simple and synchronous even when agent work is long-running.
- Backends only return structured job results and never manipulate pager UI directly.
- Failures are isolated per job and must not corrupt the session store.

---

## Components

### 1. Pager Payload (`payload.sh`)

The shell entrypoint owns the pager-native workflow:

- Verify required tools (`python3`, `tmux`, `jq` if used).
- Create the base loot directory.
- Offer session actions:
  - create session
  - reopen session
  - send message
  - refresh status
  - view last response
  - switch backend/profile
  - close session
- Start or reuse a named tmux session for long-running helper activity if needed.
- Render short status and errors using DuckyScript primitives such as `LOG`, `PROMPT`, `ALERT`, and `ERROR_DIALOG`.

The shell should not implement queueing, transcript parsing, or backend-specific logic beyond collecting user input and invoking the helper.

### 2. Python Helper (`agent_console.py`)

The Python helper is the durable control plane. It should:

- Create and list sessions.
- Append user and assistant messages to a transcript.
- Create per-message job records.
- Submit jobs to the selected adapter.
- Update job state through `queued`, `running`, `completed`, or `failed`.
- Persist backend metadata and error details.
- Expose subcommands suitable for shell invocation, for example:
  - `create-session`
  - `list-sessions`
  - `show-session`
  - `send-message`
  - `poll-job`
  - `show-last-response`
  - `set-backend`

### 3. Backend Adapters

Backends should share one interface:

- input: session metadata, prompt text, job id, adapter config
- output: structured result with status, response text, timing, and stderr/error if present

Initial adapter types:

- `http`
  - Sends prompts to a local or LAN bridge.
  - Supports async job submission and polling.
  - Best fit when an agent service can expose a local HTTP API.
- `command`
  - Invokes a local wrapper or mailbox processor.
  - Can support tmux-fed CLIs, watched directories, or direct subprocess execution.
  - Best fit for agent CLIs that do not expose an API.

Agent-specific support for Claude Code, Codex, and OpenCode should be implemented as adapter profiles and wrapper commands, not as separate payloads.

---

## Data Model

Each session should live under:

```text
/root/loot/agent-console/sessions/<session-id>/
```

Recommended contents:

- `session.json`
  - session id
  - title
  - created/updated timestamps
  - active backend/profile
  - optional model/runtime metadata
- `transcript.jsonl`
  - append-only message log
  - one JSON object per line
  - includes role, timestamp, job id, and content
- `jobs/<job-id>.json`
  - prompt
  - backend
  - state
  - created/started/completed timestamps
  - response summary
  - stderr/error info
- `artifacts/`
  - optional raw adapter outputs or exported transcripts

This layout keeps sessions recoverable and debuggable with standard shell tools.

---

## User Flow

### Session Lifecycle

1. Start payload.
2. Choose existing session or create a new one.
3. Choose backend/profile.
4. Enter prompt text.
5. Helper creates a job and submits it.
6. User refreshes status or views the latest response.
7. Transcript persists even if the payload exits.

### Pager UX Goals

- The experience should feel like a chat, not a low-level job queue.
- The operator should always know whether work is queued, running, failed, or done.
- Common actions should be available without leaving the session.
- Session resumes should be cheap and reliable.

---

## Error Handling

Failures should be explicit and non-destructive.

### Dependency Failures

- Missing `python3` or `tmux`: detect before session startup and offer installation or a clear exit path.
- Missing adapter binary or wrapper: block backend selection and show a concrete error.

### Runtime Failures

- HTTP bridge unreachable: mark job `failed`, store a short network error, preserve transcript/session state.
- Command backend exits non-zero: capture stderr, mark `failed`, offer retry.
- Command timeout: mark `failed` with timeout details and keep the job record for inspection.
- Malformed backend output: reject the result, store raw output in artifacts if useful, and leave the session intact.

### Recovery

- Retrying a failed prompt should create a new job, not mutate the old one.
- Reopening a session should rebuild state from disk, not from in-memory assumptions.

---

## Security and Safety

- Default configuration should assume local execution or localhost-only bridges.
- Remote HTTP targets should be explicit, not implicit.
- Backends should be configured through known profiles or explicit wrapper paths, not ad hoc shell interpolation.
- Prompt and response artifacts may contain sensitive content; all output should remain under `/root/loot/agent-console/`.
- Shell entrypoints should validate and quote all user-controlled values before invoking helper commands.

---

## Testing Strategy

### Shell Verification

- `bash -n payload.sh`
- `shellcheck payload.sh`

### Python Verification

Focus tests on helper boundaries:

- create session
- list and reopen sessions
- enqueue job
- successful HTTP adapter execution
- successful command adapter execution
- adapter timeout path
- adapter non-zero exit path
- transcript persistence across process restarts

### Manual Pager Verification

- Start a session, send a message, and read the reply.
- Exit and reopen the payload, then verify the transcript is still present.
- Switch between `http` and `command` backends in the same payload.
- Verify clear failure messaging when a backend is unavailable.

---

## Proposed File Layout

```text
library/user/remote_access/agent_console/
  payload.sh
  README.md
  agent_console.py
  adapters/
    __init__.py
    http_adapter.py
    command_adapter.py
  profiles/
    claude-code.example.json
    codex.example.json
    opencode.example.json
```

If the repository prefers a single-file Python helper for portability, adapter code can remain inside `agent_console.py` for v1 and be split later.

---

## Implementation Priorities

### Phase 1

- Create payload scaffold and README.
- Add Python helper with session store and transcript persistence.
- Implement a `command` adapter with a simple wrapper contract.
- Add one example profile for a local agent command.

### Phase 2

- Add HTTP adapter with job polling.
- Add backend/profile switching from pager UI.
- Improve transcript browsing and last-response rendering.

### Phase 3

- Add example profiles for Claude Code, Codex, and OpenCode.
- Add export/import utilities and optional transcript summarization helpers.

