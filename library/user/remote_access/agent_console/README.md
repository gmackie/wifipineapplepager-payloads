# Agent Console

Agent Console provides persistent pager-side sessions for coding agents. It is designed to work with local command wrappers or a small HTTP bridge, so Claude Code, Codex, and OpenCode can all be plugged in through adapter profiles.

## Setup

Install the required dependencies on the Pager first:

- `python3`

Place the payload at `library/user/remote_access/agent_console/` and launch it from the Pager UI. The shell entrypoint creates `/root/loot/agent-console/` automatically and uses the Python helper for session storage and job tracking.

## How It Works

1. Start Agent Console and let it resume the most recent valid session when possible.
2. Review the denser dashboard summary, which now compresses the active context into fewer lines while still showing the session title, backend, profile label, last job state, and response preview or error summary.
3. Use the main loop for `Send`, `Refresh`, a state-aware result action that opens matching data (`Last reply`, `Last error`, or `Last result`), `Recent turns`, `Sessions`, `Profile`, or `Exit`.
4. Open `Sessions` to `Resume recent`, `Choose session`, `New session`, or `Rename session`.
5. `Sessions -> Choose session` now shows a compact one-line summary for each session, including the title, backend, and last job state.
6. Open `Profile` to `Show current profile`, `Switch profile`, or go `Back`.
7. `Profile -> Switch profile` now opens a bundled profile picker first, with a manual custom path fallback if you need one.
8. Backend compatibility checks still apply, so the selected profile must match the active session backend.
9. `Send` reuses the previous prompt for the active session so follow-up turns are faster.
10. If the session still has a generic title, the first prompt auto-seeds a better title from that message.
11. Use `Sessions -> Rename session` any time you want to replace the auto-generated or default title manually.
12. Short completed replies open immediately, while longer replies stay summarized on the dashboard and can be reopened with `Last reply`.
13. Failed jobs surface a short error summary first; the full stored error remains available through `Last error` and the persisted job data.
14. When the current state is less specific or unknown, the menu may show `Last result` instead.
15. Use `Recent turns` to open a compact read-only view of the last few `You` and `Agent` entries when you need context without opening the full transcript.
16. Use `Refresh running job` when the current job is still active, or `Check last job` after it settles.
17. Empty states give next-step guidance instead of dead ends, such as choosing or creating a session, sending a prompt first, or refreshing the current job when there is no reply, error, or result to open yet.

The payload supports two backend types:

- `command` for local wrappers, mailbox processors, or tmux-fed CLIs
- `http` for a local or LAN HTTP bridge that accepts prompt jobs and returns results

## Session Storage

Session data lives under:

`/root/loot/agent-console/sessions/<session-id>/`

Expected contents:

- `session.json` for session metadata
- `transcript.jsonl` for append-only chat history
- `jobs/` for per-prompt job state
- `artifacts/` for raw adapter output or exports

## Example Flow

1. Start Agent Console.
2. Review the dashboard summary for the active session context.
3. Use `Send` to reuse the previous prompt, submit a new turn, and auto-open only short replies.
4. Let the first prompt auto-seed a better session title when the current title is still generic.
5. Use `Profile -> Switch profile` to pick a bundled profile first, or fall back to a manual path when needed.
6. Use `Sessions -> Rename session` when you want a cleaner manual title.
7. Let longer replies settle on the dashboard, then use `Last reply` to open the full text.
8. Use `Recent turns` when you want a compact read-only summary of the last few exchanges.
9. Use `Sessions -> Choose session` when you want a compact summary list with title, backend, and last job state.
10. Use `Refresh` or `Refresh running job` when the current job is still active.
11. Use `Last reply` to reopen the latest assistant response, `Last error` to inspect stored failure details, or `Last result` when the current state is not specific enough to choose one of the other two.
12. Use `Sessions` only when you need to resume, choose, create, or rename a session.
13. Use `Profile` only when you need to inspect or switch the active wrapper.
14. When the payload has no active session or no reply, error, or result to open yet, follow the guidance it shows: choose or create a session, send a prompt first, or refresh the current job.

## Example Profiles

These are templates. Point them at your own local wrapper scripts or local bridge.

### Claude Code Wrapper

```json
{
  "type": "command",
  "command": [
    "/bin/sh",
    "-lc",
    "/root/agent-wrappers/claude-code-wrapper.sh \"$AGENT_CONSOLE_PROMPT\""
  ],
  "timeout_seconds": 120
}
```

### Codex Wrapper

```json
{
  "type": "command",
  "command": [
    "/bin/sh",
    "-lc",
    "/root/agent-wrappers/codex-wrapper.sh \"$AGENT_CONSOLE_PROMPT\""
  ],
  "timeout_seconds": 120
}
```

### OpenCode Wrapper

```json
{
  "type": "command",
  "command": [
    "/bin/sh",
    "-lc",
    "/root/agent-wrappers/opencode-wrapper.sh \"$AGENT_CONSOLE_PROMPT\""
  ],
  "timeout_seconds": 120
}
```

### HTTP Bridge

```json
{
  "type": "http",
  "submit_url": "http://127.0.0.1:8080/jobs",
  "status_url": "http://127.0.0.1:8080/jobs/{remote_job_id}",
  "method": "POST",
  "poll_method": "GET",
  "timeout_seconds": 30
}
```

## Transcript Safety

Treat `/root/loot/agent-console/` as sensitive operator data. Transcripts can contain prompts, agent responses, tool output, tokens, and error traces.

- Do not point profiles at live secrets or production endpoints.
- Use wrapper scripts that sanitize their own logs.
- Rotate or delete transcripts after an engagement if the contents should not remain on the Pager.
- Prefer `example.com` or local-only bridge addresses when documenting external services.
