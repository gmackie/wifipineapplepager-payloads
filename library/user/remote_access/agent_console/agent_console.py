#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(os.environ.get("AGENT_CONSOLE_ROOT", "/root/loot/agent-console"))
SESSIONS_DIR = ROOT / "sessions"
MAX_AUTO_TITLE_LENGTH = 60


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_root() -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def session_dir(session_id: str) -> Path:
    return SESSIONS_DIR / session_id


def session_file(session_id: str) -> Path:
    return session_dir(session_id) / "session.json"


def transcript_file(session_id: str) -> Path:
    return session_dir(session_id) / "transcript.jsonl"


def jobs_dir(session_id: str) -> Path:
    return session_dir(session_id) / "jobs"


def job_file(session_id: str, job_id: str) -> Path:
    return jobs_dir(session_id) / f"{job_id}.json"


def load_json_file(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_template(template: str, values: Dict[str, Any]) -> str:
    if not isinstance(template, str) or not template:
        raise ValueError("template must be a non-empty string")
    return template.format(**values)


def json_request(
    url: str,
    method: str,
    payload: Dict[str, Any] = None,
    timeout_seconds: float = 30.0,
    headers: Dict[str, str] = None,
) -> Dict[str, Any]:
    data = None
    request_headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    request = Request(url, data=data, method=method.upper())
    for key, value in request_headers.items():
        request.add_header(key, value)

    with urlopen(request, timeout=timeout_seconds) as response:
        raw_body = response.read().decode("utf-8").strip()
        body: Any = raw_body
        if raw_body:
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError:
                body = raw_body
        else:
            body = ""
        return {
            "status_code": response.getcode(),
            "body": body,
            "raw_body": raw_body,
            "headers": dict(response.headers.items()),
        }


def response_text(body: Any) -> str:
    if isinstance(body, dict):
        for key in ("response", "content", "text", "output", "result", "error", "detail", "reason"):
            value = body.get(key)
            if isinstance(value, str):
                return value.strip()
        nested = body.get("data")
        if isinstance(nested, dict):
            nested_text = response_text(nested)
            if nested_text:
                return nested_text
        return ""
    if isinstance(body, str):
        return body.strip()
    if body is None:
        return ""
    return str(body).strip()


def response_status(body: Any) -> str:
    if isinstance(body, dict):
        for key in ("status", "state", "job_status"):
            value = body.get(key)
            if isinstance(value, str):
                return value.lower()
    return ""


def response_job_id(body: Any) -> str:
    if isinstance(body, dict):
        for key in ("remote_job_id", "job_id", "id", "request_id"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, int):
                return str(value)
    return ""


def collapse_whitespace(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split()).strip()


def cap_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3] + "..."


def normalize_explicit_title(title: Any) -> str:
    return collapse_whitespace(title)


def normalize_auto_title(title: Any) -> str:
    return cap_text(collapse_whitespace(title), MAX_AUTO_TITLE_LENGTH)


def is_generic_session_title(session: Dict[str, Any]) -> bool:
    title = collapse_whitespace(session.get("title", ""))
    session_id = collapse_whitespace(session.get("id", ""))
    return title in ("", "Agent Console") or title == f"Session {session_id}"


def update_session_title(session_id: str, title: str) -> Dict[str, Any]:
    session = read_session(session_id)
    session["title"] = title
    session["updated_at"] = utc_now()
    write_session(session_id, session)
    return session


def read_session(session_id: str) -> Dict[str, Any]:
    path = session_file(session_id)
    if not path.is_file():
        raise FileNotFoundError(f"unknown session: {session_id}")
    return load_json_file(path)


def write_session(session_id: str, data: Dict[str, Any]) -> None:
    session_file(session_id).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_job(session_id: str, job_id: str) -> Dict[str, Any]:
    path = job_file(session_id, job_id)
    if not path.is_file():
        raise FileNotFoundError(f"unknown job: {job_id}")
    return load_json_file(path)


def write_job(session_id: str, job_id: str, data: Dict[str, Any]) -> None:
    job_file(session_id, job_id).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def update_job_state(session_id: str, job_id: str, state: str, **fields: Any) -> Dict[str, Any]:
    job = read_job(session_id, job_id)
    job.update(fields)
    job["state"] = state
    job["updated_at"] = utc_now()
    write_job(session_id, job_id, job)
    return job


def append_transcript(session_id: str, role: str, content: str, job_id: str) -> None:
    event = {
        "timestamp": utc_now(),
        "role": role,
        "job_id": job_id,
        "content": content,
    }
    with transcript_file(session_id).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def list_jobs(session_id: str) -> List[Dict[str, Any]]:
    read_session(session_id)
    jobs_path = jobs_dir(session_id)
    if not jobs_path.is_dir():
        return []

    jobs: List[Dict[str, Any]] = []
    for path in sorted(jobs_path.glob("*.json")):
        jobs.append(load_json_file(path))

    jobs.sort(key=lambda item: (item.get("created_at") or "", item.get("id") or ""))
    return jobs


def show_session(session_id: str) -> Dict[str, Any]:
    return read_session(session_id)


def show_last_response(session_id: str) -> str:
    read_session(session_id)
    path = transcript_file(session_id)
    if not path.is_file():
        return ""

    last_response = ""
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("role") == "assistant":
                    content = event.get("content")
                    if isinstance(content, str):
                        last_response = content
    return last_response


def show_recent_turns(session_id: str, limit: int) -> List[Dict[str, Any]]:
    read_session(session_id)
    path = transcript_file(session_id)
    if not path.is_file():
        return []

    try:
        normalized_limit = int(limit)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")

    if normalized_limit <= 0:
        return []

    turns: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            turns.append(json.loads(line))

    return turns[-normalized_limit:]


def preview_text(value: str, limit: int = 60) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def show_session_status(session_id: str) -> Dict[str, Any]:
    session = read_session(session_id)
    jobs = list_jobs(session_id)
    last_job = jobs[-1] if jobs else {}
    last_response = show_last_response(session_id)

    return {
        "id": session.get("id", session_id),
        "title": session.get("title", ""),
        "backend": session.get("backend", ""),
        "last_job_id": last_job.get("id", ""),
        "last_job_state": last_job.get("state", "none"),
        "last_response_preview": preview_text(last_response),
    }


def load_profile(profile_path: str) -> Dict[str, Any]:
    path = Path(profile_path)
    if not path.is_file():
        raise FileNotFoundError(f"unknown profile: {profile_path}")
    return load_json_file(path)


def profile_timeout_seconds(profile: Dict[str, Any]) -> float:
    timeout_seconds = profile.get("timeout_seconds", 30)
    try:
        return float(timeout_seconds)
    except (TypeError, ValueError):
        raise ValueError("profile timeout_seconds must be numeric")


def run_http_adapter(profile: Dict[str, Any], session_id: str, job_id: str, message: str) -> Dict[str, Any]:
    if profile.get("type") != "http":
        raise ValueError("profile type must be http")

    submit_url = profile.get("submit_url")
    if not isinstance(submit_url, str) or not submit_url:
        raise ValueError("profile submit_url must be a non-empty string")

    method = profile.get("method", "POST")
    if not isinstance(method, str) or not method:
        raise ValueError("profile method must be a non-empty string")

    timeout_seconds = profile_timeout_seconds(profile)
    submit_payload = {
        "session_id": session_id,
        "job_id": job_id,
        "message": message,
    }

    headers = profile.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("profile headers must be a map if provided")

    submit_result = json_request(
        submit_url,
        method,
        payload=submit_payload,
        timeout_seconds=timeout_seconds,
        headers=headers if isinstance(headers, dict) else None,
    )

    body = submit_result["body"]
    response = response_text(body)
    remote_job_id = response_job_id(body)
    status = response_status(body)
    status_url = profile.get("status_url")
    if status_url is not None and not isinstance(status_url, str):
        raise ValueError("profile status_url must be a string if provided")

    state = "running"
    if status in ("failed", "error"):
        state = "failed"
    elif status in ("queued", "running", "pending", "in_progress"):
        state = "running"
        response = ""
    elif response:
        state = "completed"
    elif not remote_job_id:
        state = "failed"

    result: Dict[str, Any] = {
        "state": state,
        "returncode": 0,
        "stdout": submit_result["raw_body"],
        "stderr": "",
        "response": response,
        "remote_job_id": remote_job_id,
        "remote_status": status,
        "submit_url": submit_url,
        "status_url": status_url or "",
        "submit_response": body,
    }

    if state == "failed":
        result["error"] = response or "HTTP submit failed"
    elif not response and not remote_job_id:
        result["state"] = "failed"
        result["error"] = "HTTP submit did not return a response or job id"

    return result


def poll_http_job(profile: Dict[str, Any], session_id: str, job_id: str) -> Dict[str, Any]:
    if profile.get("type") != "http":
        raise ValueError("profile type must be http")

    status_url = profile.get("status_url")
    if not isinstance(status_url, str) or not status_url:
        raise ValueError("profile status_url must be a non-empty string")

    job = read_job(session_id, job_id)
    remote_job_id = job.get("remote_job_id") or job.get("id")
    if not isinstance(remote_job_id, str) or not remote_job_id:
        raise ValueError("job does not have a remote_job_id")

    timeout_seconds = profile_timeout_seconds(profile)
    headers = profile.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("profile headers must be a map if provided")

    url = render_template(
        status_url,
        {
            "session_id": session_id,
            "job_id": job_id,
            "remote_job_id": remote_job_id,
        },
    )
    result = json_request(
        url,
        profile.get("poll_method", "GET"),
        timeout_seconds=timeout_seconds,
        headers=headers if isinstance(headers, dict) else None,
    )

    body = result["body"]
    response = response_text(body)
    remote_status = response_status(body)
    if not remote_status and response:
        remote_status = "completed"

    if remote_status in ("queued", "running", "pending", "in_progress"):
        return {
            "state": "running",
            "returncode": 0,
            "stdout": result["raw_body"],
            "stderr": "",
            "response": "",
            "remote_job_id": remote_job_id,
            "remote_status": remote_status,
            "status_url": status_url,
            "poll_response": body,
        }

    if remote_status in ("failed", "error"):
        return {
            "state": "failed",
            "returncode": 1,
            "stdout": result["raw_body"],
            "stderr": "",
            "response": response,
            "remote_job_id": remote_job_id,
            "remote_status": remote_status,
            "status_url": status_url,
            "poll_response": body,
            "error": response or "remote job failed",
        }

    return {
        "state": "completed",
        "returncode": 0,
        "stdout": result["raw_body"],
        "stderr": "",
        "response": response or result["raw_body"],
        "remote_job_id": remote_job_id,
        "remote_status": remote_status or "completed",
        "status_url": status_url,
        "poll_response": body,
    }


def run_command_adapter(profile: Dict[str, Any], session_id: str, job_id: str, message: str) -> Dict[str, Any]:
    if profile.get("type") != "command":
        raise ValueError("profile type must be command")

    command = profile.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise ValueError("profile command must be a non-empty list of strings")

    timeout_seconds = profile.get("timeout_seconds")
    if timeout_seconds is None:
        timeout_seconds = 30

    env = os.environ.copy()
    env["AGENT_CONSOLE_SESSION_ID"] = session_id
    env["AGENT_CONSOLE_JOB_ID"] = job_id
    env["AGENT_CONSOLE_PROMPT"] = message

    completed = subprocess.run(
        command,
        capture_output=True,
        env=env,
        text=True,
        timeout=float(timeout_seconds),
        check=False,
    )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    response_text = stdout.strip()

    result: Dict[str, Any] = {
        "state": "completed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "response": response_text,
    }
    return result


def create_job(session_id: str, message: str) -> Dict[str, Any]:
    session = read_session(session_id)
    job_id = uuid.uuid4().hex[:12]
    now = utc_now()
    job = {
        "id": job_id,
        "session_id": session_id,
        "backend": session["backend"],
        "state": "queued",
        "message": message,
        "created_at": now,
        "updated_at": now,
    }
    jobs_dir(session_id).mkdir(parents=True, exist_ok=True)
    job_file(session_id, job_id).write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    append_transcript(session_id, "user", message, job_id)
    if is_generic_session_title(session) and len(list_jobs(session_id)) == 1:
        auto_title = normalize_auto_title(message)
        if auto_title:
            session["title"] = auto_title
    session["updated_at"] = now
    write_session(session_id, session)
    return job


def run_job(session_id: str, job_id: str, profile_path: str) -> Dict[str, Any]:
    session = read_session(session_id)
    try:
        profile = load_profile(profile_path)
        job = update_job_state(session_id, job_id, "running", profile_path=profile_path)
        if profile.get("type") == "command":
            adapter_result = run_command_adapter(profile, session_id, job_id, job["message"])
        elif profile.get("type") == "http":
            adapter_result = run_http_adapter(profile, session_id, job_id, job["message"])
        else:
            raise ValueError("profile type must be command or http")
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        job = update_job_state(
            session_id,
            job_id,
            "failed",
            profile_path=profile_path,
            error=str(exc),
        )
        session["updated_at"] = utc_now()
        write_session(session_id, session)
        return job
    except subprocess.TimeoutExpired as exc:
        job = update_job_state(
            session_id,
            job_id,
            "failed",
            profile_path=profile_path,
            error="timeout",
            stderr=str(exc),
        )
        session["updated_at"] = utc_now()
        write_session(session_id, session)
        return job
    except (OSError, ValueError) as exc:
        job = update_job_state(
            session_id,
            job_id,
            "failed",
            profile_path=profile_path,
            error=str(exc),
        )
        session["updated_at"] = utc_now()
        write_session(session_id, session)
        return job

    job_updates: Dict[str, Any] = {
        "returncode": adapter_result["returncode"],
        "stdout": adapter_result["stdout"],
        "stderr": adapter_result["stderr"],
        "response": adapter_result["response"],
        "profile_path": profile_path,
    }

    if adapter_result.get("remote_job_id"):
        job_updates["remote_job_id"] = adapter_result["remote_job_id"]
    if adapter_result.get("remote_status"):
        job_updates["remote_status"] = adapter_result["remote_status"]
    if adapter_result.get("submit_url"):
        job_updates["submit_url"] = adapter_result["submit_url"]
    if adapter_result.get("status_url"):
        job_updates["status_url"] = adapter_result["status_url"]
    if adapter_result.get("submit_response") is not None:
        job_updates["submit_response"] = adapter_result["submit_response"]
    if adapter_result.get("poll_response") is not None:
        job_updates["poll_response"] = adapter_result["poll_response"]

    if adapter_result.get("state") == "running":
        job = update_job_state(session_id, job_id, "running", **job_updates)
    elif adapter_result["state"] == "completed":
        job = update_job_state(session_id, job_id, "completed", **job_updates)
        if adapter_result["response"]:
            append_transcript(session_id, "assistant", adapter_result["response"], job_id)
    else:
        job_updates["error"] = adapter_result.get("error", "command exited non-zero")
        job = update_job_state(session_id, job_id, "failed", **job_updates)

    session["updated_at"] = utc_now()
    write_session(session_id, session)
    return job


def poll_job(session_id: str, job_id: str, profile_path: str) -> Dict[str, Any]:
    session = read_session(session_id)
    try:
        profile = load_profile(profile_path)
        job = read_job(session_id, job_id)
        if job.get("state") in ("completed", "failed"):
            return job
        if profile.get("type") != "http":
            raise ValueError("profile type must be http")
        adapter_result = poll_http_job(profile, session_id, job_id)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        job = update_job_state(
            session_id,
            job_id,
            "failed",
            profile_path=profile_path,
            error=str(exc),
        )
        session["updated_at"] = utc_now()
        write_session(session_id, session)
        return job
    except (OSError, ValueError, HTTPError, URLError) as exc:
        job = update_job_state(
            session_id,
            job_id,
            "failed",
            profile_path=profile_path,
            error=str(exc),
        )
        session["updated_at"] = utc_now()
        write_session(session_id, session)
        return job

    job_updates: Dict[str, Any] = {
        "profile_path": profile_path,
        "stdout": adapter_result["stdout"],
        "stderr": adapter_result["stderr"],
        "response": adapter_result["response"],
    }

    if adapter_result.get("remote_job_id"):
        job_updates["remote_job_id"] = adapter_result["remote_job_id"]
    if adapter_result.get("remote_status"):
        job_updates["remote_status"] = adapter_result["remote_status"]
    if adapter_result.get("status_url"):
        job_updates["status_url"] = adapter_result["status_url"]
    if adapter_result.get("poll_response") is not None:
        job_updates["poll_response"] = adapter_result["poll_response"]

    if adapter_result["state"] == "running":
        job = update_job_state(session_id, job_id, "running", **job_updates)
    elif adapter_result["state"] == "completed":
        job = update_job_state(session_id, job_id, "completed", **job_updates)
        if adapter_result["response"]:
            append_transcript(session_id, "assistant", adapter_result["response"], job_id)
    else:
        job_updates["error"] = adapter_result.get("error", "remote job failed")
        job = update_job_state(session_id, job_id, "failed", **job_updates)

    session["updated_at"] = utc_now()
    write_session(session_id, session)
    return job


def create_session(title: str, backend: str) -> Dict[str, Any]:
    ensure_root()
    session_id = uuid.uuid4().hex[:12]
    now = utc_now()
    normalized_title = normalize_explicit_title(title)
    data = {
        "id": session_id,
        "title": normalized_title or f"Session {session_id}",
        "backend": backend,
        "created_at": now,
        "updated_at": now,
    }
    path = session_dir(session_id)
    (path / "jobs").mkdir(parents=True, exist_ok=True)
    (path / "artifacts").mkdir(parents=True, exist_ok=True)
    session_file(session_id).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (path / "transcript.jsonl").touch()
    return data


def list_sessions() -> List[Dict[str, Any]]:
    ensure_root()
    sessions: List[Dict[str, Any]] = []
    for child in sorted(SESSIONS_DIR.iterdir()):
        file_path = child / "session.json"
        if file_path.is_file():
            sessions.append(json.loads(file_path.read_text(encoding="utf-8")))
    return sessions


def rename_session(session_id: str, title: str) -> Dict[str, Any]:
    normalized_title = normalize_explicit_title(title)
    if not normalized_title:
        raise ValueError("session title must be a non-empty string")
    return update_session_title(session_id, normalized_title)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    create_parser = sub.add_parser("create-session")
    create_parser.add_argument("--title", default="")
    create_parser.add_argument("--backend", default="command")

    sub.add_parser("list-sessions")

    rename_parser = sub.add_parser("rename-session")
    rename_parser.add_argument("--session-id", required=True)
    rename_parser.add_argument("--title", required=True)

    send_parser = sub.add_parser("send-message")
    send_parser.add_argument("--session-id", required=True)
    send_parser.add_argument("--message", required=True)

    run_parser = sub.add_parser("run-job")
    run_parser.add_argument("--session-id", required=True)
    run_parser.add_argument("--job-id", required=True)
    run_parser.add_argument("--profile", required=True)

    poll_parser = sub.add_parser("poll-job")
    poll_parser.add_argument("--session-id", required=True)
    poll_parser.add_argument("--job-id", required=True)
    poll_parser.add_argument("--profile", required=True)

    show_session_parser = sub.add_parser("show-session")
    show_session_parser.add_argument("--session-id", required=True)

    show_last_response_parser = sub.add_parser("show-last-response")
    show_last_response_parser.add_argument("--session-id", required=True)

    show_recent_turns_parser = sub.add_parser("show-recent-turns")
    show_recent_turns_parser.add_argument("--session-id", required=True)
    show_recent_turns_parser.add_argument("--limit", type=int, default=6)

    list_jobs_parser = sub.add_parser("list-jobs")
    list_jobs_parser.add_argument("--session-id", required=True)

    show_session_status_parser = sub.add_parser("show-session-status")
    show_session_status_parser.add_argument("--session-id", required=True)

    args = parser.parse_args()

    try:
        if args.command == "create-session":
            data = create_session(args.title, args.backend)
            print(json.dumps(data))
            return 0

        if args.command == "list-sessions":
            print(json.dumps(list_sessions()))
            return 0

        if args.command == "rename-session":
            data = rename_session(args.session_id, args.title)
            print(json.dumps(data))
            return 0

        if args.command == "send-message":
            data = create_job(args.session_id, args.message)
            print(json.dumps(data))
            return 0
        if args.command == "run-job":
            data = run_job(args.session_id, args.job_id, args.profile)
            print(json.dumps(data))
            return 0
        if args.command == "poll-job":
            data = poll_job(args.session_id, args.job_id, args.profile)
            print(json.dumps(data))
            return 0
        if args.command == "show-session":
            print(json.dumps(show_session(args.session_id)))
            return 0
        if args.command == "show-last-response":
            print(show_last_response(args.session_id))
            return 0
        if args.command == "show-recent-turns":
            print(json.dumps(show_recent_turns(args.session_id, args.limit)))
            return 0
        if args.command == "list-jobs":
            print(json.dumps(list_jobs(args.session_id)))
            return 0
        if args.command == "show-session-status":
            print(json.dumps(show_session_status(args.session_id)))
            return 0
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.TimeoutExpired, HTTPError, URLError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
