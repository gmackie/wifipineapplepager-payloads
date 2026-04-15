"""DuckyScript UI bridge — call pager UI commands from Python."""
import json
import subprocess


def log(color, msg):
    subprocess.run(["bash", "-c", f'LOG {color} "{msg}"'], check=False)


def alert(msg):
    subprocess.run(["bash", "-c", f'ALERT "{msg}"'], check=False)


def start_spinner(msg):
    result = subprocess.run(
        ["bash", "-c", f'START_SPINNER "{msg}"'],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip()


def stop_spinner(spinner_id):
    subprocess.run(["bash", "-c", f'STOP_SPINNER {spinner_id}'], check=False)


def write_status_file(status):
    """Write agent status to /tmp/edgeops-status.json for payload.sh to read."""
    with open("/tmp/edgeops-status.json", "w") as f:
        json.dump(status, f)


def read_status_file():
    """Read agent status from /tmp/edgeops-status.json."""
    try:
        with open("/tmp/edgeops-status.json", "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"state": "unknown"}
