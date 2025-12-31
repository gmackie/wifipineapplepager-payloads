#!/bin/bash
# Laptop SSH execution wrapper

# Execute command on laptop
# Usage: laptop_exec "command"
laptop_exec() {
  local cmd="$1"
  
  if [[ "$LAPTOP_ENABLED" -eq 0 ]]; then
    LOG red "Laptop mode not enabled. Set LAPTOP_ENABLED=1 in config."
    return 1
  fi
  
  if [[ -z "$LAPTOP_HOST" ]]; then
    LOG red "LAPTOP_HOST not configured"
    return 1
  fi
  
  local ssh_opts="-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new"
  
  if [[ -n "$LAPTOP_KEY" && -f "$LAPTOP_KEY" ]]; then
    ssh_opts="$ssh_opts -i $LAPTOP_KEY"
  fi
  
  # shellcheck disable=SC2086
  ssh $ssh_opts "$LAPTOP_HOST" "$cmd"
}

# Execute command on laptop in background, return PID
# Usage: pid=$(laptop_exec_bg "long-running-command")
laptop_exec_bg() {
  local cmd="$1"
  local log_file="${2:-/tmp/pager-bg.log}"
  
  laptop_exec "mkdir -p '$LAPTOP_RESULTS_DIR' && nohup $cmd > '$log_file' 2>&1 & echo \$!"
}

# Check if laptop is reachable
laptop_ping() {
  if [[ "$LAPTOP_ENABLED" -eq 0 ]]; then
    return 1
  fi
  
  laptop_exec "echo ok" >/dev/null 2>&1
}

# Fetch file from laptop to local
# Usage: laptop_fetch "/remote/path" "/local/path"
laptop_fetch() {
  local remote_path="$1"
  local local_path="$2"
  
  if [[ "$LAPTOP_ENABLED" -eq 0 ]]; then
    LOG red "Laptop mode not enabled"
    return 1
  fi
  
  local scp_opts="-o BatchMode=yes -o ConnectTimeout=5"
  
  if [[ -n "$LAPTOP_KEY" && -f "$LAPTOP_KEY" ]]; then
    scp_opts="$scp_opts -i $LAPTOP_KEY"
  fi
  
  # shellcheck disable=SC2086
  scp $scp_opts "$LAPTOP_HOST:$remote_path" "$local_path"
}

# Fetch all results from laptop results directory
laptop_fetch_results() {
  local local_dir="${1:-$ARTIFACT_DIR}"
  
  mkdir -p "$local_dir"
  laptop_fetch "$LAPTOP_RESULTS_DIR/*" "$local_dir/" 2>/dev/null || true
}

# Run command with laptop fallback
# Usage: run_with_fallback "local_cmd" "laptop_cmd"
run_with_fallback() {
  local local_cmd="$1"
  local laptop_cmd="${2:-$1}"
  
  # Try local first
  local local_bin
  local_bin=$(echo "$local_cmd" | awk '{print $1}')
  
  if have "$local_bin"; then
    eval "$local_cmd"
    return $?
  fi
  
  # Fall back to laptop
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    LOG blue "Running on laptop: $laptop_cmd"
    laptop_exec "$laptop_cmd"
    return $?
  fi
  
  LOG red "Tool '$local_bin' not available locally and laptop mode disabled"
  return 1
}
