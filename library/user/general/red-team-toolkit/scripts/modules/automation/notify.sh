#!/bin/bash
set -euo pipefail

# Notification System
# Send alerts via webhook, email, or other channels

# Notification configuration (set in config.sh or here)
: "${NOTIFY_WEBHOOK_URL:=""}"
: "${NOTIFY_EMAIL_TO:=""}"
: "${NOTIFY_EMAIL_FROM:="pager@example.com"}"
: "${NOTIFY_SMTP_HOST:=""}"
: "${NOTIFY_SLACK_WEBHOOK:=""}"
: "${NOTIFY_DISCORD_WEBHOOK:=""}"
: "${NOTIFY_TELEGRAM_BOT_TOKEN:=""}"
: "${NOTIFY_TELEGRAM_CHAT_ID:=""}"

notify_menu() {
  local choice
  choice=$(menu_pick "Notifications" \
    "test:Test Notification" \
    "configure:Configure Channels" \
    "send:Send Custom Alert" \
    "watch:Watch for Events" \
    "history:Notification History")
  
  case "$choice" in
    test)      notify_test ;;
    configure) notify_configure ;;
    send)      notify_send_custom ;;
    watch)     notify_watch ;;
    history)   notify_history ;;
    *)         return 1 ;;
  esac
}

# Send notification to all configured channels
notify_send() {
  local title="$1"
  local message="$2"
  local priority="${3:-normal}"  # low, normal, high, critical
  
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  # Log notification
  echo "[$timestamp] [$priority] $title: $message" >> "$ARTIFACT_DIR/notifications.log"
  
  # Send to each configured channel
  local sent=0
  
  # Webhook (generic)
  if [[ -n "$NOTIFY_WEBHOOK_URL" ]]; then
    notify_webhook "$title" "$message" "$priority" && ((sent++)) || true
  fi
  
  # Slack
  if [[ -n "$NOTIFY_SLACK_WEBHOOK" ]]; then
    notify_slack "$title" "$message" "$priority" && ((sent++)) || true
  fi
  
  # Discord
  if [[ -n "$NOTIFY_DISCORD_WEBHOOK" ]]; then
    notify_discord "$title" "$message" "$priority" && ((sent++)) || true
  fi
  
  # Telegram
  if [[ -n "$NOTIFY_TELEGRAM_BOT_TOKEN" ]] && [[ -n "$NOTIFY_TELEGRAM_CHAT_ID" ]]; then
    notify_telegram "$title" "$message" "$priority" && ((sent++)) || true
  fi
  
  # Email
  if [[ -n "$NOTIFY_EMAIL_TO" ]] && [[ -n "$NOTIFY_SMTP_HOST" ]]; then
    notify_email "$title" "$message" "$priority" && ((sent++)) || true
  fi
  
  return 0
}

# Generic webhook
notify_webhook() {
  local title="$1"
  local message="$2"
  local priority="$3"
  
  local payload
  payload=$(cat <<EOF
{
  "title": "$title",
  "message": "$message",
  "priority": "$priority",
  "timestamp": "$(date -Iseconds)",
  "source": "red-team-toolkit",
  "engagement": "$ENGAGEMENT_NAME"
}
EOF
)
  
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "$NOTIFY_WEBHOOK_URL" \
    --connect-timeout 5 \
    -o /dev/null 2>&1 || return 1
}

# Slack notification
notify_slack() {
  local title="$1"
  local message="$2"
  local priority="$3"
  
  local color
  case "$priority" in
    critical) color="#dc3545" ;;
    high)     color="#fd7e14" ;;
    normal)   color="#0d6efd" ;;
    low)      color="#6c757d" ;;
    *)        color="#0d6efd" ;;
  esac
  
  local payload
  payload=$(cat <<EOF
{
  "attachments": [{
    "color": "$color",
    "title": "$title",
    "text": "$message",
    "footer": "Red Team Toolkit | $ENGAGEMENT_NAME",
    "ts": $(date +%s)
  }]
}
EOF
)
  
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "$NOTIFY_SLACK_WEBHOOK" \
    --connect-timeout 5 \
    -o /dev/null 2>&1 || return 1
}

# Discord notification
notify_discord() {
  local title="$1"
  local message="$2"
  local priority="$3"
  
  local color
  case "$priority" in
    critical) color=14370560 ;;  # Red
    high)     color=16744192 ;;  # Orange
    normal)   color=3447003 ;;   # Blue
    low)      color=7105644 ;;   # Gray
    *)        color=3447003 ;;
  esac
  
  local payload
  payload=$(cat <<EOF
{
  "embeds": [{
    "title": "$title",
    "description": "$message",
    "color": $color,
    "footer": {
      "text": "Red Team Toolkit | $ENGAGEMENT_NAME"
    },
    "timestamp": "$(date -Iseconds)"
  }]
}
EOF
)
  
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "$NOTIFY_DISCORD_WEBHOOK" \
    --connect-timeout 5 \
    -o /dev/null 2>&1 || return 1
}

# Telegram notification
notify_telegram() {
  local title="$1"
  local message="$2"
  local priority="$3"
  
  local emoji
  case "$priority" in
    critical) emoji="🚨" ;;
    high)     emoji="⚠️" ;;
    normal)   emoji="ℹ️" ;;
    low)      emoji="📝" ;;
    *)        emoji="ℹ️" ;;
  esac
  
  local text="$emoji *$title*

$message

_$ENGAGEMENT_NAME | $(date '+%H:%M:%S')_"
  
  curl -s -X POST \
    "https://api.telegram.org/bot${NOTIFY_TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=$NOTIFY_TELEGRAM_CHAT_ID" \
    -d "text=$text" \
    -d "parse_mode=Markdown" \
    --connect-timeout 5 \
    -o /dev/null 2>&1 || return 1
}

# Email notification
notify_email() {
  local title="$1"
  local message="$2"
  local priority="$3"
  
  local subject="[$priority] Red Team Alert: $title"
  local body="$message

---
Engagement: $ENGAGEMENT_NAME
Time: $(date)
Source: Red Team Toolkit"
  
  # Try different mail methods
  if have sendmail; then
    echo -e "Subject: $subject\nFrom: $NOTIFY_EMAIL_FROM\nTo: $NOTIFY_EMAIL_TO\n\n$body" | \
      sendmail -t 2>/dev/null || return 1
  elif have mail; then
    echo "$body" | mail -s "$subject" "$NOTIFY_EMAIL_TO" 2>/dev/null || return 1
  elif have curl && [[ -n "$NOTIFY_SMTP_HOST" ]]; then
    # Use curl for SMTP
    curl -s --url "smtp://$NOTIFY_SMTP_HOST" \
      --mail-from "$NOTIFY_EMAIL_FROM" \
      --mail-rcpt "$NOTIFY_EMAIL_TO" \
      --upload-file - <<EOF 2>/dev/null || return 1
From: $NOTIFY_EMAIL_FROM
To: $NOTIFY_EMAIL_TO
Subject: $subject

$body
EOF
  else
    return 1
  fi
}

# Test notification
notify_test() {
  LOG blue "Testing notifications..."
  
  local channels=""
  [[ -n "$NOTIFY_WEBHOOK_URL" ]] && channels="$channels webhook"
  [[ -n "$NOTIFY_SLACK_WEBHOOK" ]] && channels="$channels slack"
  [[ -n "$NOTIFY_DISCORD_WEBHOOK" ]] && channels="$channels discord"
  [[ -n "$NOTIFY_TELEGRAM_BOT_TOKEN" ]] && channels="$channels telegram"
  [[ -n "$NOTIFY_EMAIL_TO" ]] && channels="$channels email"
  
  if [[ -z "$channels" ]]; then
    LOG red "No notification channels configured"
    LOG "Use 'Configure Channels' to set up notifications"
    return 1
  fi
  
  LOG "Configured channels:$channels"
  LOG ""
  
  notify_send "Test Alert" "This is a test notification from Red Team Toolkit" "normal"
  
  LOG green "Test notification sent!"
}

# Configure notification channels
notify_configure() {
  local choice
  choice=$(menu_pick "Configure Channel" \
    "slack:Slack Webhook" \
    "discord:Discord Webhook" \
    "telegram:Telegram Bot" \
    "webhook:Generic Webhook" \
    "email:Email (SMTP)")
  
  case "$choice" in
    slack)
      local url
      url=$(TEXT_PICKER "Slack Webhook URL" "$NOTIFY_SLACK_WEBHOOK") || return 1
      check_return_code || return 1
      export NOTIFY_SLACK_WEBHOOK="$url"
      LOG green "Slack webhook configured"
      ;;
    discord)
      local url
      url=$(TEXT_PICKER "Discord Webhook URL" "$NOTIFY_DISCORD_WEBHOOK") || return 1
      check_return_code || return 1
      export NOTIFY_DISCORD_WEBHOOK="$url"
      LOG green "Discord webhook configured"
      ;;
    telegram)
      local token
      token=$(TEXT_PICKER "Telegram Bot Token" "$NOTIFY_TELEGRAM_BOT_TOKEN") || return 1
      check_return_code || return 1
      local chat_id
      chat_id=$(TEXT_PICKER "Telegram Chat ID" "$NOTIFY_TELEGRAM_CHAT_ID") || return 1
      check_return_code || return 1
      export NOTIFY_TELEGRAM_BOT_TOKEN="$token"
      export NOTIFY_TELEGRAM_CHAT_ID="$chat_id"
      LOG green "Telegram configured"
      ;;
    webhook)
      local url
      url=$(TEXT_PICKER "Webhook URL" "$NOTIFY_WEBHOOK_URL") || return 1
      check_return_code || return 1
      export NOTIFY_WEBHOOK_URL="$url"
      LOG green "Generic webhook configured"
      ;;
    email)
      local email
      email=$(TEXT_PICKER "Email To" "$NOTIFY_EMAIL_TO") || return 1
      check_return_code || return 1
      local smtp
      smtp=$(TEXT_PICKER "SMTP Host" "$NOTIFY_SMTP_HOST") || return 1
      check_return_code || return 1
      export NOTIFY_EMAIL_TO="$email"
      export NOTIFY_SMTP_HOST="$smtp"
      LOG green "Email configured"
      ;;
  esac
  
  LOG ""
  LOG "Note: These settings are temporary"
  LOG "Add to config.sh for persistence"
}

# Send custom alert
notify_send_custom() {
  local title
  title=$(TEXT_PICKER "Alert Title" "Custom Alert") || return 1
  check_return_code || return 1
  
  local message
  message=$(TEXT_PICKER "Message" "") || return 1
  check_return_code || return 1
  
  local priority
  priority=$(menu_pick "Priority" \
    "low:Low" \
    "normal:Normal" \
    "high:High" \
    "critical:Critical")
  
  notify_send "$title" "$message" "$priority"
  
  LOG green "Alert sent!"
}

# Watch for events and notify
notify_watch() {
  LOG blue "Event Watcher"
  LOG "This will monitor for specific events and send notifications"
  LOG ""
  
  local watch_type
  watch_type=$(menu_pick "Watch For" \
    "handshake:New Handshake Captures" \
    "creds:New Credentials" \
    "host:New Host Discovered" \
    "file:File Changes")
  
  local duration
  duration=$(NUMBER_PICKER "Watch duration (seconds)" 300) || return 1
  check_return_code || return 1
  
  LOG "Watching for $watch_type events for ${duration}s..."
  LOG "Press any button to stop"
  
  local end_time=$(($(date +%s) + duration))
  
  case "$watch_type" in
    handshake)
      local last_count
      last_count=$(find "$ARTIFACT_DIR" -name "*handshake*" -o -name "*.hc22000" 2>/dev/null | wc -l)
      
      while [[ $(date +%s) -lt $end_time ]]; do
        local current_count
        current_count=$(find "$ARTIFACT_DIR" -name "*handshake*" -o -name "*.hc22000" 2>/dev/null | wc -l)
        
        if [[ "$current_count" -gt "$last_count" ]]; then
          local new_file
          new_file=$(find "$ARTIFACT_DIR" -name "*handshake*" -o -name "*.hc22000" -newer "$ARTIFACT_DIR/notifications.log" 2>/dev/null | head -1)
          notify_send "Handshake Captured" "New handshake: $new_file" "high"
          LOG green "[!] New handshake detected - notification sent"
          last_count=$current_count
        fi
        
        sleep 5
      done
      ;;
    creds)
      local last_count
      last_count=$(find "$ARTIFACT_DIR" -name "*cred*" -o -name "*hash*" 2>/dev/null | wc -l)
      
      while [[ $(date +%s) -lt $end_time ]]; do
        local current_count
        current_count=$(find "$ARTIFACT_DIR" -name "*cred*" -o -name "*hash*" 2>/dev/null | wc -l)
        
        if [[ "$current_count" -gt "$last_count" ]]; then
          notify_send "Credentials Captured" "New credential file detected" "critical"
          LOG green "[!] New credentials detected - notification sent"
          last_count=$current_count
        fi
        
        sleep 5
      done
      ;;
    host)
      local hosts_file="$ARTIFACT_DIR/known_hosts.txt"
      touch "$hosts_file"
      
      while [[ $(date +%s) -lt $end_time ]]; do
        # Quick ARP check
        local current_hosts
        current_hosts=$(arp -n 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]' || true)
        
        for host in $current_hosts; do
          if ! grep -q "^$host$" "$hosts_file"; then
            echo "$host" >> "$hosts_file"
            notify_send "New Host" "Discovered: $host" "normal"
            LOG green "[!] New host: $host - notification sent"
          fi
        done
        
        sleep 10
      done
      ;;
    file)
      local watch_dir="$ARTIFACT_DIR"
      local last_mod
      last_mod=$(find "$watch_dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1 || echo 0)
      
      while [[ $(date +%s) -lt $end_time ]]; do
        local current_mod
        current_mod=$(find "$watch_dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1 || echo 0)
        
        if [[ "$current_mod" != "$last_mod" ]]; then
          local new_file
          new_file=$(find "$watch_dir" -type f -newer "$ARTIFACT_DIR/notifications.log" 2>/dev/null | head -1)
          notify_send "File Changed" "New/modified: $(basename "$new_file")" "low"
          LOG "[!] File change detected"
          last_mod=$current_mod
        fi
        
        sleep 5
      done
      ;;
  esac
  
  LOG "Watch ended"
}

# View notification history
notify_history() {
  local log_file="$ARTIFACT_DIR/notifications.log"
  
  if [[ ! -f "$log_file" ]]; then
    LOG "No notifications sent yet"
    return 0
  fi
  
  LOG blue "=== Notification History ==="
  tail -30 "$log_file"
  LOG ""
  LOG "Total notifications: $(wc -l < "$log_file")"
}

# Convenience functions for use by other modules
notify_handshake() {
  local ssid="$1"
  local bssid="$2"
  notify_send "Handshake Captured" "SSID: $ssid\nBSSID: $bssid" "high"
}

notify_credential() {
  local type="$1"
  local target="$2"
  notify_send "Credential Captured" "Type: $type\nTarget: $target" "critical"
}

notify_discovery() {
  local host="$1"
  local info="${2:-}"
  notify_send "New Discovery" "Host: $host\n$info" "normal"
}

notify_attack_complete() {
  local attack="$1"
  local result="$2"
  notify_send "Attack Complete" "Attack: $attack\nResult: $result" "normal"
}
