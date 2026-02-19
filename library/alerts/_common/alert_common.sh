#!/bin/bash

alert_common_have() {
  command -v "$1" >/dev/null 2>&1
}

alert_common_payload_name() {
  printf "%s" "alert_common"
}

alert_common_watchlist_payload_name() {
  printf "%s" "alert_watchlist"
}

alert_common_get_config() {
  local key="$1"
  local default_value="${2:-}"

  if alert_common_have PAYLOAD_GET_CONFIG; then
    local v
    v="$(PAYLOAD_GET_CONFIG "$(alert_common_payload_name)" "$key" 2>/dev/null || true)"
    if [[ -n "$v" ]]; then
      printf "%s" "$v"
      return 0
    fi
  fi

  printf "%s" "$default_value"
}

alert_common_set_config() {
  local key="$1"
  local value="$2"

  if ! alert_common_have PAYLOAD_SET_CONFIG; then
    return 1
  fi

  PAYLOAD_SET_CONFIG "$(alert_common_payload_name)" "$key" "$value" 2>/dev/null || true
}

alert_common_severity_rank() {
  local severity="${1:-}"

  case "$severity" in
    critical) printf "%s" 4 ;;
    high) printf "%s" 3 ;;
    medium) printf "%s" 2 ;;
    low) printf "%s" 1 ;;
    *) printf "%s" 0 ;;
  esac
}

alert_common_max_severity() {
  local a="${1:-}"
  local b="${2:-}"

  if [[ "$(alert_common_severity_rank "$a")" -ge "$(alert_common_severity_rank "$b")" ]]; then
    printf "%s" "$a"
  else
    printf "%s" "$b"
  fi
}

alert_common_severity_to_pattern() {
  local severity="${1:-}"

  case "$severity" in
    critical) printf "%s" "DOUBLE" ;;
    high) printf "%s" "FAST" ;;
    medium) printf "%s" "SINGLE" ;;
    low) printf "%s" "SLOW" ;;
    *) printf "%s" "SLOW" ;;
  esac
}

alert_common_category_to_color() {
  local category="${1:-}"

  case "$category" in
    deauth|deauth_flood_detected) printf "%s" "R" ;;
    handshake|handshake_captured) printf "%s" "G" ;;
    auth|pineapple_auth_captured) printf "%s" "M" ;;
    client|pineapple_client_connected) printf "%s" "C" ;;

    evil_twin|rogue_twin) printf "%s" "R" ;;
    probe|probes) printf "%s" "B" ;;
    hidden|hidden_ssid) printf "%s" "M" ;;
    anomaly|rf_anomaly) printf "%s" "R" ;;
    channel|interference) printf "%s" "B" ;;
    high_value|enterprise) printf "%s" "Y" ;;
    new_ap) printf "%s" "Y" ;;

    watchlist) printf "%s" "R" ;;
    *) printf "%s" "Y" ;;
  esac
}

alert_common_category_to_tone() {
  local category="${1:-}"

  case "$category" in
    deauth|deauth_flood_detected) printf "%s" "deauth:d=8,o=5,b=160:c,c,p,c,c" ;;
    handshake|handshake_captured) printf "%s" "shake:d=16,o=6,b=200:e,g,e,c" ;;
    auth|pineapple_auth_captured) printf "%s" "auth:d=8,o=6,b=140:g,e,c,e" ;;
    client|pineapple_client_connected) printf "%s" "client:d=16,o=6,b=180:c,e,g" ;;

    evil_twin|rogue_twin) printf "%s" "evil:d=16,o=5,b=140:c,e,g,c6,g,e,c" ;;
    probe|probes) printf "%s" "probe:d=16,o=6,b=200:c,p,c" ;;
    hidden|hidden_ssid) printf "%s" "hidden:d=16,o=5,b=100:e,d,c,d,e" ;;
    anomaly|rf_anomaly) printf "%s" "anom:d=8,o=5,b=170:c,p,c,p,c" ;;
    channel|interference) printf "%s" "chan:d=16,o=6,b=180:g,p,g" ;;
    high_value|enterprise) printf "%s" "value:d=8,o=6,b=120:c,p,e,p,g" ;;
    new_ap) printf "%s" "newap:d=16,o=5,b=160:g,a,b" ;;

    watchlist) printf "%s" "watch:d=8,o=6,b=200:g,p,g,p,e,p,c" ;;
    *) printf "%s" "notify" ;;
  esac
}

alert_common_watchlist_enabled() {
  local v
  v="$(alert_common_get_config "watchlist_enabled" "1")"
  [[ "$v" == "1" ]]
}

alert_common_severity_sound_enabled() {
  local severity="${1:-}"
  local key="sound_${severity}"
  local v

  v="$(alert_common_get_config "$key" "")"
  if [[ -n "$v" ]]; then
    [[ "$v" == "1" ]]
    return
  fi

  case "$severity" in
    critical|high) return 0 ;;
    *) return 1 ;;
  esac
}

alert_common_severity_vibrate_enabled() {
  local severity="${1:-}"
  local key="vibrate_${severity}"
  local v

  v="$(alert_common_get_config "$key" "")"
  if [[ -n "$v" ]]; then
    [[ "$v" == "1" ]]
    return
  fi

  case "$severity" in
    critical|high|medium) return 0 ;;
    *) return 1 ;;
  esac
}

alert_common_notify() {
  local severity="$1"
  local category="$2"
  local message="$3"

  local color pattern tone
  color="$(alert_common_category_to_color "$category")"
  pattern="$(alert_common_severity_to_pattern "$severity")"
  tone="$(alert_common_category_to_tone "$category")"

  if alert_common_have LED; then
    LED "$color" "$pattern" 2>/dev/null || true
  fi

  if alert_common_have RINGTONE && alert_common_severity_sound_enabled "$severity"; then
    if alert_common_severity_vibrate_enabled "$severity"; then
      RINGTONE --vibrate "$tone" 2>/dev/null &
    else
      RINGTONE "$tone" 2>/dev/null &
    fi
  elif alert_common_have VIBRATE && alert_common_severity_vibrate_enabled "$severity"; then
    VIBRATE 200 2>/dev/null || true
  fi

  if alert_common_have ALERT; then
    ALERT "$message" 2>/dev/null || true
  fi

  if alert_common_have LED; then
    LED OFF 2>/dev/null || true
  fi
}

alert_common_normalize_mac() {
  local mac="$1"
  printf "%s" "$mac" | tr '[:lower:]' '[:upper:]' | tr -d ' ' | tr -d '\n' | sed 's/[^0-9A-F:]//g'
}



alert_common_watchlist_count() {
  if ! alert_common_have PAYLOAD_GET_CONFIG; then
    printf "%s" "0"
    return 0
  fi

  local v
  v="$(PAYLOAD_GET_CONFIG "$(alert_common_watchlist_payload_name)" "count" 2>/dev/null || true)"
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    printf "%s" "$v"
  else
    printf "%s" "0"
  fi
}

alert_common_watchlist_get_entry() {
  local idx="$1"

  if ! alert_common_have PAYLOAD_GET_CONFIG; then
    return 1
  fi

  PAYLOAD_GET_CONFIG "$(alert_common_watchlist_payload_name)" "entry_${idx}" 2>/dev/null || true
}

alert_common_watchlist_add() {
  local entry_type="$1"
  local entry_value="$2"
  local entry_label="${3:-}"
  local entry_severity="${4:-high}"

  if ! alert_common_have PAYLOAD_SET_CONFIG || ! alert_common_have PAYLOAD_GET_CONFIG; then
    return 1
  fi

  if [[ "$entry_type" != "mac" && "$entry_type" != "ssid" ]]; then
    return 1
  fi

  if [[ "$entry_type" == "mac" ]]; then
    entry_value="$(alert_common_normalize_mac "$entry_value")"
  fi

  if [[ -z "$entry_value" ]]; then
    return 1
  fi

  local count next
  count="$(alert_common_watchlist_count)"
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi

  next=$((count + 1))

  PAYLOAD_SET_CONFIG "$(alert_common_watchlist_payload_name)" "entry_${next}" "${entry_type}|${entry_value}|${entry_label}|${entry_severity}" 2>/dev/null || true
  PAYLOAD_SET_CONFIG "$(alert_common_watchlist_payload_name)" "count" "$next" 2>/dev/null || true
}

alert_common_watchlist_remove() {
  local idx="$1"

  if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  if ! alert_common_have PAYLOAD_SET_CONFIG || ! alert_common_have PAYLOAD_GET_CONFIG || ! alert_common_have PAYLOAD_DEL_CONFIG; then
    return 1
  fi

  local count
  count="$(alert_common_watchlist_count)"
  if ! [[ "$count" =~ ^[0-9]+$ ]] || [[ "$count" -lt 1 ]] || [[ "$idx" -lt 1 ]] || [[ "$idx" -gt "$count" ]]; then
    return 1
  fi

  local i
  for i in $(seq "$idx" "$((count - 1))"); do
    local next_entry
    next_entry="$(alert_common_watchlist_get_entry "$((i + 1))")"
    PAYLOAD_SET_CONFIG "$(alert_common_watchlist_payload_name)" "entry_${i}" "$next_entry" 2>/dev/null || true
  done

  PAYLOAD_DEL_CONFIG "$(alert_common_watchlist_payload_name)" "entry_${count}" 2>/dev/null || true

  if [[ "$count" -eq 1 ]]; then
    PAYLOAD_DEL_CONFIG "$(alert_common_watchlist_payload_name)" "count" 2>/dev/null || true
  else
    PAYLOAD_SET_CONFIG "$(alert_common_watchlist_payload_name)" "count" "$((count - 1))" 2>/dev/null || true
  fi
}

alert_common_watchlist_match() {
  local match_type="$1"
  local match_value="$2"

  if ! alert_common_watchlist_enabled; then
    return 1
  fi

  local count
  count="$(alert_common_watchlist_count)"
  if [[ "$count" -lt 1 ]]; then
    return 1
  fi

  local norm_value=""
  if [[ "$match_type" == "mac" ]]; then
    norm_value="$(alert_common_normalize_mac "$match_value")"
  fi

  local i
  for i in $(seq 1 "$count"); do
    local entry
    entry="$(alert_common_watchlist_get_entry "$i")"
    [[ -z "$entry" ]] && continue

    local entry_type entry_value entry_label entry_sev
    IFS='|' read -r entry_type entry_value entry_label entry_sev <<< "$entry"

    if [[ "$match_type" == "ssid" && "$entry_type" == "ssid" ]]; then
      if [[ -n "$entry_value" && "$match_value" == *"$entry_value"* ]]; then
        printf "%s|%s" "${entry_sev:-high}" "${entry_label:-watchlist ssid}"
        return 0
      fi
    fi

    if [[ "$match_type" == "mac" && "$entry_type" == "mac" ]]; then
      local norm_entry
      norm_entry="$(alert_common_normalize_mac "${entry_value:-}")"
      if [[ -n "$norm_entry" && "$norm_value" == "$norm_entry" ]]; then
        printf "%s|%s" "${entry_sev:-high}" "${entry_label:-watchlist mac}"
        return 0
      fi
    fi
  done

  return 1
}
