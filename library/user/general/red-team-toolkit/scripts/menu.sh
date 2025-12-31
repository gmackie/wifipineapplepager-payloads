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
