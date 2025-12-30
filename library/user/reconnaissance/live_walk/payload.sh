#!/bin/bash
# Title: live_walk
# Description: A live logging system for continuous Wi-Fi reconnaissance using airodump-ng.
# Author: MusicalVR

LOOTDIR="/root/loot/live_walk"
mkdir -p "$LOOTDIR"
IFACE="wlan1mon"
PREFIX="walk_$(date +%H%M)"

# 1. Force kill conflicting background processes
killall -9 airodump-ng > /dev/null 2>&1
killall -9 pineapd > /dev/null 2>&1
sleep 2

LOG "Discovery Started..."
cd "$LOOTDIR" || exit

# 2.Output set up
airodump-ng --output-format csv -w "$PREFIX" "$IFACE" > /dev/null 2>&1 &
PID=$!

# 3. The Persistence Loop
while kill -0 "$PID" 2>/dev/null; do
    LOG "Logging session... $(date +%H:%M)"
    sleep 60
done

# Cleanup
killall airodump-ng
LOG "Session archived to $LOOTDIR"
