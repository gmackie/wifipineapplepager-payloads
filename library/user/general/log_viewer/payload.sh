#!/bin/bash
# Title: Pocket Viewer v15 (MAC Update)

# --- CONFIG ---
DIR_PAYLOADS="/root/payloads/user"
DIR_LOOT="/root/loot"

# --- 1. ROOT SOURCE SELECTION ---
PROMPT "LOG VIEWER

Select Source:
1. Payloads (Scripts)
2. Loot (Captured Data)

Press OK."

SOURCE_ID=$(NUMBER_PICKER "Select Source ID" 1)

if [ "$SOURCE_ID" -eq 1 ]; then
    # --- BRANCH A: PAYLOADS ---
    PROMPT "SELECT CATEGORY:
1. examples
2. exfiltration
3. general
4. incident_resp
5. interception
6. prank
7. reconnaissance
8. remote_access

Press OK."

    CAT_ID=$(NUMBER_PICKER "Select Category ID" 1)
    
    case "$CAT_ID" in
        1) CAT_DIR="examples" ;;
        2) CAT_DIR="exfiltration" ;;
        3) CAT_DIR="general" ;;
        4) CAT_DIR="incident_response" ;;
        5) CAT_DIR="interception" ;;
        6) CAT_DIR="prank" ;;
        7) CAT_DIR="reconnaissance" ;;
        8) CAT_DIR="remote_access" ;;
        *) exit 1 ;;
    esac

    TARGET_PATH="$DIR_PAYLOADS/$CAT_DIR"
    
elif [ "$SOURCE_ID" -eq 2 ]; then
    # --- BRANCH B: LOOT ---
    TARGET_PATH="$DIR_LOOT"
else
    PROMPT "Invalid Source."
    exit 1
fi

if [ ! -d "$TARGET_PATH" ]; then
    PROMPT "ERROR: Dir not found."
    exit 1
fi
cd "$TARGET_PATH"

# --- 2. SUB-FOLDER SELECTION ---
SUB_DIRS=$(ls -d */ 2>/dev/null)
if [ -z "$SUB_DIRS" ]; then
    PROMPT "EMPTY FOLDER
    
No sub-folders found
in target."
    exit 1
fi

count=1
LIST_STR=""
for d in $SUB_DIRS; do
    clean_name=$(echo "$d" | sed 's|/$||')
    LIST_STR="$LIST_STR $count:$clean_name"
    count=$((count + 1))
done

PROMPT "SELECT FOLDER:

$LIST_STR

Press OK."

DIR_ID=$(NUMBER_PICKER "Enter Folder ID:" 1)

CURRENT_COUNT=1
TARGET_SUB=""
for d in $SUB_DIRS; do
    if [ "$CURRENT_COUNT" -eq "$DIR_ID" ]; then
        TARGET_SUB="$d"
        break
    fi
    CURRENT_COUNT=$((CURRENT_COUNT + 1))
done

if [ -z "$TARGET_SUB" ]; then exit 1; fi
cd "$TARGET_SUB"

# --- 3. FILE SELECTION ---
FILES=$(ls *.txt *.log *.nmap *.gnmap *.xml 2>/dev/null)

if [ -z "$FILES" ]; then
    PROMPT "NO FILES
    
No logs/scans found."
    exit 1
fi

count=1
LIST_STR=""
for f in $FILES; do
    LIST_STR="$LIST_STR $count:$f"
    count=$((count + 1))
done

PROMPT "SELECT FILE:

$LIST_STR

Press OK."

FILE_ID=$(NUMBER_PICKER "Enter File ID:" 1)

CURRENT_COUNT=1
TARGET_FILE=""
for f in $FILES; do
    if [ "$CURRENT_COUNT" -eq "$FILE_ID" ]; then
        TARGET_FILE="$f"
        break
    fi
    CURRENT_COUNT=$((CURRENT_COUNT + 1))
done

if [ -z "$TARGET_FILE" ]; then exit 1; fi

# --- 4. VIEW MODE SELECTION ---
PROMPT "VIEW MODE

1. Raw Log (Standard)
2. Parsed Log (Color)

Press OK."

MODE_ID=$(NUMBER_PICKER "Select Mode" 1)

PROMPT "LOADING LOG...
$TARGET_FILE

Press OK to Generate."

LOG blue "=== FILE: $TARGET_FILE ==="

# --- 5. GENERATION ENGINE ---

if [ "$MODE_ID" -eq 1 ]; then
    # === RAW MODE ===
    while IFS= read -r line; do
        LOG "$line"
    done < "$TARGET_FILE"

elif [ "$MODE_ID" -eq 2 ]; then
    # === PARSED MODE (DECONSTRUCTOR) ===
    while IFS= read -r line; do
        if [ -z "$line" ]; then continue; fi

        # A. TIMESTAMP (Yellow)
        TS=$(echo "$line" | grep -oE "[0-9]{2}:[0-9]{2}:[0-9]{2}")
        if [ -n "$TS" ]; then
            LOG yellow "TIME: $TS"
        fi

        # B. STATUS (Green/Red)
        if echo "$line" | grep -qiE "error|down|closed|fail|refused|denied|critical"; then
            LOG red "STATUS: FAILURE"
        elif echo "$line" | grep -qiE "open|up|success|connected|established|200 OK"; then
            LOG green "STATUS: SUCCESS"
        fi

        # C. ADDRESS (Blue) - IP or MAC
        # Check for IP
        IP=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
        # Check for MAC (XX:XX:XX:XX:XX:XX)
        MAC=$(echo "$line" | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
        
        if [ -n "$IP" ]; then
            LOG blue "ADDR: $IP"
        fi
        if [ -n "$MAC" ]; then
            LOG blue "ADDR: $MAC"
        fi

        # D. INFO (White)
        CLEAN_MSG="$line"
        if [ -n "$TS" ]; then CLEAN_MSG=$(echo "$CLEAN_MSG" | sed "s/$TS//g"); fi
        if [ -n "$IP" ]; then CLEAN_MSG=$(echo "$CLEAN_MSG" | sed "s/$IP//g"); fi
        if [ -n "$MAC" ]; then CLEAN_MSG=$(echo "$CLEAN_MSG" | sed "s/$MAC//g"); fi
        
        # Trim whitespace
        CLEAN_MSG=$(echo "$CLEAN_MSG" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        
        if [ -n "$CLEAN_MSG" ]; then
            LOG "INFO: $CLEAN_MSG"
        fi

        LOG "---"

    done < "$TARGET_FILE"
else
    LOG red "INVALID MODE SELECTED"
fi

LOG blue "=== END OF FILE ==="

exit 0