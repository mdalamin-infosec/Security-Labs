#!/bin/bash

# CodeAlpha Task 4
# Suricata IDS Response Mechanism
# Lab use only

ALERT_LOG="/var/log/suricata/fast.log"
RESPONSE_LOG="$HOME/suricata_response.log"

echo "========================================"
echo " CodeAlpha Suricata Response Mechanism"
echo "========================================"
echo

LATEST_ATTACKER=$(
    sudo grep "CODEALPHA Possible SYN Scan" "$ALERT_LOG" \
    | tail -n 1 \
    | grep -oP '\{TCP\} \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    | head -n 1
)

if [ -z "$LATEST_ATTACKER" ]; then
    echo "No SYN scan alert found."
    exit 0
fi

echo "Detected suspicious source IP:"
echo "$LATEST_ATTACKER"

echo
echo "$(date) - Suspicious source detected: $LATEST_ATTACKER" \
    >> "$RESPONSE_LOG"

# Safety check:
# Never block localhost or the IDS server itself.
if [ "$LATEST_ATTACKER" = "127.0.0.1" ] || \
   [ "$LATEST_ATTACKER" = "192.168.56.102" ]; then

    echo "Protected IP detected. Blocking skipped."
    exit 0
fi

echo
echo "Response options:"
echo "1. Log only"
echo "2. Block source IP using UFW"
echo

read -p "Select response [1/2]: " OPTION

case "$OPTION" in

    1)
        echo "Alert logged only."
        echo "$(date) - Action: LOG ONLY - $LATEST_ATTACKER" \
            >> "$RESPONSE_LOG"
        ;;

    2)
        echo
        echo "Blocking $LATEST_ATTACKER using UFW..."

        sudo ufw deny from "$LATEST_ATTACKER"

        echo "$(date) - Action: BLOCKED - $LATEST_ATTACKER" \
            >> "$RESPONSE_LOG"

        echo
        echo "Blocked successfully."
        ;;

    *)
        echo "Invalid option. No blocking performed."
        ;;

esac

echo
echo "Response log:"
echo "$RESPONSE_LOG"
