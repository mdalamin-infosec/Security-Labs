#!/bin/bash

ALERT_LOG="/var/log/suricata/fast.log"

echo "========================================"
echo " CodeAlpha Suricata Live Alert Monitor"
echo "========================================"
echo
echo "Monitoring:"
echo "$ALERT_LOG"
echo
echo "Press CTRL+C to stop."
echo

sudo tail -Fn0 "$ALERT_LOG" | while read -r line
do
    if echo "$line" | grep -q "CODEALPHA"; then
        echo
        echo "----------------------------------------"
        echo "ALERT DETECTED"
        echo "----------------------------------------"
        echo "$line"
        echo "----------------------------------------"
    fi
done
