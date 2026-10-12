#!/bin/bash

set -e

PROJECT="$HOME/CodeAlpha/BasicPhishingAwarenessTraining"
HTML="file://$PROJECT/index.html"
OUT="$PROJECT/screenshots"

mkdir -p "$OUT"

if command -v firefox >/dev/null 2>&1; then
    BROWSER="firefox"
elif command -v firefox-esr >/dev/null 2>&1; then
    BROWSER="firefox-esr"
else
    echo "Firefox not found."
    exit 1
fi

echo "[1/4] Capturing main training page..."

"$BROWSER" \
    --headless \
    --window-size 1440,900 \
    --screenshot "$OUT/01-training-module.png" \
    "$HTML"

sleep 2

echo "[2/4] Capturing phishing email example..."

"$BROWSER" \
    --headless \
    --window-size 1440,900 \
    --screenshot "$OUT/02-phishing-email-example.png" \
    "$HTML#email"

sleep 2

echo "[3/4] Capturing social engineering section..."

"$BROWSER" \
    --headless \
    --window-size 1440,900 \
    --screenshot "$OUT/03-social-engineering.png" \
    "$HTML#social"

sleep 2

echo "[4/4] Capturing interactive quiz..."

"$BROWSER" \
    --headless \
    --window-size 1440,900 \
    --screenshot "$OUT/04-interactive-quiz.png" \
    "$HTML#quiz"

echo
echo "========================================"
echo " ALL SCREENSHOTS CREATED"
echo "========================================"

ls -lh "$OUT"
