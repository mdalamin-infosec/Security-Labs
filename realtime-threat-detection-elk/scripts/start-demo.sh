#!/usr/bin/env bash
# Offline demo: no Docker, Suricata or internet needed.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m threatwatch demo
