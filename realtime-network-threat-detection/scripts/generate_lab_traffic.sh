#!/usr/bin/env bash
# Generate a small amount of detectable traffic against YOUR OWN lab target to exercise the rules.
# Usage: TARGET=192.168.56.10 I_OWN_THIS_LAB=yes scripts/generate_lab_traffic.sh
# Refuses non-private targets. Do not point this at systems you do not own or administer.
set -euo pipefail

TARGET="${TARGET:-}"
if [[ "${I_OWN_THIS_LAB:-}" != "yes" || -z "$TARGET" ]]; then
  echo "Set TARGET=<lab ip> and I_OWN_THIS_LAB=yes to confirm you are authorised to test it." >&2
  exit 1
fi
if ! [[ "$TARGET" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.) ]]; then
  echo "Refusing: $TARGET is not a private or loopback IPv4 address." >&2
  exit 1
fi

echo "[1/4] ICMP burst (sid 9000003)";             ping -c 15 -i 0.2 "$TARGET" >/dev/null || true
echo "[2/4] TCP SYN burst (sid 9000002)";          nmap -sT -p 1-200 -T4 "$TARGET" >/dev/null
echo "[3/4] Repeated SSH connections (sid 9000001)"
for _ in $(seq 1 8); do timeout 2 bash -c "exec 3<>/dev/tcp/$TARGET/22" 2>/dev/null || true; done
echo "[4/4] Scanner user-agent (sid 9000004)";     curl -s -o /dev/null -m 5 -A "sqlmap/1.7" "http://$TARGET/" || true
echo "Done. Allow a few seconds, then check Kibana Discover (event_type : \"alert\")."
