#!/usr/bin/env bash
# Replay the synthetic pcap through Suricata with only the local rules and check that
# each of the 8 signatures fired and the benign DNS control did not.
# Requires: suricata, python3 with scapy.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# Retain real PCAP/config/EVE/log evidence; never merge with a previous run.
mkdir -p "$ROOT/outputs"
if [[ $# -gt 0 ]]; then
  [[ ! -e "$1" ]] || { echo "Choose a new output directory: $1" >&2; exit 2; }
  mkdir -p "$1"
  WORK="$(cd "$1" && pwd)"
else
  WORK="$(mktemp -d "$ROOT/outputs/replay.XXXXXX")"
fi
echo "Replay evidence: $WORK"
suricata --build-info > "$WORK/engine-version.txt"

python3 "$ROOT/tests/pcap/make_pcap.py" "$WORK/lab.pcap"
cat > "$WORK/suricata.yaml" <<YAML
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
default-rule-path: $ROOT/src/threatwatch/data
rule-files:
  - local.rules
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
app-layer:
  protocols:
    http: {enabled: yes}
    dns: {enabled: yes}
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
YAML
suricata -c "$WORK/suricata.yaml" -r "$WORK/lab.pcap" -l "$WORK" -k none --runmode single >"$WORK/suricata.log" 2>&1 || { cat "$WORK/suricata.log"; exit 1; }

status=0
for sid in 9000001 9000002 9000003 9000004 9000005 9000006 9000007 9000008; do
  count=$(grep -c "\"signature_id\":$sid" "$WORK/eve.json" || true)
  if [[ "$count" -ge 1 ]]; then echo "PASS sid $sid fired ($count alert)"; else echo "FAIL sid $sid did not fire"; status=1; fi
done
benign=$(grep -c '"src_ip":"192.168.56.21"' "$WORK/eve.json" || true)
if [[ "$benign" -eq 0 ]]; then echo "PASS benign DNS control produced no alert"; else echo "FAIL benign control alerted"; status=1; fi
exit $status
