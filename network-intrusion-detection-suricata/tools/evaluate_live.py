#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

if len(sys.argv) != 4:
    print("Usage: evaluate_live.py eve.json ground_truth.csv output.json",
          file=sys.stderr)
    raise SystemExit(2)

eve_path = Path(sys.argv[1])
gt_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])

alerts = []
malformed = 0

with eve_path.open(encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue

        if event.get("event_type") == "alert":
            alerts.append(event)

with gt_path.open(newline="", encoding="utf-8") as fh:
    ground_truth = list(csv.DictReader(fh))

attacks = [
    row for row in ground_truth
    if row.get("label", "").strip().lower() == "attack"
]

if not attacks:
    print("ERROR: no attack cases in ground truth", file=sys.stderr)
    raise SystemExit(2)

alert_sids = {
    int(event["alert"]["signature_id"])
    for event in alerts
    if event.get("alert", {}).get("signature_id") is not None
}

detected = []
missed = []

for row in attacks:
    case_id = row["case_id"]
    sid = int(row["expected_sid"])

    record = {
        "case_id": case_id,
        "expected_sid": sid
    }

    if sid in alert_sids:
        detected.append(record)
    else:
        missed.append(record)

total = len(attacks)
tp = len(detected)
fn = len(missed)

rate = (tp / total) * 100.0

source_ips = sorted({
    event.get("src_ip")
    for event in alerts
    if event.get("src_ip")
})

destination_ips = sorted({
    event.get("dest_ip")
    for event in alerts
    if event.get("dest_ip")
})

metrics = {
    "source": "owner-run live VM-to-VM Suricata lab session",
    "evidence_type": "live isolated lab traffic",
    "ground_truth_attack_cases": total,
    "detected_attack_cases": tp,
    "missed_attack_cases": fn,
    "TP": tp,
    "FN": fn,
    "detection_rate_percent": round(rate, 2),
    "alert_events": len(alerts),
    "observed_signature_ids": sorted(alert_sids),
    "source_ips": source_ips,
    "destination_ips": destination_ips,
    "detected_cases": detected,
    "missed_cases": missed,
    "malformed_eve_lines": malformed,
    "false_positive_rate": None,
    "false_positive_note":
        "Not measured: this ground-truth cohort contains attack cases only."
}

out_path.parent.mkdir(parents=True, exist_ok=True)

out_path.write_text(
    json.dumps(metrics, indent=2) + "\n",
    encoding="utf-8"
)

missed_names = ",".join(x["case_id"] for x in missed) or "none"

print(
    f"{tp}/{total} live attack cases detected; "
    f"detection rate={rate:.1f}%; "
    f"TP={tp}; FN={fn}; missed={missed_names}"
)
