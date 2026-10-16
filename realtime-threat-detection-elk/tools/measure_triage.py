#!/usr/bin/env python3

import argparse
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TW = ROOT / "realtime-threat-detection-elk"

OUTDIR = TW / "outputs" / "lifecycle"
EVIDENCE = OUTDIR / "evidence"
CSV_FILE = OUTDIR / "owner-lifecycle-records.csv"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def find_latest_demo():
    candidates = sorted(
        ROOT.glob(
            "outputs/all-results/*/"
            "threatwatch-demo-report/demo-incidents.json"
        ),
        key=lambda p: p.stat().st_mtime
    )

    if not candidates:
        raise SystemExit(
            "ERROR: no threatwatch demo-incidents.json found. "
            "Run ./run_all_security_results.sh first."
        )

    return candidates[-1]


def find_incidents(obj):
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            return obj

        for item in obj:
            result = find_incidents(item)
            if result:
                return result

    if isinstance(obj, dict):
        for key in ("incidents", "cases", "results"):
            value = obj.get(key)
            if isinstance(value, list) and value:
                if all(isinstance(x, dict) for x in value):
                    return value

        for value in obj.values():
            result = find_incidents(value)
            if result:
                return result

    return None


def incident_id(item, index):
    for key in ("incident_id", "id", "case_id"):
        value = item.get(key)
        if value:
            return str(value)

    return f"CASE-{index:02d}"


def existing_cohorts():
    if not CSV_FILE.exists():
        return set()

    with CSV_FILE.open(newline="", encoding="utf-8") as f:
        return {
            row["cohort"]
            for row in csv.DictReader(f)
            if row.get("cohort")
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cohort",
        required=True,
        choices=["before-playbook", "with-playbook"]
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5
    )

    args = parser.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)

    if args.cohort in existing_cohorts():
        raise SystemExit(
            f"ERROR: cohort {args.cohort!r} already exists in {CSV_FILE}"
        )

    report = find_latest_demo()

    data = json.loads(report.read_text(encoding="utf-8"))
    incidents = find_incidents(data)

    if not incidents:
        raise SystemExit(
            f"ERROR: could not locate incidents in {report}"
        )

    incidents = incidents[:args.limit]

    retained = EVIDENCE / "measurement-source-demo-incidents.json"

    if not retained.exists():
        shutil.copy2(report, retained)

    new_file = not CSV_FILE.exists()

    print()
    print("=" * 70)
    print("THREATWATCH CONTROLLED TRIAGE MEASUREMENT")
    print("=" * 70)
    print("Cohort :", args.cohort)
    print("Cases  :", len(incidents))
    print("Source :", report)
    print()
    print("For every case:")
    print("  1. Review the displayed incident.")
    print("  2. When you FIRST classify it, press Enter.")
    print("  3. Continue the investigation.")
    print("  4. When you consider the case closed, press Enter.")
    print()
    input("Press Enter when you are ready to begin...")

    rows = []

    for index, item in enumerate(incidents, 1):
        iid = incident_id(item, index)

        print()
        print("=" * 70)
        print(f"CASE {index}/{len(incidents)} — {iid}")
        print("=" * 70)

        print(json.dumps(item, indent=2, ensure_ascii=False))

        print()
        print("Incident is now presented/detected for this replay.")

        detected = now()

        input(
            "\nInvestigate now. "
            "Press Enter immediately when you have FIRST classified it..."
        )
        triaged = now()

        input(
            "Continue investigation. "
            "Press Enter when you consider the incident CLOSED..."
        )
        closed = now()

        rows.append({
            "incident_id": f"{iid}-{args.cohort}",
            "cohort": args.cohort,
            "detected_at": detected,
            "triaged_at": triaged,
            "closed_at": closed,
        })

        print("Recorded.")

    with CSV_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "incident_id",
                "cohort",
                "detected_at",
                "triaged_at",
                "closed_at",
            ]
        )

        if new_file:
            writer.writeheader()

        writer.writerows(rows)

    print()
    print("=" * 70)
    print("COHORT COMPLETE")
    print("=" * 70)
    print("Saved:", CSV_FILE)


if __name__ == "__main__":
    main()
