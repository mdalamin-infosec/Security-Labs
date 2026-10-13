"""Measure triage and closure times from incident lifecycle records.

This module only computes what the records contain. It does not estimate or assume an
improvement: any before/after comparison is only as valid as the records and cohorts
the operator supplies (see docs/METRICS.md).

CSV columns: incident_id,cohort,detected_at,triaged_at,closed_at   (ISO 8601 timestamps)
"""

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean, median

REQUIRED = ("incident_id", "cohort", "detected_at", "triaged_at", "closed_at")


class MetricsError(ValueError):
    """Raised for malformed or inconsistent lifecycle records."""


@dataclass(frozen=True)
class Record:
    incident_id: str
    cohort: str
    triage_minutes: float
    close_minutes: float


def _when(value: str, row: int, column: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as error:
        raise MetricsError(f"row {row}: {column} is not an ISO 8601 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise MetricsError(f"row {row}: {column} needs a timezone offset (for example +00:00)")
    return parsed


def load_records(path: Path) -> list[Record]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
        if missing:
            raise MetricsError(f"missing columns: {', '.join(missing)}")
        records = []
        for row, item in enumerate(reader, 2):
            detected, triaged, closed = (_when(item[c], row, c) for c in ("detected_at", "triaged_at", "closed_at"))
            if not detected <= triaged <= closed:
                raise MetricsError(f"row {row}: timestamps must satisfy detected <= triaged <= closed")
            records.append(Record(item["incident_id"], item["cohort"].strip(),
                                  (triaged - detected).total_seconds() / 60, (closed - detected).total_seconds() / 60))
    if not records:
        raise MetricsError("no incident records found")
    return records


def summarize(records: list[Record]) -> dict[str, dict[str, float]]:
    cohorts: dict[str, list[Record]] = {}
    for record in records:
        cohorts.setdefault(record.cohort, []).append(record)
    return {
        name: {
            "incidents": len(items),
            "median_triage_min": round(median(r.triage_minutes for r in items), 2),
            "mean_triage_min": round(mean(r.triage_minutes for r in items), 2),
            "median_close_min": round(median(r.close_minutes for r in items), 2),
            "mean_close_min": round(mean(r.close_minutes for r in items), 2),
        }
        for name, items in sorted(cohorts.items())
    }


def compare(summary: dict[str, dict[str, float]], baseline: str, treatment: str) -> dict[str, float]:
    """Percent change of the treatment cohort versus baseline (negative means faster)."""
    for name in (baseline, treatment):
        if name not in summary:
            raise MetricsError(f"cohort {name!r} not found; available: {', '.join(summary)}")
    result = {}
    for metric in ("median_triage_min", "median_close_min"):
        before = summary[baseline][metric]
        if before == 0:
            raise MetricsError(f"baseline {metric} is zero; percent change is undefined")
        result[metric] = round((summary[treatment][metric] - before) / before * 100, 1)
    return result
