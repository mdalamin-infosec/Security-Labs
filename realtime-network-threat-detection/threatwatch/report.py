"""Render incidents and beacon leads as plain text, JSON, or Markdown."""

import json
from .beacon import Beacon
from .triage import Incident


def to_json(incidents: list[Incident], beacons: list[Beacon], skipped: int = 0) -> str:
    payload = {"summary": _summary(incidents, beacons, skipped), "incidents": [i.to_dict() for i in incidents],
               "beacon_leads": [b.to_dict() for b in beacons]}
    return json.dumps(payload, indent=2) + "\n"


def _summary(incidents: list[Incident], beacons: list[Beacon], skipped: int) -> dict:
    counts = {p: sum(1 for i in incidents if i.priority == p) for p in ("P1", "P2", "P3", "P4")}
    return {"incidents": len(incidents), "alerts": sum(i.alert_count for i in incidents), "priorities": counts,
            "beacon_leads": len(beacons), "skipped_lines": skipped}


def to_text(incidents: list[Incident], beacons: list[Beacon], skipped: int = 0) -> str:
    info = _summary(incidents, beacons, skipped)
    lines = [f"{info['incidents']} incident(s) from {info['alerts']} alert(s) | " +
             " ".join(f"{p}:{n}" for p, n in info["priorities"].items()) +
             f" | {info['beacon_leads']} beacon lead(s) | {skipped} malformed line(s) skipped", ""]
    for i in sorted(incidents, key=lambda x: (-x.score, x.first_seen)):
        lines.append(f"{i.id} {i.priority} score={i.score} src={i.src_ip} alerts={i.alert_count} targets={','.join(sorted(i.targets))}")
        lines.append(f"    {i.first_seen:%H:%M:%S}-{i.last_seen:%H:%M:%S}Z tactics={','.join(i.tactics) or 'unmapped'} playbook={','.join(i.playbooks) or 'n/a'}")
        lines.extend(f"    * {reason}" for reason in i.reasons)
    for b in beacons:
        lines.append(f"BEACON {b.confidence}: {b.src_ip} -> {b.dest_ip}:{b.dest_port} {b.connections} conns, every ~{b.mean_interval_s:.0f}s (cv={b.jitter_cv:.3f})")
    return "\n".join(lines) + "\n"


def to_markdown(incidents: list[Incident], beacons: list[Beacon], skipped: int = 0) -> str:
    info = _summary(incidents, beacons, skipped)
    out = ["# Incident triage report", "",
           f"{info['incidents']} incident(s) from {info['alerts']} alert(s). Priorities: " +
           ", ".join(f"{p} {n}" for p, n in info["priorities"].items()) + ".", "",
           "| ID | Priority | Score | Source | Targets | Tactics | Playbook | Alerts |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i in sorted(incidents, key=lambda x: (-x.score, x.first_seen)):
        out.append(f"| {i.id} | {i.priority} | {i.score} | {i.src_ip} | {', '.join(sorted(i.targets))} | {', '.join(i.tactics) or 'unmapped'} "
                   f"| {', '.join(i.playbooks) or 'n/a'} | {i.alert_count} |")
    for i in incidents:
        if i.reasons:
            out += ["", f"**{i.id} escalation notes**", *[f"- {r}" for r in i.reasons]]
    out += ["", "## Beacon leads", ""]
    if beacons:
        out += ["| Source | Destination | Connections | Mean interval (s) | Jitter (cv) | Confidence |", "| --- | --- | --- | --- | --- | --- |"]
        out += [f"| {b.src_ip} | {b.dest_ip}:{b.dest_port} | {b.connections} | {b.mean_interval_s:.1f} | {b.jitter_cv:.3f} | {b.confidence} |" for b in beacons]
        out += ["", "Periodic traffic is a lead, not a verdict. Confirm the process and destination before escalating."]
    else:
        out.append("None above the configured thresholds.")
    return "\n".join(out) + "\n"
