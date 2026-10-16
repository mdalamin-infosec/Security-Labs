"""Group alerts into incidents per source and score them with a transparent, documented formula.

Score = 10 x highest rule severity weight (low 1, medium 2, high 3)
      + 5 per additional ATT&CK tactic seen from the same source (max 15)
      + volume bonus (5+ alerts: 2, 20+: 4, 100+: 6)
Priority: P1 >= 35, P2 >= 25, P3 >= 15, otherwise P4.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from .eve import Alert
from .rules import SEVERITY_WEIGHT, Rule

# Suricata alert.severity 1 is most severe; used only when a SID is not in the local catalogue.
_SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low"}
_RECON = {"reconnaissance", "discovery"}
_ACCESS = {"initial-access", "credential-access"}


@dataclass
class Incident:
    id: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int = 0
    signatures: dict[int, str] = field(default_factory=dict)
    sid_counts: dict[int, int] = field(default_factory=dict)
    targets: set[str] = field(default_factory=set)
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    playbooks: list[str] = field(default_factory=list)
    unmapped_sids: list[int] = field(default_factory=list)
    score: int = 0
    priority: str = "P4"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "src_ip": self.src_ip, "priority": self.priority, "score": self.score,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "alert_count": self.alert_count, "targets": sorted(self.targets),
            "signatures": {str(s): {"msg": self.signatures[s], "count": self.sid_counts[s]} for s in self.signatures},
            "tactics": self.tactics, "techniques": self.techniques, "playbooks": self.playbooks,
            "unmapped_sids": self.unmapped_sids, "reasons": self.reasons,
        }


def priority_for(score: int) -> str:
    if score >= 35:
        return "P1"
    if score >= 25:
        return "P2"
    if score >= 15:
        return "P3"
    return "P4"


def _volume_bonus(count: int) -> int:
    return 6 if count >= 100 else 4 if count >= 20 else 2 if count >= 5 else 0


def _severity_name(alert: Alert, rule: Rule | None) -> str:
    return rule.severity if rule else _SURICATA_SEVERITY.get(alert.severity, "low")


def _score(incident: Incident, group: list[Alert], catalogue: dict[int, Rule]) -> None:
    weights, first_by_tactic = [], {}
    for alert in group:
        rule = catalogue.get(alert.sid)
        weights.append(SEVERITY_WEIGHT[_severity_name(alert, rule)])
        if rule is None:
            if alert.sid not in incident.unmapped_sids:
                incident.unmapped_sids.append(alert.sid)
            continue
        first_by_tactic.setdefault(rule.tactic, alert.time)
        for items, value in ((incident.tactics, rule.tactic), (incident.techniques, rule.technique), (incident.playbooks, rule.playbook)):
            if value not in items:
                items.append(value)
    extra_tactics = min(max(len(incident.tactics) - 1, 0), 3)
    incident.score = 10 * max(weights) + 5 * extra_tactics + _volume_bonus(len(group))
    incident.priority = priority_for(incident.score)
    if extra_tactics:
        incident.reasons.append(f"{len(incident.tactics)} ATT&CK tactics observed from one source")
    recon = [t for tac, t in first_by_tactic.items() if tac in _RECON]
    access = [t for tac, t in first_by_tactic.items() if tac in _ACCESS]
    if recon and access and min(recon) < max(access):
        incident.reasons.append("Reconnaissance followed by an access attempt from the same source")
    if incident.unmapped_sids:
        incident.reasons.append("Contains alerts outside the local rule catalogue; severity taken from Suricata")


def build_incidents(alerts: list[Alert], catalogue: dict[int, Rule], gap_minutes: int = 15) -> list[Incident]:
    """Alerts from one source stay in one incident until a quiet gap longer than gap_minutes."""
    gap = timedelta(minutes=gap_minutes)
    by_source: dict[str, list[list[Alert]]] = {}
    for alert in sorted(alerts, key=lambda a: a.time):
        groups = by_source.setdefault(alert.src_ip, [])
        if groups and alert.time - groups[-1][-1].time <= gap:
            groups[-1].append(alert)
        else:
            groups.append([alert])
    built = []
    for source, groups in by_source.items():
        for group in groups:
            incident = Incident("", source, group[0].time, group[-1].time, alert_count=len(group))
            for alert in group:
                incident.signatures.setdefault(alert.sid, alert.signature)
                incident.sid_counts[alert.sid] = incident.sid_counts.get(alert.sid, 0) + 1
                incident.targets.add(alert.dest_ip)
            _score(incident, group, catalogue)
            built.append(incident)
    built.sort(key=lambda i: (i.first_seen, i.src_ip))
    for number, incident in enumerate(built, 1):
        incident.id = f"INC-{number:04d}"
    return built
