"""Deterministic synthetic EVE events for the offline demo and tests.

Every record is tagged ``synthetic-demo``. Addresses are lab-private or RFC 5737
documentation ranges. The scenarios illustrate the pipeline; they are not measurements
of any real network.
"""

from datetime import datetime, timedelta, timezone
import json
import random
from pathlib import Path
from .rules import Rule, load_catalogue

START = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)
SERVER, ATTACKER, SCANNER, WORKSTATION, LEGACY = "192.168.56.10", "192.168.56.66", "192.168.56.77", "192.168.56.20", "192.168.56.31"
C2 = "203.0.113.50"
_CATEGORY = {"credential-access": "Attempted Administrator Privilege Gain", "discovery": "Attempted Information Leak",
             "reconnaissance": "Web Application Attack", "initial-access": "Web Application Attack",
             "command-and-control": "Potentially Bad Traffic", "lateral-movement": "Potential Corporate Privacy Violation"}
_SEVERITY = {"high": 1, "medium": 2, "low": 3}


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def _base(moment: datetime, kind: str, src: str, dest: str, port: int, proto: str, flow_id: int) -> dict:
    return {"timestamp": _stamp(moment), "flow_id": flow_id, "event_type": kind, "src_ip": src, "src_port": 40000 + flow_id % 20000,
            "dest_ip": dest, "dest_port": port, "proto": proto, "tags": ["synthetic-demo"]}


def _alert(moment: datetime, rule: Rule, src: str, dest: str, port: int, proto: str, flow_id: int) -> dict:
    event = _base(moment, "alert", src, dest, port, proto, flow_id)
    event["alert"] = {"action": "allowed", "gid": 1, "signature_id": rule.sid, "rev": 1, "signature": rule.msg,
                      "category": _CATEGORY.get(rule.tactic, "Potentially Bad Traffic"), "severity": _SEVERITY[rule.severity]}
    return event


def generate_events() -> list[dict]:
    rules = load_catalogue()
    rng = random.Random(7)
    events, flow_id = [], 1000

    def add_alert(offset_s: float, sid: int, src: str, dest: str, port: int, proto: str = "TCP") -> None:
        nonlocal flow_id
        flow_id += 1
        events.append(_alert(START + timedelta(seconds=offset_s), rules[sid], src, dest, port, proto, flow_id))

    # Scenario 1: reconnaissance followed by SSH brute force from one source (expected P1).
    add_alert(60, 9000003, ATTACKER, SERVER, 0, "ICMP")
    for step in range(3):
        add_alert(120 + step * 25, 9000002, ATTACKER, SERVER, 1 + step * 300)
    for step in range(6):
        add_alert(360 + step * 60 + rng.random() * 5, 9000001, ATTACKER, SERVER, 22)
    # Scenario 2: web scanning (recon + traversal, expected P1).
    for step in range(4):
        add_alert(4500 + step * 20, 9000004, SCANNER, SERVER, 80)
    for step in range(3):
        add_alert(4600 + step * 15, 9000007, SCANNER, SERVER, 80)
    # Scenario 3: DNS anomaly on a workstation that also beacons (expected P3, plus a beacon lead).
    add_alert(1800, 9000006, WORKSTATION, "198.51.100.53", 53, "UDP")
    add_alert(1860, 9000006, WORKSTATION, "198.51.100.53", 53, "UDP")
    # Scenario 4: cleartext credentials from a legacy host (expected P3).
    add_alert(2400, 9000005, LEGACY, SERVER, 8080)
    # Scenario 5: an alert from outside the local catalogue exercises the severity fallback.
    flow_id += 1
    other = _base(START + timedelta(seconds=3000), "alert", "192.168.56.90", "198.51.100.10", 443, "TCP", flow_id)
    other["alert"] = {"action": "allowed", "gid": 1, "signature_id": 2100498, "rev": 7,
                      "signature": "GPL ATTACK_RESPONSE id check returned root", "category": "Potentially Bad Traffic", "severity": 2}
    events.append(other)
    # Beacon: workstation to 203.0.113.50:8443 every 60 seconds with about one second of jitter.
    for step in range(30):
        flow_id += 1
        moment = START + timedelta(seconds=1500 + step * 60 + rng.uniform(-1, 1))
        flow = _base(moment, "flow", WORKSTATION, C2, 8443, "TCP", flow_id)
        flow["flow"] = {"pkts_toserver": 6, "pkts_toclient": 5, "start": _stamp(moment)}
        events.append(flow)
    # Benign background flows with irregular timing.
    for _ in range(40):
        flow_id += 1
        moment = START + timedelta(seconds=rng.uniform(0, 5400))
        flow = _base(moment, "flow", f"192.168.56.{rng.randint(100, 120)}", f"198.51.100.{rng.randint(1, 30)}", rng.choice([80, 443]), "TCP", flow_id)
        flow["flow"] = {"pkts_toserver": rng.randint(3, 40), "pkts_toclient": rng.randint(3, 40), "start": _stamp(moment)}
        events.append(flow)
    return sorted(events, key=lambda e: e["timestamp"])


def write_events(path: Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    events = generate_events()
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events), encoding="utf-8")
    return len(events)
