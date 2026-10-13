"""Detect regular, machine-like callbacks from internal hosts to external destinations.

Suricata signatures cannot express "this connection repeats every N seconds". This module
looks at flow events and flags (src, dest, port) triples whose inter-connection timing is
unusually regular. It is a hunting lead, not a verdict: backups, NTP, monitoring agents and
software updaters are also periodic.
"""

from dataclasses import dataclass
from statistics import mean, pstdev
from .eve import is_internal, parse_time


@dataclass(frozen=True)
class Beacon:
    src_ip: str
    dest_ip: str
    dest_port: int
    connections: int
    mean_interval_s: float
    jitter_cv: float
    confidence: str

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "dest_ip": self.dest_ip, "dest_port": self.dest_port,
            "connections": self.connections, "mean_interval_s": round(self.mean_interval_s, 2),
            "jitter_cv": round(self.jitter_cv, 4), "confidence": self.confidence,
        }


def find_beacons(events: list[dict], min_connections: int = 8, max_cv: float = 0.15,
                 min_interval_s: float = 5.0, max_interval_s: float = 3600.0) -> list[Beacon]:
    """cv is the coefficient of variation (stdev / mean) of the gaps between connections."""
    series: dict[tuple, list[float]] = {}
    for event in events:
        if event.get("event_type") != "flow":
            continue
        src, dest, port = event.get("src_ip"), event.get("dest_ip"), event.get("dest_port")
        if not (src and dest and isinstance(port, int)) or not is_internal(src) or is_internal(dest):
            continue
        started = (event.get("flow") or {}).get("start") or event["timestamp"]
        series.setdefault((src, dest, port), []).append(parse_time(started).timestamp())
    found = []
    for (src, dest, port), stamps in series.items():
        if len(stamps) < min_connections:
            continue
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        average = mean(gaps)
        if not (min_interval_s <= average <= max_interval_s):
            continue
        cv = pstdev(gaps) / average
        if cv > max_cv:
            continue
        confidence = "high" if len(stamps) >= 20 and cv <= 0.05 else "medium" if len(stamps) >= 12 else "low"
        found.append(Beacon(src, dest, port, len(stamps), average, cv, confidence))
    return sorted(found, key=lambda b: (b.jitter_cv, -b.connections))
