"""Read Suricata EVE JSON (one JSON object per line) and normalise alert events."""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def parse_time(value: str) -> datetime:
    """Parse Suricata timestamps such as 2026-10-14T09:02:11.123456+0000 into aware UTC."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_internal(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in _INTERNAL) if ip.version == 4 else ip.is_loopback or ip.is_link_local


@dataclass(frozen=True)
class Alert:
    time: datetime
    src_ip: str
    dest_ip: str
    dest_port: int | None
    proto: str
    sid: int
    signature: str
    severity: int
    category: str


@dataclass
class EveFile:
    events: list[dict]
    skipped: int


def read_events(path: Path) -> EveFile:
    """Load events, counting (not raising on) malformed lines so one bad record cannot stop triage."""
    events, skipped = [], 0
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict) or "timestamp" not in event:
                    raise ValueError("not an event object")
                parse_time(event["timestamp"])
            except (ValueError, TypeError):
                skipped += 1
                continue
            events.append(event)
    return EveFile(events, skipped)


def alerts_from(events: list[dict]) -> list[Alert]:
    alerts = []
    for event in events:
        if event.get("event_type") != "alert":
            continue
        info = event.get("alert") or {}
        if "signature_id" not in info or "src_ip" not in event or "dest_ip" not in event:
            continue
        port = event.get("dest_port")
        alerts.append(Alert(
            time=parse_time(event["timestamp"]),
            src_ip=event["src_ip"],
            dest_ip=event["dest_ip"],
            dest_port=port if isinstance(port, int) else None,
            proto=str(event.get("proto", "")),
            sid=int(info["signature_id"]),
            signature=str(info.get("signature", "")),
            severity=int(info.get("severity", 3)),
            category=str(info.get("category", "")),
        ))
    return sorted(alerts, key=lambda a: a.time)
