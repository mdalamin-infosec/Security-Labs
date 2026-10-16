"""Read rule metadata from the Suricata rules file so the catalogue never drifts from the rules."""

from dataclasses import dataclass
from pathlib import Path
import re

DEFAULT_RULES = Path(__file__).resolve().parent / "data" / "local.rules"

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}

_MSG = re.compile(r'msg:"([^"]*)"')
_SID = re.compile(r"\bsid:(\d+)\s*;")
_META = re.compile(r"metadata:([^;]*);")


class RuleError(ValueError):
    """Raised when a rule line cannot be parsed into the catalogue."""


@dataclass(frozen=True)
class Rule:
    sid: int
    msg: str
    technique: str
    tactic: str
    severity: str
    playbook: str


def _metadata(raw: str) -> dict[str, str]:
    result = {}
    for item in raw.split(","):
        key, _, value = item.strip().partition(" ")
        if key:
            result[key] = value.strip()
    return result


def parse_rule(line: str) -> Rule:
    msg, sid, meta = _MSG.search(line), _SID.search(line), _META.search(line)
    if not (msg and sid and meta):
        raise RuleError(f"rule needs msg, sid and metadata: {line[:80]}")
    data = _metadata(meta.group(1))
    severity = data.get("severity", "")
    if severity not in SEVERITY_WEIGHT:
        raise RuleError(f"sid {sid.group(1)} has invalid severity {severity!r}")
    for key in ("mitre_technique", "mitre_tactic", "playbook"):
        if not data.get(key):
            raise RuleError(f"sid {sid.group(1)} is missing metadata {key}")
    return Rule(int(sid.group(1)), msg.group(1), data["mitre_technique"], data["mitre_tactic"], severity, data["playbook"])


def load_catalogue(path: Path = DEFAULT_RULES) -> dict[int, Rule]:
    catalogue: dict[int, Rule] = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rule = parse_rule(stripped)
        if rule.sid in catalogue:
            raise RuleError(f"duplicate sid {rule.sid} at line {number}")
        catalogue[rule.sid] = rule
    return catalogue
