# Real-Time Network Threat Detection & Incident Monitoring System

**ThreatWatch Lab** is a small, reproducible detection pipeline: Suricata inspects traffic with custom rules, Filebeat ships the alerts to Elasticsearch, Kibana provides triage views, and a Python toolkit groups alerts into prioritised incidents, flags beacon-like callbacks, and records response timing. An incident response playbook ties each alert to a first-15-minutes procedure.

| Project attribute | Value |
| --- | --- |
| Software version | 1.0.0 |
| Sensor | Suricata 7 (passive IDS) with 8 custom rules mapped to MITRE ATT&CK |
| Pipeline | Filebeat, Elasticsearch 8.15, Kibana 8.15 (Docker Compose) |
| Analyst tooling | Python 3.11+, standard library only |
| Intended scope | Authorised lab networks and private IPv4 ranges |
| License | MIT |

The included demo data is synthetic and tagged `synthetic-demo`. Results on a real network require separately collected traffic and analyst validation.

## Implemented capabilities

- **8 custom Suricata rules** (SID 9000001 to 9000008) covering SSH brute force, port scans, host sweeps, scanner user-agents, cleartext credentials, DNS anomalies, directory traversal and Telnet. Each rule carries ATT&CK technique, tactic, severity and playbook metadata.
- **Rules proven to fire:** `tests/pcap/run_suricata_pcap.sh` replays a synthetic pcap through Suricata and checks every SID alerts and a benign control does not.
- **Live pipeline** via `configs/docker-compose.yml`: Suricata, Filebeat, Elasticsearch and Kibana, with loopback-only ports.
- **Kibana setup script** creating a data view, six saved searches and a triage dashboard.
- **Incident triage:** alerts grouped per source, scored with a documented formula (P1 to P4), with escalation when reconnaissance is followed by an access attempt.
- **Beacon leads:** regular outbound callbacks found from flow timing (coefficient of variation), as a hunting lead rather than a verdict.
- **Incident response playbook** for five scenarios with analysis, containment, recovery and closure criteria.
- **Response metrics tool** computing median time to triage and close per cohort from your own incident records.
- **32 offline unit tests** and CI that also validates the rules with Suricata.

## Quick start: offline demo (no Docker, no Suricata)

```bash
cd realtime-network-threat-detection
python3 -m unittest discover -s tests
python3 -m threatwatch demo
```

The demo writes synthetic events to `data/` and reports to `reports/demo-incidents.md` and `.json`. It produces 5 incidents (2 at P1) from 21 alerts and one beacon lead to `203.0.113.50:8443`.

## Quick start: live stack

```bash
cp .env.example .env            # set SURICATA_IFACE to your lab interface (ip -br a)
docker compose up -d
python scripts/setup_kibana.py
TARGET=<lab-ip> I_OWN_THIS_LAB=yes scripts/generate_lab_traffic.sh
```

Then open http://127.0.0.1:5601, the **ThreatWatch - Alert triage** dashboard, and follow the [playbook](docs/INCIDENT_RESPONSE_PLAYBOOK.md). Export alerts for the triage tool with the EVE file in the `suricata-logs` volume. The traffic script refuses non-private targets and requires explicit confirmation.

## Command reference

| Command | Purpose |
| --- | --- |
| `python -m threatwatch rules` | Print the rule catalogue read from `local.rules` |
| `python -m threatwatch demo` | Synthetic events, triage, beacon leads, reports |
| `python -m threatwatch triage <eve.json> [--format text\|json\|markdown]` | Group and score alerts |
| `python -m threatwatch beacons <eve.json>` | List periodic outbound connection leads |
| `python -m threatwatch metrics <records.csv> --baseline A --treatment B` | Triage and closure time summary |

## Documentation set

| Document | Purpose |
| --- | --- |
| [Quick start](START_HERE.md) | Setup and publishing |
| [Architecture](docs/ARCHITECTURE.md) | Data flow, trust boundaries, design decisions, limits |
| [Detection rules](docs/DETECTION_RULES.md) | Rule catalogue, false positives, change procedure |
| [Incident response playbook](docs/INCIDENT_RESPONSE_PLAYBOOK.md) | Triage routine and scenario playbooks |
| [Kibana guide](docs/KIBANA_GUIDE.md) | Dashboard setup, fields, hunting queries |
| [Metrics](docs/METRICS.md) | How to measure triage time fairly |
| [Validation record](docs/VALIDATION.md) | What was tested and what was not |
| [Incident record template](docs/templates/INCIDENT_RECORD_TEMPLATE.md) | Per-incident evidence and timestamps |
| [Security policy](SECURITY.md) | Operating boundaries |
| [Change log](CHANGELOG.md) | History |

## Limits

- The IDS is passive and sees only its interface. Encrypted payloads are not inspected.
- Thresholds are untuned lab defaults, and per-source thresholds miss distributed attacks.
- The compose stack has no authentication and is for local use only.
- The Compose stack and Kibana script were not run against live services in the build environment; see the [validation record](docs/VALIDATION.md) and first-run checklist.
- No detection-rate or time-saved figure is claimed. Measure your own with the metrics tool.
