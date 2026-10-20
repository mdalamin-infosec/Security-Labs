# realtime-threat-detection-elk

An offline analyst CLI for Suricata EVE JSON. It groups related alerts, assigns an
explainable incident priority and checks outbound flow timing for beacon-like patterns.
An optional Elastic lab configuration supports exploring ingestion and investigation.

## Try it

From this project directory, with Python 3.11+:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m threatwatch demo
python -m threatwatch rules
python -m threatwatch triage data/demo-eve.json --format markdown --output reports/triage.md
python -m threatwatch beacons data/demo-eve.json
```

The deterministic demo generates **21 alerts**, grouped into **five incidents**:
two P1 incidents and one periodic-flow lead. JSON and Markdown reports are written
to `reports/`. The CLI works offline after installation and does not require Docker.

## How the analysis works

Alerts from the same source stay together until a quiet gap exceeds 15 minutes.
The incident preserves signatures, destinations, ATT&CK context and playbooks.
Priority combines the highest severity, tactic diversity and alert volume; escalation
reasons are included in the report. Unknown SIDs use the Suricata severity fallback.

The separate flow heuristic looks for at least eight internal-to-external connection
starts with regular intervals. Investigate the owning process and destination;
monitoring agents and updaters can also produce periodic traffic.

[Correlation and scoring](src/threatwatch/triage.py) · [Flow analysis](src/threatwatch/beacon.py) · [Playbooks](docs/INCIDENT_RESPONSE_PLAYBOOK.md)

## Test the Python workflow

```bash
python -m unittest discover -s tests -v
```

The existing suite passes **32 tests** covering parsing, rule metadata, grouping,
priority boundaries, flow timing, lifecycle metrics and CLI output.

## Optional Elastic integration

The repository also includes Suricata, Filebeat, Elasticsearch and Kibana configuration.
See [the Kibana guide](docs/KIBANA_GUIDE.md) and [integration checklist](docs/LIVE_PIPELINE_VALIDATION.md).
The supplied Compose stack disables authentication for a local lab and binds published
Elastic ports to loopback; review [Security](SECURITY.md) before starting it.

The offline tests do not establish that the entire capture-to-dashboard stack works.
Source-based grouping can merge unrelated activity behind shared addresses. The next
integration milestone is to trace one labeled event from raw EVE through Elasticsearch
into Kibana. Measure investigation time separately using [lifecycle records](docs/METRICS.md).
