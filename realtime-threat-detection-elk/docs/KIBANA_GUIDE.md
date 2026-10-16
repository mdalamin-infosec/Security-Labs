# Kibana Guide

## Setup

1. Start the stack: `docker compose --env-file configs/.env -f configs/docker-compose.yml up -d`, wait until Kibana answers on http://127.0.0.1:5601.
2. Create the data view, saved searches and dashboard:
   ```bash
   python scripts/setup_kibana.py
   ```
3. No live traffic yet? Load the synthetic demo events:
   ```bash
   python -m threatwatch generate-sample --output data/demo-eve.json
   python scripts/load_sample_to_es.py data/demo-eve.json
   ```
   Set Kibana's time range to cover 14 Oct 2026 (the synthetic events' date).

The setup script creates a data view (`threatwatch-eve-*`, time field `@timestamp`), six saved searches, and a dashboard named **ThreatWatch - Alert triage** that shows those searches. It has been written against the documented Kibana 8.x saved-object APIs; see `docs/VALIDATION.md` for what was and was not tested against a live stack.

## Useful fields

| Field | Meaning |
| --- | --- |
| `event_type` | `alert`, `flow`, `dns`, `http` and so on |
| `src_ip`, `dest_ip`, `dest_port` | Connection tuple |
| `alert.signature`, `alert.signature_id` | Which rule fired |
| `alert.severity` | Suricata severity, 1 is most severe |
| `alert.metadata.mitre_technique`, `alert.metadata.mitre_tactic`, `alert.metadata.playbook` | Metadata from the rule |

## Charts to add with Lens (about 10 minutes)

1. **Alerts over time**: Lens, bar chart, X `@timestamp`, Y count, break down by `alert.signature`, filter `event_type : "alert"`.
2. **Top sources**: horizontal bar, Y `src_ip` top 10 by count, same filter.
3. **ATT&CK tactics**: donut, slice by `alert.metadata.mitre_tactic`.
4. **Targets under attack**: table with `dest_ip`, count, unique count of `alert.signature_id`.

Add them to the dashboard and save. Charts are not scripted here because Lens definitions change between Kibana releases.

## Hunting queries

- Beacon candidates: `event_type : "flow" and not dest_ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)`, then check timing with `python -m threatwatch beacons <eve.json>`.
- Recon then access from one host: search the source IP in Discover and sort by time.
- Rules that never fire after a week: candidates for review.
