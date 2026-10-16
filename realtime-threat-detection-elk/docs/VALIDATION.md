# Validation Record

| Check | Result | Limit |
| --- | --- | --- |
| Rule load: `suricata -T` with Suricata 7.0.3 | 8 rules loaded, 0 failed | Tested on 7.0.3; the compose file pins 7.0.7 |
| Rule firing: `tests/pcap/run_suricata_pcap.sh` replays a synthetic pcap through Suricata | All 8 SIDs fired once; the benign DNS control produced no alert | Synthetic packets, not production traffic. Says nothing about false-positive rates |
| Real EVE output through the triage tool | Suricata's own `eve.json` parsed with 0 skipped lines and produced 6 incidents | Single small pcap |
| Unit tests: `python -m unittest discover -s tests` | 32 tests pass | Cover parsing, scoring, grouping, beacon logic, metrics, CLI and rule metadata |
| YAML syntax: `configs/docker-compose.yml`, `configs/filebeat.yml`, CI workflow | Parse without error | Parsing is not execution |
| Script syntax: Python compile and `bash -n` | Pass | Not executed against live services |

## Not validated

- **The Docker Compose stack was not started** in the build environment (no Docker). Image tags, the Filebeat timestamp layout, the EVE field mapping in Elasticsearch, and healthchecks should be confirmed on first run.
- **`scripts/setup_kibana.py` and `scripts/load_sample_to_es.py`** were checked for syntax only, not against a live Kibana or Elasticsearch.
- **Detection performance** (detection rate, false-positive rate, analyst time saved) is not measured. Use `docs/METRICS.md` to measure it in your own environment.
- Alert volumes and thresholds are untuned lab defaults.

## First-run checklist

1. `docker compose up -d` and confirm all four containers are running.
2. `curl -s http://127.0.0.1:9200/_cat/indices` shows a `threatwatch-eve-*` index after traffic is generated.
3. Run `scripts/generate_lab_traffic.sh` against your lab target; confirm alerts in Kibana Discover.
4. Run `python scripts/setup_kibana.py` and open the dashboard.
