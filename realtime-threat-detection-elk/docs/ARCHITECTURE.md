# System Architecture

## Data flow

```
network interface --> Suricata 7 (local.rules) --> eve.json --> Filebeat --> Elasticsearch 8 --> Kibana
                                                     |
                                                     +--> threatwatch CLI (triage, beacon leads, reports)
```

| Component | Role | Notes |
| --- | --- | --- |
| Suricata | Passive IDS. Inspects traffic on one interface and writes alerts, flows, DNS and HTTP events as EVE JSON | Runs with host networking and `NET_ADMIN`, `NET_RAW`. Loads only `src/threatwatch/data/local.rules` (`-S`) |
| Filebeat | Tails `eve.json`, parses each line as JSON, sets `@timestamp` from the event time | Index pattern `threatwatch-eve-YYYY.MM.DD`, ILM disabled for the lab |
| Elasticsearch | Stores events for search and aggregation | Single node, security disabled, bound to 127.0.0.1 |
| Kibana | Discover, saved searches, dashboards | `scripts/setup_kibana.py` creates the data view and triage dashboard |
| `threatwatch` | Offline Python tooling: rule catalogue, alert grouping and scoring, beacon leads, metrics | Standard library only; reads EVE files, never touches the network |

## Trust boundaries

- Suricata sees raw traffic, including any cleartext secrets on the monitored segment. Treat `eve.json` and the Elasticsearch index as sensitive.
- The compose stack publishes Elasticsearch and Kibana on loopback only. Do not change the bindings to `0.0.0.0` while security is disabled.
- The IDS is passive: it raises alerts and does not block traffic. Blocking is a manual response action defined in the playbook.

## Design decisions

- **One rules file is the source of truth.** MITRE technique, tactic, severity and playbook live in each rule's `metadata`. The triage tool reads them from the same file, so documentation, dashboards and scoring cannot disagree with the rules. Tests enforce complete metadata.
- **Transparent scoring.** Priority comes from a short formula in `src/threatwatch/triage.py`, not a model. An analyst can explain why an incident is P1.
- **Beacon detection lives outside Suricata.** Signatures are stateless per match; periodicity needs a view across many flow events, so it is a separate hunting lead with documented limits.
- **Fail soft on bad input.** Malformed EVE lines are counted and skipped; unknown SIDs fall back to Suricata's own severity and are flagged.

## Known limits

- IDS visibility depends on placement: encrypted payloads cannot be inspected, and a single interface sees only its own segment.
- Threshold rules count packets or connections per source; a distributed attack from many sources will not cross a per-source threshold.
- The compose stack is a lab. A production deployment needs authentication and TLS for Elasticsearch/Kibana, retention policy, sizing, and a rule update process.
