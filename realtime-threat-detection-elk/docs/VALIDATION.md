# ThreatWatch validation

## Completed automated checks

```text
32 unit tests passed
21 synthetic alerts -> 5 incidents
2 P1 incidents
1 beacon lead
```

The Python package exercises parsing, rule metadata, incident grouping, priority scoring, beacon heuristics, lifecycle metric arithmetic and CLI behavior.

## Completed owner lifecycle measurement

Two matched five-incident cohorts were recorded with timezone-aware timestamps:

```text
before-playbook: 5
with-playbook:   5
```

Observed medians in that small replay:

```text
median triage: 0.02 min -> 0.02 min (0.0%)
median close:  0.03 min -> 0.02 min (-33.3%)
```

Because durations are second-scale and N=5 per cohort, this is retained as workflow evidence only.

## Engine and full-stack boundaries

The repository contains a Suricata PCAP replay harness and an Elastic/Filebeat/Kibana lab configuration. The GitHub Suricata workflow exercises the committed replay path; an owner-retained full live Compose ingestion session is still a next step.

See [LIVE_PIPELINE_VALIDATION.md](LIVE_PIPELINE_VALIDATION.md).
