# Testing strategy

## Goal

Make every security claim traceable to a test type, labeled input, reproducible command, and explicit limitation.

## Test layers

| Layer | Purpose | Current examples |
| --- | --- | --- |
| Unit/source tests | Validate parsers, rule metadata, counting, scope controls and report behavior | Sigma 4 tests, ThreatWatch 32 tests, NetSentry 34 tests |
| Synthetic fixtures | Exercise known attack/benign expectations deterministically | 38 Sigma events, 12 Suricata PCAP cases, ThreatWatch demo data |
| Real-engine replay | Verify rules load and fire in the intended engine | Suricata replay: 8/8 attacks, 0/4 benign FP |
| Controlled live lab | Test real packet visibility or scanning inside an authorized VM network | Standalone NIDS 4/4 attack cases; NetSentry Metasploitable2 assessment |
| Runtime application regression | Verify actual HTTP behavior, not only compilation | Planned for the Rust comparison |
| Held-out evaluation | Reduce rule/test co-design bias | Planned; must remain untouched during tuning |

## Detection metrics

For any independently labeled cohort:

```text
recall    = TP / (TP + FN)
precision = TP / (TP + FP)
FPR       = FP / (FP + TN)
```

Report raw counts and sample size next to percentages. Do not combine synthetic and live cohorts into one headline metric.

## Held-out protocol

1. Freeze the rule revision before seeing the evaluation labels.
2. Keep training/tuning fixtures separate from the held-out corpus.
3. Assign stable case IDs and labels outside the rule implementation.
4. Replay the exact same held-out cases against baseline and tuned rules.
5. Record engine/backend versions, configuration hash, case counts and failures.
6. Publish limitations and any excluded cases.

## Evidence retention

Raw EVE, databases, PCAPs and local runtime output stay under ignored `outputs/` paths. Only sanitized summaries, hashes, configuration and small excerpts should be committed.

A screenshot is supporting context, not a substitute for machine-readable evidence.
