# Owner-Run Validation Summary

## Latest Result

```text
PASS=16
FAIL=0
SKIP=0
```

The owner-run validation combines reproducible offline tests with explicitly labeled retained live-lab evidence.

## Measured Results

| Area | Result |
| --- | --- |
| Sigma unit tests | 4 passed |
| Sigma synthetic detection | 20/20 attack fixtures |
| Sigma FP tuning | baseline FP 3 -> tuned FP 0 |
| Suricata retained replay | 8/8 attack cases; 0/4 benign false positives |
| NIDS live detection | 4/4 controlled attack scenarios |
| ThreatWatch tests | 32 passed |
| ThreatWatch demo | 21 alerts -> 5 incidents |
| Lifecycle measurement | 5 before-playbook + 5 with-playbook |
| NetSentry tests | 34 passed |
| NetSentry live assessment | 23 open services |
| NetSentry CVE candidates | 296 unique; 297 instances |
| NetSentry enrichment coverage | 8/8 eligible services |
| Rust cargo checks | PASS |
| Rust Clippy checks | PASS |

## Interpretation

The results above are intentionally bounded to the evidence collected.

- Synthetic detection metrics are not production detection rates.
- The retained NIDS result applies to four controlled attack scenarios.
- The live NIDS cohort does not support a live benign false-positive-rate claim.
- NetSentry CVE results are NVD/CPE candidates, not confirmed exploitable vulnerabilities.
- ThreatWatch timing measurements are based on a small, second-scale replay cohort and are not generalized to analyst productivity.

See `RESULTS-LATEST.md` for the generated repeatable-results table.
