# Engineering roadmap

This roadmap contains only work that is still worth doing. Completed validation is recorded in [RESULTS-LATEST.md](RESULTS-LATEST.md), not left as stale TODO text.

## P0 — Evidence depth

| Item | Status | Completion criterion |
| --- | --- | --- |
| Live benign NIDS cohort | Next | Capture independently labeled benign sessions and report TP/FN/FP/TN, recall and FPR alongside the existing 4 attack cases. |
| Held-out detection corpus | Next | Freeze rules, evaluate an untouched attack/benign corpus, and publish case IDs, sample size, precision/recall/FPR and limitations. |
| NetSentry applicability review | Next | Manually disposition 3–5 representative CVE candidates using package/vendor/backport/configuration evidence. |
| Rust HTTP regression | Next | Start both localhost apps and retain response/status evidence for the exact cases in the validation plan. |
| Full ELK pipeline | Next | Demonstrate Suricata → EVE → Filebeat → Elasticsearch → Kibana with retained sanitized evidence and version pins. |

## P1 — Security engineering maturity

| Item | Status | Completion criterion |
| --- | --- | --- |
| Sigma backend execution | Next | Convert selected Sigma rules with a documented backend and replay normalized Windows/Linux process telemetry. |
| Threat model review | In place | Keep [THREAT_MODEL.md](THREAT_MODEL.md) current as features change. |
| Architecture decisions | In place | Record high-impact choices in `docs/adr/`. |
| Dependency/security auditing | Next | Add verified dependency-audit checks only after they pass locally and in CI. |
| Release discipline | Next | Publish a tagged release after P0 evidence is updated and all CI remains green. |

## Already completed

- Unified owner validation reports `PASS=16`, `FAIL=0`, `SKIP=0`.
- Actual Suricata offline replay is retained for 8 attack and 4 benign PCAP cases.
- Standalone NIDS has retained live evidence for 4/4 controlled attack scenarios.
- ThreatWatch has 32 tests and a 5-vs-5 owner lifecycle timing exercise.
- NetSentry completed an authorized live Metasploitable2 scan with NVD enrichment.
- Both Rust variants pass locked Cargo checks and Clippy.
- GitHub Actions workflows cover Python, Rust, and offline Suricata validation.

No item in the **Next** tables should be described as complete until its evidence is retained.
