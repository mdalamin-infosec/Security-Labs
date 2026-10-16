# Security Labs — Latest Repeatable Results

- Run (UTC): 20261016T051419Z
- Repository commit: a1bd64e
- Host: Linux 6.12.111+deb13-amd64 x86_64 GNU/Linux
- Python requested: python3
- Raw run directory: `outputs/all-results/20261016T051419Z/`

> **Metric boundary:** synthetic/demo results are labeled as such. Live and owner-measured lab results are scoped laboratory evidence and should not be interpreted as production detection efficacy, confirmed exploitability, or organization-wide analyst productivity.

| Project | Check / metric | Result | Raw evidence |
| --- | --- | --- | --- |
| Sigma/Suricata rules | Unit tests | 4 tests passed | `outputs/all-results/20261016T051419Z/sigma-unittest.log` |
| Sigma/Suricata rules | Synthetic fixture detection | 20/20 attacks detected; recall=100.0%; FP=0/18; precision=100.0%; FPR=0.0% | `outputs/all-results/20261016T051419Z/sigma-metrics.json` |
| Sigma/Suricata rules | Synthetic FP reduction | 100.0% (baseline FP 3 -> tuned FP 0) — fixture-only | `outputs/all-results/20261016T051419Z/sigma-metrics.json` |
| Sigma/Suricata rules | Actual Suricata replay (retained) | actual offline replay: 8/8 attack cases detected; recall=100.0%; FP=0/4; FPR=0.0% | `sigma-suricata-detection-rules/outputs/suricata_metrics.json` |
| Network IDS | Shell syntax | 2 scripts passed bash -n | `outputs/all-results/20261016T051419Z/network-ids-syntax.log` |
| Network IDS | Rule inventory | 4 custom SIDs: 1000001,1000002,1000003,1000004 | `network-intrusion-detection-suricata/rules/local.rules` |
| Network IDS | Live VM-to-VM detection rate | 4/4 live attack cases detected; detection rate=100.0%; TP=4; FN=0; missed=none | `network-intrusion-detection-suricata/outputs/live/live_metrics.json` |
| ELK threat triage | Unit tests | 32 tests passed | `outputs/all-results/20261016T051419Z/threatwatch-unittest.log` |
| ELK threat triage | Synthetic offline demo | 21 synthetic alerts -> 5 incidents; P1=2; beacon leads=1 | `outputs/all-results/20261016T051419Z/threatwatch-demo-report/demo-incidents.json` |
| ELK threat triage | Investigation/triage time | comparison: before-playbook -> with-playbook {'median_triage_min': 0.0, 'median_close_min': -33.3} | `outputs/all-results/20261016T051419Z/investigation-time.txt` |
| Vulnerability scanner | Unit tests | 34 tests passed | `outputs/all-results/20261016T051419Z/netsentry-unittest.log` |
| Vulnerability scanner | Synthetic demo | DEMO: 4 hosts, 8 services, 4 unique synthetic CVE candidates, 6 endpoint instances | `outputs/all-results/20261016T051419Z/netsentry-demo-report.json` |
| Vulnerability scanner | Retained live Nmap/NVD assessment | 296 unique CVE candidates; 297 candidate instances; checked 8/8 eligible services — candidates, not confirmed exploitable vulnerabilities | `enterprise-vulnerability-scanner/outputs/live/evidence/netsentry-live-report.json` |
| Secure code review | cargo check vulnerable-app | PASS | `outputs/all-results/20261016T051419Z/cargo-check-vulnerable-app.log` |
| Secure code review | cargo check secure-app | PASS | `outputs/all-results/20261016T051419Z/cargo-check-secure-app.log` |
| Secure code review | cargo clippy vulnerable-app | PASS | `outputs/all-results/20261016T051419Z/cargo-clippy-vulnerable-app.log` |
| Secure code review | cargo clippy secure-app | PASS | `outputs/all-results/20261016T051419Z/cargo-clippy-secure-app.log` |
| Secure code review | Source comparison | Static source comparison retained; runtime endpoint regression still separate | `secure-code-review/docs/security-review.md` |

## Run totals

- PASS checks: 16
- FAIL checks: 0
- SKIP / not-yet-measured checks: 0

## Metrics snapshot

| Metric | Current result |
| --- | --- |
| Detection rate | Live lab NIDS: 4/4 live attack cases detected; detection rate=100.0%; TP=4; FN=0; missed=none |
| False-positive reduction | Synthetic Sigma fixture: 100.0% (baseline FP 3 -> tuned FP 0) |
| Investigation-time improvement | comparison: before-playbook -> with-playbook {'median_triage_min': 0.0, 'median_close_min': -33.3} |
| Potential/retained CVE count | 296 unique CVE candidates; 297 candidate instances; checked 8/8 eligible services |

## CV-safe interpretation

Use only measurements above that match the evidence type. In particular:

- Sigma percentages from the bundled 38-event corpus are **synthetic fixture metrics**, not operational held-out performance.
- A CVE ID from Nmap/NVD is a **candidate/potential CVE** until applicability is confirmed.
- Investigation-time comparison is supported by the retained 5-case before-playbook and 5-case with-playbook lifecycle records. Because this small replay produced second-scale timings, the observed median-close change should be treated as a lab workflow measurement, not a general analyst-productivity claim.
- Standalone IDS detection rate is supported by the retained labeled live VM-to-VM session (4/4 controlled attack cases detected). Live false-positive rate is not yet measured because the retained live cohort contains no benign cases.

Raw outputs are kept under the ignored run directory shown at the top. Review and sanitize small evidence before committing it to `docs/` or `sample-data/`.
