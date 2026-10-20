# Security Labs

A cybersecurity portfolio covering service inventory, alert triage, detection rules
and application security review. The projects combine Python tooling with small,
controlled network and Rust exercises.

**Python · Flask · SQLite · Suricata · Sigma · Rust · GitHub Actions**

## Projects

| Project | Purpose | Implementation to inspect |
| --- | --- | --- |
| [NetSentry](enterprise-vulnerability-scanner/) | Collect scoped service inventory and turn NVD matches into a reviewable dashboard | [Scope validation](enterprise-vulnerability-scanner/src/netsentry/config.py), [report construction](enterprise-vulnerability-scanner/src/netsentry/analysis.py) |
| [ThreatWatch](realtime-threat-detection-elk/) | Group Suricata alerts into prioritized incidents and identify periodic outbound flows | [Correlation](realtime-threat-detection-elk/src/threatwatch/triage.py), [beacon analysis](realtime-threat-detection-elk/src/threatwatch/beacon.py) |
| [Sigma and Suricata rules](sigma-suricata-detection-rules/) | Test process and protocol indicators against labeled examples | [Sigma evaluator](sigma-suricata-detection-rules/tools/evaluate_sigma.py), [signatures](sigma-suricata-detection-rules/rules/suricata/custom.rules) |
| [Network IDS](network-intrusion-detection-suricata/) | Observe four traffic patterns in an isolated VM network | [Rules](network-intrusion-detection-suricata/rules/local.rules), [session evaluator](network-intrusion-detection-suricata/tools/evaluate_live.py) |
| [Rust security review](secure-code-review/) | Compare vulnerable code with specific remediation patterns | [Findings](secure-code-review/docs/security-review.md), [remediated source](secure-code-review/src/secure-app/src/main.rs) |

## Start with NetSentry

From the repository root, with Python 3.11+:

```bash
python3 -m venv .venv
. .venv/bin/activate
cd enterprise-vulnerability-scanner
python -m pip install -r requirements.txt -e .
python -m netsentry demo
python -m netsentry serve
```

Open **http://127.0.0.1:8080**. The synthetic dataset contains four hosts, eight
services and four unique CVE examples. Installation needs internet access; the demo
itself works without Nmap, an API key or network access. Stop with Ctrl+C.

## What the projects demonstrate

- **Defensive programming:** explicit scan scope, safe XML parsing, bound database parameters and spreadsheet-safe CSV export.
- **Analysis:** service-level lookup coverage, explainable incident priority and periodic-flow detection.
- **Detection engineering:** rule metadata, labeled attack/benign fixtures and separate real-engine replay scripts.
- **Security review:** tracing untrusted input to SQL and process execution, then comparing safer implementations.

The three existing Python suites pass **70 tests**: NetSentry 34, ThreatWatch 32 and
the Sigma harness 4. Their project READMEs include the commands to reproduce them.
The Sigma fixture run detects 20 attack examples and leaves 18 benign examples quiet.
ThreatWatch's synthetic demo groups 21 alerts into five incidents.

## Project status

The Python demos are the quickest paths to inspect. Suricata replay needs the engine;
live assessment needs authorized targets; the Elastic stack needs a separate integration
run. Rust HTTP regression and authentication lifecycle work remain unfinished.

Earlier live figures are recorded in [the supplied results summary](docs/RESULTS-LATEST.md).
Its referenced raw outputs were absent from the archive and were not revalidated here.
The current IDS evaluator checks SID presence within a log; see its README before
interpreting a case-level detection percentage. Use these tools in authorized labs.
