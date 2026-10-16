# Security Labs

A cybersecurity portfolio for SOC analyst and blue-team practice: network
visibility, detection rules, alert triage, scoped vulnerability assessment and
secure code review. Results below distinguish executed offline checks from
pending lab validation.

| Project | Focus | Current evidence / next validation |
| --- | --- | --- |
| [Sigma and Suricata rules](sigma-suricata-detection-rules/) | Process and HTTP/DNS detection logic | 4 tests passed on synthetic fixtures; real engine/SIEM TODO |
| [Network IDS](network-intrusion-detection-suricata/) | Four Suricata signals and manual response | Shell syntax checked; live packet/response validation TODO |
| [ELK threat triage](realtime-threat-detection-elk/) | Suricata → Elastic pipeline; offline triage | 32 offline tests passed; live ingestion/replay TODO |
| [Vulnerability scanner](enterprise-vulnerability-scanner/) | Scoped Nmap inventory and NVD candidate review | 34 offline tests passed; actual applicability/live integrations TODO |
| [Secure code review](secure-code-review/) | Vulnerable and partially remediated Rust APIs | Source comparison preserved; build/HTTP regression TODO |

## Getting started
```bash
git clone https://github.com/mdalamin-infosec/Security-Labs.git
cd Security-Labs
```
Choose a project above and follow its README from that project directory.
Python packages use `src/` layouts: install them with the documented `pip -e .`
step before running their CLI or tests. Active CI definitions are under the
root [.github/workflows](.github/workflows/).

## Tools
Suricata, Sigma YAML, Python, Bash, Rust/Cargo, Actix-web, SQLite, Nmap, NVD,
Flask/Waitress, Filebeat, Elasticsearch, Kibana, Docker Compose and VirtualBox.
Install external tools from their official projects; their source/build trees
are not part of this portfolio. Cargo lockfiles remain for reproducible
application dependencies.

## Evidence and scope
- Cleanup verification used Ubuntu 24.04.3 LTS and Python 3.12.14. The three
  Python suites passed **70 tests** in total; [actual records](docs/VALIDATION.md)
  identify commands and scope.
- Synthetic events, curated CVE examples and fixture scores are demonstrations,
  not measured operational findings. Recall, false-positive reduction,
  confirmed applicable CVEs and analyst time improvement are **TODO: measure**.
- The six inherited IDS screenshots are [described by their actual content](network-intrusion-detection-suricata/docs/screenshots/README.md); several show capture commands rather than test results. Their provenance remains pending.
  Source authorship and any adaptations also require the owner's confirmation.
- Work only on an authorized lab scope. The deliberately vulnerable Rust app
  and unauthenticated Elastic lab are educational local services.

[All personal TODOs](docs/TODO.md) · [Three interview questions per project](docs/INTERVIEW_QUESTIONS.md).
