# Security Labs

[![Python Validation](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/python-validation.yml/badge.svg?branch=master)](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/python-validation.yml)
[![Rust Validation](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/rust-validation.yml/badge.svg?branch=master)](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/rust-validation.yml)
[![Suricata Validation](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/suricata-validation.yml/badge.svg?branch=master)](https://github.com/mdalamin-infosec/Security-Labs/actions/workflows/suricata-validation.yml)

Cybersecurity engineering portfolio focused on SOC analysis, blue-team detection engineering, network monitoring, incident triage, vulnerability assessment, and secure-code review.

The repository emphasizes **reproducible validation, retained evidence, explicit scope, and accurate claim boundaries**.

## Validation Snapshot

Latest owner-run unified validation:

```text
PASS = 16
FAIL = 0
SKIP = 0
```

Full results: [docs/RESULTS-LATEST.md](docs/RESULTS-LATEST.md)

## Portfolio Projects

| Project | Focus | Validated result |
| --- | --- | --- |
| [Sigma + Suricata](sigma-suricata-detection-rules/) | Detection engineering | 20/20 synthetic attacks detected; retained replay detected 8/8 attack cases with 0/4 benign false positives |
| [Network IDS](network-intrusion-detection-suricata/) | Suricata IDS | 4/4 controlled live VM-to-VM attack scenarios detected |
| [ThreatWatch / ELK](realtime-threat-detection-elk/) | Alert correlation and triage | 32 tests; 21 alerts correlated into 5 incidents; matched 5-vs-5 lifecycle measurement |
| [NetSentry](enterprise-vulnerability-scanner/) | Vulnerability assessment | 23 open services; 296 unique CVE candidates; 8/8 eligible services checked |
| [Secure Code Review](secure-code-review/) | Rust security review | Cargo check and Clippy validation passed for both application variants |

## Engineering Highlights

### Detection Engineering

Developed and validated Sigma and Suricata detection logic covering suspicious execution, HTTP attacks, DNS behavior, reconnaissance, authentication, and credential-related activity.

Validation includes synthetic fixtures, false-positive tuning, controlled benign traffic, and actual Suricata-engine PCAP replay.

### Network Detection

Built a standalone Suricata IDS in an isolated VirtualBox lab.

Four custom signatures were validated against four labeled live attack scenarios with retained EVE JSON and explicit ground truth.

The retained live cohort does not include labeled benign sessions, so no live false-positive-rate claim is made.

### Incident Triage

Implemented ThreatWatch for alert grouping, priority scoring, MITRE ATT&CK context, playbook mapping, beacon analysis, and lifecycle measurement.

A matched five-case before-playbook and five-case with-playbook measurement is retained locally. Because the timings are second-scale and the sample is small, the result is treated as a lab workflow measurement rather than a general productivity claim.

### Vulnerability Assessment

Implemented NetSentry with explicit scope controls, Nmap discovery, CPE extraction, NVD enrichment, CVE review, SQLite-backed storage, and JSON/CSV reporting.

An authorized live Metasploitable2 assessment identified 23 open TCP services and 296 unique NVD CVE candidates across 8/8 eligible services.

**CVE candidate does not mean confirmed exploitability.**

### Secure Code Review

Reviewed vulnerable and remediated Rust application variants using source review, locked Cargo builds, and Clippy checks.

Compiler and linter success is treated as build-quality evidence, not proof of complete application security.

## Repository Structure

```text
Security-Labs/
├── .github/workflows/
├── docs/
├── enterprise-vulnerability-scanner/
├── network-intrusion-detection-suricata/
├── realtime-threat-detection-elk/
├── secure-code-review/
├── sigma-suricata-detection-rules/
└── run_all_security_results.sh
```

## Run the Validation Suite

```bash
git clone https://github.com/mdalamin-infosec/Security-Labs.git
cd Security-Labs
chmod +x run_all_security_results.sh
./run_all_security_results.sh
```

Some live-lab checks depend on owner-retained local evidence that is intentionally excluded from Git. GitHub Actions validates the reproducible offline portions of the repository.

## Technologies

**Detection / SOC:** Suricata, Sigma, EVE JSON, MITRE ATT&CK, Elasticsearch, Kibana
**Assessment:** Nmap, NVD, CPE, CVE analysis
**Development:** Python, Bash, Rust, Cargo, Flask, SQLite
**Lab / Infrastructure:** Debian Linux, Kali Linux, Ubuntu Server, Metasploitable2, VirtualBox, GitHub Actions

## Evidence and Claim Boundaries

```text
synthetic fixture result
!= controlled live-lab result
!= production performance

CVE candidate
!= confirmed applicable vulnerability
!= confirmed exploitability

small lab timing measurement
!= organization-wide analyst productivity
```

Raw packet captures, databases, runtime output, local environments, credentials, and other unnecessary lab artifacts are excluded from Git.

## Scope and Ethics

Active scanning and attack simulation are performed only against isolated systems owned by or explicitly authorized for the operator.

The projects are designed for defensive security engineering, validation, and portfolio demonstration.
