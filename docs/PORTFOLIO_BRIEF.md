# Security Engineering Portfolio Brief

## Primary Focus

SOC analysis, blue-team engineering, detection validation, network monitoring, incident triage, vulnerability assessment, and secure-code review.

## Key Engineering Evidence

### Detection Engineering
- Developed Sigma and Suricata detection content.
- Validated 20/20 synthetic attack fixtures.
- Executed retained Suricata PCAP replay against 8 controlled attack cases and 4 benign controls.
- Observed 8/8 attack detections and 0/4 benign false positives in that replay corpus.

### Network IDS
- Built a standalone Suricata IDS in an isolated VirtualBox environment.
- Retained four custom SIDs.
- Detected 4/4 labeled live Kali-to-Ubuntu attack scenarios.
- Preserved EVE JSON and explicit ground-truth evidence.

### Incident Triage
- Built ThreatWatch alert correlation and prioritization.
- Added MITRE ATT&CK context, playbook mapping, and beacon analysis.
- Passed 32 automated tests.
- Grouped 21 synthetic alerts into 5 incidents.
- Measured five matched incidents before and with the playbook.

### Vulnerability Assessment
- Built NetSentry around explicit authorized scope.
- Integrated Nmap service discovery with NVD/CPE-based enrichment.
- Completed an authorized live Metasploitable2 assessment.
- Identified 23 open TCP services.
- Checked 8/8 eligible services.
- Retained 296 unique CVE candidates and 297 candidate instances.
- Explicitly separates CVE candidates from confirmed exploitability.

### Secure Code Review
- Reviewed vulnerable and remediated Rust application variants.
- Validated both with locked Cargo checks and Clippy.
- Retained source-level review evidence for query-handling differences.

## Current Unified Validation

```text
PASS=16
FAIL=0
SKIP=0
```

## Engineering Principles Demonstrated

- Evidence before claims
- Explicit authorization and scope
- Reproducible testing
- False-positive awareness
- Attack / benign control separation
- CVE applicability discipline
- Secure-code review
- CI integration
- Retained validation artifacts
- Concise technical documentation

## Claim Boundaries

Laboratory results are reported as laboratory results.

Synthetic results are reported as synthetic.

CVE version matches are reported as candidates rather than confirmed exploitation.

Small timing cohorts are retained as workflow measurements rather than generalized productivity claims.
