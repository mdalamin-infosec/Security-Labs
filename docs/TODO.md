# Personal lab validation and evidence checklist

The executed offline checks are in [VALIDATION.md](VALIDATION.md).
The grouped items below cover outstanding TODOs across project READMEs,
validation documents, sample-data notes and the inherited lab configuration.
A TODO is not a completed result.

| ID | Project / remaining work | How to complete it |
| --- | --- | --- |
| T01 | All: source ownership, attribution, licensing and screenshots — TODO: verify | Confirm which files you wrote/adapted. Replace third-party source with upstream links; if an explicitly justified copy remains, retain its license and mark only those paths `linguist-vendored`. Review owner provenance and sensitive data for the six visually inspected IDS screenshots and retained samples; capture-command images are not alert/status/response evidence. |
| T02 | All: personally tested environment — TODO: record | Retain actual OS/tool builds, repository revision, configuration, commands, exit status and dates from your own lab. The cleanup's Ubuntu/Python record does not validate every target platform. |
| T03 | Sigma: backend and real telemetry — TODO: test | Repeat the four unit tests and all 38 fixture cases. Convert the 15 rules with your chosen Sigma backend; record backend/version/command, field mappings and replayed Windows/Linux process telemetry. The local subset evaluator is not a SIEM. |
| T04 | Sigma: PCAP generation and actual engine — TODO: test | Run the documented generator and replay with `configs/suricata-lab.yaml`. Retain all 12 scenario outcomes, PCAP hashes, EVE, build-info and logs. Generation was blocked by socket permissions here; the engine was unavailable. |
| T05 | Detection quality — TODO: measure | Independently label representative held-out attack and benign sessions. Count TP/FN/FP/TN and publish recall, precision, FPR, sample sizes and conditions. Compare baseline/tuned rules on the same workload before claiming FP reduction; do not promote toy-fixture percentages to operational performance. |
| T06 | Standalone IDS: four SIDs — TODO: test | Follow its `docs/VALIDATION.md` for ICMP, SYN burst, SSH TCP and TCP-4444 cases, plus separate-window benign controls. Record packet visibility/loss, timestamps, configuration and actual SID matches. |
| T07 | Standalone IDS: manual response — TODO: test | Begin with log-only. On a disposable VM review the hardcoded protected address, verify UFW exit status and firewall state, check stale-alert/IPv4 parsing limitations, and demonstrate rollback. Printed success is insufficient. |
| T08 | ELK: actual-engine replay — TODO: test | Repeat the 32 unit tests and run `bash tests/pcap/run_suricata_pcap.sh`. Review all eight SIDs and the benign DNS control against the exact `sample-data/cases.json` manifest. Retain the output directory. |
| T09 | ELK: supported versions and full live pipeline — TODO: test | Review inherited image support/security status and test compatible pins. Set the actual interface in `configs/.env`. Verify Suricata → EVE → Filebeat timestamps/mappings → Elasticsearch index → Kibana/dashboard; test both setup and sample-loader scripts. |
| T10 | ELK: investigation improvement — TODO: measure | Fill lifecycle records with real timezone-aware detected/triaged/closed timestamps. Compare equivalent cohorts via the metrics CLI; retain case mix, sample sizes, absolute median times and percentage change. No time-saved claim is currently measured. |
| T11 | Scanner: live integration and browser — TODO: test | Repeat the 34 tests, then collect on an explicit authorized lab scope. Retain Nmap XML, scope and tool build. Exercise live NVD success/cache/failure/pagination and record query/time provenance. Test real desktop/mobile browser filters, details and downloads. |
| T12 | Scanner: real vulnerability results — TODO: measure | Confirm installed vendor build, distribution backports and configuration prerequisites for every candidate. Count unique applicable CVEs separately from host/service instances and service reviews; preserve analyst dispositions. Demo counts are not discovered vulnerabilities. |
| T13 | Rust: build and localhost regressions — TODO: test | Run locked Cargo checks/Clippy and every case in its `docs/VALIDATION.md`. Record actual HTTP responses. Implement and test explicit synthetic Argon2 user provisioning before claiming successful secure login; an empty DB returning 401 proves little. |
| T14 | Rust: remaining security gaps — TODO: verify | Personally explain GET credentials, missing authorization/enrollment/session controls, unused secret/fallback, startup errors and outbound-target risk. Any functional remediation beyond this cleanup should get its own scoped change and tests. |
| T15 | Final repo: remote CI and independent fresh-clone walkthrough — TODO: test | Run all three root workflows after publishing the branch. Repeat each README from a clean clone on your lab host, review the recorded checks, and verify sample sanitization and generated-file exclusions. Check GitHub's language chart after it reprocesses the tree. Prior committed build history is not erased. |

No Atomic Red Team test IDs or executions are claimed. Add exact IDs, tool
versions and retained evidence only after selecting and running those tests.

## How to retain evidence
Keep raw private outputs under ignored `outputs/` or `data/`. After reviewing
and sanitizing, retain only small relevant excerpts under `sample-data/` or
`docs/`. Record input identity/hash, command, tool version, starting state and
actual result. Preserve failed checks as failures; do not make screenshots or
logs to fill missing evidence.
