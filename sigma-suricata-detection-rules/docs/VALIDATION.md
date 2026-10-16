# Validation record and repeatable test set

The cleanup run used Ubuntu 24.04.3 LTS, Python 3.12.14 and PyYAML 6.0.3.
[Actual test output](validation-run.txt) records four passing test methods.
Run from the project root after installing `requirements.txt`:

```bash
python -m unittest discover -s tests -v
python tools/evaluate_sigma.py --output outputs/sigma-metrics.json
sha256sum sample-data/sigma_events.jsonl sample-data/suricata_cases.json
```

## Exact synthetic corpus
- [sigma_events.jsonl](../sample-data/sigma_events.jsonl): `atk_01`–`atk_15`,
  `ben_01`–`ben_15`, `ben_approved_04`, `ben_approved_08`,
  `ben_approved_11`, and `atk_variant_01`, `02`, `03`, `06`, `09`
  (the variants have the full `atk_variant_` prefix). Total: 38 rows.
- [suricata_cases.json](../sample-data/suricata_cases.json): attack-labeled
  `http_traversal`, `http_passwd`, `http_sqli`, `http_git`, `http_env`,
  `http_scanner`, `http_cgi`, `dns_exfil`; benign `http_normal`,
  `http_docs`, `http_health` and `dns_normal`. Total: 12 cases.

These labels are fixture expectations, not claims that an attack succeeded.

## Actual-engine replay
```bash
python -m pip install -r requirements-pcap.txt
python tools/generate_pcaps.py
python tools/replay_suricata.py --config configs/suricata-lab.yaml
```

The replay runs Suricata `-T` before reading individual PCAPs with `-r`,
`-k none` and single run mode. Disabling checksum validation is an offline-test
choice. Keep the generated captures, engine build info, EVE files, command logs,
input hashes and summary from the retained output directory. A configuration
load pass alone does not prove signatures fire.

Cleanup outcome: Scapy 2.8.0 imported its Linux interface module and encountered
`PermissionError: [Errno 1] Operation not permitted` while opening a netlink
socket. No PCAP-generation or Suricata success is claimed. Suricata was absent.

## Deployment and efficacy checks
TODO: convert these rules with the intended Sigma backend, record its exact
version/command, and replay normalized process telemetry. A Windows source can
be Sysmon Event ID 1; Linux needs compatible process-creation telemetry.
The evaluator supports only the modifiers and expressions in its source.

TODO: measure on an independently labeled held-out dataset. Count TP/FN by
attacked session and FP/TN by benign session. Report:
`recall=TP/(TP+FN)`, `precision=TP/(TP+FP)`, `FPR=FP/(FP+TN)`.
For tuning, replay the same dataset against frozen baseline/tuned rules and
report `(FP_baseline-FP_tuned)/FP_baseline` only when the denominator is nonzero.
Retain case IDs, observation window, rule revision, sample size and uncertainty.
No Atomic Red Team test execution is recorded.
