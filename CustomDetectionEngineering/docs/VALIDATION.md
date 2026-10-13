# Detection validation strategy

## Telemetry and prerequisites
- **Sigma**: requires normalized Windows/Linux process-creation logs with `Image`, `CommandLine`, `ParentImage`, `User`, `Computer`. Windows Sysmon Event ID 1 is one possible input. Linux requires auditd/eBPF/EDR process data normalized into this schema. A SIEM backend needs compatible field mappings.
- **Suricata**: tests need Suricata installed, actual YAML config, HOME_NET containing `192.168.1.0/24`, EXTERNAL_NET containing `198.51.100.0/24`, HTTP/DNS protocol detection, and EVE JSON alert output. All PCAPs use documentation or lab-only IPs; no payload is transmitted.
- The one-off regex/command rules are low-to-medium-fidelity **signals**, not a substitute for multi-event correlation or validated detection engineering.

## Unit test and toy event fixtures

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/evaluate_sigma.py --output outputs/sigma_metrics.json
```

The offline evaluator intentionally supports **only** direct field matching and `contains`, `endswith`, `startswith`, `and`, `or`, `not`. It is **not** Sigma's full grammar and **not** a production SIEM. Its generated synthetic events were written to demonstrate rule behavior, not to measure real-world detection efficacy.

## Validate syntax with real engines

The Sigma rules use standard keys for `process_creation`. Validate conversion using SigmaHQ tooling and your SIEM backend. See https://sigmahq.io/docs/ and https://github.com/SigmaHQ/pySigma . Actual production validation must use replay of correctly normalized telemetry into the chosen SIEM.

```bash
sudo apt-get update
sudo apt-get install -y suricata
sudo suricata -T -c /etc/suricata/suricata.yaml -S suricata/custom.rules
```

If using a nonstandard HOME_NET (common), set it in your copy of `/etc/suricata/suricata.yaml` to include your **lab** destination `192.168.1.0/24`; keep real production HOME_NET separate from the lab if appropriate.

## Suricata actual offline replay

```bash
pip install -r requirements-pcap.txt
python tools/generate_pcaps.py
sudo -E $(which python3) tools/replay_suricata.py --config /etc/suricata/suricata.yaml
```

Depending on file permissions and your setup, use a terminal with Suricata permissions instead of `sudo -E`. Synthetic HTTP handshake and DNS traffic is parsed by the *real* Suricata engine; failures to trigger require inspection and tuning. `-T` validates configuration, not whether detection works.

## Real alert metrics (event-level labels)

A labeled evaluation dataset should include representative attack **and benign** sessions. Every case needs a stable `case_id` and a corresponding ground-truth label independent of the engine. For each attack case, at least one relevant alert counts as detected. For each benign case, any alert counts as a false positive.

| Metric | Formula |
|---|---|
| Detection rate / Recall | TP / (TP + FN) |
| False-positive rate | FP / (FP + TN) |
| Relative reduction in FP alerts | (FP_baseline - FP_tuned) / FP_baseline |
| Precision | TP / (TP + FP) |

One should **not** advertise 95% detection or 30% reduction based only on hand-authored toy fixtures, or confuse per-rule matches with distinct attacked sessions. Use representative samples, compare against a frozen baseline on the *same* held-out dataset, and report sample size, distribution, observation window, and confidence intervals.

## Tuning and operations
1. Capture pre-tuning alerts on a held-out, labeled workload and record rule SIDs/IDs.
2. Group false positives by command-line, executable signer, parent process, user/service account and host role.
3. Add *narrow, documented* exclusions; never blanket-exclude PowerShell, admin tools, or an entire network range.
4. Re-evaluate both attack recall and benign FP rate; roll back exclusions that hide replayed attacks.
5. Record baselines, post-tuning metrics, traffic volumes, reviewed cases, rule versions, and deployment date.
6. Set an alert owner, runbook, triage severity, and maintenance cadence.

**Risk:** `ParentImage`-based exclusions in example Sigma rules are only starter allowlist examples; signed/admin parent processes can be abused. Verify executable signature, file path, command parameters, parent/child behavior, and change provenance before using suppressions in production.
