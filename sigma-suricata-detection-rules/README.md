# Custom Detection Engineering: Sigma + Suricata

An **experimental SOC / Blue-Team lab** with 15 Sigma process-creation detection rules (13 Windows + 2 Linux), 8 Suricata IDS signatures (7 HTTP + 1 DNS), synthetic test fixtures, automated unit tests, offline PCAP generation, optional **real Suricata** replay, and measurable alert statistics.

**Do not claim 95% attack detection or 30% fewer false positives without measuring on representative labeled data.** The included fixtures are deliberately synthetic tests of the detection logic; they provide zero evidence for operational performance.

## Layout

```
sigma-suricata-detection-rules/
├── sigma/windows/                # 13 process-creation Sigma YAML rules
├── sigma/linux/                  # 2 process-creation Sigma YAML rules
├── suricata/custom.rules        # 8 HTTP/DNS signatures (SIDs 4200001..4200008)
├── tests/fixtures/              # Labeled synthetic Sigma JSONL & PCAP scenarios
├── tests/test_detection.py      # Standard-library unittest suite
├── tools/evaluate_sigma.py      # Restricted-subset local evaluator and metrics
├── tools/generate_pcaps.py      # Scapy offline PCAP creator (optional)
├── tools/replay_suricata.py     # Real Suricata replay + EVE alert scoring (optional)
└── docs/VALIDATION.md           # Deployment prerequisites and limits
```

## Quick start (Debian / Ubuntu / Kali)

```bash
cd ~/GitHub-Repositories/Security-Labs/CustomDetectionEngineering
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/evaluate_sigma.py --output outputs/sigma_metrics.json
```

`outputs/` is gitignored and stores only local evaluation results. To test **real** Suricata syntax on a Debian host:

```bash
sudo apt update && sudo apt install -y suricata
sudo suricata -T -c /etc/suricata/suricata.yaml -S suricata/custom.rules
```

For executable offline packet testing with Scapy, see [`docs/VALIDATION.md`](docs/VALIDATION.md).

### What it detects
- **Sigma (Windows):** encoded PowerShell, PowerShell downloads, certutil, BITSAdmin, mshta, regsvr32, MiniDump via rundll32, schtasks, shadow deletion, WMIC remote process create, local admin group changes, event log clearing, InstallUtil suspicious flags.
- **Sigma (Linux):** curl-piped shell, world-writable chmod operation. Linux rules depend on normalized process-creation telemetry, *not* syslog by default.
- **Suricata:** traversal, passwd read, UNION SELECT probing, `.git/config`, `.env`, sqlmap user-agent, CGI shell probes, **lab-only** DNS exfil indicator under the reserved `.invalid` TLD.

### Limits / caution
- The DNS signature is an explicit **laboratory IOC** and will not detect arbitrary real exfiltration.
- Signature matches may be due to authorized scans, administration, or adversarial evasion. Test against real benign workloads and tune by environment.
- The limited Python Sigma harness is **not** a SIEM backend. Field mappings must be verified against your deployment.
- Parent-based filters illustrate possible false-positive tuning but can conceal malicious activity; production use requires review.
- Suricata only observes traffic visible to its sensor; HTTPS URI contents are encrypted without decryption.

## GitHub upload
Extract this folder into your existing `~/GitHub-Repositories/Security-Labs/` checkout, inspect changes, then commit and push it to `master`. Do not copy secrets, credentials, captured private PCAPs, or lab-generated logs into the public repo.
