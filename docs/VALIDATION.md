# Validation model and current evidence

This repository separates four evidence classes so that a passing test is not presented as a production-security claim:

1. **Automated source/unit validation** — deterministic tests and build/lint checks.
2. **Synthetic fixture validation** — labeled events or PCAPs created for the lab.
3. **Controlled live-lab validation** — owner-run traffic or scans inside an isolated VirtualBox network.
4. **Operational claims** — production efficacy, exploitability, and organization-wide analyst productivity. These are **not** established by this repository.

## Latest owner-run result

The generated source of truth is [RESULTS-LATEST.md](RESULTS-LATEST.md).

```text
PASS=16
FAIL=0
SKIP=0
```

Key retained measurements from the latest owner run:

| Area | Evidence class | Current result |
| --- | --- | --- |
| Sigma unit suite | Automated | 4 tests passed |
| Sigma labeled fixture evaluation | Synthetic | 20/20 attack fixtures detected; 18 benign fixtures evaluated |
| Suricata PCAP replay | Real engine + synthetic PCAP | 8/8 attack cases detected; 0/4 benign false positives |
| Standalone NIDS | Controlled live lab | 4/4 labeled attack scenarios detected; no live benign cohort yet |
| ThreatWatch | Automated + synthetic | 32 tests; 21 alerts grouped into 5 incidents |
| ThreatWatch lifecycle timing | Owner-measured lab workflow | 5 before-playbook + 5 with-playbook incidents; second-scale timings |
| NetSentry | Controlled live lab | 23 open services; 296 unique NVD/CPE CVE candidates; 8/8 eligible services checked |
| Rust review | Automated build/lint + source review | `cargo check --locked` and Clippy passed for both variants; HTTP runtime regression remains separate |

## Reproduction

From the repository root:

```bash
chmod +x run_all_security_results.sh
./run_all_security_results.sh
```

A clean public clone can reproduce the committed offline portions. Some live checks depend on owner-retained evidence under ignored `outputs/` directories and therefore may report a different status on another machine until the same authorized lab is recreated.

GitHub Actions independently exercises the committed Python, Rust and Suricata/offline-PCAP paths. CI does not reproduce the owner's private VirtualBox topology.

## Claim boundaries

- A fixture percentage is a fixture percentage, not an operational detection rate.
- A controlled VM-lab result applies only to the labeled cases retained for that run.
- A CPE/NVD match is a **CVE candidate**, not proof that the target is vulnerable or exploitable.
- The ThreatWatch 5-vs-5 timing exercise is a small workflow measurement, not a general productivity claim.
- The live standalone NIDS cohort contains attack cases only; therefore live false-positive rate is not measured.

See [TESTING_STRATEGY.md](TESTING_STRATEGY.md), [LIMITATIONS.md](LIMITATIONS.md), and [ROADMAP.md](ROADMAP.md) for the next evidence upgrades.
