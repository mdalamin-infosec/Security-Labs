# Validation record

## Automated and fixture checks

```bash
python -m unittest discover -s tests -v
python tools/evaluate_sigma.py --output outputs/sigma-metrics.json
```

Current owner-validated result:

```text
4 unit tests passed
20/20 synthetic attack fixtures detected
18 benign fixtures evaluated
baseline FP 3 -> tuned FP 0
```

## Actual Suricata replay

```bash
python -m pip install -r requirements-pcap.txt
python tools/generate_pcaps.py
python tools/replay_suricata.py --config configs/suricata-lab.yaml
```

The retained owner run executed the real Suricata engine against 12 generated PCAP cases:

- Attack: `http_traversal`, `http_passwd`, `http_sqli`, `http_git`, `http_env`, `http_scanner`, `http_cgi`, `dns_exfil`
- Benign: `http_normal`, `http_docs`, `http_health`, `dns_normal`

Recorded result: **8/8 attack cases detected and 0/4 benign false positives**.

This is controlled synthetic replay evidence, not an operational benchmark.

## Next evidence upgrade

Use an independent held-out corpus and a real Sigma backend. See [HELD_OUT_EVALUATION.md](HELD_OUT_EVALUATION.md).
