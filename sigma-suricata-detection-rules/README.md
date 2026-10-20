# Sigma and Suricata Detection Rules

A small detection-engineering collection: **15 Sigma process-creation rules** and
**eight Suricata HTTP/DNS signatures**, with labeled examples for repeatable checks.

## Run the Sigma examples

From this project directory, with Python 3.11+:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/evaluate_sigma.py --output outputs/sigma-metrics.json
```

The existing suite passes **four tests**. The bundled corpus has 38 events: 20
attack-labeled and 18 benign. The tuned evaluator matches all 20 attack examples
and none of the 18 benign controls. Removing approved-parent suppressions produces
three false positives in the defined baseline.

[Windows/Linux rules](rules/sigma/) · [Fixture events](sample-data/sigma_events.jsonl) · [Evaluator](tools/evaluate_sigma.py)

## What the evaluator supports

The Python harness handles the selections, boolean conditions and field modifiers
used by these rules. It rejects unsupported constructs. This makes local regressions
quick to inspect; deployment to an Elastic or Splunk backend needs separate conversion
and execution checks. The fixtures were developed with the rules, so they measure
regression behavior rather than performance on unseen operational logs.

## Replay the Suricata signatures

Install Suricata through your Linux distribution, then:

```bash
python -m pip install -r requirements-pcap.txt
python tools/generate_pcaps.py
python tools/replay_suricata.py --config configs/suricata-lab.yaml
```

The generator creates synthetic HTTP/DNS PCAPs. Replay validates the engine
configuration, checks the labeled captures and retains engine output plus hashes
under `outputs/`. This reads local captures and sends no traffic.

The engine replay was not rerun in the documentation review environment. Earlier
8/8 attack and 0/4 benign replay figures are recorded in the supplied validation
notes, but their raw replay outputs were absent from the archive.

## Next evaluation step

Freeze the rules, then test an untouched corpus containing legitimate administration
and normal protocol traffic. Review missed cases and unexpected matches alongside raw
counts. Plaintext HTTP signatures require visibility into HTTP; encrypted payloads
need a separate visibility path.

[Existing validation notes](docs/VALIDATION.md) · [Held-out evaluation plan](docs/HELD_OUT_EVALUATION.md)
