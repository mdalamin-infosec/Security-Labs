# Portfolio limitations

The repository is intentionally explicit about what the evidence does **not** prove.

## Detection

- Sigma fixture cases were designed alongside the rules, so they are not independent held-out evidence.
- The Suricata PCAP replay uses controlled synthetic traffic; it is not production network traffic.
- The standalone live NIDS result contains four attack cases and no labeled benign live cohort, so live FPR is not available.
- Several signatures are intentionally broad learning signals and can match legitimate behavior.

## ThreatWatch / ELK

- The 5-vs-5 timing exercise is small and second-scale; the percentage change should not be generalized to analyst productivity.
- The Python triage path is validated more deeply than the full Docker/Elastic/Kibana operational path.

## NetSentry

- Nmap version detection and NVD/CPE matching produce candidates, not confirmed vulnerable packages.
- Distribution backports, product configuration and prerequisite conditions require analyst review.
- The current live target is intentionally vulnerable Metasploitable2 and is not representative of a modern enterprise fleet.

## Secure code review

- `cargo check` and Clippy validate build/lint quality, not HTTP security behavior.
- The remediated sample is deliberately incomplete and should not be treated as a production authentication service.

## Generalization

This is a portfolio lab. The strongest use of the results is to demonstrate engineering process: scoping, repeatability, measurement, evidence handling, and honest interpretation.
