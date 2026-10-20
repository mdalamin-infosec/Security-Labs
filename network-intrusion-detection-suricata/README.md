# network-intrusion-detection-suricata

A VM-based lab for observing custom Suricata alerts, reading EVE JSON and practicing
manual response decisions. Four signatures provide simple traffic signals:

| SID | Matches |
| --- | --- |
| 1000001 | ICMP traffic to `HOME_NET` |
| 1000002 | A source reaching the SYN threshold: 10 packets in five seconds |
| 1000003 | TCP traffic to port 22 |
| 1000004 | TCP traffic to port 4444 |

These signatures show packet visibility and rule behavior. The SYN threshold counts
packets, not distinct destination ports. SSH, ICMP and port 4444 can be legitimate.

## Start the sensor

Install Suricata on the monitored Linux VM. Set `HOME_NET` in
[the configuration](configs/suricata-lab.yaml) and select the actual lab interface.
From this project directory:

```bash
mkdir -p outputs/config-check outputs/live
export LAB_IFACE=enp0s8  # Replace with the actual host-only interface.
sudo suricata -T -c configs/suricata-lab.yaml -S rules/local.rules -l outputs/config-check
sudo suricata -i "$LAB_IFACE" -c configs/suricata-lab.yaml -S rules/local.rules -l outputs/live
```

Keep the vulnerable lab isolated. The monitored VM must receive the test packets;
a host-only switch does not automatically mirror traffic between other VMs.

In another terminal, follow the generated alerts:

```bash
ALERT_LOG=outputs/live/fast.log bash src/monitor_alerts.sh
```

The optional [response script](src/response.sh) offers log-only or UFW actions after
manual selection. Review the event and source before changing a firewall rule.

## Evaluate a recorded session

The existing Python script takes an EVE file, a CSV and an output path:

```bash
python3 tools/evaluate_live.py outputs/live/eve.json outputs/live/ground_truth.csv outputs/live/metrics.json
```

CSV format:

```csv
case_id,label,expected_sid
icmp-session,attack,1000001
syn-session,attack,1000002
```

Populate this from your actual labeled session. **The current evaluator checks only
whether each expected SID appears anywhere in the supplied log.** It does not match
case timestamps or endpoints. Use fresh, isolated evidence for each case; a reused
log can overstate the result. Benign false-positive scoring is not implemented.

An earlier summary records 4/4 live scenarios, but raw EVE and ground truth were
absent from the supplied archive. That result was not reproduced here. The next
code milestone is endpoint/time-window matching with negative-case regression tests.

[Rules](rules/local.rules) · [Existing validation notes](docs/VALIDATION.md) · [Benign cohort plan](docs/BENIGN_COHORT_PLAN.md)
