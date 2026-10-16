# Current validation record

Verified cleanup runtime: Ubuntu 24.04.3 LTS, Python 3.12.14.
[Actual unit output](validation-run.txt) contains 32 passing tests:
`python -m unittest discover -s tests -v`.

The synthetic CLI completed and reported 21 alerts, five grouped incidents and
one beacon lead. These are generated demo counts, not observed attack outcomes.
[Installed-wheel evidence](../../docs/packaging-run.txt) verifies that the rule
catalogue remains packaged and the CLI runs outside the checkout.

## Exact real-engine test set — TODO: test
The [scenario manifest](../sample-data/cases.json) corresponds to
`tests/pcap/make_pcap.py`: 12 ICMP packets, 35 SYN probes, six SSH SYNs,
scanner HTTP user-agent, cleartext demo Basic header, traversal URI, Telnet
session, long DNS label and benign DNS control.

From the project root:
```bash
python -m pip install -r ../sigma-suricata-detection-rules/requirements-pcap.txt
bash tests/pcap/run_suricata_pcap.sh
```

The script retains a unique `outputs/replay.*` directory containing input PCAP,
engine build info, configuration, EVE and engine logs. The assertions require
SIDs 9000001–9000008 and no alert from the benign DNS control source.
This deliberately small corpus does not measure operational recall or FPR.

During cleanup, the generator could not import Scapy's Linux interface module
because opening a netlink socket was denied. Suricata was absent. Older
unretained claims about Suricata 7.0.3, eight firing signatures or six incidents
are not carried forward as current measured results.

## End-to-end stack — TODO: test
Copy/edit `configs/.env.example`, then run the Compose command in the README.
Confirm the actual interface, engine version, file permissions, EVE output,
Filebeat timestamp parsing, Elasticsearch `threatwatch-eve-*` index/mappings,
and Kibana dashboard setup against live services. Also test
`scripts/load_sample_to_es.py`; its synthetic import must remain clearly labeled.

TODO: review inherited image pins for support/security and test compatible
updates. The declared Suricata image is 7.0.7, not the historical 7.0.3 claim.

## Operational metrics — TODO: measure
Follow [METRICS.md](METRICS.md). Populate real lifecycle records with timezone-
aware timestamps and case/cohort labels. Replay comparable case sets for both
workflows. Report sample size and absolute median times alongside percentage
changes. No triage-time improvement or operational detection percentage is
measured by this repository.
