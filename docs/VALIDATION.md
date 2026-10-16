# Cleanup validation evidence

Environment: Ubuntu 24.04.3 LTS; Python 3.12.14. These are checks executed in the
cleanup environment, not a statement that the owner already repeated the labs.

| Check | Recorded outcome | Evidence / reproduction |
| --- | --- | --- |
| Sigma unit suite | 4 tests passed | [Run output](../sigma-suricata-detection-rules/docs/validation-run.txt); `python -m unittest discover -s tests -v` |
| ThreatWatch unit suite | 32 tests passed | [Run output](../realtime-threat-detection-elk/docs/validation-run.txt); same command from its project |
| NetSentry unit suite | 34 tests passed | [Run output](../enterprise-vulnerability-scanner/docs/validation-run.txt); same command from its project |
| Synthetic Sigma evaluator | All 38 fixture expectations matched | `python tools/evaluate_sigma.py --output outputs/sigma-metrics.json` from the Sigma project |
| Offline ThreatWatch CLI | 21 synthetic alerts, 5 grouped incidents, 1 beacon lead | `python -m threatwatch demo --data-dir outputs/demo-data --report-dir outputs/demo-reports` |
| Offline scanner/export | Demo retained 4 hosts, 8 services, 4 unique example CVEs, 6 endpoint instances, 3 service reviews | Project README demo/export commands; `demo: true` |
| Python packaging | Both wheels built, separately installed, and exercised outside the repo; catalogue and scanner resources available | [Actual packaging record](packaging-run.txt); `python -m build --wheel` in each Python package |
| Flask wheel resources | Six in-process HTTP routes returned 200 | Same packaging record; not a browser/TCP integration test |
| Dependency consistency | `pip check` passed | In the cleanup virtual environment |
| Shell/config/source syntax | Checked during final review | Syntax parsing does not execute the configured services |

Scapy 2.8.0 was installed, but both PCAP generators failed during Linux netlink
socket initialization with `PermissionError: [Errno 1] Operation not permitted`.
Suricata, Docker, Nmap and Rust were absent. Package installation for Suricata
was blocked by this runtime's OS permission constraints. None of those missing
runtime checks is reported as passed.

Operational metrics remain TODO: measure. The root GitHub workflows declare
future checks; their existence does not establish a successful remote CI run.
An independent fresh shallow clone with a separate environment also passed all 70 unit tests; [its actual output](fresh-clone-run.txt) is retained. The full owner-run checklist is [TODO.md](TODO.md).
