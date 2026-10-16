# Detection Rule Catalogue

Rules live in `src/threatwatch/data/local.rules` (SID 9000001 to 9000008). `python -m threatwatch rules` prints the catalogue from the same file.

| SID | Detects | ATT&CK | Severity | Playbook | Trigger |
| --- | --- | --- | --- | --- | --- |
| 9000001 | Repeated SSH connection attempts | T1110 Brute Force | high | `ssh-brute-force` | 5 SYNs to port 22 from one source in 60 s |
| 9000002 | SYN burst across ports | T1046 Network Service Discovery | medium | `recon-scan` | 30 SYNs from one source in 10 s |
| 9000003 | ICMP echo burst | T1018 Remote System Discovery | low | `recon-scan` | 10 echo requests from one source in 10 s |
| 9000004 | Scanner user-agent | T1595 Active Scanning | medium | `web-attack` | User-Agent matches sqlmap, nikto or Nmap Scripting Engine |
| 9000005 | HTTP Basic auth in cleartext | T1040 Network Sniffing (exposure) | medium | `cleartext-credentials` | `Authorization: Basic` header over HTTP |
| 9000006 | Long DNS label | T1071.004 Application Layer Protocol: DNS | medium | `dns-anomaly` | Query label of 40 or more characters |
| 9000007 | Directory traversal | T1190 Exploit Public-Facing Application | high | `web-attack` | `../` or `%2e%2e%2f` in the request URI |
| 9000008 | Telnet to an internal host | T1021 Remote Services | medium | `cleartext-credentials` | Established session to port 23, one alert per source per 5 minutes |

## Known false positives and tuning

- **9000001** Automation that reconnects often (backups, Ansible, monitoring) will fire. Add the source to a pass rule or an allowlist threshold, and record the reason.
- **9000002 / 9000003** Authorised vulnerability scanners and network monitoring. Use `suppress` entries in `threshold.config` for approved scanner addresses rather than editing the rule.
- **9000004** Authorised security testing uses the same user-agents. Coordinate with testers.
- **9000005** Legacy internal tools using Basic auth over HTTP are real exposure, not false positives, but may be accepted risk.
- **9000006** CDNs, some security products and anti-spam lookups use long labels. Review the domain before acting; the rule is a lead for tunnelling or DGA, not proof.
- **9000007** Pentest and QA traffic, and applications that legitimately pass relative paths.

## Change procedure

1. Edit the rule and increment `rev`. Keep the `metadata` keys complete.
2. Run `python -m unittest discover -s tests` (metadata and format checks).
3. Run `tests/pcap/run_suricata_pcap.sh` (needs Suricata and scapy). Add a pcap case for any new rule or any false positive you fixed.
4. Record the change and the reason in `CHANGELOG.md`.

Thresholds are lab defaults chosen for clarity, not tuned values from production traffic. Measure alert volume on your own network for at least a week before relying on them.
