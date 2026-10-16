# Security Policy and Operating Boundaries

| Document control | Value |
| --- | --- |
| Identifier | TW-SEC-001 |
| Applies to | ThreatWatch Lab 1.0.0 |

## Supported scope

Use only on networks you own or are authorised to monitor. Packet inspection can expose credentials and personal data in cleartext traffic. Check your organisation's policy and applicable law before capturing.

## Controls and residual risk

- Elasticsearch and Kibana run with security disabled for lab convenience and bind to 127.0.0.1. Do not expose them. For anything beyond a lab, enable authentication and TLS.
- Suricata runs with host networking and `NET_ADMIN`/`NET_RAW`. Run it on a dedicated lab host.
- `scripts/generate_lab_traffic.sh` refuses non-private targets and requires `I_OWN_THIS_LAB=yes`. `scripts/load_sample_to_es.py` refuses non-private Elasticsearch hosts.
- The repository contains no credentials. Keep `.env`, packet captures and real `eve.json` files out of version control.
- Alert data and the incident record can reveal network topology. Handle exports accordingly.

## Vulnerability reporting

If uploaded to GitHub and private vulnerability reporting is enabled, use Security, then Report a vulnerability. Otherwise open a non-sensitive issue requesting a private contact channel. Do not post credentials, private captures, or an active exploit against a third-party system.
