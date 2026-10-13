# Incident Response Playbook

| Document control | Value |
| --- | --- |
| Identifier | TW-IR-001 |
| Applies to | ThreatWatch Lab 1.0.0, alerts from `suricata/rules/local.rules` |
| Lifecycle terminology | NIST SP 800-61 Rev. 2: preparation, detection and analysis, containment/eradication/recovery, post-incident activity |
| Audience | Analyst on duty in an authorised lab or small environment |

The playbook gives every alert a repeatable first 15 minutes. It is guidance for a lab-scale team, not legal or regulatory advice. Where an action changes a production system (blocking, isolating, resetting credentials), follow your organisation's approval path.

## 1. Triage routine (all alerts)

1. Open the incident from `python -m threatwatch triage <eve.json>` or the Kibana dashboard. Record the incident ID, source, targets, first and last seen.
2. **Confirm the sensor saw what the rule claims.** In Kibana Discover, open the alert and read the raw event and, if captured, the packet or HTTP fields.
3. **Scope.** Search `src_ip : "<source>"` and `dest_ip : "<target>"` over the last 24 hours. Note other signatures, other targets, and any successful connections that follow the alert.
4. **Classify** as true positive, benign positive (authorised scanner, known service), or false positive, and write the reason. Benign positives feed tuning (see `DETECTION_RULES.md`).
5. **Prioritise** using the score: P1 act immediately, P2 within the hour, P3 same working day, P4 batch review. Raise priority by one level if the target is a crown-jewel asset or any host shows evidence of success.
6. **Open the matching playbook below** (the `playbook` value on the rule and in the incident output) and stamp the timestamps `detected_at`, `triaged_at`, `closed_at` in the incident record. These feed `docs/METRICS.md`.

## 2. Playbooks

### `recon-scan` : port scan or host sweep (sid 9000002, 9000003)

- **Likely meaning:** discovery by an attacker, an unmanaged vulnerability scanner, or an administrator.
- **Analyse:** Is the source an approved scanner (check the change calendar or asset list)? Which ports and hosts were touched? Did any connection complete? Did the same source later trigger an access-stage alert? The triage tool raises priority when reconnaissance is followed by an access attempt.
- **Contain:** if unauthorised and internal, isolate the source host from the network segment; if external, block at the perimeter firewall for a fixed period and review exposed services.
- **Eradicate/recover:** close services that should not be reachable; confirm patch level on whatever answered.
- **Close when:** source identified and either authorised or contained, and exposed services reviewed.

### `ssh-brute-force` : repeated SSH connections (sid 9000001)

- **Likely meaning:** credential guessing, or an automation tool with a stale password. The rule counts connection attempts, so it cannot see whether a login succeeded.
- **Analyse:** On the target, review authentication logs (`/var/log/auth.log` or the journal) for the same time window. Failed-only means the attempt failed; an `Accepted` entry from the same source means treat as a **compromise**, not an attempt.
- **Contain:** block the source; if any login succeeded, disable the account, terminate its sessions, and isolate the host.
- **Eradicate/recover:** reset the credentials, require key-based authentication, remove password logins where possible, search for persistence (new keys, cron entries, new accounts).
- **Close when:** no successful login is proven, or compromise handling is complete.

### `web-attack` : scanner user-agent or directory traversal (sid 9000004, 9000007)

- **Likely meaning:** automated web reconnaissance or a probe for file disclosure.
- **Analyse:** Check the web server access log for the response status of each request. 4xx/3xx means the probe was rejected; a 200 on a traversal URI means content may have been disclosed. Check the requested paths against sensitive files.
- **Contain:** block the source at the WAF or firewall; if a 200 returned sensitive content, treat as data exposure and notify the data owner.
- **Eradicate/recover:** patch or reconfigure the vulnerable path, add input validation, review whether credentials in exposed files must be rotated.
- **Close when:** responses are confirmed non-sensitive, or the exposure is remediated and notified.

### `cleartext-credentials` : Basic auth or Telnet (sid 9000005, 9000008)

- **Likely meaning:** a policy violation that exposes credentials to anyone on the path.
- **Analyse:** Identify the application and user, and whether the credentials were reused elsewhere. Check whether the path crosses an untrusted network.
- **Contain:** rotate the exposed credentials; restrict the service to a protected segment until it is fixed.
- **Eradicate/recover:** move the service to TLS or SSH, disable Telnet, and document an exception only if the risk is accepted.
- **Close when:** credentials are rotated and the service no longer accepts cleartext authentication.

### `dns-anomaly` : unusually long DNS label (sid 9000006)

- **Likely meaning:** DNS tunnelling, a domain generation algorithm, or a legitimate service that uses long encoded names (some CDNs, security products, mail validation).
- **Analyse:** Collect the full query names, the querying host, and volume over time. Check whether the same host also appears in the beacon leads (`python -m threatwatch beacons <eve.json>`). Identify the process on the host that issues the queries.
- **Contain:** if unexplained, isolate the host or sinkhole the domain at the resolver.
- **Eradicate/recover:** remove the responsible software, rebuild the host if malicious code is confirmed, and review other hosts that queried the same domain.
- **Close when:** the queries are attributed to a legitimate service, or the host is remediated.

## 3. Escalation criteria

Escalate to the incident owner or security lead when any of these holds: a successful authentication follows a brute-force or credential-exposure alert; data was returned for a traversal request; the same host appears in both a DNS anomaly and a beacon lead; more than one internal host is affected; or a P1 incident is not contained within one hour.

## 4. Evidence handling

Keep the raw EVE lines, relevant packet captures, and server logs. Record hashes for any exported files. Do not paste credentials or full personal data into tickets; reference the log location instead. Retain evidence for the period your policy defines.

## 5. Post-incident review

Within a week of closing a P1 or P2: record what the sensor saw, what it missed, time to triage, and one change to the rules or playbook. Update `suricata/rules/local.rules` (increment `rev`), the CHANGELOG, and re-run `tests/pcap/run_suricata_pcap.sh`.
