# Interview questions

## sigma-suricata-detection-rules
1. Why do 38 passing synthetic fixture expectations fail to establish an operational detection rate, and how would you design a held-out evaluation?
2. What telemetry/field normalization do the Sigma rules need, and how can the local evaluator differ from a real backend?
3. How would you tune parent-process exclusions without concealing malicious use of administrative tools?

## network-intrusion-detection-suricata
1. Which packets can this VM topology observe, and what visibility would a separate passive sensor need?
2. Why are an SSH connection, SYN burst or port-4444 match insufficient to establish brute force, a port scan or malware?
3. How would you validate a manual block, protect management access, reject stale alerts and demonstrate rollback?

## realtime-threat-detection-elk
1. Follow one alert through Suricata, EVE, Filebeat, Elasticsearch and Kibana: how would you diagnose a missing or mis-timestamped event?
2. How does the triage logic group/score events, and where can its heuristic tactic labels overstate an attack sequence?
3. What evidence would justify a triage-time improvement claim while controlling case mix and analyst learning?

## enterprise-vulnerability-scanner
1. Why is a CPE-to-CVE match only a candidate, and how do platform prerequisites and vendor backports affect applicability?
2. How are scan scope and partial/failed NVD enrichment represented without incorrectly declaring a clean result?
3. Why are unique CVEs, endpoint instances, CVSS severity and the custom priority score different quantities?

## secure-code-review
1. How can SQL and shell injection exist in memory-safe Rust, and which source changes address the relevant sinks?
2. What does Argon2 verification demonstrate when the application has neither enrollment nor seeded hashes?
3. Which remaining controls prevent the partially remediated app from being used as a production login service?
