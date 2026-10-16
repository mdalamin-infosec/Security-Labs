# Standalone IDS validation

Recorded cleanup check: `bash -n src/monitor_alerts.sh src/response.sh` passed.
All real-engine and response behavior below is **TODO: test**.

## Exact live case set
On the Kali VM, install `hping3`, `netcat-openbsd` and `iputils-ping`.
Set `TARGET_IP` to the isolated Ubuntu target you control:

```bash
TARGET_IP=192.168.56.102
ping -c 4 "$TARGET_IP"
sudo hping3 -S -p 8080 -c 12 -i u100000 "$TARGET_IP"
sudo hping3 -S -p 22 -c 1 "$TARGET_IP"
nc -vz -w 2 "$TARGET_IP" 4444
```

Run cases separately, allowing threshold windows to expire. The expected
relevant SIDs are 1000001, 1000002, 1000003 and 1000004 respectively.
Additional SYN matches can occur when cases share a source/window. A closed
destination port can still produce an alert because the sensor sees the probe.

For a control, send one ordinary HTTP request to an authorized lab web service
on port 80, in a separate fresh observation window. Record the target/service
configuration; no HTTP service is supplied by this project. The broad rules can
match benign activity. Do not invent a zero false-positive result.

## Evidence and response
Record OS, Suricata build, interface, HOME_NET, rules hash, exact commands, case
start/end times, packet loss and actual SIDs. Save a small sanitized EVE/PCAP
excerpt with stable case labels under `sample-data/` only after reviewing it.

Use the response script's log-only choice first. On a disposable VM, review the
hardcoded protected IP, test the UFW command's exit status and verify the actual
firewall state. Record the exact rollback for the test rule before blocking.
No containment success is currently measured.

TODO: measure recall/FPR only with independent attack/benign labels and session
counts. Four generated probes or six screenshots cannot establish efficacy.
