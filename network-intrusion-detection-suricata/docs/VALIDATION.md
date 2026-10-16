# Standalone IDS validation

## Completed owner-run live attack cohort

Authorized isolated topology:

```text
Kali source:   192.168.56.104
Ubuntu target: 192.168.56.102
```

The retained live session evaluated four labeled cases and observed the expected SID for each:

| Case | Expected SID | Result |
| --- | ---: | --- |
| ICMP | 1000001 | Detected |
| SYN threshold | 1000002 | Detected |
| TCP/22 | 1000003 | Detected |
| TCP/4444 | 1000004 | Detected |

Recorded metrics:

```text
TP=4
FN=0
Detection rate=4/4 (100%) for this controlled attack cohort
```

Raw EVE and ground-truth artifacts remain under ignored local `outputs/live/` paths.

## What is not yet measured

The retained live cohort contains no independently labeled benign sessions. Therefore live TN, FP and FPR are not claimed.

Use [BENIGN_COHORT_PLAN.md](BENIGN_COHORT_PLAN.md) for the next validation step. Manual UFW response behavior also remains separate from detection validation.
