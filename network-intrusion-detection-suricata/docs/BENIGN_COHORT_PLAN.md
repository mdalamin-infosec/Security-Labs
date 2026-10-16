# Live benign cohort plan

Status: **not yet executed**.

Run benign sessions in separate observation windows against the same Ubuntu target, for example:

- normal SSH connection to an authorized account
- ordinary ping
- normal HTTP request to a lab web service
- standard DNS query
- package metadata update
- Git clone from an allowed destination
- idle/background traffic window

Assign stable case IDs before replay. For every case, record start/end time, source/destination, expected label and observed SIDs.

Combine the resulting benign labels with the existing four attack cases and report TP/FN/FP/TN, recall and FPR. Do not assume zero false positives before running the cohort.
