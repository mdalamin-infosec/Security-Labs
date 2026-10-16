# Held-out evaluation protocol

This project does not yet claim held-out detection performance.

To produce defensible next-stage metrics:

1. Freeze the Sigma and Suricata rule revisions.
2. Build or acquire a separate attack/benign corpus that was not used while tuning the rules.
3. Keep labels outside the rule implementation and assign stable case IDs.
4. Convert selected Sigma rules using a documented backend/version.
5. Replay the same held-out cases against baseline and tuned rules.
6. Report TP, FN, FP, TN, recall, precision and FPR with sample sizes.
7. Retain configuration/rule hashes and failed cases.

Do not replace this protocol with additional hand-authored examples and call them independent evidence.
