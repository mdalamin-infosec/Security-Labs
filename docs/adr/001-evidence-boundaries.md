# ADR-001: Separate synthetic, live-lab and operational claims

**Status:** Accepted

## Context

Security portfolios can accidentally turn a successful unit test, a synthetic replay, or a version-match CVE into a much broader claim than the evidence supports.

## Decision

Every metric in this repository must identify its evidence class:

- automated/unit
- synthetic fixture
- real-engine replay
- controlled live lab
- operational/production

The generated results report uses this distinction when wording detection rates, false positives, lifecycle timing and CVE counts.

## Consequences

- Some headline numbers are intentionally qualified.
- Live evidence can remain local when publishing raw artifacts would be unnecessary or unsafe.
- A candidate CVE remains a candidate until applicability is reviewed.
- Missing benign live traffic is reported as an unmeasured live FPR rather than converted into a zero.
