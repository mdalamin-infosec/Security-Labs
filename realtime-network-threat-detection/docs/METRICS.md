# Measuring Triage and Investigation Time

The project records incident timestamps so that time-to-triage and time-to-close can be **measured** rather than assumed. No improvement figure is claimed by this repository. Any percentage you publish must come from your own records.

## Records

Copy `docs/templates/lifecycle-records.csv` and add one row per incident:

```
incident_id,cohort,detected_at,triaged_at,closed_at
INC-0001,before-playbook,2026-10-14T09:00:00+00:00,2026-10-14T09:25:00+00:00,2026-10-14T10:10:00+00:00
```

Timestamps are ISO 8601 with an offset. `detected_at` is when the alert was generated, `triaged_at` when an analyst first classified it, `closed_at` when the incident record was closed.

## Commands

```bash
python -m threatwatch metrics records.csv
python -m threatwatch metrics records.csv --baseline before-playbook --treatment with-playbook
```

The tool prints incident count, median and mean minutes to triage and to close per cohort, and the percent change in medians (negative means faster).

## What makes a comparison fair

- Use the same incident types in both cohorts, or compare per type. A cohort of easy port scans against a cohort of web compromises says nothing.
- Medians resist outliers; report the sample size next to every percentage.
- Replay the same set of simulated attacks (for example `scripts/generate_lab_traffic.sh`) under both conditions so only the process differs: ad hoc investigation against the playbook with dashboards.
- Small samples are anecdotes. State the number of incidents and the conditions whenever you quote a result, for example "median time to triage fell from X to Y minutes across N simulated incidents".
