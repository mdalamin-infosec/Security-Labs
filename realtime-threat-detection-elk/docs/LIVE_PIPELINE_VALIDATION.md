# Full live pipeline validation plan

Status: **not yet retained as owner-run end-to-end evidence**.

Target path:

```text
Suricata -> EVE JSON -> Filebeat -> Elasticsearch -> Kibana
```

Completion criteria:

1. Record supported image/tool versions and the exact Git revision.
2. Set the actual lab capture interface in the local `.env` file.
3. Start the Compose stack and confirm service health.
4. Generate controlled labeled traffic.
5. Verify the same event timestamp/flow can be followed from EVE into Elasticsearch.
6. Confirm Kibana index/data view and at least one investigation filter/dashboard.
7. Retain sanitized screenshots plus machine-readable EVE/query evidence.
8. Stop the stack without deleting evidence required for review.

Do not describe this path as completed until those artifacts are retained.
