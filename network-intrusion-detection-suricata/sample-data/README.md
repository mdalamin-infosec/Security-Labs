# Sample-data policy

The owner-run live NIDS evidence is retained locally under ignored `outputs/live/` paths because raw EVE can contain environment-specific network data.

Public sample data should be added only after sanitization and should preserve stable case IDs, labels and the minimum fields needed to reproduce metric calculations.

Current public documentation records the measured 4/4 attack result while explicitly leaving live benign FPR unmeasured.
