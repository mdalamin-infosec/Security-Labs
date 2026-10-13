from pathlib import Path
import tempfile
import unittest

from threatwatch.metrics import MetricsError, compare, load_records, summarize

HEADER = "incident_id,cohort,detected_at,triaged_at,closed_at\n"


class MetricsTests(unittest.TestCase):
    def csv(self, body):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "m.csv"
        path.write_text(HEADER + body)
        return path

    def test_summary_and_comparison_use_medians(self):
        body = ("A1,before,2026-10-14T09:00:00+00:00,2026-10-14T09:20:00+00:00,2026-10-14T10:00:00+00:00\n"
                "A2,before,2026-10-14T09:00:00+00:00,2026-10-14T09:40:00+00:00,2026-10-14T11:00:00+00:00\n"
                "B1,after,2026-10-14T09:00:00+00:00,2026-10-14T09:15:00+00:00,2026-10-14T09:45:00+00:00\n")
        summary = summarize(load_records(self.csv(body)))
        self.assertEqual(summary["before"]["median_triage_min"], 30)
        self.assertEqual(summary["after"]["incidents"], 1)
        self.assertEqual(compare(summary, "before", "after"), {"median_triage_min": -50.0, "median_close_min": -50.0})

    def test_out_of_order_timestamps_are_rejected(self):
        with self.assertRaises(MetricsError):
            load_records(self.csv("A,x,2026-10-14T09:10:00+00:00,2026-10-14T09:00:00+00:00,2026-10-14T10:00:00+00:00\n"))

    def test_timestamp_without_timezone_is_rejected(self):
        with self.assertRaises(MetricsError):
            load_records(self.csv("A,x,2026-10-14T09:00:00,2026-10-14T09:05:00,2026-10-14T10:00:00\n"))

    def test_missing_column_and_empty_file_are_rejected(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        bad = Path(folder.name) / "bad.csv"
        bad.write_text("incident_id,cohort\nA,x\n")
        with self.assertRaises(MetricsError):
            load_records(bad)
        with self.assertRaises(MetricsError):
            load_records(self.csv(""))

    def test_unknown_cohort_is_rejected(self):
        summary = summarize(load_records(self.csv("A,x,2026-10-14T09:00:00+00:00,2026-10-14T09:05:00+00:00,2026-10-14T10:00:00+00:00\n")))
        with self.assertRaises(MetricsError):
            compare(summary, "x", "missing")


if __name__ == "__main__":
    unittest.main()
