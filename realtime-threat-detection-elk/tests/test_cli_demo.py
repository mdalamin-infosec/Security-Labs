from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from threatwatch.cli import main
from threatwatch.demo import generate_events


class DemoTests(unittest.TestCase):
    def test_generated_events_are_deterministic_and_tagged_synthetic(self):
        first, second = generate_events(), generate_events()
        self.assertEqual(first, second)
        self.assertTrue(all("synthetic-demo" in e["tags"] for e in first))

    def test_demo_command_produces_expected_incidents_and_beacon(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            code = main(["demo", "--data-dir", f"{folder}/data", "--report-dir", f"{folder}/reports"])
            report = json.loads((Path(folder) / "reports" / "demo-incidents.json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["incidents"], 5)
        self.assertEqual(report["summary"]["alerts"], 21)
        self.assertEqual(report["summary"]["priorities"]["P1"], 2)
        self.assertEqual(report["summary"]["beacon_leads"], 1)
        self.assertEqual(report["beacon_leads"][0]["dest_ip"], "203.0.113.50")

    def test_missing_input_returns_error_code(self):
        self.assertEqual(main(["triage", "does-not-exist.json"]), 1)

    def test_triage_markdown_output_file(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            main(["generate-sample", "--output", f"{folder}/e.json"])
            code = main(["triage", f"{folder}/e.json", "--format", "markdown", "--output", f"{folder}/out.md"])
            text = (Path(folder) / "out.md").read_text()
        self.assertEqual(code, 0)
        self.assertIn("| INC-0001 | P1 |", text)


if __name__ == "__main__":
    unittest.main()
