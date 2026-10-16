from pathlib import Path
import tempfile
import unittest

from threatwatch.rules import DEFAULT_RULES, RuleError, load_catalogue, parse_rule


class RuleCatalogueTests(unittest.TestCase):
    def test_all_local_rules_load_with_complete_metadata(self):
        catalogue = load_catalogue()
        self.assertEqual(len(catalogue), 8)
        for sid, rule in catalogue.items():
            self.assertTrue(9000001 <= sid <= 9000008)
            self.assertRegex(rule.technique, r"^T\d{4}(\.\d{3})?$")
            self.assertIn(rule.severity, {"low", "medium", "high"})
            self.assertTrue(rule.playbook)

    def test_every_rule_line_is_well_formed(self):
        for line in DEFAULT_RULES.read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            self.assertTrue(line.startswith("alert "), line)
            self.assertTrue(line.rstrip().endswith(";)"), line)
            self.assertIn("rev:", line)

    def test_every_playbook_name_has_a_section_in_the_playbook_document(self):
        text = (Path(__file__).resolve().parents[1] / "docs" / "INCIDENT_RESPONSE_PLAYBOOK.md").read_text()
        for rule in load_catalogue().values():
            self.assertIn(f"`{rule.playbook}`", text, rule.playbook)

    def test_missing_metadata_is_rejected(self):
        with self.assertRaises(RuleError):
            parse_rule('alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)')

    def test_invalid_severity_is_rejected(self):
        line = 'alert tcp any any -> any any (msg:"x"; sid:1; rev:1; metadata:mitre_technique T1000, mitre_tactic a, severity urgent, playbook p;)'
        with self.assertRaises(RuleError):
            parse_rule(line)

    def test_duplicate_sid_is_rejected(self):
        line = 'alert tcp any any -> any any (msg:"x"; sid:5; rev:1; metadata:mitre_technique T1000, mitre_tactic a, severity low, playbook p;)\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dup.rules"
            path.write_text(line * 2)
            with self.assertRaises(RuleError):
                load_catalogue(path)


if __name__ == "__main__":
    unittest.main()
