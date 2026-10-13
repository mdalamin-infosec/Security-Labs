from datetime import datetime, timedelta, timezone
import unittest

from threatwatch.eve import Alert
from threatwatch.rules import load_catalogue
from threatwatch.triage import build_incidents, priority_for

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def make(minutes, sid, src="10.0.0.5", dest="10.0.0.9", severity=2):
    return Alert(T0 + timedelta(minutes=minutes), src, dest, 22, "TCP", sid, f"sig {sid}", severity, "c")


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.catalogue = load_catalogue()

    def test_priority_boundaries(self):
        self.assertEqual([priority_for(s) for s in (10, 14, 15, 24, 25, 34, 35, 60)], ["P4", "P4", "P3", "P3", "P2", "P2", "P1", "P1"])

    def test_single_high_rule_is_p2_and_single_low_rule_is_p4(self):
        high = build_incidents([make(0, 9000001)], self.catalogue)[0]
        low = build_incidents([make(0, 9000003)], self.catalogue)[0]
        self.assertEqual((high.score, high.priority), (30, "P2"))
        self.assertEqual((low.score, low.priority), (10, "P4"))

    def test_recon_then_access_escalates_to_p1_with_reason(self):
        incident = build_incidents([make(0, 9000002), make(5, 9000001)], self.catalogue)[0]
        self.assertEqual(incident.priority, "P1")
        self.assertTrue(any("followed by an access" in r for r in incident.reasons))

    def test_access_before_recon_gets_tactic_bonus_but_no_sequence_reason(self):
        incident = build_incidents([make(0, 9000001), make(5, 9000002)], self.catalogue)[0]
        self.assertEqual(incident.score, 35)
        self.assertFalse(any("followed by an access" in r for r in incident.reasons))

    def test_quiet_gap_splits_incidents_and_sources_stay_separate(self):
        alerts = [make(0, 9000001), make(10, 9000001), make(40, 9000001), make(1, 9000001, src="10.0.0.6")]
        incidents = build_incidents(alerts, self.catalogue, gap_minutes=15)
        self.assertEqual(sorted((i.src_ip, i.alert_count) for i in incidents), [("10.0.0.5", 1), ("10.0.0.5", 2), ("10.0.0.6", 1)])
        self.assertEqual([i.id for i in incidents], ["INC-0001", "INC-0002", "INC-0003"])

    def test_unknown_sid_uses_suricata_severity_and_is_flagged(self):
        incident = build_incidents([make(0, 2100498, severity=1)], self.catalogue)[0]
        self.assertEqual(incident.score, 30)
        self.assertEqual(incident.unmapped_sids, [2100498])
        self.assertTrue(any("outside the local rule catalogue" in r for r in incident.reasons))

    def test_volume_bonus_applies(self):
        alerts = [make(i * 0.1, 9000003) for i in range(25)]
        self.assertEqual(build_incidents(alerts, self.catalogue)[0].score, 14)


if __name__ == "__main__":
    unittest.main()
