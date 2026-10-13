import json
from pathlib import Path
import tempfile
import unittest

from threatwatch.eve import alerts_from, is_internal, parse_time, read_events


def alert(ts, sid=9000001, src="10.0.0.5", dest="10.0.0.9", severity=1):
    return {"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dest, "dest_port": 22, "proto": "TCP",
            "alert": {"signature_id": sid, "signature": "sig", "severity": severity, "category": "c"}}


class EveTests(unittest.TestCase):
    def write(self, text):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "eve.json"
        path.write_text(text)
        return path

    def test_timestamp_with_numeric_offset_becomes_utc(self):
        self.assertEqual(parse_time("2026-10-14T09:00:00.500000+0000").isoformat(), "2026-10-14T09:00:00.500000+00:00")
        self.assertEqual(parse_time("2026-10-14T11:00:00+0200").hour, 9)

    def test_malformed_lines_are_counted_not_fatal(self):
        good = json.dumps(alert("2026-10-14T09:00:00.000000+0000"))
        path = self.write(f"{good}\nnot json\n[1,2]\n{{\"no_timestamp\":1}}\n{{\"timestamp\":\"garbage\"}}\n\n{good}\n")
        loaded = read_events(path)
        self.assertEqual(len(loaded.events), 2)
        self.assertEqual(loaded.skipped, 4)

    def test_alerts_are_sorted_and_non_alerts_ignored(self):
        events = [alert("2026-10-14T09:05:00+0000"), {"timestamp": "2026-10-14T09:01:00+0000", "event_type": "flow"},
                  alert("2026-10-14T09:02:00+0000"), {"timestamp": "2026-10-14T09:03:00+0000", "event_type": "alert", "alert": {}}]
        found = alerts_from(events)
        self.assertEqual([a.time.minute for a in found], [2, 5])

    def test_internal_address_classification(self):
        for ip in ("10.1.2.3", "172.16.0.1", "192.168.56.10", "127.0.0.1"):
            self.assertTrue(is_internal(ip), ip)
        for ip in ("203.0.113.50", "8.8.8.8", "172.32.0.1", "not-an-ip"):
            self.assertFalse(is_internal(ip), ip)


if __name__ == "__main__":
    unittest.main()
