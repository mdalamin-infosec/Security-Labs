from datetime import datetime, timedelta, timezone
import random
import unittest

from threatwatch.beacon import find_beacons

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def flows(offsets, src="192.168.56.20", dest="203.0.113.50", port=8443):
    return [{"timestamp": (T0 + timedelta(seconds=o)).isoformat(), "event_type": "flow", "src_ip": src, "dest_ip": dest, "dest_port": port} for o in offsets]


class BeaconTests(unittest.TestCase):
    def test_regular_callbacks_are_found(self):
        found = find_beacons(flows([i * 60 for i in range(25)]))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].confidence, "high")
        self.assertAlmostEqual(found[0].mean_interval_s, 60, delta=0.01)

    def test_irregular_traffic_is_not_flagged(self):
        rng = random.Random(3)
        offsets = sorted(rng.uniform(0, 3600) for _ in range(40))
        self.assertEqual(find_beacons(flows(offsets)), [])

    def test_too_few_connections_are_ignored(self):
        self.assertEqual(find_beacons(flows([i * 60 for i in range(7)])), [])

    def test_internal_destinations_and_non_flow_events_are_ignored(self):
        self.assertEqual(find_beacons(flows([i * 60 for i in range(20)], dest="192.168.56.10")), [])
        events = flows([i * 60 for i in range(20)])
        for event in events:
            event["event_type"] = "dns"
        self.assertEqual(find_beacons(events), [])

    def test_interval_outside_bounds_is_ignored(self):
        self.assertEqual(find_beacons(flows([i * 2 for i in range(30)])), [])
        self.assertEqual(find_beacons(flows([i * 7200 for i in range(10)])), [])

    def test_different_destinations_are_tracked_separately(self):
        mixed = flows([i * 60 for i in range(10)]) + flows([i * 60 + 17 for i in range(10)], dest="203.0.113.51")
        self.assertEqual(len(find_beacons(mixed)), 2)


if __name__ == "__main__":
    unittest.main()
