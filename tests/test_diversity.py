"""Tests for peer diversity scoring."""

import unittest

from peer_fortress.diversity import analyze_sync_info


class DiversityTests(unittest.TestCase):
    def test_empty_peers(self):
        report = analyze_sync_info({"peers": []})
        self.assertEqual(report.score, 0)
        self.assertEqual(report.grade, "poor")

    def test_concentrated_subnet_penalized(self):
        peers = [
            {"host": f"192.168.1.{i}", "address": f"192.168.1.{i}:18080"}
            for i in range(1, 9)
        ] + [{"host": "10.0.0.1", "address": "10.0.0.1:18080"}]
        report = analyze_sync_info({"peers": peers})
        self.assertLess(report.score, 80)
        self.assertGreater(report.max_bucket_share, 0.5)

    def test_onion_expectation(self):
        peers = [{"host": f"10.0.0.{i}", "address": f"10.0.0.{i}:18080"} for i in range(1, 11)]
        report = analyze_sync_info({"peers": peers}, expect_tor=True)
        self.assertTrue(any("Tor mode" in w for w in report.warnings))

    def test_duplicate_hosts(self):
        peers = [
            {"host": "203.0.113.1", "address": "203.0.113.1:18080"},
            {"host": "203.0.113.1", "address": "203.0.113.1:18081"},
            {"host": "203.0.113.2", "address": "203.0.113.2:18080"},
        ]
        report = analyze_sync_info({"peers": peers})
        self.assertEqual(report.duplicate_hosts, 1)

    def test_bare_ipv6_address_classified(self):
        # No "host" field: host must be recovered from a bare IPv6 address
        # without treating the last colon group as a port.
        peers = [{"address": "2001:db8::1"}]
        report = analyze_sync_info({"peers": peers})
        self.assertEqual(report.peers[0].kind, "ipv6")
        self.assertEqual(report.peers[0].bucket, "2001:db8::/48")

    def test_bracketed_ipv6_with_port(self):
        peers = [{"address": "[2001:db8::1]:18080"}]
        report = analyze_sync_info({"peers": peers})
        self.assertEqual(report.peers[0].host, "2001:db8::1")
        self.assertEqual(report.peers[0].kind, "ipv6")

    def test_onion_port_stripped_for_duplicates(self):
        # Same onion host on two ports should collapse to one duplicate.
        peers = [
            {"address": "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:18080"},
            {"address": "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:18081"},
        ]
        report = analyze_sync_info({"peers": peers})
        self.assertEqual(report.duplicate_hosts, 1)
        self.assertEqual(report.onion_peers, 2)


if __name__ == "__main__":
    unittest.main()
