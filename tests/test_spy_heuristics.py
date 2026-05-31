"""Tests for spy heuristics and sybil detection."""

import unittest

from peer_fortress.diversity import analyze_sync_info
from peer_fortress.spy_heuristics import analyze_spy_heuristics


class SpyHeuristicTests(unittest.TestCase):
    def test_clean_peers(self):
        peers = [
            {"host": f"192.168.1.{i}", "address": f"192.168.1.{i}:18080", "support_flags": i}
            for i in range(1, 6)
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        self.assertLess(spy.spy_saturation_score, 30)

    def test_uniform_support_flags_flagged(self):
        peers = [
            {"host": f"192.168.1.{i}", "address": f"192.168.1.{i}:18080", "support_flags": 1}
            for i in range(1, 6)
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        # uniform flags should trigger a score increase
        self.assertTrue(any("support_flags_concentration" in s.get("type", "") for s in spy.signals))

    def test_duplicate_pruning_seeds_flagged(self):
        peers = [
            {"host": f"192.168.1.{i}", "address": f"192.168.1.{i}:18080", "pruning_seed": 12345}
            for i in range(1, 6)
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        self.assertTrue(any("duplicate_pruning_seeds" in s.get("type", "") for s in spy.signals))


if __name__ == "__main__":
    unittest.main()
