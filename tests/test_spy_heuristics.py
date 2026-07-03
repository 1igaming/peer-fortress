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

    def test_uniform_flags_not_flagged_when_subnets_diverse(self):
        # support_flags=1 is the network norm; without subnet concentration
        # it must not raise a spy signal on its own.
        peers = [
            {"host": f"10.{i}.0.1", "address": f"10.{i}.0.1:18080", "support_flags": 1}
            for i in range(1, 6)
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        self.assertFalse(
            any(s.get("type") == "support_flags_concentration" for s in spy.signals)
        )

    def test_duplicate_peer_id_flagged(self):
        # Same non-zero peer_id at two distinct hosts = proxy fan-out / sybil.
        peers = [
            {"host": "10.1.0.1", "address": "10.1.0.1:18080", "peer_id": "deadbeef"},
            {"host": "10.2.0.1", "address": "10.2.0.1:18080", "peer_id": "deadbeef"},
            {"host": "10.3.0.1", "address": "10.3.0.1:18080", "peer_id": "cafebabe"},
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        dup_signals = [s for s in spy.signals if s.get("type") == "duplicate_peer_id"]
        self.assertEqual(len(dup_signals), 1)
        self.assertGreaterEqual(spy.spy_saturation_score, 15)

    def test_unique_peer_ids_not_flagged(self):
        peers = [
            {"host": f"10.{i}.0.1", "address": f"10.{i}.0.1:18080", "peer_id": f"id-{i}"}
            for i in range(1, 6)
        ]
        report = analyze_sync_info({"peers": peers})
        spy = analyze_spy_heuristics({"peers": peers}, report)
        self.assertFalse(any(s.get("type") == "duplicate_peer_id" for s in spy.signals))


if __name__ == "__main__":
    unittest.main()
