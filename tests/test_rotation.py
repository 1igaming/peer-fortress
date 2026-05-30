"""Tests for advisory rotation recommendations."""

import unittest

from peer_fortress.diversity import analyze_sync_info
from peer_fortress.rotation import recommend_rotations


class RotationTests(unittest.TestCase):
    def test_high_concentration_recommends_rotation(self):
        peers = [
            {"host": f"10.0.1.{i}", "address": f"10.0.1.{i}:18080"}
            for i in range(10)
        ] + [{"host": "10.0.2.1", "address": "10.0.2.1:18080"}]
        report = analyze_sync_info({"peers": peers})
        self.assertTrue(report.rotation_recommendations)
        self.assertTrue(all(r.get("advisory_only") for r in report.rotation_recommendations))
        high = [r for r in report.rotation_recommendations if r.get("priority") == "high"]
        self.assertTrue(high)

    def test_healthy_score_has_low_priority_or_none_high(self):
        peers = [
            {"host": f"10.{i//10}.{i%10}.1", "address": f"10.{i//10}.{i%10}.1:18080"}
            for i in range(12)
        ]
        report = analyze_sync_info({"peers": peers})
        recs = recommend_rotations(report)
        for r in recs:
            self.assertTrue(r.advisory_only)


if __name__ == "__main__":
    unittest.main()
