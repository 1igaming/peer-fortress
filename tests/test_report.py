"""Tests for human-readable report formatting."""

import unittest

from peer_fortress.diversity import analyze_sync_info
from peer_fortress.report import format_diversity_report, format_tor_report
from peer_fortress.tor_health import TorHealthReport


class ReportTests(unittest.TestCase):
    def test_diversity_report_contains_score(self):
        peers = [{"host": f"10.0.{i//256}.{i%256}", "address": f"10.0.{i//256}.{i%256}:18080"} for i in range(12)]
        report = analyze_sync_info({"peers": peers})
        text = format_diversity_report(report, source="test")
        self.assertIn("DIVERSITY REPORT", text)
        self.assertIn(f"{report.score}/100", text)
        self.assertIn("RECOMMENDATIONS", text)

    def test_tor_report_unreachable(self):
        report = TorHealthReport(reachable=False, host="127.0.0.1", port=9050, error="connection refused")
        text = format_tor_report(report)
        self.assertIn("UNREACHABLE", text)
        self.assertIn("connection refused", text)


if __name__ == "__main__":
    unittest.main()
