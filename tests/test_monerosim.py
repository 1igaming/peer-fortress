"""Tests for monerosim scenario stub."""

import unittest
from pathlib import Path

from peer_fortress.monerosim import format_scenario_summary, list_scenarios, load_scenario

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "scenarios"


class MonerosimTests(unittest.TestCase):
    def test_load_eclipse_scenario(self):
        path = SCENARIOS_DIR / "eclipse-rehearsal.yaml"
        scenario = load_scenario(path)
        self.assertEqual(scenario.name, "eclipse-rehearsal")
        self.assertEqual(scenario.scenario_type, "eclipse")
        self.assertGreater(scenario.nodes, 0)
        self.assertTrue(scenario.peer_fortress_checks)

    def test_list_scenarios(self):
        scenarios = list_scenarios(SCENARIOS_DIR)
        self.assertGreaterEqual(len(scenarios), 1)
        names = {s.name for s in scenarios}
        self.assertIn("eclipse-rehearsal", names)

    def test_format_summary(self):
        scenario = load_scenario(SCENARIOS_DIR / "eclipse-rehearsal.yaml")
        text = format_scenario_summary(scenario)
        self.assertIn("eclipse-rehearsal", text)
        self.assertIn("STUB", text)


if __name__ == "__main__":
    unittest.main()
