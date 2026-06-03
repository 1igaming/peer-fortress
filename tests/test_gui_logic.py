"""Tests for GUI logic and control panel integration."""

import sys
import unittest
from pathlib import Path

# Find repository root and add control-panel to sys.path
def find_repo_root() -> Path:
    p = Path(__file__).resolve().parent
    for _ in range(6):
        if (p / "tracking" / "STATUS.md").is_file():
            return p
        if p.parent == p:
            break
        p = p.parent
    return Path(r"G:\Monero-CC")

repo_root = find_repo_root()
control_panel_path = repo_root / "apps" / "control-panel"
if str(control_panel_path) not in sys.path:
    sys.path.insert(0, str(control_panel_path))

class GuiLogicTests(unittest.TestCase):
    def setUp(self):
        self.repo = repo_root

    def test_repo_root_resolution(self):
        """Verify that the repository root resolved correctly and has essential files."""
        self.assertTrue(self.repo.is_dir())
        self.assertTrue((self.repo / "config" / "profile.yaml").is_file())

    def test_collect_snapshot(self):
        """Verify that collect_snapshot successfully retrieves all status cards."""
        import stack_probe
        
        snap = stack_probe.collect_snapshot(self.repo)
        self.assertIsNotNone(snap)
        self.assertTrue(len(snap.cards) >= 8)
        
        # Verify card structures
        keys = {c.key for c in snap.cards}
        expected_keys = {"lmstudio", "hermes", "tor", "gitlab", "finetune", "peer", "tasks", "queue"}
        for key in expected_keys:
            self.assertIn(key, keys)

    def test_probe_tor(self):
        """Verify that Tor SOCKS5 probe returns a valid status card."""
        import stack_probe
        
        card = stack_probe.probe_tor(self.repo)
        self.assertEqual(card.key, "tor")
        self.assertIn(card.level, ("ok", "warn", "error", "unknown"))
        self.assertTrue(len(card.title) > 0)
        self.assertTrue(len(card.headline) > 0)

    def test_probe_task_queue(self):
        """Verify that the Task Queue status card parses correctly."""
        import stack_probe
        
        card = stack_probe.probe_task_queue(self.repo)
        self.assertEqual(card.key, "queue")
        self.assertIn(card.level, ("ok", "warn", "error", "unknown"))
        self.assertTrue(len(card.headline) > 0)

    def test_probe_finetune(self):
        """Verify that the Finetune status card parses correctly."""
        import stack_probe
        
        card = stack_probe.probe_finetune(self.repo)
        self.assertEqual(card.key, "finetune")
        self.assertIn(card.level, ("ok", "warn", "error", "unknown"))
        self.assertTrue(len(card.headline) > 0)

if __name__ == "__main__":
    unittest.main()
