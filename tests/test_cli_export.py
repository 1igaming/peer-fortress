"""Tests for --out and --validate-schema CLI flags."""

import json
import tempfile
import unittest
from pathlib import Path

from peer_fortress.cli import main


class CliExportTests(unittest.TestCase):
    def test_out_writes_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "report.json"
            rc = main(["--mock", "--out", str(out_file)])
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.is_file())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["report_type"], "diversity")
            self.assertIn("score", data)

    def test_out_with_validate_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "report.json"
            rc = main(["--mock", "--out", str(out_file), "--validate-schema"])
            self.assertEqual(rc, 0)
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()
