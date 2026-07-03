"""Tests for --out and --validate-schema CLI flags."""

import contextlib
import io
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

    def test_missing_fixture_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does_not_exist.json"
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = main(["--mock", str(missing)])
            self.assertEqual(rc, 2)
            self.assertIn("could not load fixture", err.getvalue())

    def test_unreachable_rpc_exits_cleanly(self):
        # Nothing listens on TCP port 9 locally; must fail fast without traceback.
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = main(["--rpc", "http://127.0.0.1:9/json_rpc"])
        self.assertEqual(rc, 2)
        self.assertIn("could not fetch sync_info", err.getvalue())


if __name__ == "__main__":
    unittest.main()
