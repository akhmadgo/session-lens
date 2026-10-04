"""End-to-end scan and redact against a synthetic ~/.claude. Run: python3 -m unittest discover -s tests"""
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE_URL = "https://billing.example.com/p/session?secret=live_" + "Qm8xT2vK9pLr4Zw7"


class ScanAndRedact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        sess = "11111111-2222-3333-4444-555555555555"
        proj = self.home / "projects" / "-Users-x-app"
        (proj / sess / "tool-results").mkdir(parents=True)
        rec = {"type": "user", "timestamp": "2026-09-01T10:00:00Z", "cwd": "/Users/x/app",
               "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": f"GITHUB_TOKEN={GH}"}]}}
        self.transcript = proj / f"{sess}.jsonl"
        self.transcript.write_text(json.dumps(rec) + "\n")
        self.saved = proj / sess / "tool-results" / "out1.txt"
        self.saved.write_text(f"2026-09-09|{STRIPE_URL}\n")
        old = 1_700_000_000
        for p in (self.transcript, self.saved):
            os.utime(p, (old, old))
        self.env = dict(os.environ, CLAUDE_CONFIG_DIR=str(self.home))

    def tearDown(self):
        self.tmp.cleanup()

    def run_lens(self, *args):
        out = subprocess.run([sys.executable, str(SCRIPTS / "lens.py"), *args], env=self.env,
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def test_scan_includes_saved_tool_outputs(self):
        d = self.run_lens("scan", "--no-open", "--out", str(self.home / "r.html"))
        kinds = {f["type"]: f for f in d["findings"]}
        self.assertIn("GitHub token", kinds)
        self.assertIn("Secret-looking assignment", kinds)
        self.assertEqual(kinds["Secret-looking assignment"]["where"], {"tool output": 1})
        self.assertEqual(kinds["Secret-looking assignment"]["sessions"], 1)

    def test_redact_then_clean(self):
        self.assertEqual(self.run_lens("redact")["replacements"], 2)
        self.assertEqual(self.run_lens("redact", "--apply")["replacements"], 2)
        json.loads(self.transcript.read_text())  # still valid JSON
        self.assertIn("[REDACTED:secret_assignment]", self.saved.read_text())
        d = self.run_lens("scan", "--no-open", "--out", str(self.home / "r.html"))
        self.assertEqual(d["findings"], [])


if __name__ == "__main__":
    unittest.main()
