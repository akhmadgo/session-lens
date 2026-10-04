"""Regression tests for the detection rules. Run: python3 -m unittest discover -s tests

Fake secrets are assembled at runtime so this file never contains a string
that secret scanners (GitHub push protection, the directory scan) would flag.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rules  # noqa: E402

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
ANT = "sk-ant-" + "api03-" + "Zx9" * 10
AMEX_TEST = "3782" + "82246310005"  # published test number, Luhn-valid


def ids(text):
    return [h[0] for h in rules.find(text)]


class Detects(unittest.TestCase):
    def test_keys(self):
        self.assertEqual(ids(f"key {AWS}"), ["aws_access_key"])
        self.assertEqual(ids(f"GITHUB_TOKEN={GH}"), ["github_token"])
        self.assertEqual(ids(f"use {ANT} now"), ["anthropic_key"])

    def test_url_password(self):
        self.assertEqual(ids("postgres://admin:Tr0ub4dor3x@db.internal:5432/app"), ["url_credentials"])

    def test_tokens_in_urls(self):
        self.assertEqual(ids("https://billing.example.com/p/session?secret=live_" + "Qm8xT2vK9pLr4Zw7"), ["secret_assignment"])
        self.assertEqual(ids("https://example.com/reset?token_hash=pkce_" + "a8f3c2e91b7d4f60"), ["secret_assignment"])

    def test_card_in_prose(self):
        self.assertEqual(ids(f"my card is {AMEX_TEST} thanks"), ["credit_card"])

    def test_assignment(self):
        self.assertEqual(ids("PASSWORD=hunter2pass!"), ["secret_assignment"])


class Ignores(unittest.TestCase):
    def test_numeric_id_in_url(self):
        self.assertEqual(ids(f"https://careers.example.gov/role/?id={AMEX_TEST}"), [])
        self.assertEqual(ids(f"https://example.com/item/{AMEX_TEST}"), [])

    def test_iso_timestamp(self):
        self.assertEqual(ids("claude_token_expires = 2026-09-21T20:54:38.622442Z"), [])

    def test_token_counters_and_code(self):
        self.assertEqual(ids("total_tokens = event.usage.output_tokens"), [])
        self.assertEqual(ids("max_tokens = model_settings.max_output"), [])
        self.assertEqual(ids("ACCESS_TOKEN = response.json_payload"), [])

    def test_timestamps_and_test_cards(self):
        self.assertEqual(ids("ts 1791144309661 and 1791144309661123"), [])
        self.assertEqual(ids("4242 4242 4242 4242"), [])

    def test_placeholders_and_markers(self):
        self.assertEqual(ids("API_KEY=your-api-key-here"), [])
        self.assertEqual(ids("postgres://admin:[REDACTED:url_credentials]@db/app"), [])
        self.assertEqual(ids("TOKEN_EXPIRY=2026-09-01-12-00"), [])


if __name__ == "__main__":
    unittest.main()
