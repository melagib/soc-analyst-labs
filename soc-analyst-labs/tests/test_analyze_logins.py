import tempfile
import unittest
from pathlib import Path

from tools.analyze_logins import load_events, summarize


class LoginAnalysisTests(unittest.TestCase):
    def load(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text("timestamp,user,source_ip,event\n" + rows, encoding="utf-8")
            return load_events(path)

    def test_fixture_counts_and_threshold(self):
        path = Path(__file__).resolve().parents[1] / "labs/01-login-investigation/sample_logins.csv"
        events = load_events(path)
        result = summarize(events)
        self.assertIn("Events: 16\nFailures: 11\nSuccesses: 5", result)
        self.assertEqual(result.count("[REVIEW]"), 2)
        self.assertIn("203.0.113.50 | admin | 5 prior failures", result)
        self.assertNotIn("[REVIEW]", summarize(events, 6))

    def test_unsorted_success_is_not_treated_as_later(self):
        events = self.load("2026-09-01T09:02:00Z,a,192.0.2.1,failure\n2026-09-01T09:01:00Z,a,192.0.2.1,success\n")
        self.assertNotIn("prior failures", summarize(events, 1))

    def test_same_timestamp_is_not_later(self):
        events = self.load("2026-09-01T09:01:00Z,a,192.0.2.1,failure\n2026-09-01T09:01:00Z,a,192.0.2.1,success\n")
        self.assertNotIn("prior failures", summarize(events, 1))

    def test_success_resets_pair_and_different_user_does_not_match(self):
        events = self.load("2026-09-01T09:01:00Z,a,192.0.2.1,failure\n2026-09-01T09:02:00Z,b,192.0.2.1,success\n2026-09-01T09:03:00Z,a,192.0.2.1,success\n2026-09-01T09:04:00Z,a,192.0.2.1,success\n")
        self.assertEqual(summarize(events, 1).count("prior failures"), 1)

    def test_invalid_input(self):
        for row in ["bad,a,192.0.2.1,failure\n", "2026-09-01T09:01:00Z,a,999.0.0.1,failure\n", "2026-09-01T09:01:00Z,a,192.0.2.1,other\n", "2026-09-01T09:01:00Z,,192.0.2.1,failure\n"]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.load(row)
        with self.assertRaises(ValueError):
            summarize([], 0)

    def test_empty_file_with_header(self):
        self.assertIn("Events: 0", summarize(self.load("")))


if __name__ == "__main__":
    unittest.main()
