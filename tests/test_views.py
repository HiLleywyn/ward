import unittest

from ward.views import badge_state


class BadgeStateTests(unittest.TestCase):
    def test_static_findings_require_review_even_after_complete_inspection(self):
        job = {
            "status": "completed",
            "result": {
                "status": "Unverified",
                "verification": {"level": "inspected"},
                "findings": [{"kind": "static-rule", "severity": "high"}],
            },
        }
        self.assertEqual(badge_state(job)[:2], ("!", "review findings"))


if __name__ == "__main__":
    unittest.main()
