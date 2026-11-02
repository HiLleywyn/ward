import unittest

from ward.views import badge_state, repository_ledger_page, scan_record_page


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


class RecordPageTests(unittest.TestCase):
    def test_scan_page_exposes_evidence_without_treating_review_as_scan_success(self):
        job = {
            "id": "fixture-scan", "kind": "repository", "target": "owner/repo", "status": "completed",
            "created_at": "2026-11-02", "updated_at": "2026-11-02",
            "result": {"status": "Unverified", "verification": {"level": "inspected"}, "findings": []},
        }
        page = scan_record_page(job, {"fixture": True}, {"repository": "owner/repo"}).decode()
        self.assertIn('href="/api/v1/reports/fixture-scan"', page)
        self.assertIn('href="/api/record?repository=owner%2Frepo"', page)
        self.assertIn("inspected", page)
        self.assertNotIn("malware detected", page)
        self.assertIn("This does not prove safety", page)

    def test_ledger_retains_review_when_no_scan_has_run_and_escapes_text(self):
        history = {"repository": "owner/repo", "scans": [], "relationship_note": "No relationship asserted."}
        page = repository_ledger_page(history, {"repository": "owner/repo", "finding": '<script>alert("test")</script>'}).decode()
        self.assertIn("No scans recorded.", page)
        self.assertIn("View reviewed evidence", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn('<script>', page)


if __name__ == "__main__":
    unittest.main()
