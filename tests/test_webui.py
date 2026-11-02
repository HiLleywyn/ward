from __future__ import annotations

import unittest
from pathlib import Path


WEB_ROOT = Path(__file__).parents[1] / "src" / "emuwatch" / "webui"


class WebInterfaceTests(unittest.TestCase):
    def test_primary_sections_have_the_intended_order(self):
        page = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
        scanner = page.index(">Scanner<")
        database = page.index(">Malware Database<")
        recent = page.index(">Recent Scans<")
        self.assertLess(scanner, database)
        self.assertLess(database, recent)

    def test_removed_secondary_panels_do_not_return(self):
        page = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
        script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
        for obsolete in ("file-input", "drop-zone", "Three rules", "Coverage & research"):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, page)
        self.assertNotIn("/api/campaigns", script)
        self.assertIn("/api/v1/scans", script)
        self.assertIn("/api/scans", script)

    def test_responsive_and_reduced_motion_styles_remain(self):
        styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 680px)", styles)
        self.assertIn("@media (prefers-reduced-motion: reduce)", styles)
        self.assertIn("focus-visible", styles)


if __name__ == "__main__":
    unittest.main()
