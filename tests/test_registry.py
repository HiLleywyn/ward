from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from emuwatch.registry import validate_registry


class RegistryTests(unittest.TestCase):
    def test_project_registry_is_valid(self):
        from emuwatch.data import advisory_directory
        directory = advisory_directory()
        self.assertEqual(validate_registry(directory), [])

    def test_invalid_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            (directory / "indicators.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "indicators": [
                            {
                                "sha256": "nope",
                                "source_url": "https://example.test/report",
                                "first_seen": "2026-01-01",
                                "status": "confirmed",
                                "validation_notes": "fixture",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            for name, key in (
                ("known-project-assets.json", "assets"),
                ("project-locations.json", "projects"),
                ("campaigns.json", "campaigns"),
            ):
                (directory / name).write_text(
                    json.dumps({"schema_version": 1, key: []}), encoding="utf-8"
                )
            problems = validate_registry(directory)
        self.assertTrue(any(problem.message == "invalid SHA-256" for problem in problems))


if __name__ == "__main__":
    unittest.main()
