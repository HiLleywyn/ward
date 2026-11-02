from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ward.registry import validate_registry


class RegistryTests(unittest.TestCase):
    def test_project_registry_is_valid(self):
        from ward.data import advisory_directory
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

    def test_santastealer_hash_is_bound_to_both_fluxus_records(self):
        from ward.data import advisory_directory

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
        digest = "9df11356c5ac61d2aa7b5425e6322fc016b0ed5790dacb201396500b3eee03f7"

        indicator = next(item for item in indicators["indicators"] if item["sha256"] == digest)
        self.assertEqual(indicator["status"], "confirmed")
        self.assertEqual(indicator["source_url"], "https://threatfox.abuse.ch/ioc/1957496/")
        self.assertEqual(
            {
                "lehhlass/Fluxus-Roblox-Executor",
                "hanneshow/Fluxus-Roblox-Executor",
            },
            {
                item["repository"]
                for item in records["records"]
                if item["malware"] == "SantaStealer"
            },
        )


if __name__ == "__main__":
    unittest.main()
