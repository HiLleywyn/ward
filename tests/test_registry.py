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

    def test_discord_nitro_built_hash_is_bound_to_pinned_record(self):
        from ward.data import advisory_directory

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
        digest = "4a5cdd67f46c92c5d00495057c7715457bef4fcd5d8915a0239018142d8101f2"

        self.assertTrue(any(item["sha256"] == digest and item["status"] == "confirmed" for item in indicators["indicators"]))
        record = next(item for item in records["records"] if item["id"] == "discord-nitro-built-pyinstaller")
        self.assertEqual(record["repository"], "sjyjoghkkjj/Discord-Nitro-Generator")
        self.assertEqual(record["artifact"], "Built.exe")
        self.assertIn("451f057fa9c67739e37b8bcff2db7e2094e8c982", record["release"])

    def test_mediafire_loader_wave_is_bound_to_eight_live_repositories(self):
        from ward.data import advisory_directory

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
        campaigns = json.loads((directory / "campaigns.json").read_text(encoding="utf-8"))
        archive_digest = "d3b73a54c8f4825bb10974799ba9674ee41863f8c73e6a059f9206258026d32b"
        loader_digest = "76d457fa4add28f9164ad547b9713caf4d89474c8f1724709f5d8ca238c92916"
        repositories = {
            "J-Vinicius/nova-ui",
            "lokyfordev/pulse-toolkit",
            "nguyenthetri2k1/aether-hub",
            "StapleParakeet/rune-dota2",
            "Mortaliewrath/manta-dota2",
            "FencerEngage/courier-dota2",
            "magentaechoenchant/glyph-dota2",
            "trapghostwall/ancient-dota2",
        }

        self.assertEqual(
            {archive_digest, loader_digest},
            {
                item["sha256"]
                for item in indicators["indicators"]
                if item.get("campaign") == "Password-5139237619 MediaFire loader wave"
                and item["status"] == "confirmed"
            },
        )
        wave_records = [
            item
            for item in records["records"]
            if item["malware"] == "ChaCha20 self-extracting Windows loader"
        ]
        self.assertEqual(repositories, {item["repository"] for item in wave_records})
        self.assertEqual(8, len(wave_records))
        self.assertTrue(all(item["status"] == "FAIL" for item in wave_records))
        self.assertTrue(all("/blob/" in item["source_url"] for item in wave_records))

        campaign = next(
            item
            for item in campaigns["campaigns"]
            if item["id"] == "2026-10-mediafire-password-loader-wave"
        )
        self.assertEqual(
            {f"https://github.com/{repository}" for repository in repositories},
            set(campaign["confirmed_repository_urls"]),
        )
        self.assertEqual({archive_digest, loader_digest}, set(campaign["confirmed_sha256"]))


if __name__ == "__main__":
    unittest.main()
