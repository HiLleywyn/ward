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

    def test_gitsoftware_wave_is_bound_to_thirty_two_live_repositories(self):
        from ward.data import advisory_directory, load_malware_records

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = load_malware_records(directory)
        campaigns = json.loads((directory / "campaigns.json").read_text(encoding="utf-8"))
        digests = {
            "366a763fcd6980a1954d05c0625306ff1db57d0902376961efbc0c4e2b0c0d80",
            "7bb0fa4816b5c494d56ac4a3ebd12b6759a55644e58c1247b4e2409cd04253bf",
            "17bea6010be2710299304fb845c88a605b7f8cfd680394e9f23722f5b9ffe353",
            "59e820b58af3abbbe7aa31c7be8cc0b65e62c326d82a4912d85de59903a30464",
        }
        repositories = {
            "CarrierForge/Fishing-Planet-Cheat",
            "elementowlhover/Marvel-Rivals-Cheat",
            "hideprovostplaza/AION-2-Cheat",
            "ShatterCourierDrag/Delta-Force-Cheat",
            "Truebrecycle/PAYDAY-3-Cheat",
            "ConstablePucker/Honkai-Star-Rail-Cheat",
            "hypergooseoverpass/Rust-External-Cheat",
            "glossnodeengage/Android-Unlocker",
            "SpringLadyDivide/IOS-Unlocker",
            "armslocksmithamplify/PassFab-Unlocker",
            "Rewindlespin/Aiseesoft-Unlocker",
            "KindPurify64/FonePaw-Unlocker",
            "Poltergeistzuplan/UltFone-Unlocker",
            "innershapepergola/IFunBox",
            "Moduledebear/Total-Commander",
            "CrewCommissioner/SoundPad",
            "Armskostrike/Discord-Server-Raider",
            "mythicassemblyladle/RX-11-Audio-Editor",
            "Sapphireclifoster/FabFilter-Total",
            "TabooColonelFactory/Uttorent",
            "NoviceDestroy/HitFilm",
            "Breezenovacode/Better-Discord",
            "ConvergeRobinDeem/SeedPhraseGenerator",
            "MetropolisFrog65/KeyShot-Pro",
            "QuartzBullShroud/Movavi-Photo-Editor",
            "GuardSupporter/Dr.Fone-Unlock",
            "MacroDeerForceps/Hwid-Spoofer",
            "holefencercall/Fishing-Planet-Cheat",
            "ScorpionSplit/Movavi-Video-Suite-Plus",
            "Noonbenprovide/Marvel-Rivals-Cheat",
            "Southorreproduce96/AION-2-Cheat",
            "RepresentativeAbyss/Movavi-Screen-Recorder",
        }

        self.assertEqual(
            digests,
            {
                item["sha256"]
                for item in indicators["indicators"]
                if item.get("campaign") == "git-software.cc PowerShell delivery wave"
                and item["status"] == "confirmed"
            },
        )
        wave_records = [
            item
            for item in records
            if item["malware"] == "Obfuscated PowerShell screenshot-exfiltration loader"
        ]
        self.assertEqual(repositories, {item["repository"] for item in wave_records})
        self.assertEqual(32, len(wave_records))
        self.assertTrue(all(item["status"] == "FAIL" for item in wave_records))
        self.assertTrue(all("/blob/" in item["source_url"] for item in wave_records))

        campaign = next(
            item
            for item in campaigns["campaigns"]
            if item["id"] == "2026-10-git-software-powershell-wave"
        )
        self.assertEqual(
            {f"https://github.com/{repository}" for repository in repositories},
            set(campaign["confirmed_repository_urls"]),
        )
        self.assertEqual(digests, set(campaign["confirmed_sha256"]))

    def test_repository_warning_uses_repository_specific_malware_records(self):
        from ward.evidence import repository_warning

        warning = repository_warning("CarrierForge/Fishing-Planet-Cheat")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.verdict, "reviewed-malicious-repository")
        self.assertEqual(
            "reviewed_malware_record",
            warning.signals[0].key,
        )
        self.assertTrue(
            any("a48fd3fc0f587bc272b1ad5dc0ea72675fed5ff9" in item for item in warning.limitations)
        )

    def test_phantom_blade_sideload_is_bound_to_live_repository(self):
        from ward.data import advisory_directory

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
        campaigns = json.loads((directory / "campaigns.json").read_text(encoding="utf-8"))
        digests = {
            "9a3d27209203ccd993516897167d864d7d1e4843b65885b9684311c214f88833",
            "63484bfb8be34c3f7b4358dcd866b14fdafe9cbd671486fc9efcec346d059874",
            "b9ac528eac8fcb490180b1a378723a2e2436042c6b32078ccbab10670de17467",
        }

        record = next(item for item in records["records"] if item["id"] == "phantom-blade-zero-libcurl-sideload")
        self.assertEqual(record["repository"], "Separatedimanacle/Phantom-Blade-Zero-Cheat")
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("1614250757d476b5c962b6b81de831a2d587595c", record["release"])
        self.assertEqual(
            digests,
            {
                item["sha256"]
                for item in indicators["indicators"]
                if item.get("campaign") == "Phantom Blade Zero libcurl sideload"
            },
        )
        campaign = next(
            item
            for item in campaigns["campaigns"]
            if item["id"] == "2026-10-phantom-blade-libcurl-sideload"
        )
        self.assertEqual(digests, set(campaign["confirmed_sha256"]))
        self.assertEqual(
            ["https://github.com/Separatedimanacle/Phantom-Blade-Zero-Cheat"],
            campaign["confirmed_repository_urls"],
        )

    def test_activation_gateway_wave_is_bound_to_two_live_repositories(self):
        from ward.data import advisory_directory

        directory = advisory_directory()
        indicators = json.loads((directory / "indicators.json").read_text(encoding="utf-8"))
        records = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
        campaigns = json.loads((directory / "campaigns.json").read_text(encoding="utf-8"))
        digests = {
            "2d335822db6d0164b3ec4df394311d832b4d804ca49430f8c25d7c329a8efd90",
            "a5d595564c0b9e6036459dac1c5ade5f1df6e779856aa2d704ea0f55d3e8c31a",
            "97d23bff9d4a34331bb2f499b7b1d6765b16f79ee6bb390b94d1fbb9d426c980",
        }
        repositories = {
            "oiluj3D/star-rail-trainer-suite",
            "rajay782/windows-suite-migration-auditor",
        }

        wave_records = [
            item
            for item in records["records"]
            if item["malware"] == "activation-gateway PNG process-hollowing loader"
        ]
        self.assertEqual(repositories, {item["repository"] for item in wave_records})
        self.assertTrue(all(item["status"] == "FAIL" for item in wave_records))
        self.assertEqual(
            digests,
            {
                item["sha256"]
                for item in indicators["indicators"]
                if item.get("campaign") == "activation-gateway PNG process-hollowing wave"
            },
        )
        campaign = next(
            item
            for item in campaigns["campaigns"]
            if item["id"] == "2026-11-activation-gateway-png-hollowing"
        )
        self.assertEqual(digests, set(campaign["confirmed_sha256"]))
        self.assertEqual(
            {f"https://github.com/{repository}" for repository in repositories},
            set(campaign["confirmed_repository_urls"]),
        )


if __name__ == "__main__":
    unittest.main()
