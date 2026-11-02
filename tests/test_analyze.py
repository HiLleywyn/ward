from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ward.analyze import assess_file, assess_repository, parse_repository_target
from ward.github import RepositorySnapshot


NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def snapshot(
    full_name: str,
    *,
    created_at: str = "2020-01-01T00:00:00Z",
    owner_created_at: str = "2018-01-01T00:00:00Z",
    fork: bool = False,
    size: int = 5_000,
    readme: str = "",
    releases: list | None = None,
) -> RepositorySnapshot:
    owner, name = full_name.split("/", 1)
    return RepositorySnapshot(
        repository={
            "full_name": full_name,
            "name": name,
            "created_at": created_at,
            "fork": fork,
            "size": size,
        },
        owner={"login": owner, "created_at": owner_created_at},
        releases=releases or [],
        readme=readme,
    )


class ParseTargetTests(unittest.TestCase):
    def test_owner_repo(self):
        self.assertEqual(parse_repository_target("owner/repo"), ("owner", "repo"))

    def test_github_url(self):
        self.assertEqual(
            parse_repository_target("https://github.com/owner/repo/releases"),
            ("owner", "repo"),
        )

    def test_rejects_other_hosts(self):
        with self.assertRaises(ValueError):
            parse_repository_target("https://example.com/owner/repo")


class RepositoryAssessmentTests(unittest.TestCase):
    def test_negative_antivirus_guidance_is_not_a_bypass_instruction(self):
        result = assess_repository(snapshot('person/guide', readme='Never disable antivirus or Defender.'), NOW)
        self.assertFalse(any(s.key == 'antivirus_bypass_instruction' for s in result.signals))

    def test_tiny_source_large_release_and_profile_name(self):
        from dataclasses import replace
        snap = snapshot('KytyPS5-lookalike/.github', releases=[{'assets':[{'name':'build.zip','size':20_000_000}]}])
        snap = replace(snap, tree_summary={'source_count':0,'source_bytes':0,'truncated':False})
        result = assess_repository(snap, NOW)
        self.assertTrue(any(s.key == 'little_source_large_release' for s in result.signals))

    def test_registry_location_is_not_penalized_for_name(self):
        result = assess_repository(
            snapshot("boykopovar/AnyPS5", created_at="2026-08-03T21:30:25Z"), NOW
        )
        self.assertEqual(result.verdict, "no-strong-signals")
        self.assertEqual(result.score, 0)

    def test_lookalike_with_defender_command_is_high_risk_metadata(self):
        result = assess_repository(
            snapshot(
                "new-owner/AnyPS5",
                created_at="2026-10-25T00:00:00Z",
                owner_created_at="2026-10-24T00:00:00Z",
                size=10,
                readme="Run " + "Add-" + "MpPreference -ExclusionPath C:\\Temp, then download https://bad.example/download/app.exe",
                releases=[
                    {
                        "assets": [
                            {"name": "AnyPS5.exe", "size": 8_000_000},
                            {"name": "AnyPS5.zip", "size": 9_000_000},
                        ]
                    }
                ],
            ),
            NOW,
        )
        self.assertEqual(result.verdict, "high-risk-metadata")
        self.assertFalse(result.exact_indicator_match)
        self.assertGreaterEqual(result.score, 75)

    def test_generic_new_repo_is_not_called_malware(self):
        result = assess_repository(
            snapshot("person/unrelated", created_at="2026-10-25T00:00:00Z"), NOW
        )
        self.assertEqual(result.verdict, "no-strong-signals")
        self.assertFalse(result.exact_indicator_match)


class FileAssessmentTests(unittest.TestCase):
    def test_exact_hash_match(self):
        payload = b"test fixture, not malware"
        sha256 = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(payload)
            result = assess_file(path, {"indicators": [{"sha256": sha256, "status": "confirmed"}]})
        self.assertTrue(result.exact_indicator_match)
        self.assertEqual(result.verdict, "confirmed-malicious-indicator")

    def test_unknown_hash_is_not_declared_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"another harmless test fixture")
            result = assess_file(path, {"indicators": []})
        self.assertEqual(result.verdict, "no-known-hash-match")
        self.assertIn("does not mean a file is safe", " ".join(result.limitations))

    def test_known_project_asset_is_provenance_not_safety(self):
        payload = b"known project fixture"
        sha256 = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(payload)
            result = assess_file(
                path,
                {"indicators": []},
                {
                    "assets": [
                        {
                            "sha256": sha256,
                            "project": "FixtureEmu",
                            "release": "v1",
                            "name": "fixture.bin",
                        }
                    ]
                },
            )
        self.assertEqual(result.verdict, "known-project-artifact")
        self.assertFalse(result.exact_indicator_match)
        self.assertIn("not a guarantee", " ".join(result.limitations))


if __name__ == "__main__":
    unittest.main()

