from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from unittest.mock import patch

from emuwatch.scanner import ScanError, _git_environment, inspect_tree, normalize_repository_url


class RepositoryUrlTests(unittest.TestCase):
    def test_git_environment_keeps_required_windows_runtime_without_credentials(self):
        with patch.dict(os.environ, {
            "PATH": "tools",
            "SystemRoot": "C:\\Windows",
            "GITHUB_TOKEN": "secret",
        }, clear=True):
            environment = _git_environment(Path("work"))
        self.assertEqual(environment["SystemRoot"], "C:\\Windows")
        self.assertEqual(environment["PATH"], "tools")
        self.assertNotIn("GITHUB_TOKEN", environment)

    def test_github_shorthand_becomes_https_clone_url(self):
        self.assertEqual(
            normalize_repository_url("owner/repository", resolve=False),
            "https://github.com/owner/repository.git",
        )

    def test_generic_public_https_repository_is_supported(self):
        self.assertEqual(
            normalize_repository_url("https://git.example.org/team/project.git", resolve=False),
            "https://git.example.org/team/project.git",
        )

    def test_credentials_and_private_networks_are_rejected(self):
        for value in (
            "https://user:pass@example.org/project.git",
            "https://127.0.0.1/project.git",
            "https://10.0.0.2/project.git",
            "http://github.com/owner/repository",
        ):
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_repository_url(value, resolve=False)


class StaticInspectionTests(unittest.TestCase):
    def test_exact_hash_and_suspicious_script_are_reported(self):
        payload = b"known fixture, not live malware"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.bin").write_bytes(payload)
            (root / "setup.ps1").write_text(
                "Add-MpPreference -ExclusionPath C:\\Temp\n"
                "powershell.exe -EncodedCommand ZgBpAHgAdAB1AHIAZQA=",
                encoding="utf-8",
            )
            result = inspect_tree(root, indicators={"indicators": [{
                "sha256": digest,
                "status": "confirmed",
                "source_url": "https://example.org/report",
            }]})
        kinds = {finding["kind"] for finding in result["findings"]}
        self.assertIn("known-malware-hash", kinds)
        self.assertIn("defender-exclusion", kinds)
        self.assertIn("encoded-powershell", kinds)

    def test_small_text_inside_zip_is_inspected_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "release.zip", "w") as archive:
                archive.writestr("install.cmd", "schtasks /create /tn updater /tr payload.exe")
            result = inspect_tree(root, indicators={"indicators": []})
        match = next(finding for finding in result["findings"] if finding["kind"] == "persistence-task")
        self.assertEqual(match["path"], "release.zip!install.cmd")


if __name__ == "__main__":
    unittest.main()
