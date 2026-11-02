from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from unittest.mock import patch

from ward.scanner import ScanError, _git_environment, inspect_tree, normalize_repository_url, scan_repository


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

    def test_git_lley_human_and_stable_urls_gain_clone_suffix(self):
        pairs = {
            "https://git.lley.cat/lleywyn/ward": "https://git.lley.cat/lleywyn/ward.git",
            "https://git.lley.cat/r/b60252cb-df6f-478f-8cb7-d18f4cdd316b":
                "https://git.lley.cat/r/b60252cb-df6f-478f-8cb7-d18f4cdd316b.git",
        }
        for entered, expected in pairs.items():
            with self.subTest(entered=entered):
                self.assertEqual(normalize_repository_url(entered, resolve=False), expected)

    def test_credentials_and_private_networks_are_rejected(self):
        for value in (
            "https://user:pass@example.org/project.git",
            "https://127.0.0.1/project.git",
            "https://10.0.0.2/project.git",
            "http://github.com/owner/repository",
        ):
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_repository_url(value, resolve=False)

    def test_invalid_branch_names_are_rejected(self):
        from ward.scanner import normalize_git_ref
        for value in ("--upload-pack=evil", "../main", "refs//heads/main", "main.lock"):
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_git_ref(value)

    def test_clone_is_pinned_to_the_validated_public_address(self):
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if "clone" in command:
                Path(command[-1]).mkdir(parents=True)
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, "a" * 40 + "\n", "")

        address = (None, None, None, None, ("93.184.216.34", 443))
        with patch("ward.scanner.socket.getaddrinfo", return_value=[address]):
            with patch("ward.scanner.subprocess.run", side_effect=run):
                result = scan_repository("https://example.com/team/repository.git")
        self.assertEqual(result["status"], "Unverified")
        self.assertIn("http.curloptResolve=+example.com:443:93.184.216.34", commands[0])

    def test_expected_commit_prevents_branch_race(self):
        def run(command, **kwargs):
            if "clone" in command:
                Path(command[-1]).mkdir(parents=True)
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, "a" * 40 + "\n", "")

        address = (None, None, None, None, ("93.184.216.34", 443))
        with patch("ward.scanner.socket.getaddrinfo", return_value=[address]):
            with patch("ward.scanner.subprocess.run", side_effect=run):
                with self.assertRaisesRegex(ScanError, "ref changed"):
                    scan_repository("https://example.com/team/repository.git", expected_commit="b" * 40)


class StaticInspectionTests(unittest.TestCase):
    @staticmethod
    def _pyinstaller_fixture(members: list[tuple[str, bytes, str]]) -> bytes:
        prefix = b"MZ" + b"\0" * 62
        payload = bytearray()
        toc = bytearray()
        for name, content, typecode in members:
            packed = zlib.compress(content)
            offset = len(payload)
            payload.extend(packed)
            encoded_name = name.encode() + b"\0"
            entry_length = 18 + len(encoded_name)
            toc.extend(struct.pack("!IIIIBc", entry_length, offset, len(packed), len(content), 1, typecode.encode()))
            toc.extend(encoded_name)
        toc_offset = len(payload)
        cookie_size = struct.calcsize("!8sIIII64s")
        package_length = len(payload) + len(toc) + cookie_size
        cookie = struct.pack(
            "!8sIIII64s",
            b"MEI\x0c\x0b\x0a\x0b\x0e",
            package_length,
            toc_offset,
            len(toc),
            313,
            b"python3.13.dll\0".ljust(64, b"\0"),
        )
        return prefix + payload + toc + cookie

    def test_pyinstaller_encrypted_payload_tooling_is_reported_without_execution(self):
        fixture = self._pyinstaller_fixture([
            ("blank.aes", b"encrypted payload fixture", "x"),
            ("rar.exe", b"MZ fixture archiver", "b"),
            ("rarreg.key", b"fixture key", "x"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Built.exe").write_bytes(fixture)
            result = inspect_tree(root, indicators={"indicators": []})

        finding = next(item for item in result["findings"] if item["kind"] == "pyinstaller-encrypted-payload")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("blank.aes", finding["detail"])
        self.assertIn("rar.exe", finding["detail"])
        self.assertEqual(result["archives"], 1)

    def test_unreadable_file_marks_scan_partial_instead_of_claiming_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.bin").write_bytes(b"fixture")
            with patch("pathlib.Path.open", side_effect=OSError("blocked by host protection")):
                result = inspect_tree(root, indicators={"indicators": []})

        self.assertTrue(result["partial"])
        self.assertEqual(result["hashed_bytes"], 0)
        self.assertIn("file-unreadable", {item["kind"] for item in result["findings"]})

    def test_unreadable_archive_marks_inspection_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "opaque.zip"
            archive.write_bytes(b"not a zip archive")
            result = inspect_tree(Path(directory))

        self.assertTrue(result["partial"])
        self.assertIn("archive-unreadable", {finding["kind"] for finding in result["findings"]})

    def test_exact_hash_and_suspicious_script_are_reported(self):
        payload = b"known fixture, not live malware"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.bin").write_bytes(payload)
            (root / "setup.ps1").write_text(
                "Add-" + "MpPreference -ExclusionPath C:\\Temp\n"
                "powershell.exe -" + "EncodedCommand ZgBpAHgAdAB1AHIAZQA=",
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
                archive.writestr("install.cmd", "sch" + "tasks /create /tn updater /tr payload.exe")
            result = inspect_tree(root, indicators={"indicators": []})
        match = next(finding for finding in result["findings"] if finding["kind"] == "persistence-task")
        self.assertEqual(match["path"], "release.zip!install.cmd")

    def test_python_behavior_inside_zip_is_inspected_without_execution(self):
        source = 'import discord\nasync def raid(channel):\n    while True:\n        await channel.send("@everyone fixture")\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "release.zip", "w") as archive:
                archive.writestr("Nuker.py", source)
            result = inspect_tree(root, indicators={"indicators": []})
        match = next(finding for finding in result["findings"] if finding["kind"] == "discord-mention-flood")
        self.assertEqual(match["path"], "release.zip!Nuker.py")

    def test_discord_abuse_source_is_flagged_without_execution(self):
        source = '''
import discord

async def raid(guild, channel):
    while True:
        await channel.send("@everyone fixture")

async def flood_roles(guild):
    while True:
        await guild.create_role(name="fixture")
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Nuker.py").write_text(source, encoding="utf-8")
            result = inspect_tree(root, indicators={"indicators": []})

        kinds = {finding["kind"] for finding in result["findings"]}
        self.assertIn("discord-mention-flood", kinds)
        self.assertIn("discord-resource-flood", kinds)
        self.assertTrue(all(finding.get("evidence_type") == "source-behavior" for finding in result["findings"]))

    def test_bounded_discord_actions_are_not_called_an_abuse_loop(self):
        source = '''
import discord

async def announce(channel):
    await channel.send("@everyone scheduled maintenance")

async def bounded(guild):
    while True:
        await guild.create_role(name="fixture")
        break
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bot.py").write_text(source, encoding="utf-8")
            result = inspect_tree(root, indicators={"indicators": []})

        kinds = {finding["kind"] for finding in result["findings"]}
        self.assertNotIn("discord-mention-flood", kinds)
        self.assertNotIn("discord-resource-flood", kinds)

    def test_embedded_discord_token_is_redacted(self):
        token = "A" * 24 + "." + "B" * 6 + "." + "C" * 30
        source = f'import discord\nbot.run("{token}")\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bot.py").write_text(source, encoding="utf-8")
            result = inspect_tree(root, indicators={"indicators": []})

        finding = next(item for item in result["findings"] if item["kind"] == "embedded-discord-token")
        self.assertEqual(finding["evidence_type"], "credential-exposure")
        serialized = str(finding)
        self.assertNotIn(token, serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_decoded_content_is_not_flagged_unless_executed(self):
        source = 'import base64\npayload = base64.b64decode("Zml4dHVyZQ==")\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "decode.py").write_text(source, encoding="utf-8")
            result = inspect_tree(root, indicators={"indicators": []})
        self.assertNotIn("decoded-python-execution", {finding["kind"] for finding in result["findings"]})


if __name__ == "__main__":
    unittest.main()
