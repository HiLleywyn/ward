import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ward.analysis import result_digest
from ward.api import report_for_job
from ward.evidence import ResultStore
from ward.windows import _guest_command, _sandbox_id, sandbox_config
from ward.windows_worker import CREATE_NO_WINDOW, bridge


class AnalysisQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = ResultStore(Path(self.temp.name) / "state.db")
        self.data = b"MZ harmless fixture"
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.job, _ = self.store.create_scan_job(kind="repository", target="https://example.org/repo.git",
            request_hash="a" * 64, idempotency_key=None, cancel_token_hash="b" * 64)
        self.store.start_scan_job(self.job["id"])
        self.result = {"status": "Unverified", "artifacts": [{"path": "sample.exe", "sha256": self.digest}]}

    def tearDown(self):
        self.temp.cleanup()

    def enqueue(self, path="sample.exe"):
        return self.store.analyses.enqueue(self.job["id"], path, self.digest, self.data)

    def complete(self):
        self.store.complete_scan_job(self.job["id"], self.result)

    def test_requires_exact_completed_scan_binding_and_discards_bytes_after_completion(self):
        analysis_id = self.enqueue()
        self.assertIsNone(self.store.analyses.claim("remnux"))
        self.complete()
        claimed = self.store.analyses.claim("remnux")
        self.assertEqual(claimed["data"], self.data)
        public = self.store.scan_job(self.job["id"])["analyses"][0]
        self.assertNotIn("data", public)
        self.assertNotIn("payload", public)
        self.assertNotIn("claim_token", public)
        result = {"sha256": self.digest, "coverage": "partial", "engines": []}
        result["evidence_digest"] = result_digest(result)
        self.store.analyses.finish(analysis_id, claimed["claim_token"], result=result)
        job = self.store.scan_job(self.job["id"])
        self.assertEqual(job["result"], self.result)
        self.assertEqual(job["analyses"][0]["result"]["coverage"], "partial")
        self.assertEqual(report_for_job(job)["verdict"]["status"], "unknown")
        self.assertEqual(report_for_job(job)["engines"][1]["name"], "remnux")
        with self.store.connect() as connection:
            self.assertIsNone(connection.execute("SELECT payload FROM artifact_analyses WHERE id=?", (analysis_id,)).fetchone()[0])

    def test_wrong_claim_artifact_or_evidence_digest_cannot_be_attached(self):
        self.enqueue()
        self.complete()
        claimed = self.store.analyses.claim("remnux")
        for token, result in (("wrong", {"sha256": self.digest}),
                              (claimed["claim_token"], {"sha256": "f" * 64}),
                              (claimed["claim_token"], {"sha256": self.digest, "evidence_digest": "wrong"})):
            with self.assertRaises(ValueError):
                self.store.analyses.finish(claimed["id"], token, result=result)
        self.assertEqual(self.store.analyses.list(self.job["id"])[0]["status"], "running")

    def test_unbound_artifact_is_never_sent_to_analyzer(self):
        self.enqueue("another.exe")
        self.complete()
        self.assertIsNone(self.store.analyses.claim("remnux"))
        self.assertEqual(self.store.analyses.list(self.job["id"])[0]["status"], "incomplete")

    def test_only_one_worker_can_claim_each_job(self):
        self.enqueue()
        self.complete()
        with ThreadPoolExecutor(max_workers=4) as executor:
            claims = list(executor.map(lambda _: self.store.analyses.claim("remnux"), range(4)))
        self.assertEqual(sum(claim is not None for claim in claims), 1)

    def test_queue_is_bounded_without_hourly_allowance(self):
        for index in range(9):
            self.enqueue(f"sample{index}.exe")
        rows = self.store.analyses.list(self.job["id"])
        self.assertEqual(sum(row["status"] == "queued" for row in rows), 8)
        self.assertEqual(rows[-1]["status"], "incomplete")

    def test_expired_jobs_lose_bytes_and_do_not_retry(self):
        self.enqueue()
        self.complete()
        with self.store.connect() as connection:
            connection.execute("UPDATE artifact_analyses SET updated_at='2000-01-01T00:00:00+00:00'")
        self.assertIsNone(self.store.analyses.claim("remnux"))
        self.assertEqual(self.store.analyses.list(self.job["id"])[0]["status"], "incomplete")

    def test_restart_recovery_discards_analysis_bytes_for_interrupted_scan(self):
        self.enqueue()
        self.assertEqual(self.store.recover_interrupted_scan_jobs(), 1)
        analysis = self.store.analyses.list(self.job["id"])[0]
        self.assertEqual(analysis["status"], "incomplete")
        with self.store.connect() as connection:
            self.assertIsNone(connection.execute(
                "SELECT payload FROM artifact_analyses WHERE id=?", (analysis["id"],)
            ).fetchone()[0])


class WindowsPolicyTests(unittest.TestCase):
    @patch("ward.windows_worker.subprocess.run")
    def test_worker_bridge_never_opens_a_console_window(self, run):
        run.return_value.stdout = "{}"
        bridge("ward", "heartbeat")
        self.assertEqual(run.call_args.kwargs["creationflags"], CREATE_NO_WINDOW)

    def test_sandbox_has_only_job_transfer_folders_and_all_network_devices_disabled(self):
        from xml.etree import ElementTree
        root = ElementTree.fromstring(sandbox_config(Path("job/input"), Path("job/output")))
        for tag in ("Networking", "vGPU", "AudioInput", "VideoInput", "ClipboardRedirection", "PrinterRedirection"):
            self.assertEqual(root.findtext(tag), "Disable")
        self.assertEqual(root.findtext("ProtectedClient"), "Enable")
        mappings = root.findall("MappedFolders/MappedFolder")
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0].findtext("ReadOnly"), "true")
        self.assertEqual(mappings[1].findtext("ReadOnly"), "false")
        self.assertIsNone(root.find("LogonCommand"))

    def test_guest_collector_is_explicitly_executed_as_system(self):
        sandbox_id = "01234567-1234-1234-1234-0123456789ab"
        command = _guest_command("wsb.exe", sandbox_id)
        self.assertEqual(command[:4], ["wsb.exe", "exec", "--id", sandbox_id])
        self.assertEqual(command[command.index("--run-as") + 1], "System")
        self.assertIn(r"C:\WardInput\collect.ps1", command[command.index("--command") + 1])

    def test_guest_collector_bounds_launch_and_defender_queries(self):
        guest = Path("src/ward/windows_guest.ps1").read_text(encoding="utf-8")
        self.assertIn("Invoke-CimMethod -ClassName Win32_Process", guest)
        self.assertIn("-OperationTimeoutSec 20", guest)
        self.assertIn("-OperationTimeoutSec 10", guest)
        self.assertIn("$values.Count -lt 2000", guest)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", guest)
        self.assertIn("executed=$executed", guest)

    def test_only_explicit_sandbox_identifiers_are_used_for_teardown(self):
        expected = "01234567-1234-1234-1234-0123456789ab"
        self.assertEqual(_sandbox_id({"sandboxId": expected}), expected)
        self.assertIsNone(_sandbox_id({"message": expected}))
        with self.assertRaises(ValueError):
            _sandbox_id({"id": "not-a-guid"})
