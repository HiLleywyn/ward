import base64
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from emuwatch.api import openapi_document
from emuwatch.evidence import ResultStore
from emuwatch.web import BoundedHTTPServer, _handler


class WardAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {"EMUWATCH_PUBLIC": "1", "EMUWATCH_STATE_DIR": self.temp.name})
        self.environment.start()
        self.server = BoundedHTTPServer(("127.0.0.1", 0), _handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.environment.stop()
        self.temp.cleanup()

    def request(self, path, *, method="GET", body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(self.base + path, data=data, method=method, headers=headers or {})
        if body is not None:
            request.add_header("Content-Type", "application/json")
        with urlopen(request, timeout=4) as response:
            payload = json.load(response) if response.length != 0 else None
            return response.status, dict(response.headers), payload

    def wait_for_scan(self, scan_id):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            _, _, job = self.request(f"/api/v1/scans/{scan_id}")
            if job["status"] in {"completed", "failed", "cancelled", "incomplete"}:
                return job
            time.sleep(0.02)
        self.fail("scan did not reach a terminal state")

    def test_hash_lifecycle_idempotency_report_and_public_artifact(self):
        indicator = json.loads(
            (Path(__file__).parents[1] / "src/emuwatch/advisories/indicators.json").read_text(encoding="utf-8")
        )["indicators"][0]
        status, headers, job = self.request(
            "/api/v1/scans", method="POST",
            body={"kind": "sha256", "sha256": indicator["sha256"]},
            headers={"Idempotency-Key": "same-hash"},
        )
        self.assertEqual(status, 202)
        self.assertIn("X-Ward-Cancel-Token", headers)
        finished = self.wait_for_scan(job["id"])
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["result"]["status"], "Malicious")

        _, _, report = self.request(f"/api/v1/reports/{job['id']}")
        self.assertEqual(report["verdict"], {"status": "malicious", "confidence": 1.0})
        self.assertEqual(report["evidence"]["verification"]["level"], "observed")
        self.assertRegex(report["evidence"]["digest"], r"^sha256:[a-f0-9]{64}$")
        _, _, artifact = self.request(f"/api/v1/artifacts/{indicator['sha256']}")
        self.assertEqual(artifact["sha256"], indicator["sha256"])

        repeated_status, repeated_headers, repeated = self.request(
            "/api/v1/scans", method="POST",
            body={"kind": "sha256", "sha256": indicator["sha256"]},
            headers={"Idempotency-Key": "same-hash"},
        )
        self.assertEqual(repeated_status, 200)
        self.assertEqual(repeated["id"], job["id"])
        self.assertNotIn("X-Ward-Cancel-Token", repeated_headers)

        with self.assertRaises(HTTPError) as conflict:
            self.request(
                "/api/v1/scans", method="POST",
                body={"kind": "sha256", "sha256": "f" * 64},
                headers={"Idempotency-Key": "same-hash"},
            )
        self.assertEqual(conflict.exception.code, 409)

    def test_transient_file_scan_is_not_published_as_an_artifact(self):
        content = b"print('hello from a harmless fixture')\n"
        digest = hashlib.sha256(content).hexdigest()
        status, _, job = self.request("/api/v1/scans", method="POST", body={
            "kind": "file",
            "filename": "fixture.py",
            "content_base64": base64.b64encode(content).decode(),
        })
        self.assertEqual(status, 202)
        finished = self.wait_for_scan(job["id"])
        self.assertEqual(finished["result"]["artifact"]["sha256"], digest)
        self.assertEqual(finished["result"]["status"], "Unverified")
        _, _, listed = self.request("/api/v1/scans")
        self.assertNotIn(job["id"], {item["id"] for item in listed["items"]})
        with urlopen(self.base + f"/api/v1/scans/{job['id']}/events", timeout=3) as response:
            events = response.read().decode()
        self.assertIn("event: scan", events)
        self.assertIn('"status":"completed"', events)
        with self.assertRaises(HTTPError) as absent:
            self.request(f"/api/v1/artifacts/{digest}")
        self.assertEqual(absent.exception.code, 404)

    def test_errors_pagination_openapi_and_ssrf_rejection(self):
        document = openapi_document()
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertIn("/api/v1/scans/{scan_id}/events", document["paths"])
        _, _, served = self.request("/api/v1/openapi.json")
        self.assertEqual(served["info"]["version"], document["info"]["version"])

        with self.assertRaises(HTTPError) as rejected:
            self.request("/api/v1/scans", method="POST", body={"kind": "repository", "url": "https://127.0.0.1/repo.git"})
        self.assertEqual(rejected.exception.code, 422)
        error = json.loads(rejected.exception.read())
        self.assertEqual(error["error"]["code"], "invalid_repository")
        self.assertIn("request_id", error["error"])

        store = ResultStore(Path(self.temp.name) / "results.sqlite3")
        for index in range(2):
            store.create_scan_job(
                kind="repository", target=f"https://example.test/repository-{index}.git",
                request_hash=str(index) * 64, idempotency_key=None,
                cancel_token_hash=hashlib.sha256(f"token-{index}".encode()).hexdigest(),
            )
        _, _, page = self.request("/api/v1/scans?limit=1")
        self.assertEqual(len(page["items"]), 1)
        self.assertIsNotNone(page["next_cursor"])

    def test_mcp_discovery_tools_and_openapi_resource(self):
        status, _, initialized = self.request("/mcp", method="POST", body={
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}
            },
        })
        self.assertEqual(status, 200)
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-06-18")
        _, _, tools = self.request("/mcp", method="POST", body={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertIn("ward_submit_scan", {item["name"] for item in tools["result"]["tools"]})
        self.assertIn("ward_get_badge", {item["name"] for item in tools["result"]["tools"]})
        _, _, submitted = self.request("/mcp", method="POST", body={
            "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "ward_submit_scan", "arguments": {"kind": "sha256", "sha256": "c" * 64}
            }
        })
        scan_id = submitted["result"]["structuredContent"]["id"]
        self.assertEqual(self.wait_for_scan(scan_id)["status"], "completed")
        _, _, resource = self.request("/mcp", method="POST", body={
            "jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "ward://openapi"}
        })
        self.assertIn('"openapi": "3.1.0"', resource["result"]["contents"][0]["text"])

    def test_repository_scans_populate_pages_history_comparison_and_records(self):
        def result(repository, url, commit, branch, status, findings):
            return {
                "id": "replaced-by-job",
                "repository": repository,
                "repository_url": url,
                "commit": commit,
                "branch": branch,
                "status": status,
                "scanned_at": f"2026-11-01T12:00:0{len(findings)}+00:00",
                "duration_ms": 10,
                "summary": {"files": 1, "bytes": 10, "hashed_bytes": 10, "text_files": 1, "archives": 0, "executable_files": 0, "truncated": False},
                "findings": findings,
                "sources": [],
                "verification": {"level": "inspected", "checks": []},
                "limitations": ["Unknown does not mean safe."],
            }

        detection = {"kind": "known-malware-hash", "severity": "critical", "title": "Exact match", "path": "payload.exe", "sha256": "d" * 64}
        results = [
            result("owner/repo", "https://github.com/owner/repo.git", "a" * 40, "main", "Unverified", []),
            result("owner/repo", "https://github.com/owner/repo.git", "b" * 40, "feature", "Malicious", [detection]),
            result("someone/fork", "https://github.com/someone/fork.git", "b" * 40, "main", "Malicious", [detection]),
        ]

        def normalized(value):
            return value if value.endswith(".git") else value + ".git"

        scan_ids = []
        with patch("emuwatch.api.normalize_repository_url", side_effect=normalized):
            with patch("emuwatch.api.scan_repository", side_effect=results):
                for url, ref in (
                    ("https://github.com/owner/repo", "main"),
                    ("https://github.com/owner/repo", "feature"),
                    ("https://github.com/someone/fork", "main"),
                ):
                    _, _, job = self.request("/api/v1/scans", method="POST", body={"kind": "repository", "url": url, "ref": ref})
                    self.assertEqual(self.wait_for_scan(job["id"])["status"], "completed")
                    scan_ids.append(job["id"])

        _, _, recent = self.request("/api/scans")
        self.assertTrue(set(scan_ids).issubset({item["id"] for item in recent["scans"]}))
        _, _, history = self.request("/api/v1/repositories/history?target=owner%2Frepo")
        self.assertEqual(len(history["scans"]), 2)
        self.assertEqual(history["transitions"][0]["assessment"], "new_findings_detected")
        self.assertEqual(history["related_repositories"][0]["relationship"], "shared_commit")

        _, _, comparison = self.request(f"/api/v1/comparisons?base_scan={scan_ids[0]}&head_scan={scan_ids[1]}")
        self.assertEqual(comparison["assessment"], "new_findings_detected")
        self.assertEqual(comparison["head"]["branch"], "feature")
        _, _, records = self.request("/api/v1/malware-records")
        self.assertGreater(len(records["items"]), 0)
        _, _, record = self.request(f"/api/v1/malware-records/{records['items'][0]['id']}")
        self.assertEqual(record["id"], records["items"][0]["id"])

        with urlopen(self.base + "/api/v1/badges/owner/repo.svg?branch=feature") as response:
            badge = response.read().decode()
            self.assertEqual(response.headers.get_content_type(), "image/svg+xml")
        self.assertIn("malware detected", badge)
        generic_target = "https%3A%2F%2Fgithub.com%2Fowner%2Frepo.git"
        with urlopen(self.base + f"/api/v1/badge.svg?repository={generic_target}&branch=feature") as response:
            self.assertIn("malware detected", response.read().decode())
        with urlopen(self.base + f"/repository?target={generic_target}") as response:
            self.assertIn("Repository Ledger", response.read().decode())
        with urlopen(self.base + f"/scans/{scan_ids[1]}") as response:
            record_page = response.read().decode()
        self.assertIn("Evidence digest", record_page)
        with urlopen(self.base + "/repositories/owner/repo") as response:
            ledger_page = response.read().decode()
        self.assertIn("Observed Changes", ledger_page)


class ScanJobStoreTests(unittest.TestCase):
    def test_restart_marks_unfinished_job_incomplete_and_cancel_requires_capability(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ResultStore(Path(temp) / "results.db")
            token_hash = hashlib.sha256(b"secret").hexdigest()
            job, created = store.create_scan_job(
                kind="sha256", target="a" * 64, request_hash="b" * 64,
                idempotency_key=None, cancel_token_hash=token_hash,
            )
            self.assertTrue(created)
            with self.assertRaises(PermissionError):
                store.cancel_scan_job(job["id"], hashlib.sha256(b"wrong").hexdigest())
            self.assertEqual(store.recover_interrupted_scan_jobs(), 1)
            self.assertEqual(store.scan_job(job["id"])["status"], "incomplete")
