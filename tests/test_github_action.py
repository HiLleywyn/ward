from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ACTION_SCRIPT = Path(__file__).parents[1] / ".github/actions/ward/ward_scan.py"
ACTION_MANIFEST = Path(__file__).parents[1] / ".github/actions/ward/action.yml"
SPEC = importlib.util.spec_from_file_location("ward_github_action", ACTION_SCRIPT)
ward_action = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ward_action)


class WardGitHubActionTests(unittest.TestCase):
    def test_manifest_binds_pull_requests_to_their_head_commit(self):
        manifest = ACTION_MANIFEST.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.head.repo.clone_url", manifest)
        self.assertIn("github.event.pull_request.head.sha", manifest)

    def test_completed_inspection_writes_linked_badge_and_exact_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            summary = Path(temporary) / "summary"
            environment = {
                "WARD_URL": "https://ward.example",
                "WARD_REPOSITORY_URL": "https://github.com/owner/repo",
                "WARD_REF": "main",
                "WARD_EXPECTED_COMMIT": "a" * 40,
                "WARD_TIMEOUT_SECONDS": "15",
                "WARD_IDEMPOTENCY_KEY": "fixture",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
            }
            responses = [
                {"id": "scan-1", "status": "completed", "links": {"self": "/api/v1/scans/scan-1"}},
                {
                    "verdict": {"status": "unknown"},
                    "evidence": {"verification": {"level": "inspected"}},
                    "engines": [{"detections": []}],
                },
            ]
            with patch.dict(os.environ, environment, clear=True):
                with patch.object(ward_action, "request_json", side_effect=responses) as request:
                    self.assertEqual(ward_action.main(), 0)
            submitted = request.call_args_list[0].kwargs["payload"]
            self.assertEqual(submitted["expected_commit"], "a" * 40)
            self.assertEqual(submitted["ref"], "main")
            outputs = output.read_text(encoding="utf-8")
            self.assertIn("record-url=https://ward.example/scans/scan-1", outputs)
            self.assertIn("api/v1/badges/owner/repo.svg?branch=main", outputs)
            self.assertIn("Verification: **inspected**", summary.read_text(encoding="utf-8"))

    def test_malicious_verdict_fails_workflow(self):
        environment = {
            "WARD_REPOSITORY_URL": "https://github.com/owner/repo",
            "WARD_EXPECTED_COMMIT": "b" * 40,
        }
        responses = [
            {"id": "scan-2", "status": "completed", "links": {"self": "/api/v1/scans/scan-2"}},
            {"verdict": {"status": "malicious"}, "evidence": {}, "engines": [{"detections": [{}]}]},
        ]
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(ward_action, "request_json", side_effect=responses):
                self.assertEqual(ward_action.main(), 1)

    def test_partial_unknown_result_fails_workflow(self):
        environment = {
            "WARD_REPOSITORY_URL": "https://github.com/owner/repo",
            "WARD_EXPECTED_COMMIT": "b" * 40,
        }
        responses = [
            {"id": "scan-3", "status": "completed", "links": {"self": "/api/v1/scans/scan-3"}},
            {
                "verdict": {"status": "unknown"},
                "evidence": {"verification": {"level": "partial"}},
                "engines": [{"detections": []}],
            },
        ]
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(ward_action, "request_json", side_effect=responses):
                self.assertEqual(ward_action.main(), 1)

    def test_badge_repository_must_be_github_owner_and_name(self):
        with self.assertRaises(RuntimeError):
            ward_action.repository_name("https://git.example/team/group/repo.git")


if __name__ == "__main__":
    unittest.main()
