import hashlib
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from ward.cli import build_parser
from ward.remnux import MAX_SAMPLE_BYTES, analyze_remnux


class RemnuxTests(unittest.TestCase):
    def test_operator_command(self):
        args = build_parser().parse_args(["remnux", "sample.bin", "--sha256", "a" * 64])
        self.assertEqual(args.command, "remnux")
        self.assertEqual(args.sha256, "a" * 64)

    def test_rejects_mismatched_and_oversized_inputs_before_starting_docker(self):
        with patch("ward.remnux.subprocess.run") as run:
            for data, expected in ((b"fixture", "a" * 64), (b"", None), (b"x" * (MAX_SAMPLE_BYTES + 1), None)):
                with self.subTest(size=len(data)), self.assertRaises(ValueError):
                    analyze_remnux(data, expected_sha256=expected)
            run.assert_not_called()

    def test_offline_container_is_pinned_bounded_and_evidence_bound(self):
        data = b"harmless fixture"
        digest = hashlib.sha256(data).hexdigest()
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(command, 0, json.dumps([{
                    "Id": "sha256:" + "b" * 64, "RepoDigests": ["remnux/remnux-distro@sha256:" + "c" * 64],
                }]), "")
            if command[1] == "run":
                payload = json.loads(kwargs["input"])
                self.assertEqual(payload["sha256"], digest)
                self.assertEqual(kwargs["timeout"], 120)
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "sha256": digest, "coverage": "partial", "engines": [{"name": "capa", "status": "timeout"}],
                }), "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("ward.remnux.subprocess.run", side_effect=run):
            report = analyze_remnux(data)
        command = commands[1]
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--user=remnux", "--pull=never",
                     "--security-opt=no-new-privileges:true", "--pids-limit=64", "--memory=2g", "--cpus=1"):
            self.assertIn(flag, command)
        self.assertFalse(any(flag in command for flag in ("-v", "--volume", "--mount", "--privileged", "-p")))
        self.assertIn("sha256:" + "b" * 64, command)
        self.assertIn("--tmpfs=/samples:rw,noexec,nosuid,nodev,size=64m,mode=1777", command)
        self.assertIn("--entrypoint=/opt/dnfile/bin/python3", command)
        self.assertEqual(report["coverage"], "partial")
        self.assertFalse(report["isolation"]["sample_executed"])
        evidence_digest = report.pop("evidence_digest")
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(evidence_digest, "sha256:" + hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(commands[-1][1:3], ["rm", "--force"])
        self.assertEqual(commands[-1][-1], command[command.index("--name") + 1])

    def test_timeout_removes_server_side_container(self):
        def run(command, **kwargs):
            if command[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(command, 0, '[{"Id":"sha256:fixture"}]', "")
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, 120)
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("ward.remnux.subprocess.run", side_effect=run) as mocked:
            with self.assertRaisesRegex(ValueError, "120 second"):
                analyze_remnux(b"fixture")
        self.assertEqual(mocked.call_args_list[-1].args[0][1:3], ["rm", "--force"])

    def test_worker_cannot_bind_report_to_another_hash(self):
        responses = [
            subprocess.CompletedProcess([], 0, '[{"Id":"sha256:fixture"}]', ""),
            subprocess.CompletedProcess([], 0, '{"sha256":"wrong"}', ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with patch("ward.remnux.subprocess.run", side_effect=responses):
            with self.assertRaisesRegex(ValueError, "different artifact"):
                analyze_remnux(b"fixture")


@unittest.skipUnless(sys.platform.startswith("linux"), "Worker runs inside Linux REMnux")
class RemnuxWorkerTests(unittest.TestCase):
    def test_packed_files_use_packer_analysis_and_keep_partial_coverage(self):
        from ward.remnux_worker import analyze
        data = b"MZ fixture MEI\x0c\x0b\x0a\x0b\x0e"

        def tool(name, command, timeout):
            self.assertNotEqual(name, "capa")
            return {"name": name, "status": "completed", "output": '{"rules":{}}'}

        with patch("ward.remnux_worker.Path.write_bytes", return_value=len(data)):
            with patch("ward.remnux_worker.run_tool", side_effect=tool):
                report = analyze(data)
        capa = next(engine for engine in report["engines"] if engine["name"] == "capa")
        self.assertEqual(capa["scope"], "packed-content-unresolved")
        self.assertEqual(capa["status"], "not-run")
        self.assertIn("detect-it-easy", {engine["name"] for engine in report["engines"]})
        self.assertEqual(report["coverage"], "partial")
        self.assertEqual(report["behavioral_analysis"], "not-run")

    def test_tool_stderr_does_not_contaminate_json_stdout(self):
        from ward.remnux_worker import run_tool
        result = run_tool("fixture", [sys.executable, "-c",
                          "import sys; print('{\"rules\":{}}'); print('warning',file=sys.stderr)"], 5)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(json.loads(result["output"]), {"rules": {}})
        self.assertIn("warning", result["warnings"])

    def test_oversized_tool_report_is_partial(self):
        from ward.remnux_worker import run_tool
        with patch("ward.remnux_worker.MAX_OUTPUT", 64):
            result = run_tool("fixture", [sys.executable, "-c", "print('x'*1000)"], 5)
        self.assertEqual(result["status"], "partial")

    def test_tool_failures_keep_exit_code_when_stderr_is_empty(self):
        from ward.remnux_worker import run_tool
        result = run_tool("fixture", [sys.executable, "-c", "raise SystemExit(7)"], 5)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 7)
