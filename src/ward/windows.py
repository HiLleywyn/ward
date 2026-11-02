"""Disposable Windows Sandbox execution, available only after host setup."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from .analysis import result_digest
from .remnux import MAX_SAMPLE_BYTES

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def sandbox_config(input_path: Path, output_path: Path) -> str:
    return rf"""<Configuration>
<Networking>Disable</Networking><vGPU>Disable</vGPU>
<AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
<ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection>
<ProtectedClient>Enable</ProtectedClient><MemoryInMB>4096</MemoryInMB>
<MappedFolders><MappedFolder><HostFolder>{escape(str(input_path))}</HostFolder><SandboxFolder>C:\WardInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
<MappedFolder><HostFolder>{escape(str(output_path))}</HostFolder><SandboxFolder>C:\WardOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders>
</Configuration>"""


def _directory_bytes(path: Path, maximum: int) -> int:
    total = 0
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        total += item.stat().st_size
        if total > maximum:
            break
    return total


def _sandbox_id(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"id", "sandboxid", "sandbox_id"} and isinstance(item, str):
                from uuid import UUID
                return str(UUID(item))
        for item in value.values():
            found = _sandbox_id(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _sandbox_id(item)
            if found:
                return found
    return None


def _guest_command(executable: str, sandbox_id: str) -> list[str]:
    # The unattended worker has no active guest login, so ExistingLogin cannot run the collector.
    return [
        executable, "exec", "--id", sandbox_id,
        "--command", r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\WardInput\collect.ps1",
        "--run-as", "System", "--raw",
    ]


def analyze_windows(
    data: bytes, *, expected_sha256: str,
    heartbeat: Callable[[], None] | None = None,
) -> dict:
    executable = shutil.which("wsb.exe") if os.name == "nt" else None
    if executable is None:
        raise ValueError("Windows Sandbox CLI is unavailable; finish host setup and restart Windows")
    if not data or len(data) > MAX_SAMPLE_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Windows sample size or digest is invalid")
    # Only newly created, job-specific transfer directories are shared. No personal folders.
    with tempfile.TemporaryDirectory(prefix="ward-windows-") as temporary:
        root = Path(temporary)
        inputs, outputs = root / "input", root / "output"
        inputs.mkdir()
        outputs.mkdir()
        (inputs / "collect.ps1").write_text(Path(__file__).with_name("windows_guest.ps1").read_text(encoding="utf-8"), encoding="utf-8")
        (inputs / "request.json").write_text(json.dumps({"sha256": expected_sha256, "content_base64": base64.b64encode(data).decode()}), encoding="utf-8")
        # Refuse to attach to or stop a sandbox that belongs to another task.
        existing = subprocess.run(
            [executable, "list", "--raw"], capture_output=True, text=True,
            timeout=15, check=True, creationflags=CREATE_NO_WINDOW,
        )
        existing_value = json.loads(existing.stdout or "[]")
        if _sandbox_id(existing_value):
            raise ValueError("Another Windows Sandbox is active; it was left untouched")
        started = subprocess.run(
            [executable, "start", "--config", sandbox_config(inputs, outputs), "--raw"],
            capture_output=True, text=True, timeout=90, check=True,
            creationflags=CREATE_NO_WINDOW,
        )
        sandbox_id = _sandbox_id(json.loads(started.stdout))
        if not sandbox_id:
            raise ValueError("Windows Sandbox did not return a valid instance ID")
        execution = None
        try:
            execution = subprocess.Popen(
                _guest_command(executable, sandbox_id),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                creationflags=CREATE_NO_WINDOW,
            )
            deadline = time.monotonic() + 180
            next_heartbeat = time.monotonic() + 30
            report_path = outputs / "result.json"
            while time.monotonic() < deadline:
                if heartbeat is not None and time.monotonic() >= next_heartbeat:
                    heartbeat()
                    next_heartbeat = time.monotonic() + 30
                if execution.poll() not in (None, 0):
                    stdout, stderr = execution.communicate(timeout=1)
                    detail = (stderr or stdout or "unknown error").strip()[:300]
                    raise ValueError(f"Windows guest collector failed: {detail}")
                if _directory_bytes(outputs, 16 * 1024 * 1024) > 16 * 1024 * 1024:
                    raise ValueError("Windows guest exceeded its 16 MiB result-directory limit")
                if report_path.is_file() and report_path.stat().st_size <= 2 * 1024 * 1024:
                    try:
                        telemetry = json.loads(report_path.read_text(encoding="utf-8-sig"))
                    except (OSError, ValueError):
                        time.sleep(0.5)
                        continue
                    if telemetry.get("sha256") != expected_sha256 or telemetry.get("network") != "disabled":
                        raise ValueError("Windows guest telemetry did not match this artifact and policy")
                    break
                time.sleep(0.25)
            else:
                raise ValueError("Windows guest analysis exceeded its 180 second limit")
        finally:
            if execution is not None and execution.poll() is None:
                execution.terminate()
                try:
                    execution.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    execution.kill()
                    execution.wait(timeout=5)
            subprocess.run(
                [executable, "stop", "--id", sandbox_id], capture_output=True,
                timeout=30, check=True, creationflags=CREATE_NO_WINDOW,
            )
        report = {
            "schema": "ward-windows-behavior-v1", "sha256": expected_sha256,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "behavioral_analysis": "executed" if telemetry.get("executed") else "blocked-or-failed",
            "coverage": "partial", "sandbox_id": sandbox_id, "guest": telemetry,
            "isolation": {"network": "disabled", "clipboard": False, "gpu": False, "disposable": True,
                          "transfer_folders": "job-specific input and output only", "stopped": True},
            "limitations": [
                "Offline execution can prevent later stages from running. It cannot prove software safe.",
                "Guest telemetry can be incomplete or tampered with; profile changes can include background Windows activity.",
                "File-change coverage is limited to selected top-level user and ProgramData locations.",
                "Input is read-only; the only writable host mapping is this job's isolated, size-monitored result directory.",
                "This run does not satisfy Ward's reserved Verified tier or independently authenticate guest telemetry.",
            ],
        }
        report["evidence_digest"] = result_digest(report)
        return report
