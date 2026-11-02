"""Windows host controller using local Docker exec as its private queue bridge."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from .windows import CREATE_NO_WINDOW, analyze_windows


def bridge(container, action, payload=None):
    completed = subprocess.run(
        ["docker", "exec", "-i", container, "python", "-m", "ward", "worker-bridge", "--engine", "windows", action],
        input=json.dumps(payload), capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
        creationflags=CREATE_NO_WINDOW,
    )
    return json.loads(completed.stdout)


def run_windows_worker(container="ward", *, once=False):
    if os.name != "nt":
        raise ValueError("The Windows controller must run on a Windows host")
    # A real benign launch and teardown must succeed before publishing availability.
    deadline = time.monotonic() + 900
    while not shutil.which("wsb.exe"):
        if once or time.monotonic() >= deadline:
            raise ValueError("Windows Sandbox CLI is unavailable after setup; restart Windows and open Sandbox once")
        time.sleep(10)
    control = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "whoami.exe"
    data = control.read_bytes()
    probe = analyze_windows(data, expected_sha256=hashlib.sha256(data).hexdigest())
    if probe.get("behavioral_analysis") != "executed" or not probe.get("isolation", {}).get("stopped"):
        raise ValueError("Windows Sandbox's benign execution and teardown test did not pass")
    while True:
        bridge(container, "heartbeat")
        job = bridge(container, "claim")
        if job:
            try:
                data = base64.b64decode(job.pop("content_base64"), validate=True)
                result = analyze_windows(
                    data, expected_sha256=job["sha256"],
                    heartbeat=lambda: bridge(container, "heartbeat"),
                )
                bridge(container, "finish", {"id": job["id"], "claim_token": job["claim_token"], "result": result})
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                bridge(container, "finish", {"id": job["id"], "claim_token": job["claim_token"], "error": str(exc)[:500]})
        if once:
            return
        if not job:
            time.sleep(5)
