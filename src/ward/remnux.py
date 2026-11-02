"""Operator-only static analysis using a disposable REMnux container."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


REMNUX_IMAGE = "ward-remnux:0.8.0"
MAX_SAMPLE_BYTES = 32 * 1024 * 1024
WORKER_TIMEOUT = 200


def analyze_remnux(data: bytes, *, expected_sha256: str | None = None) -> dict:
    """Send bytes over stdin; expose no host directories, ports, or sockets."""
    if not data or len(data) > MAX_SAMPLE_BYTES:
        raise ValueError("REMnux accepts files containing 1 byte to 32 MiB")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256.lower():
        raise ValueError("Sample SHA-256 does not match the expected artifact")
    try:
        inspected = subprocess.run(
            ["docker", "image", "inspect", REMNUX_IMAGE], capture_output=True,
            text=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"REMnux image unavailable; run: docker pull {REMNUX_IMAGE}") from exc
    image = json.loads(inspected.stdout)[0]
    image_id = image["Id"]
    name = "ward-remnux-" + uuid4().hex
    driver = Path(__file__).with_name("remnux_worker.py").read_text(encoding="utf-8")
    command = [
        "docker", "run", "--rm", "--pull=never", "--name", name, "-i",
        "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--user=remnux",
        "--workdir=/tmp",
        "--pids-limit=64", "--memory=2g", "--memory-swap=2g", "--cpus=1",
        "--tmpfs=/samples:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint=/opt/dnfile/bin/python3", image_id, "-c", driver,
    ]
    payload = json.dumps({"sha256": digest, "content_base64": base64.b64encode(data).decode()})
    try:
        completed = subprocess.run(
            command, input=payload, capture_output=True, text=True,
            encoding="utf-8", timeout=WORKER_TIMEOUT, check=False,
        )
        if completed.returncode:
            raise ValueError("REMnux analysis failed: " + completed.stderr.strip()[:500])
        if len(completed.stdout) > 2 * 1024 * 1024:
            raise ValueError("REMnux returned an oversized report")
        result = json.loads(completed.stdout)
        if result.get("sha256") != digest:
            raise ValueError("REMnux returned evidence for a different artifact")
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"REMnux analysis exceeded the {WORKER_TIMEOUT} second limit") from exc
    finally:
        # docker's client timeout does not stop the server-side container.
        subprocess.run(
            ["docker", "rm", "--force", name], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
    result.update({
        "schema": "ward-remnux-static-v1",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "image": {"reference": REMNUX_IMAGE, "id": image_id, "digests": image.get("RepoDigests", [])},
        "isolation": {"network": "none", "read_only": True, "host_mounts": False, "sample_executed": False},
        "limitations": [
            "Static evidence describes capabilities and structure, not observed runtime behavior.",
            "Packed or encrypted content can hide capabilities; no matches does not establish safety.",
            "A Docker container is not the VM isolation required for behavioral execution or Ward's Verified tier.",
        ],
    })
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    result["evidence_digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return result
