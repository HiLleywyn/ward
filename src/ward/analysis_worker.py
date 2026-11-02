"""Trusted controller. Only its disposable child receives artifact bytes."""
from __future__ import annotations

import time
import hashlib

from .evidence import default_store
from .remnux import analyze_remnux


def run_worker(*, once=False):
    store = default_store()
    smoke = b"Ward REMnux worker smoke test\n"
    probe = analyze_remnux(smoke, expected_sha256=hashlib.sha256(smoke).hexdigest())
    if probe.get("sha256") != hashlib.sha256(smoke).hexdigest() or probe.get("isolation", {}).get("sample_executed") is not False:
        raise ValueError("REMnux worker smoke test did not preserve its artifact and no-execution policy")
    while True:
        store.analyses.heartbeat("remnux")
        job = store.analyses.claim("remnux")
        if job:
            try:
                result = analyze_remnux(job["data"], expected_sha256=job["sha256"])
                store.analyses.finish(job["id"], job["claim_token"], result=result)
            except Exception as exc:
                store.analyses.finish(job["id"], job["claim_token"], error=str(exc))
        if once:
            return
        if not job:
            time.sleep(2)
