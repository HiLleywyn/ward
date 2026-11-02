from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import secrets
import tempfile
import threading
from importlib.resources import files
from pathlib import Path

from .analyze import load_indicators
from .data import advisory_directory
from .evidence import ResultStore
from .scanner import COMMIT_PATTERN, ScanError, inspect_tree, normalize_git_ref, normalize_repository_url, scan_repository


MAX_FILE_BYTES = 5 * 1024 * 1024
TERMINAL_STATES = {"completed", "failed", "cancelled", "incomplete"}
SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def openapi_document() -> dict:
    return json.loads(files("ward").joinpath("openapi.json").read_text(encoding="utf-8"))


def normalize_sha256(value: object) -> str:
    digest = str(value or "").strip().lower()
    if not SHA256.fullmatch(digest):
        raise APIError(422, "invalid_sha256", "sha256 must contain exactly 64 hexadecimal characters")
    return digest


def _indicator(digest: str) -> dict | None:
    indicators = load_indicators(advisory_directory() / "indicators.json")
    return next((
        item for item in indicators.get("indicators", [])
        if item.get("status") == "confirmed" and item.get("sha256", "").lower() == digest
    ), None)


def scan_hash(digest: str) -> dict:
    indicator = _indicator(digest)
    findings = []
    sources = []
    if indicator:
        findings.append({
            "kind": "known-malware-hash",
            "severity": "critical",
            "title": "Exact known-malware hash",
            "sha256": digest,
            "detail": "SHA-256 exactly matches a confirmed malicious-file indicator.",
            "source_url": indicator["source_url"],
        })
        sources.append(indicator["source_url"])
    return {
        "status": "Malicious" if indicator else "Unverified",
        "artifact": {"sha256": digest},
        "summary": {"files": 0, "bytes": None, "hashed_bytes": 0, "truncated": False},
        "findings": findings,
        "sources": sources,
        "verification": {
            "level": "observed",
            "checks": [{"name": "known-indicators", "status": "completed"}],
        },
        "limitations": [
            "Ward compared this hash with its reviewed indicator registry; it did not receive or inspect the file.",
            "No known indicator match does not prove that an artifact is safe.",
        ],
    }


def scan_file(data: bytes, filename: str, digest: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="ward-file-") as temporary:
        safe_name = Path(filename).name or "artifact.bin"
        path = Path(temporary) / safe_name
        path.write_bytes(data)
        inspected = inspect_tree(Path(temporary))
    exact_match = any(item.get("kind") == "known-malware-hash" for item in inspected["findings"])
    return {
        "status": "Malicious" if exact_match else "Unverified",
        "artifact": {"sha256": digest, "filename": safe_name, "size": len(data)},
        "summary": {key: inspected[key] for key in (
            "files", "bytes", "hashed_bytes", "text_files", "archives",
            "executable_files", "truncated",
        )},
        "findings": inspected["findings"],
        "sources": list(dict.fromkeys(
            item["source_url"] for item in inspected["findings"] if item.get("source_url")
        )),
        "verification": {
            "level": "partial" if inspected["partial"] else "inspected",
            "checks": [
                {"name": "sha256", "status": "completed"},
                {"name": "known-indicators", "status": "completed"},
                {"name": "static-rules", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "bounded-archive-inspection", "status": "partial" if inspected["partial"] else "completed"},
                {"name": "behavioral-analysis", "status": "not-run"},
            ],
        },
        "limitations": [
            "Ward inspected this file without executing it and did not retain its contents.",
            "No known indicator match does not prove that an artifact is safe.",
            "Encrypted, oversized, unsupported, or dynamically downloaded content may not be visible to this scan.",
        ],
    }


def public_scan(job: dict) -> dict:
    value = dict(job)
    scan_id = value["id"]
    value["links"] = {
        "self": f"/api/v1/scans/{scan_id}",
        "events": f"/api/v1/scans/{scan_id}/events",
        "report": f"/api/v1/reports/{scan_id}",
    }
    return value


def finalize_result(scan_id: str, result: dict) -> dict:
    """Bind an evidence digest to the exact persisted scan result."""
    value = dict(result)
    value["id"] = scan_id
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    value["evidence_digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return value


def report_for_job(job: dict) -> dict:
    if job["status"] not in TERMINAL_STATES:
        raise APIError(409, "scan_not_finished", "The scan has not reached a terminal state")
    result = job.get("result") or {}
    status_map = {
        "Malicious": ("malicious", 1.0),
        "Corroborated": ("suspicious", 0.9),
        "Suspicious": ("suspicious", 0.65),
        "Unverified": ("unknown", 0.0),
    }
    verdict, confidence = status_map.get(result.get("status"), ("incomplete", 0.0))
    if job["status"] != "completed":
        verdict, confidence = "incomplete", 0.0
    engine_status = "completed" if job["status"] == "completed" else job["status"]
    return {
        "id": job["id"],
        "scan_id": job["id"],
        "created_at": job["created_at"],
        "completed_at": job["updated_at"] if job["status"] in TERMINAL_STATES else None,
        "verdict": {"status": verdict, "confidence": confidence},
        "engines": [{
            "name": "ward-static",
            "status": engine_status,
            "detections": result.get("findings", []),
            "error": ({"code": job["error_code"], "message": job["error_message"]}
                      if job.get("error_code") else None),
        }] + [{
            "name": analysis["engine"], "status": analysis["status"],
            "path": analysis["path"], "sha256": analysis["sha256"],
            "details": analysis.get("result"), "error": analysis.get("error"),
        } for analysis in job.get("analyses", [])],
        "evidence": {
            "sources": result.get("sources", []),
            "summary": result.get("summary", {}),
            "verification": result.get("verification", {"level": "observed", "checks": []}),
            "digest": result.get("evidence_digest"),
        },
        "artifact": result.get("artifact"),
        "limitations": result.get("limitations", []),
    }


class ScanCoordinator:
    """One bounded worker around Ward's existing scanner."""

    def __init__(self, store: ResultStore, repository_slot: threading.BoundedSemaphore):
        self.store = store
        self.repository_slot = repository_slot
        self.queue: queue.Queue[tuple[str, str, dict]] = queue.Queue(maxsize=32)
        self.store.recover_interrupted_scan_jobs()
        self.worker = threading.Thread(target=self._work, name="ward-scan-worker", daemon=True)
        self.worker.start()

    def prepare(self, payload: object) -> tuple[str, str, dict]:
        if not isinstance(payload, dict):
            raise APIError(400, "invalid_request", "Request body must be a JSON object")
        kind = str(payload.get("kind", "")).strip().lower()
        if kind == "repository":
            analysis = payload.get("analysis", "extended" if os.environ.get("WARD_REMNUX_AUTO") == "1" else "static")
            if analysis not in {"static", "extended", "behavioral"}:
                raise APIError(422, "invalid_analysis", "analysis must be static, extended, or behavioral")
            if analysis == "behavioral" and not self.store.analyses.workers()["windows"]["available"]:
                raise APIError(503, "windows_worker_unavailable", "The Windows behavioral worker is not available")
            try:
                target = normalize_repository_url(str(payload.get("url", "")))
                ref = normalize_git_ref(payload.get("ref"))
            except ScanError as exc:
                raise APIError(422, "invalid_repository", str(exc)) from exc
            expected_commit = payload.get("expected_commit")
            if expected_commit is not None:
                expected_commit = str(expected_commit).strip().lower()
                if not COMMIT_PATTERN.fullmatch(expected_commit):
                    raise APIError(422, "invalid_commit", "expected_commit must be a 40 to 64 character hexadecimal object ID")
            return kind, target, {"target": target, "ref": ref, "expected_commit": expected_commit, "analysis": analysis}
        if kind == "sha256":
            digest = normalize_sha256(payload.get("sha256"))
            return kind, digest, {"sha256": digest}
        if kind == "file":
            content = payload.get("content_base64")
            if not isinstance(content, str) or not content:
                raise APIError(422, "invalid_file", "content_base64 is required for file scans")
            try:
                data = base64.b64decode(content, validate=True)
            except (ValueError, TypeError) as exc:
                raise APIError(422, "invalid_file", "content_base64 must be valid base64") from exc
            if not data or len(data) > MAX_FILE_BYTES:
                raise APIError(413, "file_too_large", "Files must contain 1 byte to 5 MiB")
            filename = Path(str(payload.get("filename") or "artifact.bin")).name
            if filename in {"", ".", ".."}:
                raise APIError(422, "invalid_file", "filename must identify one file")
            digest = hashlib.sha256(data).hexdigest()
            return kind, digest, {"data": data, "filename": filename, "sha256": digest}
        raise APIError(422, "unsupported_scan_kind", "kind must be repository, file, or sha256")

    def submit(self, payload: object, idempotency_key: str | None = None) -> tuple[dict, str | None, bool]:
        kind, target, work = self.prepare(payload)
        if idempotency_key is not None:
            if not 1 <= len(idempotency_key) <= 128 or not idempotency_key.isascii():
                raise APIError(400, "invalid_idempotency_key", "Idempotency-Key must be 1 to 128 ASCII characters")
        canonical_value = {"kind": kind, "target": target}
        if kind == "repository":
            canonical_value["ref"] = work["ref"]
            canonical_value["expected_commit"] = work["expected_commit"]
            canonical_value["analysis"] = work["analysis"]
        elif kind == "file":
            canonical_value["filename"] = work["filename"]
        canonical = json.dumps(canonical_value, sort_keys=True, separators=(",", ":"))
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()
        cancel_token = secrets.token_urlsafe(32)
        try:
            job, created = self.store.create_scan_job(
                kind=kind,
                target=target,
                request_hash=request_hash,
                idempotency_key=idempotency_key,
                cancel_token_hash=hashlib.sha256(cancel_token.encode()).hexdigest(),
                requested_ref=work.get("ref"),
            )
        except ValueError as exc:
            raise APIError(409, "idempotency_conflict", str(exc)) from exc
        if created:
            try:
                self.queue.put_nowait((job["id"], kind, work))
            except queue.Full as exc:
                self.store.fail_scan_job(job["id"], "queue_full", "The scan queue is full")
                raise APIError(503, "queue_full", "The scan queue is full; try again later") from exc
        return public_scan(job), cancel_token if created else None, created

    def cancel(self, scan_id: str, token: str | None) -> dict:
        if not token:
            raise APIError(401, "cancel_token_required", "X-Ward-Cancel-Token is required")
        try:
            job = self.store.cancel_scan_job(scan_id, hashlib.sha256(token.encode()).hexdigest())
        except PermissionError as exc:
            raise APIError(403, "invalid_cancel_token", str(exc)) from exc
        except RuntimeError as exc:
            raise APIError(409, "scan_not_cancellable", str(exc)) from exc
        if job is None:
            raise APIError(404, "scan_not_found", "Scan not found")
        return public_scan(job)

    def _work(self) -> None:
        while True:
            scan_id, kind, work = self.queue.get()
            try:
                if not self.store.start_scan_job(scan_id):
                    continue
                if kind == "repository":
                    samples = []

                    def capture(path, digest, source):
                        if len(samples) < 2:
                            data = source.read_bytes()
                            samples.append((path, digest, data))

                    self.repository_slot.acquire()
                    try:
                        if work["analysis"] != "static":
                            result = scan_repository(work["target"], work["ref"], work["expected_commit"], artifact_sink=capture)
                        else:
                            result = scan_repository(work["target"], work["ref"], work["expected_commit"])
                    finally:
                        self.repository_slot.release()
                    if work["analysis"] != "static":
                        for path, digest, data in samples:
                            self.store.analyses.enqueue(scan_id, path, digest, data)
                            if work["analysis"] == "behavioral":
                                self.store.analyses.enqueue(scan_id, path, digest, data, "windows")
                        result["analysis_policy"] = {"requested": work["analysis"], "max_artifacts": 2,
                                                     "selected": len(samples), "eligible": len(result.get("artifacts", []))}
                elif kind == "file":
                    result = scan_file(work["data"], work["filename"], work["sha256"])
                else:
                    result = scan_hash(work["sha256"])
                result = finalize_result(scan_id, result)
                self.store.complete_scan_job(scan_id, result, publish_repository=kind == "repository")
            except (OSError, ScanError, ValueError, json.JSONDecodeError) as exc:
                self.store.fail_scan_job(scan_id, "scan_failed", str(exc))
                self.store.analyses.abandon_scan(scan_id)
            except Exception:
                self.store.fail_scan_job(scan_id, "internal_error", "The scan failed unexpectedly")
                self.store.analyses.abandon_scan(scan_id)
            finally:
                self.queue.task_done()
