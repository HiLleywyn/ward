from __future__ import annotations

import json
import hmac
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .analyze import Assessment, Signal, parse_repository_target
from .data import advisory_directory


def reviewed_repositories() -> list[dict]:
    path = advisory_directory() / "repositories.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [dict(payload["sources"][item["source"]], **item, scope=payload["scope"]) for item in payload["repositories"]]


def malware_records() -> list[dict]:
    path = advisory_directory() / "malware-records.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["records"]


def malware_record(target: str) -> dict | None:
    owner, name = parse_repository_target(target)
    key = f"{owner}/{name}".lower()
    return next((item for item in malware_records() if item["repository"].lower() == key), None)


def repository_warning(target: str) -> Assessment | None:
    owner, name = parse_repository_target(target)
    key = f"{owner}/{name}".lower()
    for item in reviewed_repositories():
        if item["repository"].lower() == key and item["status"] == "FAIL":
            return Assessment(
                target=f"{owner}/{name}", verdict="reported-malicious-repository", score=100,
                exact_indicator_match=True, canonical_project=None,
                signals=[Signal("primary_source_repository", 100,
                    f"{item['source_name']} identified this repository in {item['campaign']} ({item['published']}).")],
                limitations=[item["scope"], f"Evidence: {item['source_url']}",
                    "This is a historical repository indicator. Current availability and ownership require a fresh check.",
                    "No file was downloaded or executed."],
            )
    return None


class ResultStore:
    """Append-only observations; reports never promote themselves to confirmed."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY, recorded_at TEXT NOT NULL, target TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PASS','FAIL','UNKNOWN')),
                kind TEXT NOT NULL, payload TEXT NOT NULL
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('repository','file','sha256')),
                target TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN
                    ('queued','running','completed','failed','cancelled','incomplete')),
                progress INTEGER NOT NULL CHECK(progress BETWEEN 0 AND 100),
                request_hash TEXT NOT NULL, idempotency_key TEXT UNIQUE,
                cancel_token_hash TEXT NOT NULL, result TEXT,
                error_code TEXT, error_message TEXT, requested_ref TEXT
            )""")
            columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_jobs)")}
            if "requested_ref" not in columns:
                connection.execute("ALTER TABLE scan_jobs ADD COLUMN requested_ref TEXT")
            legacy = connection.execute(
                "SELECT id, recorded_at, target, payload FROM observations WHERE kind = 'repository-scan'"
            ).fetchall()
            for scan_id, recorded_at, target, payload in legacy:
                result = json.loads(payload)
                canonical_target = result.get("repository_url") or target
                connection.execute(
                    "INSERT OR IGNORE INTO scan_jobs "
                    "(id, created_at, updated_at, kind, target, status, progress, request_hash, idempotency_key, cancel_token_hash, result, error_code, error_message, requested_ref) "
                    "VALUES (?, ?, ?, 'repository', ?, 'completed', 100, ?, NULL, ?, ?, NULL, NULL, ?)",
                    (
                        scan_id, recorded_at, recorded_at, canonical_target,
                        hashlib.sha256(f"legacy:{scan_id}".encode()).hexdigest(),
                        hashlib.sha256(f"legacy-cancel:{scan_id}".encode()).hexdigest(),
                        payload, result.get("branch"),
                    ),
                )

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def record(self, target: str, payload: dict, *, kind: str = "scan", status: str = "UNKNOWN") -> str:
        if status not in {"PASS", "FAIL", "UNKNOWN"}:
            raise ValueError("Invalid status")
        if kind == "community-report" and status != "UNKNOWN":
            raise ValueError("Community reports require review before assigning a result")
        record_id = str(uuid4())
        with self.connect() as connection:
            connection.execute("INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?)", (
                record_id, datetime.now(timezone.utc).isoformat(), target, status, kind,
                json.dumps(payload, sort_keys=True),
            ))
        return record_id

    def record_assessment(self, assessment: Assessment, snapshot: dict | None = None) -> str:
        status = "FAIL" if assessment.exact_indicator_match else "UNKNOWN"
        return self.record(assessment.target, {"assessment": assessment.to_dict(), "snapshot": snapshot}, status=status)

    def record_repository_scan(self, result: dict) -> str:
        status = "FAIL" if result.get("status") in {"Malicious", "Corroborated"} else "UNKNOWN"
        record_id = result.get("id") or str(uuid4())
        payload = dict(result, id=record_id)
        with self.connect() as connection:
            connection.execute("INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?)", (
                record_id,
                result.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
                result["repository"],
                status,
                "repository-scan",
                json.dumps(payload, sort_keys=True),
            ))
        return record_id

    @staticmethod
    def _scan_job(row: tuple | None, *, include_private: bool = False) -> dict | None:
        if row is None:
            return None
        fields = (
            "id", "created_at", "updated_at", "kind", "target", "status",
            "progress", "request_hash", "idempotency_key", "cancel_token_hash",
            "result", "error_code", "error_message", "requested_ref",
        )
        value = dict(zip(fields, row))
        if value["result"]:
            value["result"] = json.loads(value["result"])
        if not include_private:
            value.pop("request_hash")
            value.pop("idempotency_key")
            value.pop("cancel_token_hash")
        return value

    def create_scan_job(
        self,
        *,
        kind: str,
        target: str,
        request_hash: str,
        idempotency_key: str | None,
        cancel_token_hash: str,
        requested_ref: str | None = None,
    ) -> tuple[dict, bool]:
        now = datetime.now(timezone.utc).isoformat()
        scan_id = str(uuid4())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key:
                existing = connection.execute(
                    "SELECT * FROM scan_jobs WHERE idempotency_key = ?", (idempotency_key,)
                ).fetchone()
                if existing:
                    job = self._scan_job(existing, include_private=True)
                    if not hmac.compare_digest(job["request_hash"], request_hash):
                        raise ValueError("The idempotency key was already used for a different request")
                    return self._scan_job(existing), False
            connection.execute(
                "INSERT INTO scan_jobs "
                "(id, created_at, updated_at, kind, target, status, progress, request_hash, idempotency_key, cancel_token_hash, result, error_code, error_message, requested_ref) "
                "VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, NULL, NULL, NULL, ?)",
                (scan_id, now, now, kind, target, request_hash, idempotency_key, cancel_token_hash, requested_ref),
            )
            row = connection.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_job(row), True

    def scan_job(self, scan_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_job(row)

    def list_scan_jobs(
        self,
        *,
        limit: int = 20,
        cursor: str | None = None,
        status: str | None = None,
        public_only: bool = True,
    ) -> tuple[list[dict], str | None]:
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        if status and status not in {"queued", "running", "completed", "failed", "cancelled", "incomplete"}:
            raise ValueError("Unknown scan status")
        before_rowid = None
        with self.connect() as connection:
            if cursor:
                cursor_row = connection.execute("SELECT rowid FROM scan_jobs WHERE id = ?", (cursor,)).fetchone()
                if cursor_row is None:
                    raise ValueError("Invalid cursor")
                before_rowid = cursor_row[0]
            clauses = []
            values: list[object] = []
            if public_only:
                clauses.append("kind = 'repository'")
            if before_rowid is not None:
                clauses.append("rowid < ?")
                values.append(before_rowid)
            if status:
                clauses.append("status = ?")
                values.append(status)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = connection.execute(
                f"SELECT * FROM scan_jobs{where} ORDER BY rowid DESC LIMIT ?", (*values, limit + 1)
            ).fetchall()
        next_cursor = rows[limit - 1][0] if len(rows) > limit else None
        return [self._scan_job(row) for row in rows[:limit]], next_cursor

    def start_scan_job(self, scan_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scan_jobs SET status = 'running', progress = 10, updated_at = ? "
                "WHERE id = ? AND status = 'queued'", (now, scan_id),
            )
        return cursor.rowcount == 1

    def complete_scan_job(self, scan_id: str, result: dict, *, publish_repository: bool = False) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scan_jobs SET status = 'completed', progress = 100, updated_at = ?, "
                "result = ?, error_code = NULL, error_message = NULL WHERE id = ? AND status = 'running'",
                (now, json.dumps(result, sort_keys=True), scan_id),
            )
            if publish_repository and cursor.rowcount == 1:
                status = "FAIL" if result.get("status") in {"Malicious", "Corroborated"} else "UNKNOWN"
                connection.execute("INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?)", (
                    scan_id,
                    result.get("scanned_at") or now,
                    result["repository"],
                    status,
                    "repository-scan",
                    json.dumps(dict(result, id=scan_id), sort_keys=True),
                ))

    def fail_scan_job(self, scan_id: str, code: str, message: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                "UPDATE scan_jobs SET status = 'failed', progress = 100, updated_at = ?, "
                "error_code = ?, error_message = ? WHERE id = ? AND status IN ('queued','running')",
                (now, code, message[:500], scan_id),
            )

    def cancel_scan_job(self, scan_id: str, cancel_token_hash: str) -> dict | None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            job = self._scan_job(row, include_private=True)
            if not hmac.compare_digest(job["cancel_token_hash"], cancel_token_hash):
                raise PermissionError("Invalid cancellation token")
            if job["status"] == "running":
                raise RuntimeError("Running scans cannot currently be interrupted safely")
            if job["status"] == "queued":
                connection.execute(
                    "UPDATE scan_jobs SET status = 'cancelled', progress = 100, updated_at = ? WHERE id = ?",
                    (now, scan_id),
                )
                row = connection.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_job(row)

    def recover_interrupted_scan_jobs(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scan_jobs SET status = 'incomplete', progress = 100, updated_at = ?, "
                "error_code = 'worker_restarted', error_message = 'The scanner restarted before this job finished' "
                "WHERE status IN ('queued','running')", (now,),
            )
        return cursor.rowcount

    def public_artifact(self, sha256: str) -> dict | None:
        indicators = json.loads((advisory_directory() / "indicators.json").read_text(encoding="utf-8"))
        indicator = next((
            item for item in indicators.get("indicators", [])
            if item.get("status") == "confirmed" and item.get("sha256", "").lower() == sha256.lower()
        ), None)
        if indicator is None:
            return None
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, result FROM scan_jobs WHERE kind = 'repository' AND status = 'completed' AND result IS NOT NULL"
            ).fetchall()
        history = []
        for scan_id, payload in rows:
            result = json.loads(payload)
            paths = [
                finding.get("path") for finding in result.get("findings", [])
                if finding.get("sha256", "").lower() == sha256.lower()
            ]
            if paths:
                history.append({"scan_id": scan_id, "repository": result.get("repository"), "paths": paths})
        return {"sha256": sha256.lower(), "indicator": indicator, "analysis_history": history}

    def repository_history(self, target: str) -> dict:
        keys = self._repository_keys(target)
        if not keys or len(target) > 500:
            raise ValueError("Repository target is required")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, result FROM scan_jobs WHERE kind = 'repository' AND status = 'completed' "
                "AND result IS NOT NULL ORDER BY rowid DESC"
            ).fetchall()
        scans = []
        all_results = []
        for scan_id, payload in rows:
            result = json.loads(payload)
            item = {"scan_id": scan_id, **result}
            all_results.append(item)
            if keys & self._repository_keys(result.get("repository_url") or result.get("repository") or ""):
                scans.append(item)
        commits = {item.get("commit") for item in scans if item.get("commit")}
        scan_ids = {item["scan_id"] for item in scans}
        related = []
        seen = set()
        for item in all_results:
            repository = item.get("repository_url") or item.get("repository")
            if item.get("commit") in commits and item["scan_id"] not in scan_ids:
                relation_key = (repository, item.get("commit"))
                if relation_key not in seen:
                    seen.add(relation_key)
                    related.append({
                        "repository": repository,
                        "commit": item.get("commit"),
                        "scan_id": item["scan_id"],
                        "relationship": "shared_commit",
                    })
        ordered = sorted(scans, key=lambda item: (item.get("scanned_at", ""), item["scan_id"]))
        transitions = []
        for previous, current in zip(ordered, ordered[1:]):
            comparison = self._compare_results(previous, current)
            if previous.get("status") != current.get("status") or comparison["new_findings"] or comparison["removed_findings"]:
                transitions.append({
                    "base_scan_id": previous["scan_id"],
                    "head_scan_id": current["scan_id"],
                    "base_commit": previous.get("commit"),
                    "head_commit": current.get("commit"),
                    "branch": current.get("branch"),
                    "from_status": previous.get("status"),
                    "to_status": current.get("status"),
                    **comparison,
                })
        return {
            "repository": target,
            "scans": ordered,
            "transitions": transitions,
            "related_repositories": related,
            "relationship_note": "A shared commit is evidence of shared history, not proof of current ownership or fork ancestry.",
        }

    @staticmethod
    def _repository_keys(target: str) -> set[str]:
        from urllib.parse import urlparse
        value = str(target).strip().lower().removesuffix(".git").rstrip("/")
        if not value:
            return set()
        keys = {value}
        parsed = urlparse(value)
        if parsed.hostname and parsed.path.strip("/"):
            keys.add(parsed.path.strip("/"))
        return keys

    def latest_repository_scan(self, target: str, branch: str | None = None) -> dict | None:
        keys = self._repository_keys(target)
        if not keys or len(target) > 500:
            raise ValueError("Repository target is required")
        if branch and len(branch) > 200:
            raise ValueError("Repository branch is too long")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scan_jobs WHERE kind = 'repository' ORDER BY rowid DESC"
            ).fetchall()
        for row in rows:
            job = self._scan_job(row)
            result = job.get("result") or {}
            result_target = result.get("repository_url") or result.get("repository") or job["target"]
            result_branch = result.get("branch") or job.get("requested_ref")
            if keys & self._repository_keys(result_target) and (not branch or branch == result_branch):
                return job
        return None

    @staticmethod
    def _finding_key(finding: dict) -> tuple:
        return (
            finding.get("kind"), finding.get("path"), finding.get("line"),
            finding.get("sha256"), finding.get("title"),
        )

    @classmethod
    def _compare_results(cls, base: dict, head: dict) -> dict:
        base_findings = {cls._finding_key(item): item for item in base.get("findings", [])}
        head_findings = {cls._finding_key(item): item for item in head.get("findings", [])}
        new_keys = head_findings.keys() - base_findings.keys()
        removed_keys = base_findings.keys() - head_findings.keys()
        if new_keys:
            assessment = "new_findings_detected"
        elif removed_keys:
            assessment = "findings_removed"
        else:
            assessment = "no_finding_change"
        return {
            "assessment": assessment,
            "new_findings": [head_findings[key] for key in sorted(new_keys, key=str)],
            "removed_findings": [base_findings[key] for key in sorted(removed_keys, key=str)],
            "interpretation": "This comparison identifies differences between two bounded scans; it does not prove author intent or that unscanned commits were safe.",
        }

    def compare_repository_scans(self, base_scan_id: str, head_scan_id: str) -> dict:
        base_job = self.scan_job(base_scan_id)
        head_job = self.scan_job(head_scan_id)
        if base_job is None or head_job is None:
            raise LookupError("One or both scans were not found")
        for job in (base_job, head_job):
            if job["kind"] != "repository" or job["status"] != "completed" or not job.get("result"):
                raise ValueError("Comparisons require two completed repository scans")
        base = {"scan_id": base_scan_id, **base_job["result"]}
        head = {"scan_id": head_scan_id, **head_job["result"]}
        return {
            "base": {key: base.get(key) for key in ("scan_id", "repository", "repository_url", "branch", "commit", "status", "scanned_at")},
            "head": {key: head.get(key) for key in ("scan_id", "repository", "repository_url", "branch", "commit", "status", "scanned_at")},
            **self._compare_results(base, head),
        }

    def recent_repository_scans(self, limit: int = 20) -> list[dict]:
        if not 1 <= limit <= 100:
            raise ValueError("Scan history limit must be 1 to 100")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM observations WHERE kind = 'repository-scan' ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def report(self, target: str, evidence_url: str, description: str) -> str:
        owner, name = parse_repository_target(target)
        from urllib.parse import urlparse
        url = urlparse(evidence_url)
        if url.scheme != "https" or not url.netloc:
            raise ValueError("Evidence must have an HTTPS URL")
        if not description.strip() or len(description) > 4000:
            raise ValueError("Description must contain 1 to 4000 characters")
        return self.record(f"{owner}/{name}", {"evidence_url": evidence_url, "description": description.strip()}, kind="community-report")

    def history(self, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 1000:
            raise ValueError("History limit must be 1 to 1000")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id,recorded_at,target,status,kind,payload FROM observations ORDER BY rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(zip(("id", "recorded_at", "target", "status", "kind", "payload"), (*row[:5], json.loads(row[5])))) for row in rows]


def default_store() -> ResultStore:
    import os
    base = Path(os.environ.get("WARD_STATE_DIR", Path.home() / ".ward"))
    return ResultStore(base / "results.sqlite3")


def snapshot_evidence(snapshot) -> dict:
    repo = snapshot.repository
    return {
        "repository_id": repo.get("id"), "full_name": repo["full_name"],
        "created_at": repo.get("created_at"), "pushed_at": repo.get("pushed_at"),
        "default_branch": repo.get("default_branch"), "head_sha": repo.get("head_sha"),
        "readme_sha256": __import__("hashlib").sha256(snapshot.readme.encode()).hexdigest(),
        "tree_summary": snapshot.tree_summary,
        "assets": [{"id": asset.get("id"), "name": asset.get("name"), "digest": asset.get("digest"),
            "size": asset.get("size"), "created_at": asset.get("created_at"),
            "release_id": release.get("id"), "tag": release.get("tag_name")}
            for release in snapshot.releases for asset in release.get("assets", [])],
        "coverage": "Metadata and README; first 20 releases only; no binaries executed or downloaded",
    }
