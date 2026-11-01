from __future__ import annotations

import json
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
    base = Path(os.environ.get("EMUWATCH_STATE_DIR", Path.home() / ".emuwatch"))
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
