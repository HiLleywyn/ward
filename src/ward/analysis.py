"""Durable bounded follow-up analysis, separate from immutable scan results."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4


ACTIVE_LIMIT = 8
SAMPLE_LIMIT = 32 * 1024 * 1024


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def result_digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


class AnalysisQueue:
    def __init__(self, store):
        self.store = store
        with store.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS artifact_analyses (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, engine TEXT NOT NULL,
                path TEXT NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, claim_token TEXT,
                payload BLOB, result TEXT, error TEXT,
                UNIQUE(scan_id, engine, path)
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS analysis_workers (
                engine TEXT PRIMARY KEY, seen_at TEXT NOT NULL, version TEXT NOT NULL
            )""")

    @staticmethod
    def _public(row):
        if row is None:
            return None
        value = dict(zip(("id", "scan_id", "engine", "path", "sha256", "status", "created_at", "updated_at",
                          "claim_token", "payload", "result", "error"), row))
        value.pop("payload")
        value.pop("claim_token")
        if value["result"]:
            value["result"] = json.loads(value["result"])
        return value

    def list(self, scan_id):
        with self.store.connect() as connection:
            rows = connection.execute("SELECT * FROM artifact_analyses WHERE scan_id=? ORDER BY rowid", (scan_id,)).fetchall()
        return [self._public(row) for row in rows]

    def enqueue(self, scan_id, path, digest, data, engine="remnux"):
        if engine not in {"remnux", "windows"}:
            raise ValueError("Unknown analysis engine")
        if not data or len(data) > SAMPLE_LIMIT or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Analysis sample size or digest is invalid")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute("SELECT status FROM scan_jobs WHERE id=? AND kind='repository'", (scan_id,)).fetchone()
            if not job or job[0] not in {"running", "completed"}:
                raise ValueError("Analysis requires a running or completed repository scan")
            existing = connection.execute("SELECT id FROM artifact_analyses WHERE scan_id=? AND path=? AND engine=?", (scan_id, path, engine)).fetchone()
            if existing:
                return existing[0]
            count = connection.execute("SELECT count(*) FROM artifact_analyses WHERE status IN ('queued','running')").fetchone()[0]
            analysis_id = str(uuid4())
            status = "queued" if count < ACTIVE_LIMIT else "incomplete"
            connection.execute("INSERT INTO artifact_analyses VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)", (
                analysis_id, scan_id, engine, path, digest, status, now_iso(), now_iso(), None,
                data if status == "queued" else None, None if status == "queued" else "Analysis queue reached its limit",
            ))
        return analysis_id

    def heartbeat(self, engine):
        from . import __version__
        if engine not in {"remnux", "windows"}:
            raise ValueError("Unknown analysis engine")
        with self.store.connect() as connection:
            connection.execute("INSERT OR REPLACE INTO analysis_workers VALUES (?,?,?)", (engine, now_iso(), __version__))

    def workers(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
        with self.store.connect() as connection:
            rows = connection.execute("SELECT * FROM analysis_workers").fetchall()
        values = {row[0]: {"available": row[1] >= cutoff, "last_seen": row[1], "version": row[2]} for row in rows}
        return {engine: values.get(engine, {"available": False}) for engine in ("remnux", "windows")}

    def claim(self, engine):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE artifact_analyses SET status='incomplete',payload=NULL,error='Analysis expired before completion',updated_at=? WHERE status IN ('queued','running') AND updated_at<?", (now_iso(), cutoff))
            row = connection.execute("SELECT a.* FROM artifact_analyses a JOIN scan_jobs s ON s.id=a.scan_id WHERE a.engine=? AND a.status='queued' AND s.status='completed' ORDER BY a.rowid LIMIT 1", (engine,)).fetchone()
            if row is None:
                return None
            job = connection.execute("SELECT result FROM scan_jobs WHERE id=?", (row[1],)).fetchone()
            artifacts = json.loads(job[0]).get("artifacts", [])
            if not any(item.get("path") == row[3] and item.get("sha256") == row[4] for item in artifacts):
                connection.execute("UPDATE artifact_analyses SET status='incomplete',payload=NULL,error='Artifact was not bound to the completed scan' WHERE id=?", (row[0],))
                return None
            token = secrets.token_urlsafe(32)
            connection.execute("UPDATE artifact_analyses SET status='running',claim_token=?,updated_at=? WHERE id=?", (token, now_iso(), row[0]))
            value = self._public(row)
            value.update({"status": "running", "claim_token": token, "data": row[9]})
        return value

    def finish(self, analysis_id, token, *, result=None, error=None):
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM artifact_analyses WHERE id=?", (analysis_id,)).fetchone()
            if row is None or row[5] != "running" or not secrets.compare_digest(row[8] or "", token):
                raise ValueError("Analysis claim is no longer valid")
            if result is not None:
                if result.get("sha256") != row[4]:
                    raise ValueError("Analysis result references a different artifact")
                canonical = {key: value for key, value in result.items() if key != "evidence_digest"}
                if result.get("evidence_digest") != result_digest(canonical):
                    raise ValueError("Analysis evidence digest is invalid")
                if len(json.dumps(result)) > 2 * 1024 * 1024:
                    raise ValueError("Analysis report exceeds its size limit")
            connection.execute("UPDATE artifact_analyses SET status=?,updated_at=?,payload=NULL,claim_token=NULL,result=?,error=? WHERE id=?", (
                "completed" if result is not None else "incomplete", now_iso(),
                json.dumps(result) if result is not None else None, str(error)[:500] if error else None, analysis_id,
            ))

    def abandon_scan(self, scan_id):
        with self.store.connect() as connection:
            connection.execute("UPDATE artifact_analyses SET status='incomplete',payload=NULL,error='Originating scan did not complete' WHERE scan_id=? AND status='queued'", (scan_id,))
