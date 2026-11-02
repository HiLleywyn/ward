from __future__ import annotations

import json
import os
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import uuid4

from .api import APIError, ScanCoordinator, normalize_sha256, openapi_document, public_scan, report_for_job
from .analyze import assess_repository, parse_repository_target
from .github import GitHubClient, GitHubError
from .data import advisory_directory
from .evidence import default_store, malware_record, malware_records, repository_warning, snapshot_evidence
from .scanner import ScanError, normalize_repository_url, scan_repository
from .mcp import handle_message as handle_mcp_message
from .views import badge_svg, repository_ledger_page, scan_record_page


WEB_ROOT = Path(__file__).with_name("webui")


def _handler() -> type[BaseHTTPRequestHandler]:
    public = os.environ.get("WARD_PUBLIC") == "1"
    client = GitHubClient()
    if public:
        client.token = None
    store = default_store()
    cache = {}
    check_lock = threading.Lock()
    scan_lock = threading.Lock()
    scan_slot = threading.BoundedSemaphore(1)
    coordinator = ScanCoordinator(store, scan_slot)

    class Handler(BaseHTTPRequestHandler):
        server_version = "Ward/0.6.5"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(25)

        def _allowed_host(self):
            host = self.headers.get("Host", "").split(":", 1)[0].lower()
            return host in {"127.0.0.1", "localhost", "ward.lley.cat", "ward", "testserver"}

        def _headers(
            self,
            content_type: str,
            length: int,
            status: int = 200,
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("X-Request-ID", getattr(self, "request_id", str(uuid4())))
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()

        def _send_json(self, value: object, status: int = 200, extra: dict[str, str] | None = None) -> None:
            body = json.dumps(value).encode("utf-8")
            self._headers("application/json; charset=utf-8", len(body), status, extra)
            self.wfile.write(body)

        def _send_bytes(
            self, body: bytes, content_type: str, status: int = 200, extra: dict[str, str] | None = None
        ) -> None:
            self._headers(content_type, len(body), status, extra)
            self.wfile.write(body)

        def _api_error(self, error: APIError) -> None:
            self._send_json({"error": {
                "code": error.code,
                "message": error.message,
                "request_id": self.request_id,
            }}, error.status)

        def _read_json(self, maximum: int) -> object:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise APIError(400, "invalid_content_length", "Content-Length must be an integer") from exc
            if length <= 0:
                raise APIError(400, "empty_request", "A JSON request body is required")
            if length > maximum:
                raise APIError(413, "request_too_large", "Request body exceeds the permitted size")
            try:
                return json.loads(self.rfile.read(length))
            except json.JSONDecodeError as exc:
                raise APIError(400, "invalid_json", "Request body must contain valid JSON") from exc

        def _origin_allowed(self) -> bool:
            origin = self.headers.get("Origin")
            return not origin or origin in {"https://ward.lley.cat", f"http://{self.headers.get('Host')}"}

        def _scan_id_from_path(self, path: str, suffix: str = "") -> str | None:
            prefix = "/api/v1/scans/"
            if not path.startswith(prefix):
                return None
            remainder = path.removeprefix(prefix)
            if suffix:
                if not remainder.endswith(suffix):
                    return None
                remainder = remainder.removesuffix(suffix)
            if "/" in remainder or not remainder:
                return None
            return remainder

        def _send_scan_events(self, scan_id: str) -> None:
            if store.scan_job(scan_id) is None:
                raise APIError(404, "scan_not_found", "Scan not found")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("X-Request-ID", self.request_id)
            self.end_headers()
            self.close_connection = True
            deadline = time.monotonic() + 20
            previous = None
            while time.monotonic() < deadline:
                job = store.scan_job(scan_id)
                if job is None:
                    return
                marker = (job["status"], job["updated_at"])
                if marker != previous:
                    payload = json.dumps(public_scan(job), separators=(",", ":"))
                    self.wfile.write(f"event: scan\nid: {job['updated_at']}\ndata: {payload}\n\n".encode())
                    self.wfile.flush()
                    previous = marker
                if job["status"] in {"completed", "failed", "cancelled", "incomplete"}:
                    return
                time.sleep(0.25)

        def _v1_get(self, request) -> bool:
            path = request.path
            if path == "/api/v1":
                self._send_json({
                    "name": "Ward API",
                    "version": "1",
                    "openapi": "/api/v1/openapi.json",
                    "mcp": "/mcp",
                    "resources": {
                        "engines": "/api/v1/engines",
                        "scans": "/api/v1/scans",
                        "repository_history": "/api/v1/repositories/history?target={repository}",
                        "scan_comparison": "/api/v1/comparisons?base_scan={id}&head_scan={id}",
                        "malware_records": "/api/v1/malware-records",
                        "artifacts": "/api/v1/artifacts/{sha256}",
                        "reports": "/api/v1/reports/{scan_id}",
                    },
                    "warning": "Unknown does not mean safe.",
                })
                return True
            if path == "/api/v1/engines":
                self._send_json({"items": store.analyses.workers(), "default_analysis": "extended" if os.environ.get("WARD_REMNUX_AUTO") == "1" else "static"})
                return True
            if path == "/api/v1/openapi.json":
                self._send_json(openapi_document())
                return True
            if path == "/api/v1/scans":
                query = parse_qs(request.query)
                try:
                    limit = int(query.get("limit", ["20"])[0])
                    jobs, cursor = store.list_scan_jobs(
                        limit=limit,
                        cursor=query.get("cursor", [None])[0],
                        status=query.get("status", [None])[0],
                    )
                except ValueError as exc:
                    raise APIError(400, "invalid_query", str(exc)) from exc
                self._send_json({"items": [public_scan(job) for job in jobs], "next_cursor": cursor})
                return True
            if path == "/api/v1/repositories/history":
                target = parse_qs(request.query).get("target", [""])[0]
                try:
                    self._send_json(store.repository_history(target))
                except ValueError as exc:
                    raise APIError(400, "invalid_repository", str(exc)) from exc
                return True
            if path == "/api/v1/comparisons":
                query = parse_qs(request.query)
                base_scan = query.get("base_scan", [""])[0]
                head_scan = query.get("head_scan", [""])[0]
                try:
                    self._send_json(store.compare_repository_scans(base_scan, head_scan))
                except LookupError as exc:
                    raise APIError(404, "scan_not_found", str(exc)) from exc
                except ValueError as exc:
                    raise APIError(422, "scans_not_comparable", str(exc)) from exc
                return True
            if path == "/api/v1/malware-records":
                self._send_json({"items": malware_records()})
                return True
            if path.startswith("/api/v1/malware-records/"):
                record_id = path.removeprefix("/api/v1/malware-records/")
                record = next((item for item in malware_records() if item.get("id") == record_id), None)
                if record is None:
                    raise APIError(404, "record_not_found", "Malware record not found")
                self._send_json(record)
                return True
            scan_id = self._scan_id_from_path(path, "/events")
            if scan_id:
                self._send_scan_events(scan_id)
                return True
            scan_id = self._scan_id_from_path(path)
            if scan_id:
                job = store.scan_job(scan_id)
                if job is None:
                    raise APIError(404, "scan_not_found", "Scan not found")
                self._send_json(public_scan(job))
                return True
            if path.startswith("/api/v1/reports/"):
                scan_id = path.removeprefix("/api/v1/reports/")
                if not scan_id or "/" in scan_id:
                    raise APIError(404, "not_found", "Endpoint not found")
                job = store.scan_job(scan_id)
                if job is None:
                    raise APIError(404, "scan_not_found", "Scan not found")
                self._send_json(report_for_job(job))
                return True
            if path.startswith("/api/v1/artifacts/"):
                digest = normalize_sha256(path.removeprefix("/api/v1/artifacts/"))
                artifact = store.public_artifact(digest)
                if artifact is None:
                    raise APIError(404, "artifact_not_found", "No reviewed public indicator matches this SHA-256")
                self._send_json(artifact)
                return True
            return False

        def do_GET(self) -> None:  # noqa: N802
            self.request_id = str(uuid4())
            if not self._allowed_host():
                self._send_json({"error": "Invalid host"}, HTTPStatus.BAD_REQUEST)
                return
            request = urlsplit(self.path)
            if request.path == "/api/v1/badge.svg":
                query = parse_qs(request.query)
                repository = query.get("repository", [""])[0]
                branch = query.get("branch", [None])[0]
                if not repository:
                    self._api_error(APIError(400, "invalid_repository", "repository query parameter is required"))
                    return
                try:
                    job = store.latest_repository_scan(repository, branch)
                except ValueError as exc:
                    self._api_error(APIError(400, "invalid_repository", str(exc)))
                    return
                self._send_bytes(badge_svg(job), "image/svg+xml; charset=utf-8")
                return
            if request.path.startswith("/api/v1/badges/") and request.path.endswith(".svg"):
                repository = unquote(request.path.removeprefix("/api/v1/badges/").removesuffix(".svg"))
                if len([part for part in repository.split("/") if part]) != 2:
                    self._api_error(APIError(404, "badge_not_found", "Badge repository must use owner/repository"))
                    return
                branch = parse_qs(request.query).get("branch", [None])[0]
                try:
                    job = store.latest_repository_scan(repository, branch)
                except ValueError as exc:
                    self._api_error(APIError(400, "invalid_repository", str(exc)))
                    return
                self._send_bytes(badge_svg(job), "image/svg+xml; charset=utf-8")
                return
            if request.path.startswith("/scans/"):
                scan_id = request.path.removeprefix("/scans/")
                job = store.scan_job(scan_id)
                if job is None or "/" in scan_id:
                    self._send_bytes(scan_record_page({
                        "id": scan_id, "kind": "repository", "target": "not found", "status": "incomplete",
                        "progress": 100, "created_at": "", "updated_at": "", "requested_ref": None,
                        "result": None,
                    }, None), "text/html; charset=utf-8", HTTPStatus.NOT_FOUND)
                    return
                try:
                    report = report_for_job(job)
                except APIError:
                    report = None
                self._send_bytes(scan_record_page(job, report), "text/html; charset=utf-8")
                return
            if request.path.startswith("/repositories/"):
                repository = unquote(request.path.removeprefix("/repositories/")).strip("/")
                if len(repository.split("/")) != 2:
                    self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._send_bytes(repository_ledger_page(store.repository_history(repository)), "text/html; charset=utf-8")
                return
            if request.path == "/repository":
                target = parse_qs(request.query).get("target", [""])[0]
                try:
                    history = store.repository_history(target)
                except ValueError:
                    self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._send_bytes(repository_ledger_page(history), "text/html; charset=utf-8")
                return
            if request.path == "/mcp":
                self._send_json({"error": {
                    "code": "method_not_allowed",
                    "message": "Ward MCP uses stateless Streamable HTTP POST requests",
                    "request_id": self.request_id,
                }}, HTTPStatus.METHOD_NOT_ALLOWED, {"Allow": "POST"})
                return
            try:
                if self._v1_get(request):
                    return
            except APIError as exc:
                self._api_error(exc)
                return
            if request.path == "/healthz":
                from . import __version__
                self._send_json({"status": "ok", "version": __version__, "public": public})
                return
            routes = {
                "/": (WEB_ROOT / "index.html", "text/html; charset=utf-8"),
                "/developers": (WEB_ROOT / "developers.html", "text/html; charset=utf-8"),
                "/developers.html": (WEB_ROOT / "developers.html", "text/html; charset=utf-8"),
                "/styles.css": (WEB_ROOT / "styles.css", "text/css; charset=utf-8"),
                "/app.js": (WEB_ROOT / "app.js", "text/javascript; charset=utf-8"),
                "/developers.js": (WEB_ROOT / "developers.js", "text/javascript; charset=utf-8"),
            }
            if request.path == "/api/indicators":
                indicator_path = advisory_directory() / "indicators.json"
                known_path = advisory_directory() / "known-project-assets.json"
                try:
                    indicators = json.loads(indicator_path.read_text(encoding="utf-8"))
                    known_assets = json.loads(known_path.read_text(encoding="utf-8"))
                    self._send_json(
                        {
                            "indicators": [item for item in indicators.get("indicators", []) if item.get("status") == "confirmed"],
                            "known_assets": known_assets.get("assets", []),
                        }
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            if request.path == "/api/campaigns":
                campaign_path = advisory_directory() / "campaigns.json"
                try:
                    self._send_json(json.loads(campaign_path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            if request.path == "/api/reviewed":
                review_data = json.loads((advisory_directory() / "review-status.json").read_text(encoding="utf-8"))
                self._send_json({"records": malware_records(), "coverage": review_data["coverage"]})
                return
            if request.path == "/api/record":
                target = parse_qs(request.query).get("repository", [""])[0]
                try:
                    record = malware_record(target)
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                if record is None:
                    self._send_json({"error": "record not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._send_json(record)
                return
            if request.path == "/api/history":
                self._send_json({"observations": [] if public else store.history()})
                return
            if request.path == "/api/scans":
                query = parse_qs(request.query)
                try:
                    page = int(query.get("page", ["1"])[0])
                    if not 1 <= page <= 20_000:
                        raise ValueError("Invalid page")
                except ValueError:
                    self._send_json({"error": "page must be a positive integer"}, HTTPStatus.BAD_REQUEST)
                    return
                total = store.repository_scan_count()
                pages = max(1, (total + 49) // 50)
                page = min(page, pages)
                recent = store.recent_repository_scans(50, (page - 1) * 50)
                histories = {}
                for scan in recent:
                    scan["analyses"] = store.analyses.list(scan["id"])
                    target = scan.get("repository_url") or scan["repository"]
                    if target not in histories:
                        histories[target] = store.repository_history(target)
                    history = histories[target]
                    scan["history"] = {
                        "scan_count": len(history["scans"]),
                        "transitions": history["transitions"],
                        "related_repositories": history["related_repositories"],
                    }
                self._send_json({"scans": recent, "page": page, "page_size": 50, "total": total, "pages": pages})
                return
            route = routes.get(request.path)
            if route is None:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            path, content_type = route
            try:
                body = path.read_bytes()
            except OSError:
                self._send_json({"error": "web asset unavailable"}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self._headers(content_type, len(body))
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            self.request_id = str(uuid4())
            if not self._allowed_host():
                self._send_json({"error": "Invalid host"}, HTTPStatus.BAD_REQUEST)
                return
            if not self._origin_allowed():
                self._send_json({"error": "Invalid origin"}, HTTPStatus.FORBIDDEN)
                return
            request = urlsplit(self.path)
            if request.path in {"/mcp", "/api/v1/scans"}:
                try:
                    if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                        raise APIError(415, "unsupported_media_type", "Content-Type must be application/json")
                    payload = self._read_json(7 * 1024 * 1024)
                    if request.path == "/mcp":
                        if isinstance(payload, list):
                            responses = [
                                response for item in payload
                                if (response := handle_mcp_message(item, coordinator, store)) is not None
                            ]
                            if not responses:
                                self._headers("application/json; charset=utf-8", 0, HTTPStatus.ACCEPTED)
                                return
                            self._send_json(responses)
                            return
                        response = handle_mcp_message(payload, coordinator, store)
                        if response is None:
                            self._headers("application/json; charset=utf-8", 0, HTTPStatus.ACCEPTED)
                        else:
                            self._send_json(response)
                        return
                    job, cancel_token, created = coordinator.submit(payload, self.headers.get("Idempotency-Key"))
                    extra = {"Location": job["links"]["self"]}
                    if cancel_token:
                        extra["X-Ward-Cancel-Token"] = cancel_token
                    self._send_json(job, HTTPStatus.ACCEPTED if created else HTTPStatus.OK, extra)
                    return
                except APIError as exc:
                    self._api_error(exc)
                    return
            if request.path not in {"/api/check-repo", "/api/scan-repo"}:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("invalid request size")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Request must be a JSON object")
                if request.path == "/api/scan-repo":
                    target = normalize_repository_url(str(payload.get("target", "")))
                    with scan_lock:
                        if not scan_slot.acquire(blocking=False):
                            self._send_json({"error": "Another repository scan is running. Try again in a moment."}, HTTPStatus.TOO_MANY_REQUESTS)
                            return
                    try:
                        result = scan_repository(target)
                        store.record_repository_scan(result)
                    finally:
                        scan_slot.release()
                    self._send_json(result)
                    return
                owner, repository = parse_repository_target(str(payload.get("target", "")))
                assessment = repository_warning(f"{owner}/{repository}")
                evidence = None
                if assessment is None:
                    with check_lock:
                        key = f"{owner}/{repository}".lower()
                        now = time.monotonic()
                        cached = cache.get(key)
                        if cached and now - cached[0] < 900:
                            assessment, evidence = cached[1:]
                        else:
                            snapshot = client.snapshot(owner, repository)
                            assessment = assess_repository(snapshot)
                            evidence = snapshot_evidence(snapshot)
                            if len(cache) >= 256:
                                cache.pop(next(iter(cache)))
                            cache[key] = (now, assessment, evidence)
                store.record_assessment(assessment, evidence)
                result = assessment.to_dict()
                result["status"] = "FAIL" if assessment.exact_indicator_match else "UNKNOWN"
                self._send_json(result)
            except (GitHubError, ScanError, ValueError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)[:500]}, HTTPStatus.BAD_REQUEST)

        def do_DELETE(self) -> None:  # noqa: N802
            self.request_id = str(uuid4())
            if not self._allowed_host():
                self._send_json({"error": "Invalid host"}, HTTPStatus.BAD_REQUEST)
                return
            if not self._origin_allowed():
                self._send_json({"error": "Invalid origin"}, HTTPStatus.FORBIDDEN)
                return
            request = urlsplit(self.path)
            scan_id = self._scan_id_from_path(request.path)
            if not scan_id:
                self._api_error(APIError(404, "not_found", "Endpoint not found"))
                return
            try:
                self._send_json(coordinator.cancel(scan_id, self.headers.get("X-Ward-Cancel-Token")))
            except APIError as exc:
                self._api_error(exc)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def serve(port: int = 8787, open_browser: bool = True) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    address = ("0.0.0.0" if os.environ.get("WARD_PUBLIC") == "1" else "127.0.0.1", port)
    server = BoundedHTTPServer(address, _handler())
    url = f"http://127.0.0.1:{port}"
    print(f"Ward is ready at {url}")
    print("Press Ctrl+C to stop it.")
    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

