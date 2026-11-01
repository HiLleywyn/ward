from __future__ import annotations

import json
import os
import threading
import time
import webbrowser
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .analyze import assess_repository, parse_repository_target
from .github import GitHubClient, GitHubError
from .data import advisory_directory
from .evidence import default_store, repository_warning, reviewed_repositories, snapshot_evidence


WEB_ROOT = Path(__file__).with_name("webui")


def _handler() -> type[BaseHTTPRequestHandler]:
    public = os.environ.get("EMUWATCH_PUBLIC") == "1"
    client = GitHubClient()
    if public:
        client.token = None
    store = default_store()
    cache = {}
    checks = deque()
    check_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "EmuWatch/0.1"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(25)

        def _allowed_host(self):
            host = self.headers.get("Host", "").split(":", 1)[0].lower()
            return host in {"127.0.0.1", "localhost", "ward.lley.cat", "ward", "testserver"}

        def _headers(self, content_type: str, length: int, status: int = 200) -> None:
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
            self.end_headers()

        def _send_json(self, value: object, status: int = 200) -> None:
            body = json.dumps(value).encode("utf-8")
            self._headers("application/json; charset=utf-8", len(body), status)
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not self._allowed_host():
                self._send_json({"error": "Invalid host"}, HTTPStatus.BAD_REQUEST)
                return
            if self.path == "/healthz":
                from . import __version__
                self._send_json({"status": "ok", "version": __version__, "public": public})
                return
            routes = {
                "/": (WEB_ROOT / "index.html", "text/html; charset=utf-8"),
                "/styles.css": (WEB_ROOT / "styles.css", "text/css; charset=utf-8"),
                "/app.js": (WEB_ROOT / "app.js", "text/javascript; charset=utf-8"),
            }
            if self.path == "/api/indicators":
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
            if self.path == "/api/campaigns":
                campaign_path = advisory_directory() / "campaigns.json"
                try:
                    self._send_json(json.loads(campaign_path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            if self.path == "/api/reviewed":
                review_data = json.loads((advisory_directory() / "review-status.json").read_text(encoding="utf-8"))
                self._send_json({"repositories": reviewed_repositories(), "reviews": review_data["reviews"], "coverage": review_data["coverage"]})
                return
            if self.path == "/api/history":
                self._send_json({"observations": [] if public else store.history()})
                return
            route = routes.get(self.path)
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
            if not self._allowed_host():
                self._send_json({"error": "Invalid host"}, HTTPStatus.BAD_REQUEST)
                return
            origin = self.headers.get("Origin")
            if origin and origin not in {"https://ward.lley.cat", f"http://{self.headers.get('Host')}"}:
                self._send_json({"error": "Invalid origin"}, HTTPStatus.FORBIDDEN)
                return
            if self.path != "/api/check-repo":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("invalid request size")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Request must be a JSON object")
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
                            while checks and now - checks[0] > 3600:
                                checks.popleft()
                            if public and len(checks) >= 8:
                                self._send_json({"error": "Live GitHub checks are cooling down. Known warnings and file checks still work. Try again later."}, HTTPStatus.TOO_MANY_REQUESTS)
                                return
                            checks.append(now)
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
            except (GitHubError, ValueError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)[:500]}, HTTPStatus.BAD_REQUEST)

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
    address = ("0.0.0.0" if os.environ.get("EMUWATCH_PUBLIC") == "1" else "127.0.0.1", port)
    server = BoundedHTTPServer(address, _handler())
    url = f"http://127.0.0.1:{port}"
    print(f"Emulator Safety Watch is ready at {url}")
    print("Press Ctrl+C to stop it.")
    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

