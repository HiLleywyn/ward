from __future__ import annotations

import json
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .analyze import assess_repository, parse_repository_target
from .github import GitHubClient, GitHubError


WEB_ROOT = Path(__file__).with_name("webui")


def _handler() -> type[BaseHTTPRequestHandler]:
    client = GitHubClient()

    class Handler(BaseHTTPRequestHandler):
        server_version = "EmuWatch/0.1"

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
            routes = {
                "/": (WEB_ROOT / "index.html", "text/html; charset=utf-8"),
                "/styles.css": (WEB_ROOT / "styles.css", "text/css; charset=utf-8"),
                "/app.js": (WEB_ROOT / "app.js", "text/javascript; charset=utf-8"),
            }
            if self.path == "/api/indicators":
                indicator_path = Path(__file__).resolve().parents[2] / "advisories" / "indicators.json"
                known_path = Path(__file__).resolve().parents[2] / "advisories" / "known-project-assets.json"
                try:
                    indicators = json.loads(indicator_path.read_text(encoding="utf-8"))
                    known_assets = json.loads(known_path.read_text(encoding="utf-8"))
                    self._send_json(
                        {
                            "indicators": indicators.get("indicators", []),
                            "known_assets": known_assets.get("assets", []),
                        }
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            if self.path == "/api/campaigns":
                campaign_path = Path(__file__).resolve().parents[2] / "advisories" / "campaigns.json"
                try:
                    self._send_json(json.loads(campaign_path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
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
            if self.path != "/api/check-repo":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("invalid request size")
                payload = json.loads(self.rfile.read(length))
                owner, repository = parse_repository_target(str(payload.get("target", "")))
                result = assess_repository(client.snapshot(owner, repository)).to_dict()
                self._send_json(result)
            except (GitHubError, ValueError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def serve(port: int = 8787, open_browser: bool = True) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    address = ("127.0.0.1", port)
    server = ThreadingHTTPServer(address, _handler())
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

