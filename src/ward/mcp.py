from __future__ import annotations

import json
from urllib.parse import quote

from .api import APIError, ScanCoordinator, normalize_sha256, openapi_document, public_scan, report_for_job
from .evidence import ResultStore, malware_records


PROTOCOL_VERSION = "2025-06-18"


TOOLS = [
    {
        "name": "ward_submit_scan",
        "description": "Submit a public Git repository URL or SHA-256 for bounded asynchronous analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["repository", "sha256"]},
                "url": {"type": "string", "format": "uri"},
                "ref": {"type": "string", "maxLength": 200},
                "expected_commit": {"type": "string", "pattern": "^[A-Fa-f0-9]{40,64}$"},
                "analysis": {"type": "string", "enum": ["static", "extended", "behavioral"]},
                "sha256": {"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
                "idempotency_key": {"type": "string", "maxLength": 128},
            },
            "required": ["kind"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ward_get_badge",
        "description": "Get README badge Markdown and the evidence ledger URL for a GitHub repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repository": {"type": "string", "minLength": 1, "maxLength": 500},
                "branch": {"type": "string", "maxLength": 200}
            },
            "required": ["repository"],
            "additionalProperties": False
        },
    },
    {
        "name": "ward_get_scan",
        "description": "Retrieve one Ward scan and its lifecycle state.",
        "inputSchema": {
            "type": "object", "properties": {"scan_id": {"type": "string", "format": "uuid"}},
            "required": ["scan_id"], "additionalProperties": False,
        },
    },
    {
        "name": "ward_get_report",
        "description": "Retrieve a terminal scan report with verdict, evidence, detections, and limitations.",
        "inputSchema": {
            "type": "object", "properties": {"scan_id": {"type": "string", "format": "uuid"}},
            "required": ["scan_id"], "additionalProperties": False,
        },
    },
    {
        "name": "ward_lookup_artifact",
        "description": "Look up a reviewed public SHA-256 indicator without exposing private submissions.",
        "inputSchema": {
            "type": "object", "properties": {"sha256": {"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}},
            "required": ["sha256"], "additionalProperties": False,
        },
    },
    {
        "name": "ward_list_scans",
        "description": "List recent Ward scans using bounded cursor pagination.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "cursor": {"type": "string"},
                "status": {"type": "string", "enum": ["queued", "running", "completed", "failed", "cancelled", "incomplete"]},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "ward_repository_history",
        "description": "Recall scans of one repository and identify other scanned repositories sharing an exact commit.",
        "inputSchema": {
            "type": "object", "properties": {"repository": {"type": "string", "minLength": 1}},
            "required": ["repository"], "additionalProperties": False,
        },
    },
    {
        "name": "ward_compare_scans",
        "description": "Compare two completed repository scans and return verdict and finding changes without claiming unscanned commits were safe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_scan_id": {"type": "string", "format": "uuid"},
                "head_scan_id": {"type": "string", "format": "uuid"}
            },
            "required": ["base_scan_id", "head_scan_id"],
            "additionalProperties": False
        },
    },
    {
        "name": "ward_list_malware_records",
        "description": "List Ward's reviewed, source-backed malware repository records.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ward_get_malware_record",
        "description": "Retrieve one reviewed malware record by its stable Ward record ID.",
        "inputSchema": {
            "type": "object", "properties": {"record_id": {"type": "string", "minLength": 1}},
            "required": ["record_id"], "additionalProperties": False,
        },
    },
]


def _tool_result(value: object, *, error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": json.dumps(value, indent=2)}], "structuredContent": value}
    if error:
        result["isError"] = True
    return result


def _call_tool(
    name: str,
    arguments: object,
    coordinator: ScanCoordinator,
    store: ResultStore,
) -> dict:
    if not isinstance(arguments, dict):
        raise APIError(400, "invalid_arguments", "Tool arguments must be an object")
    if name == "ward_submit_scan":
        kind = arguments.get("kind")
        if kind == "file":
            raise APIError(422, "unsupported_scan_kind", "MCP accepts repository and sha256 scans; use the REST API for files")
        payload = {key: arguments[key] for key in ("kind", "url", "ref", "expected_commit", "sha256", "analysis") if key in arguments}
        job, _, _ = coordinator.submit(payload, arguments.get("idempotency_key"))
        return _tool_result(job)
    if name == "ward_get_badge":
        repository = str(arguments.get("repository", "")).strip()
        if not repository:
            raise APIError(422, "invalid_repository", "repository is required")
        branch = str(arguments.get("branch", "")).strip() or None
        try:
            job = store.latest_repository_scan(repository, branch)
        except ValueError as exc:
            raise APIError(422, "invalid_repository", str(exc)) from exc
        if "://" not in repository and len(repository.split("/")) == 2:
            badge_url = f"https://ward.lley.cat/api/v1/badges/{quote(repository, safe='/')}.svg"
            ledger_url = "https://ward.lley.cat/repositories/" + quote(repository, safe="/")
        else:
            encoded = quote(repository, safe="")
            badge_url = "https://ward.lley.cat/api/v1/badge.svg?repository=" + encoded
            ledger_url = "https://ward.lley.cat/repository?target=" + encoded
        if branch:
            badge_url += ("&" if "?" in badge_url else "?") + "branch=" + quote(branch, safe="")
        return _tool_result({
            "repository": repository,
            "branch": branch,
            "scan": public_scan(job) if job else None,
            "badge_url": badge_url,
            "ledger_url": ledger_url,
            "markdown": f"[![Ward]({badge_url})]({ledger_url})",
            "warning": "An inspected badge records bounded checks for one revision; it does not prove software is safe.",
        })
    if name == "ward_get_scan":
        job = store.scan_job(str(arguments.get("scan_id", "")))
        if job is None:
            raise APIError(404, "scan_not_found", "Scan not found")
        return _tool_result(public_scan(job))
    if name == "ward_get_report":
        job = store.scan_job(str(arguments.get("scan_id", "")))
        if job is None:
            raise APIError(404, "scan_not_found", "Scan not found")
        return _tool_result(report_for_job(job))
    if name == "ward_lookup_artifact":
        digest = normalize_sha256(arguments.get("sha256"))
        artifact = store.public_artifact(digest)
        if artifact is None:
            raise APIError(404, "artifact_not_found", "No reviewed public indicator matches this SHA-256")
        return _tool_result(artifact)
    if name == "ward_list_scans":
        jobs, cursor = store.list_scan_jobs(
            limit=int(arguments.get("limit", 20)),
            cursor=arguments.get("cursor"),
            status=arguments.get("status"),
        )
        return _tool_result({"items": [public_scan(job) for job in jobs], "next_cursor": cursor})
    if name == "ward_repository_history":
        try:
            return _tool_result(store.repository_history(str(arguments.get("repository", ""))))
        except ValueError as exc:
            raise APIError(400, "invalid_repository", str(exc)) from exc
    if name == "ward_compare_scans":
        try:
            return _tool_result(store.compare_repository_scans(
                str(arguments.get("base_scan_id", "")), str(arguments.get("head_scan_id", ""))
            ))
        except LookupError as exc:
            raise APIError(404, "scan_not_found", str(exc)) from exc
        except ValueError as exc:
            raise APIError(422, "scans_not_comparable", str(exc)) from exc
    if name == "ward_list_malware_records":
        return _tool_result({"items": malware_records()})
    if name == "ward_get_malware_record":
        record_id = str(arguments.get("record_id", ""))
        record = next((item for item in malware_records() if item.get("id") == record_id), None)
        if record is None:
            raise APIError(404, "record_not_found", "Malware record not found")
        return _tool_result(record)
    raise APIError(404, "tool_not_found", f"Unknown tool: {name}")


def handle_message(
    message: object,
    coordinator: ScanCoordinator,
    store: ResultStore,
) -> dict | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}, "resources": {"listChanged": False}},
                "serverInfo": {"name": "ward", "version": "0.6.3"},
                "instructions": "Ward scans public Git repositories and hashes. Extended scans add isolated static analysis; Windows behavior is offered only when its disposable worker is verified online. Unknown never means safe.",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            result = _call_tool(str(params.get("name", "")), params.get("arguments") or {}, coordinator, store)
        elif method == "resources/list":
            result = {"resources": [{
                "uri": "ward://openapi", "name": "Ward OpenAPI 3.1 contract",
                "mimeType": "application/json", "description": "The complete public REST API contract.",
            }]}
        elif method == "resources/read":
            params = message.get("params") or {}
            if params.get("uri") != "ward://openapi":
                raise APIError(404, "resource_not_found", "Resource not found")
            result = {"contents": [{
                "uri": "ward://openapi", "mimeType": "application/json",
                "text": json.dumps(openapi_document(), indent=2),
            }]}
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except APIError as exc:
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": request_id, "result": _tool_result({"error": {"code": exc.code, "message": exc.message}}, error=True)}
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": exc.message, "data": {"code": exc.code}}}
    except (TypeError, ValueError) as exc:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": str(exc)}}
