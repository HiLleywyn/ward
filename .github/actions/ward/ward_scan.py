from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


TERMINAL = {"completed", "failed", "cancelled", "incomplete"}


def request_json(url: str, *, payload: dict | None = None, headers: dict[str, str] | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "ward-github-action/1",
        **(headers or {}),
    })
    try:
        with urlopen(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error", {}).get("message")
        except (json.JSONDecodeError, AttributeError):
            detail = None
        raise RuntimeError(detail or f"Ward returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Ward could not be reached: {exc.reason}") from exc


def badge_locations(base_url: str, url: str, ref: str) -> tuple[str, str]:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    if parsed.hostname == "github.com" and len(parts) == 2:
        repository = "/".join(parts)
        badge_url = f"{base_url}/api/v1/badges/{repository}.svg"
        ledger_url = f"{base_url}/repositories/{repository}"
    else:
        encoded = quote(url, safe="")
        badge_url = f"{base_url}/api/v1/badge.svg?repository={encoded}"
        ledger_url = f"{base_url}/repository?target={encoded}"
    if ref:
        separator = "&" if "?" in badge_url else "?"
        badge_url += f"{separator}branch={quote(ref, safe='')}"
    return badge_url, ledger_url


def set_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def append_summary(text: str) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")


def main() -> int:
    base_url = os.environ.get("WARD_URL", "https://ward.lley.cat").rstrip("/")
    repository_url = os.environ["WARD_REPOSITORY_URL"]
    ref = os.environ.get("WARD_REF", "").strip()
    expected_commit = os.environ.get("WARD_EXPECTED_COMMIT", "").strip()
    timeout = max(15, min(int(os.environ.get("WARD_TIMEOUT_SECONDS", "180")), 900))
    payload = {"kind": "repository", "url": repository_url}
    if ref:
        payload["ref"] = ref
    if expected_commit:
        payload["expected_commit"] = expected_commit
    job = request_json(
        f"{base_url}/api/v1/scans",
        payload=payload,
        headers={"Idempotency-Key": os.environ.get("WARD_IDEMPOTENCY_KEY", expected_commit)},
    )
    deadline = time.monotonic() + timeout
    def unfinished(value):
        return value["status"] not in TERMINAL or any(item.get("status") in {"queued", "running"} for item in value.get("analyses", []))

    while unfinished(job) and time.monotonic() < deadline:
        time.sleep(2)
        job = request_json(f"{base_url}{job['links']['self']}")
    if unfinished(job):
        raise RuntimeError(f"Ward did not finish within {timeout} seconds")
    scan_id = job["id"]
    record_url = f"{base_url}/scans/{scan_id}"
    report = request_json(f"{base_url}/api/v1/reports/{scan_id}")
    verdict = report["verdict"]["status"]
    badge_url, ledger_url = badge_locations(base_url, repository_url, ref)
    badge = f"[![Ward]({badge_url})]({ledger_url})"
    verification = report.get("evidence", {}).get("verification", {}).get("level", "not recorded")
    findings = sum(len(engine.get("detections", [])) for engine in report.get("engines", []))
    set_output("scan-id", scan_id)
    set_output("verdict", verdict)
    set_output("record-url", record_url)
    set_output("badge-markdown", badge)
    append_summary(
        "\n".join((
            "## Ward repository inspection",
            f"- Verdict: **{verdict}**",
            f"- Verification: **{verification}**",
            f"- Findings: **{findings}**",
            f"- [View evidence]({record_url})",
            "",
            "README badge:",
            f"`{badge}`",
        ))
    )
    print(f"Ward {verdict}: {record_url}")
    followup = report.get("assessment", {}).get("coverage", "not-requested")
    passed = verdict == "unknown" and verification in {"inspected", "verified"} and findings == 0 and followup in {"completed", "not-requested"}
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, RuntimeError, ValueError) as exc:
        print(f"Ward action failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
