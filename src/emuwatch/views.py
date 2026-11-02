from __future__ import annotations

import html
import json


def badge_state(job: dict | None) -> tuple[str, str, str]:
    if job is None:
        return "?", "not scanned", "#77736b"
    if job["status"] in {"queued", "running"}:
        return "…", "scanning", "#d8b45c"
    if job["status"] != "completed" or not job.get("result"):
        return "~", "incomplete", "#77736b"
    verdict = job["result"].get("status")
    if verdict == "Malicious":
        return "✕", "malware detected", "#c94f4f"
    if verdict == "Corroborated":
        return "!", "suspicious", "#c47b3a"
    if job["result"].get("findings"):
        return "!", "review findings", "#c47b3a"
    level = (job["result"].get("verification") or {}).get("level")
    if level == "verified":
        return "✓", "verified", "#c9a64f"
    if level == "inspected":
        return "✓", "inspected", "#c9a64f"
    if level == "partial":
        return "~", "partial scan", "#77736b"
    return "?", "no known match", "#77736b"


def badge_svg(job: dict | None) -> bytes:
    symbol, status, color = badge_state(job)
    left = "Ward"
    right = f"{symbol} {status}"
    left_width = 48
    right_width = max(92, len(right) * 7 + 16)
    total = left_width + right_width
    label = html.escape(f"Ward: {status}", quote=True)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}">
<title>{label}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".08"/><stop offset="1" stop-opacity=".08"/></linearGradient>
<clipPath id="r"><rect width="{total}" height="20" rx="4"/></clipPath>
<g clip-path="url(#r)"><rect width="{left_width}" height="20" fill="#24221e"/><rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/><rect width="{total}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="{left_width / 2}" y="14">{left}</text><text x="{left_width + right_width / 2}" y="14">{html.escape(right)}</text></g>
</svg>""".encode()


def _page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Ward malware scan evidence"><title>{html.escape(title)} · Ward</title><link rel="stylesheet" href="/styles.css"></head>
<body><div class="grid" aria-hidden="true"></div><main class="record-page"><header class="record-header"><a href="/">Ward</a><h1>{html.escape(title)}</h1></header>{body}</main>
<footer>By Lleywyn · <a href="/api/v1">API</a> · <a href="https://github.com/HiLleywyn/ward">Source</a></footer></body></html>""".encode()


def scan_record_page(job: dict, report: dict | None) -> bytes:
    result = job.get("result") or {}
    symbol, label, _ = badge_state(job)
    facts = [
        ("Status", f"{symbol} {label}"),
        ("Kind", job["kind"]),
        ("Target", job["target"]),
        ("Branch", result.get("branch") or job.get("requested_ref") or "not recorded"),
        ("Commit", result.get("commit") or "not recorded"),
        ("Verification", (result.get("verification") or {}).get("level") or "not recorded"),
        ("Evidence digest", result.get("evidence_digest") or "not recorded"),
        ("Created", job["created_at"]),
        ("Updated", job["updated_at"]),
    ]
    rows = "".join(
        f"<dt>{html.escape(name)}</dt><dd><code>{html.escape(str(value))}</code></dd>" for name, value in facts
    )
    findings = result.get("findings", [])
    if findings:
        finding_html = "".join(
            "<li><strong>{}</strong><code>{}</code><p>{}</p></li>".format(
                html.escape(str(item.get("title", "Finding"))),
                html.escape(str(item.get("path") or item.get("sha256") or "artifact")),
                html.escape(str(item.get("detail", ""))),
            ) for item in findings
        )
    else:
        finding_html = "<li>No configured indicator or static rule matched. This does not prove safety.</li>"
    limitations = "".join(f"<li>{html.escape(str(item))}</li>" for item in result.get("limitations", []))
    report_json = html.escape(json.dumps(report, indent=2)) if report else "Report is available when the scan reaches a terminal state."
    body = f"""<section class="record-card"><dl class="record-facts">{rows}</dl></section>
<section class="record-card"><h2>Findings</h2><ul class="record-findings">{finding_html}</ul></section>
<section class="record-card"><h2>Limits</h2><ul>{limitations or '<li>No additional limits recorded.</li>'}</ul></section>
<details class="record-card"><summary>Machine-Readable Report</summary><pre>{report_json}</pre></details>"""
    return _page("Scan Record", body)


def repository_ledger_page(history: dict) -> bytes:
    scans = list(reversed(history.get("scans", [])))
    rows = []
    for scan in scans:
        scan_id = scan["scan_id"]
        rows.append(
            "<li><a href=\"/scans/{}\"><strong>{}</strong></a><code>{}</code><span>{}</span><time>{}</time></li>".format(
                html.escape(scan_id, quote=True),
                html.escape(str(scan.get("status", "Unknown"))),
                html.escape(str(scan.get("commit", "unknown"))[:12]),
                html.escape(str(scan.get("branch", "branch not recorded"))),
                html.escape(str(scan.get("scanned_at", ""))),
            )
        )
    transitions = "".join(
        "<li><strong>{} to {}</strong><span>{} new, {} removed</span><a href=\"/api/v1/comparisons?base_scan={}&amp;head_scan={}\">View comparison</a></li>".format(
            html.escape(str(item.get("from_status"))), html.escape(str(item.get("to_status"))),
            len(item.get("new_findings", [])), len(item.get("removed_findings", [])),
            html.escape(item["base_scan_id"], quote=True), html.escape(item["head_scan_id"], quote=True),
        ) for item in history.get("transitions", [])
    )
    related = "".join(
        f"<li><code>{html.escape(str(item['repository']))}</code><span>shared commit {html.escape(str(item['commit'])[:12])}</span></li>"
        for item in history.get("related_repositories", [])
    )
    body = f"""<section class="record-card"><p>{html.escape(history['repository'])}</p><p>Earlier unknown results were not proven safe. This ledger reports only what each bounded scan observed.</p></section>
<section class="record-card"><h2>Scans</h2><ul class="ledger-list">{''.join(rows) or '<li>No scans recorded.</li>'}</ul></section>
<section class="record-card"><h2>Observed Changes</h2><ul class="ledger-list">{transitions or '<li>No finding transitions recorded.</li>'}</ul></section>
<section class="record-card"><h2>Shared-Commit Repositories</h2><ul class="ledger-list">{related or '<li>No related scanned repositories found.</li>'}</ul><p>{html.escape(history['relationship_note'])}</p></section>"""
    return _page("Repository Ledger", body)
