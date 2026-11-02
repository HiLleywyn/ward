"""Bounded, non-executing script checks independent of file extensions."""
from __future__ import annotations

import re


LUA_LITERAL_START = re.compile(r"--|['\"]|\[=*\[")


def _lua_literals(text):
    cursor = 0
    while (match := LUA_LITERAL_START.search(text, cursor)) is not None:
        start = match.start()
        marker = match.group()
        opening = start + 2 if marker == "--" else start
        bracket = re.match(r"\[(=*)\[", text[opening:opening + 128])
        if bracket:
            close = "]" + bracket.group(1) + "]"
            found = text.find(close, opening + bracket.end())
            end = len(text) if found < 0 else found + len(close)
        elif marker == "--":
            found = text.find("\n", opening)
            end = len(text) if found < 0 else found
        elif marker in {"'", '"'}:
            end = start + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == marker:
                    end += 1
                    break
                else:
                    end += 1
        else:
            end = match.end()
        yield start, min(end, len(text)), text[start:end]
        cursor = max(end, start + 1)
IP_SERVICE = re.compile(r"https?://(?:ip-api\.com|ipinfo\.io|ipwho\.is|api\.ipify\.org)(?:/|$)", re.I)
WEBHOOK = re.compile(r"https?://[^\s]+/(?:api/)?webhooks?/", re.I)


def lua_findings(text: str, path: str) -> list[dict]:
    leaf = path.lower().split("!")[-1]
    if leaf.endswith((".md", ".rst", ".txt", ".json")):
        return []
    if not (leaf.endswith((".lua", ".luau")) or re.search(r"\blocal\s+\w+\s*=|\bgame\s*:\s*(?:HttpGet|GetService)\s*\(", text)):
        return []
    if len(text) > 512 * 1024:
        return [{"kind": "lua-source-limit", "severity": "info", "title": "Lua analysis reached its size limit",
                 "path": path, "detail": "The source was recorded, but bounded Lua behavior analysis is incomplete."}]
    parts, literals, cursor = [], [], 0
    for start, end, literal in _lua_literals(text):
        parts.append(text[cursor:start])
        if not literal.startswith("--"):
            literals.append((start, end, literal.strip("\"'")))
        parts.append("".join("\n" if char == "\n" else " " for char in literal))
        cursor = end
    parts.append(text[cursor:])
    code = "".join(parts)
    findings = []

    def add(kind, title, position, detail):
        findings.append({"kind": kind, "severity": "high", "title": title, "path": path,
                         "line": text.count("\n", 0, position) + 1, "evidence_type": "source-behavior", "detail": detail})

    loader = re.search(r"\bloadstring\s*\(\s*game\s*:\s*HttpGet(?:Async)?\s*\([^)]*\)\s*\)\s*\(", code)
    if loader:
        add("lua-remote-code-execution", "Downloaded Lua code executed immediately", loader.start(),
            "loadstring immediately runs content fetched with HttpGet. The remote code is outside this pinned repository and was not fetched or executed.")
    # Follow common local assignment chains from an IP lookup to the request body.
    assignments = list(re.finditer(r"\blocal\s+(\w+)\s*=", code))
    tainted = set()
    for index, assignment in enumerate(assignments):
        end = assignments[index + 1].start() if index + 1 < len(assignments) else len(code)
        expression = code[assignment.end():end]
        source = any(IP_SERVICE.search(value) for start, _, value in literals if assignment.end() <= start < end)
        if (source and re.search(r"\b(?:request|http_request|HttpGet)\s*\(", expression)) or tainted.intersection(re.findall(r"\b\w+\b", expression)):
            tainted.add(assignment.group(1))
    has_webhook = any(WEBHOOK.search(value) for _, _, value in literals)
    has_post = any(value.upper() == "POST" and re.search(r"\bMethod\s*=\s*$", code[max(0, start - 80):start])
                   for start, _, value in literals)
    if has_webhook and has_post and re.search(r"\b(?:request|http_request)\s*\(", code):
        for body in re.finditer(r"\bBody\s*=([^\n]{1,4096})", code):
            if tainted.intersection(re.findall(r"\b\w+\b", body.group(1))):
                add("lua-ip-webhook-upload", "IP and location data sent to a webhook", body.start(),
                    "A local assignment chain carries an IP/geolocation lookup into a webhook POST body. This can disclose a player's public IP and location; destination credentials are not reproduced.")
                break
    return findings
