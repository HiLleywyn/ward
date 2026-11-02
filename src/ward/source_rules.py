"""Static Python behavior checks. Parsing never imports or executes source."""
from __future__ import annotations

import ast
import re


DISCORD_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,40}$")


def python_findings(text: str, path: str) -> list[dict]:
    if not path.lower().split("!")[-1].endswith(".py"):
        return []
    if len(text) > 512 * 1024:
        return [{"kind": "python-source-limit", "severity": "info", "title": "Python behavior analysis reached its size limit",
                 "path": path, "detail": "This file exceeded the bounded Python parser limit; behavior coverage is partial."}]
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError, MemoryError):
        return [{"kind": "python-source-unparsed", "severity": "info", "title": "Python source could not be parsed",
                 "path": path, "detail": "Ward could not build a Python syntax tree. Text rules still ran; behavior coverage is partial."}]
    nodes = list(ast.walk(tree))
    if len(nodes) > 50_000:
        return [{"kind": "python-source-limit", "severity": "info", "title": "Python behavior analysis reached its node limit",
                 "path": path, "detail": "The syntax tree exceeded the analysis bound; behavior coverage is partial."}]
    has_discord = any((isinstance(node, ast.Import) and any(item.name.split('.')[0] == 'discord' for item in node.names)) or
                      (isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[0] == 'discord') for node in nodes)
    findings = []
    lines = text.splitlines()

    def add(kind, title, node, detail, *, evidence_type="source-behavior", code=None):
        line = node.lineno
        findings.append({"kind": kind, "severity": "high", "title": title, "path": path, "line": line,
                         "detail": detail, "evidence_type": evidence_type, "evidence": {"line": line,
                         "code": code if code is not None else lines[line - 1].strip()[:160]}})

    if has_discord:
        for node in nodes:
            if not isinstance(node, ast.While) or not isinstance(node.test, ast.Constant) or node.test.value is not True:
                continue
            # Stop conditions and exits require a more precise control-flow review.
            if any(isinstance(child, (ast.Break, ast.Return)) for child in ast.walk(node)):
                continue
            calls = [child for child in ast.walk(node) if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)]
            for call in calls:
                if call.func.attr == "send" and any(isinstance(arg, ast.Constant) and isinstance(arg.value, str) and
                                                    ("@everyone" in arg.value or "@here" in arg.value) for arg in call.args):
                    add("discord-mention-flood", "Unbounded Discord mass-mention spam", node,
                        "A while-True loop repeatedly sends @everyone or @here messages without a break or return. This can flood a server with notifications.")
                    break
            if any(call.func.attr in {"create_role", "create_text_channel", "create_voice_channel"} for call in calls):
                add("discord-resource-flood", "Unbounded Discord resource creation", node,
                    "A while-True loop creates roles or channels without a break or return. This can exhaust server resources and permissions.")
        for function in nodes:
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            creations = [node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                         and node.func.attr in {"create_text_channel", "create_voice_channel"}]
            if len(creations) >= 10:
                add("discord-channel-flood", "Bulk Discord channel creation", creations[0],
                    f"One function contains {len(creations)} channel-creation calls. Review authorization and purpose; this pattern can flood a server.")
        for node in nodes:
            if not isinstance(node, (ast.For, ast.AsyncFor)) or not isinstance(node.target, ast.Name):
                continue
            collection = ast.unparse(node.iter)
            if not any(collection.endswith('.' + name) for name in ("channels", "roles", "members")):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and isinstance(child.func.value, ast.Name) and child.func.value.id == node.target.id and child.func.attr in {"delete", "ban", "kick"}:
                    add("discord-mass-destruction", "Bulk Discord deletion or member removal", node,
                        "A loop applies deletion, ban, or kick to a server-wide collection. This can destroy channels/roles or remove members; legitimate moderation still requires review.")
                    break
        for node in nodes:
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "run" or not node.args:
                continue
            token = node.args[0]
            if isinstance(token, ast.Constant) and isinstance(token.value, str) and DISCORD_TOKEN.fullmatch(token.value):
                add("embedded-discord-token", "Embedded Discord bot token", node,
                    "A Discord-style bot token is embedded directly in source. Treat it as compromised and rotate it before reuse.",
                    evidence_type="credential-exposure", code='bot.run("[REDACTED]")')
    for node in nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"} and node.args:
            decoders = [child for child in ast.walk(node.args[0]) if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr in {"b64decode", "b85decode", "decompress", "loads"}]
            if decoders:
                add("decoded-python-execution", "Decoded Python content executed", node,
                    "exec/eval directly consumes decoded or deserialized content. Review the hidden instructions; this alone does not prove malware.")
    return findings
