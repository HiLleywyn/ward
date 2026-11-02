"""Static Python behavior checks. Parsing never imports or executes source."""
from __future__ import annotations

import ast
import re


DISCORD_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,40}$")
SENSITIVE_PATH = re.compile(
    r"(?:wallet(?:\.dat|s?|s/)|seed(?:\.txt|s|phrase)?|mnemonic|private[_ -]?key|"
    r"Login Data|Local State|Cookies|logins\.json|key4\.db|\.ssh[/\\]|\.aws[/\\]|"
    r"\.config[/\\](?:solana|gcloud)|\.ethereum|\.bitcoin|\.electrum|\.env(?:$|[./\\]))", re.I,
)


def _python_upload_findings(tree: ast.AST, path: str) -> list[dict]:
    """Track common file-read -> variable/container -> network-upload flows."""
    findings = []

    def names(node):
        return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}

    def constants(node):
        return " ".join(str(item.value) for item in ast.walk(node)
                        if isinstance(item, ast.Constant) and isinstance(item.value, str))

    def visit_block(body, paths=None, tainted=None):
        paths, tainted = set(paths or ()), set(tainted or ())

        def reads_secret(node):
            for item in ast.walk(node):
                if not isinstance(item, ast.Call):
                    continue
                name = item.func.attr if isinstance(item.func, ast.Attribute) else getattr(item.func, "id", "")
                if name in {"open", "read_text", "read_bytes", "connect", "getenv"} and (
                    SENSITIVE_PATH.search(constants(item)) or names(item) & paths
                ):
                    return True
            return False

        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit_block(statement.body, paths, tainted)
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and statement.value is not None:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                assigned = set().union(*(names(target) for target in targets))
                path_value = SENSITIVE_PATH.search(constants(statement.value)) or names(statement.value) & paths
                secret_value = reads_secret(statement.value) or names(statement.value) & tainted
                if isinstance(statement, ast.AugAssign):
                    path_value = path_value or assigned & paths
                    secret_value = secret_value or assigned & tainted
                if path_value:
                    paths.update(assigned)
                else:
                    paths.difference_update(assigned)
                if secret_value:
                    tainted.update(assigned)
                else:
                    tainted.difference_update(assigned)
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if item.optional_vars and reads_secret(item.context_expr):
                        tainted.update(names(item.optional_vars))
            # Do not inspect nested function bodies using the enclosing function's locals.
            expressions = [node for field, value in ast.iter_fields(statement)
                           if field not in {"body", "orelse", "finalbody", "handlers"}
                           for node in (value if isinstance(value, list) else [value]) if isinstance(node, ast.AST)]
            for expression in expressions:
                for call in ast.walk(expression):
                    if not isinstance(call, ast.Call):
                        continue
                    name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
                    if name not in {"post", "put", "request", "Request", "urlopen", "send", "sendall", "send_file", "upload_file"}:
                        continue
                    payloads = list(call.args[1:]) if name not in {"send", "sendall", "send_file", "upload_file"} else list(call.args)
                    payloads.extend(item.value for item in call.keywords if item.arg in {"data", "json", "files", "body", "content"})
                    if any(reads_secret(item) or names(item) & tainted for item in payloads):
                        findings.append({"kind": "python-sensitive-data-upload", "severity": "high",
                            "title": "Sensitive local data sent to a network API", "path": path, "line": call.lineno,
                            "evidence_type": "source-behavior",
                            "detail": "A file-read flow involving wallet, browser credential, key, or configuration data reaches an upload call. Review consent and destination; the script was not executed."})
            if isinstance(statement, ast.If):
                left = visit_block(statement.body, paths, tainted)
                right = visit_block(statement.orelse, paths, tainted)
                paths, tainted = left[0] | right[0], left[1] | right[1]
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                body_paths, body_tainted = visit_block(statement.body, paths, tainted)
                # A loop may execute zero times, or exit through a break.
                paths, tainted = paths | body_paths, tainted | body_tainted
                else_paths, else_tainted = visit_block(statement.orelse, paths, tainted)
                paths, tainted = paths | else_paths, tainted | else_tainted
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                paths, tainted = visit_block(statement.body, paths, tainted)
            elif isinstance(statement, ast.Try):
                body_paths, body_tainted = visit_block(statement.body, paths, tainted)
                normal = visit_block(statement.orelse, body_paths, body_tainted)
                # Exceptions may occur before the body's last assignment.
                alternatives = [normal] + [visit_block(handler.body, paths | body_paths, tainted | body_tainted)
                                           for handler in statement.handlers]
                paths = set().union(*(state[0] for state in alternatives))
                tainted = set().union(*(state[1] for state in alternatives))
                paths, tainted = visit_block(statement.finalbody, paths, tainted)
        return paths, tainted

    visit_block(tree.body)
    return findings


def python_findings(text: str, path: str) -> list[dict]:
    suffix = path.lower().split("!")[-1].rsplit(".", 1)[-1]
    if suffix != "py" and (suffix in {"md", "rst", "txt", "json"} or not re.search(
        r"(?m)^(?:from\s+\w+\s+import\s|import\s+\w+|(?:async\s+)?def\s+\w+\(|#![^\n]*python)", text
    )):
        return []
    if len(text) > 512 * 1024:
        return [{"kind": "python-source-limit", "severity": "info", "title": "Python behavior analysis reached its size limit",
                 "path": path, "detail": "This file exceeded the bounded Python parser limit; behavior coverage is partial."}]
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError, MemoryError):
        if suffix != "py" and not re.match(r"#![^\n]*python", text):
            return []
        return [{"kind": "python-source-unparsed", "severity": "info", "title": "Python source could not be parsed",
                 "path": path, "detail": "Ward could not build a Python syntax tree. Text rules still ran; behavior coverage is partial."}]
    nodes = list(ast.walk(tree))
    if len(nodes) > 50_000:
        return [{"kind": "python-source-limit", "severity": "info", "title": "Python behavior analysis reached its node limit",
                 "path": path, "detail": "The syntax tree exceeded the analysis bound; behavior coverage is partial."}]
    has_discord = any((isinstance(node, ast.Import) and any(item.name.split('.')[0] == 'discord' for item in node.names)) or
                      (isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[0] == 'discord') for node in nodes)
    findings = _python_upload_findings(tree, path)
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
        if isinstance(node, (ast.For, ast.AsyncFor)):
            calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
            attributes = {child.func.attr for child in calls if isinstance(child.func, ast.Attribute)}
            if "encrypt" in attributes and attributes.intersection({"write", "write_bytes", "replace"}):
                add("python-bulk-file-encryption", "Files encrypted and overwritten in a loop", node,
                    "A loop encrypts data and writes or replaces files. This can indicate ransomware or a legitimate encryption utility; review the target scope and consent.")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "rmtree" and node.args:
            target = node.args[0]
            literal = target.value if isinstance(target, ast.Constant) and isinstance(target.value, str) else ""
            if literal in {"/", "C:\\", "C:/", "~"} or any(
                isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in {"expanduser", "home"}
                for child in ast.walk(target)
            ):
                add("python-destructive-tree-removal", "Recursive deletion targets a root or home directory", node,
                    "Recursive deletion targets a filesystem root or user home. Running this can destroy unrelated user data.")
    has_socket_connection = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect" for node in nodes)
    fd_redirection = [node for node in nodes if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "dup2"]
    shell_launch = any(isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in {"/bin/sh", "/bin/bash", "cmd.exe", "powershell.exe"} for node in nodes)
    if has_socket_connection and fd_redirection and shell_launch:
        add("python-remote-shell", "Socket connection redirected to an operating-system shell", fd_redirection[0],
            "The script combines a network connection, file-descriptor redirection, and a shell launch. This is a reverse-shell capability; execution and authorization were not established.")
    return findings
