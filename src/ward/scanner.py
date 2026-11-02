from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

from .analyze import load_indicators, parse_repository_target
from .data import advisory_directory
from .evidence import repository_warning


MAX_FILES = 5_000
MAX_REPOSITORY_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_HASH_BYTES = 128 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
CLONE_TIMEOUT_SECONDS = 60
REF_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
COMMIT_PATTERN = re.compile(r"^[A-Fa-f0-9]{40,64}$")

TEXT_SUFFIXES = {
    ".bat", ".cmd", ".conf", ".cs", ".go", ".html", ".ini", ".java", ".js",
    ".json", ".jsx", ".md", ".php", ".ps1", ".py", ".rb", ".rs", ".sh",
    ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml",
}
EXECUTABLE_SUFFIXES = {".apk", ".app", ".bat", ".cmd", ".com", ".dll", ".dylib", ".exe", ".jar", ".msi", ".ps1", ".scr", ".sh", ".so"}
ARCHIVE_SUFFIXES = {".zip", ".jar"}

PATTERNS = (
    (
        "defender-exclusion",
        "high",
        "Microsoft Defender exclusion",
        re.compile(r"\bAdd-MpPreference\b.{0,160}\bExclusion(?:Path|Process|Extension)\b", re.I),
        "Adds a Microsoft Defender exclusion. This is not proof of malware, but it materially weakens protection.",
    ),
    (
        "disable-defender",
        "high",
        "Security protection disabled",
        re.compile(r"\bSet-MpPreference\b.{0,160}\bDisableRealtimeMonitoring\b.{0,40}\b(?:true|1)\b", re.I),
        "Attempts to disable Microsoft Defender real-time monitoring.",
    ),
    (
        "encoded-powershell",
        "high",
        "Encoded PowerShell execution",
        re.compile(r"\bpowershell(?:\.exe)?\b.{0,120}\s-(?:enc|encodedcommand)\b", re.I),
        "Runs an encoded PowerShell command, which can conceal the actual instructions.",
    ),
    (
        "download-and-execute",
        "high",
        "Downloaded content executed immediately",
        re.compile(r"(?:\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sh|bash)\b|\bIEX\s*\(|\bInvoke-Expression\b)", re.I),
        "Downloads or decodes content and immediately executes it.",
    ),
    (
        "persistence-task",
        "medium",
        "Scheduled-task persistence",
        re.compile(r"\bschtasks(?:\.exe)?\b.{0,160}\/(?:create|change)\b", re.I),
        "Creates or changes a Windows scheduled task.",
    ),
    (
        "persistence-run-key",
        "medium",
        "Startup registry persistence",
        re.compile(r"\breg(?:\.exe)?\s+add\b.{0,220}\\(?:Run|RunOnce)\b", re.I),
        "Writes a Windows startup registry key.",
    ),
)


class ScanError(ValueError):
    pass


def normalize_git_ref(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScanError("Repository ref must be a string")
    if not value.strip():
        return None
    ref = value.strip()
    if (
        not REF_PATTERN.fullmatch(ref)
        or ref.startswith(("-", ".", "/"))
        or ref.endswith(("/", ".", ".lock"))
        or ".." in ref
        or "//" in ref
        or "@{" in ref
    ):
        raise ScanError("Repository ref is not a valid branch or tag name")
    return ref


def _git_environment(home: Path) -> dict[str, str]:
    runtime_keys = (
        "PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
        "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL",
    )
    environment = {key: os.environ[key] for key in runtime_keys if key in os.environ}
    environment.update({
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    return environment


def _global_addresses(hostname: str) -> list[str]:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ScanError("Repository host could not be resolved") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ScanError("Repository host resolves to a local or private network")
    return sorted(addresses, key=lambda address: (ipaddress.ip_address(address).version, address))


def normalize_repository_url(value: str, *, resolve: bool = True) -> str:
    value = value.strip()
    if not value:
        raise ScanError("Enter a repository URL")
    if not value.startswith("https://"):
        try:
            owner, repository = parse_repository_target(value)
        except ValueError as exc:
            raise ScanError("Use a public HTTPS Git repository URL") from exc
        value = f"https://github.com/{owner}/{repository}.git"
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ScanError("Only public HTTPS Git repositories are supported")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ScanError("Repository URLs cannot include credentials or custom ports")
    if parsed.query or parsed.fragment:
        raise ScanError("Remove query strings and fragments from the repository URL")
    if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ScanError("Local and private network repositories are not supported")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ScanError("Local and private network repositories are not supported")
    if resolve:
        _global_addresses(parsed.hostname)
    path = re.sub(r"/+", "/", parsed.path).rstrip("/")
    if not path or path == "/":
        raise ScanError("Repository URL must include a repository path")
    if parsed.hostname.lower() == "git.lley.cat" and not path.endswith(".git"):
        path += ".git"
    return urlunparse(("https", parsed.hostname.lower(), path, "", "", ""))


def _repository_label(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.removesuffix(".git").strip("/")
    return path if parsed.hostname == "github.com" else f"{parsed.hostname}/{path}"


def _github_target(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.hostname != "github.com":
        return None
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    return "/".join(parts[:2]) if len(parts) >= 2 else None


def _decode_text(data: bytes) -> str | None:
    if b"\0" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None


def _pattern_findings(text: str, path: str) -> list[dict]:
    findings = []
    for key, severity, title, pattern, detail in PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append({
            "kind": key,
            "severity": severity,
            "title": title,
            "path": path,
            "line": line,
            "detail": detail,
        })
    return findings


def _archive_findings(path: Path, display_path: str) -> tuple[list[dict], int]:
    findings: list[dict] = []
    inspected = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()[:500]
            total_uncompressed = sum(member.file_size for member in members)
            total_compressed = sum(max(member.compress_size, 1) for member in members)
            if total_uncompressed > 256 * 1024 * 1024 or total_uncompressed / max(total_compressed, 1) > 150:
                findings.append({
                    "kind": "archive-expansion",
                    "severity": "medium",
                    "title": "Archive expands unusually far",
                    "path": display_path,
                    "detail": "The archive was indexed but not expanded because its declared size or compression ratio is unusually high.",
                })
                return findings, 0
            budget = 4 * 1024 * 1024
            for member in members:
                if member.is_dir() or member.file_size > 512 * 1024 or budget <= 0:
                    continue
                suffix = Path(member.filename).suffix.lower()
                if suffix not in TEXT_SUFFIXES:
                    continue
                data = archive.read(member)
                budget -= len(data)
                text = _decode_text(data)
                if text is not None:
                    findings.extend(_pattern_findings(text, f"{display_path}!{member.filename}"))
                    inspected += 1
    except (OSError, zipfile.BadZipFile, RuntimeError):
        findings.append({
            "kind": "archive-unreadable",
            "severity": "info",
            "title": "Archive could not be inspected",
            "path": display_path,
            "detail": "Ward recorded the archive but could not safely inspect its entries.",
        })
    return findings, inspected


def inspect_tree(root: Path, *, indicators: dict | None = None) -> dict:
    indicators = indicators or load_indicators(advisory_directory() / "indicators.json")
    known_hashes = {
        item["sha256"].lower(): item
        for item in indicators.get("indicators", [])
        if item.get("status") == "confirmed"
    }
    findings: list[dict] = []
    file_count = total_bytes = hashed_bytes = text_files = archives = executable_files = 0
    truncated = False
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts or path.is_symlink() or not path.is_file():
            continue
        file_count += 1
        if file_count > MAX_FILES:
            truncated = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_bytes += size
        if total_bytes > MAX_REPOSITORY_BYTES:
            truncated = True
            break
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix in EXECUTABLE_SUFFIXES:
            executable_files += 1
        if size <= MAX_FILE_BYTES and hashed_bytes + size <= MAX_HASH_BYTES:
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha256 = digest.hexdigest()
                hashed_bytes += size
                if sha256 in known_hashes:
                    match = known_hashes[sha256]
                    findings.append({
                        "kind": "known-malware-hash",
                        "severity": "critical",
                        "title": "Exact known-malware hash",
                        "path": relative,
                        "sha256": sha256,
                        "detail": "SHA-256 exactly matches a confirmed malicious-file indicator.",
                        "source_url": match["source_url"],
                    })
            except OSError:
                pass
        if suffix in ARCHIVE_SUFFIXES:
            archive_findings, archive_text = _archive_findings(path, relative)
            findings.extend(archive_findings)
            text_files += archive_text
            archives += 1
        if size <= MAX_TEXT_BYTES and suffix in TEXT_SUFFIXES:
            try:
                text = _decode_text(path.read_bytes())
            except OSError:
                text = None
            if text is not None:
                text_files += 1
                findings.extend(_pattern_findings(text, relative))
                if path.name == "package.json":
                    try:
                        scripts = json.loads(text).get("scripts", {})
                    except (json.JSONDecodeError, AttributeError):
                        scripts = {}
                    hooks = {name: scripts[name] for name in ("preinstall", "install", "postinstall", "prepare") if name in scripts}
                    if hooks:
                        findings.append({
                            "kind": "package-install-hooks",
                            "severity": "info",
                            "title": "Package install hooks",
                            "path": relative,
                            "detail": "Runs during package installation: " + ", ".join(sorted(hooks)),
                        })
    rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(key=lambda item: (rank.get(item["severity"], 9), item.get("path", ""), item["title"]))
    return {
        "files": min(file_count, MAX_FILES),
        "bytes": total_bytes,
        "hashed_bytes": hashed_bytes,
        "text_files": text_files,
        "archives": archives,
        "executable_files": executable_files,
        "truncated": truncated,
        "findings": findings[:100],
    }


def scan_repository(value: str, ref: str | None = None, expected_commit: str | None = None) -> dict:
    started = time.monotonic()
    ref = normalize_git_ref(ref)
    if expected_commit is not None and not COMMIT_PATTERN.fullmatch(expected_commit):
        raise ScanError("Expected commit must be a 40 to 64 character hexadecimal object ID")
    url = normalize_repository_url(value, resolve=False)
    hostname = urlparse(url).hostname
    address = _global_addresses(hostname)[0]
    pinned_address = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    label = _repository_label(url)
    with tempfile.TemporaryDirectory(prefix="ward-scan-") as temporary:
        temporary_path = Path(temporary)
        checkout = temporary_path / "repository"
        environment = _git_environment(temporary_path)
        command = [
            "git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
            "-c", "http.followRedirects=false",
            "-c", f"http.curloptResolve=+{hostname}:443:{pinned_address}",
            "clone", "--depth", "1", "--no-tags", "--single-branch",
        ]
        if ref:
            command.extend(["--branch", ref])
        command.extend(["--filter=blob:limit=4194304", url, str(checkout)])
        try:
            completed = subprocess.run(
                command,
                cwd=temporary_path,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=CLONE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("Repository clone exceeded the 60 second limit") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "clone failed"
            raise ScanError(f"Repository could not be cloned: {message[:240]}")
        try:
            commit = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=True,
            ).stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            raise ScanError("Repository commit could not be recorded") from exc
        if expected_commit and commit.lower() != expected_commit.lower():
            raise ScanError("Repository ref changed before Ward could inspect the expected commit; run the check again")
        try:
            branch = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "--abbrev-ref", "HEAD"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=True,
            ).stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            raise ScanError("Repository branch could not be recorded") from exc
        inspected = inspect_tree(checkout)
    warning = repository_warning(_github_target(url)) if _github_target(url) else None
    exact_matches = sum(1 for item in inspected["findings"] if item["kind"] == "known-malware-hash")
    if exact_matches:
        status = "Malicious"
    elif warning is not None:
        status = "Corroborated"
    else:
        status = "Unverified"
    sources = [
        item["source_url"]
        for item in inspected["findings"]
        if item.get("source_url")
    ]
    if warning is not None:
        for limitation in warning.limitations:
            if limitation.startswith("Evidence: "):
                sources.append(limitation.removeprefix("Evidence: "))
    sources = list(dict.fromkeys(sources))
    return {
        "id": str(uuid4()),
        "repository": label,
        "repository_url": url,
        "commit": commit,
        "expected_commit": expected_commit,
        "branch": branch,
        "status": status,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "summary": {key: inspected[key] for key in ("files", "bytes", "hashed_bytes", "text_files", "archives", "executable_files", "truncated")},
        "findings": inspected["findings"],
        "sources": sources,
        "verification": {
            "level": "partial" if inspected["truncated"] else "inspected",
            "checks": [
                {"name": "revision-pinned", "status": "completed"},
                {"name": "file-inventory", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "sha256-inventory", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "known-indicators", "status": "completed"},
                {"name": "static-rules", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "bounded-archive-inspection", "status": "completed"},
                {"name": "isolated-build", "status": "not-run"},
                {"name": "behavioral-analysis", "status": "not-run"},
            ],
        },
        "limitations": [
            "Ward cloned and inspected repository files but did not execute code, installers, build scripts, or package hooks.",
            "No known indicator match does not prove that a repository is safe.",
            "Encrypted, oversized, unsupported, or dynamically downloaded content may not be visible to this scan.",
        ],
    }
