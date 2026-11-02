from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

from .analyze import load_indicators, parse_repository_target
from .archives import archive_kind, inspect_archive
from .data import advisory_directory
from .evidence import repository_warning
from .source_rules import python_findings
from .script_rules import lua_findings


MAX_FILES = 5_000
MAX_REPOSITORY_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_HASH_BYTES = 128 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
CLONE_TIMEOUT_SECONDS = 60
REF_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
COMMIT_PATTERN = re.compile(r"^[A-Fa-f0-9]{40,64}$")

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYINSTALLER_COOKIE_FORMATS = ((88, "!8sIIII64s"), (24, "!8sIIII"))
MAX_PYINSTALLER_TOC_BYTES = 1024 * 1024
MAX_PYINSTALLER_ENTRIES = 2_000
MAX_PYINSTALLER_MEMBER_BYTES = 4 * 1024 * 1024

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
        "powershell-download-scriptblock-execute",
        "high",
        "Downloaded PowerShell executed through ScriptBlock",
        re.compile(
            r"\.DownloadString\s*\([^)]*\)[\s\S]{0,320}"
            r"(?:\.\s*)?\(\s*\[scriptblock\]\s*::\s*Create\s*\(",
            re.I,
        ),
        "Downloads PowerShell text and immediately invokes a ScriptBlock built from the response.",
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
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\0" in data:
        return None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    if any(ord(char) < 32 and char not in "\t\n\r\f" for char in text[:4096]):
        return None
    return text


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


def _content_findings(data: bytes, path: str, known_hashes: dict | None = None) -> tuple[list[dict], bool]:
    findings = []
    digest = hashlib.sha256(data).hexdigest()
    if known_hashes and digest in known_hashes:
        findings.append({"kind": "known-malware-hash", "severity": "critical", "title": "Exact known-malware hash",
                         "path": path, "sha256": digest, "source_url": known_hashes[digest]["source_url"],
                         "detail": "Archive member SHA-256 exactly matches a confirmed malicious-file indicator."})
    if len(data) > MAX_TEXT_BYTES:
        return findings, False
    text = _decode_text(data)
    if text is None:
        return findings, False
    findings.extend(_pattern_findings(text, path))
    findings.extend(python_findings(text, path))
    findings.extend(lua_findings(text, path))
    return findings, True


def _pyinstaller_entries(data: bytes) -> list[dict] | None:
    cookie_position = data.rfind(PYINSTALLER_MAGIC)
    if cookie_position < 0:
        return None
    for cookie_size, cookie_format in PYINSTALLER_COOKIE_FORMATS:
        if cookie_position + cookie_size > len(data):
            continue
        try:
            cookie = struct.unpack(cookie_format, data[cookie_position:cookie_position + cookie_size])
        except struct.error:
            continue
        package_length, toc_offset, toc_length = cookie[1:4]
        package_start = cookie_position + cookie_size - package_length
        toc_start = package_start + toc_offset
        toc_end = toc_start + toc_length
        if (
            package_start < 0
            or toc_length <= 0
            or toc_length > MAX_PYINSTALLER_TOC_BYTES
            or toc_start < package_start
            or toc_end > cookie_position
        ):
            continue
        entries: list[dict] = []
        cursor = toc_start
        valid = True
        while cursor < toc_end and len(entries) < MAX_PYINSTALLER_ENTRIES:
            if cursor + 18 > toc_end:
                valid = False
                break
            try:
                entry_length, offset, compressed_length, uncompressed_length, compressed, typecode = struct.unpack(
                    "!IIIIBc", data[cursor:cursor + 18]
                )
            except struct.error:
                valid = False
                break
            if entry_length < 19 or cursor + entry_length > toc_end:
                valid = False
                break
            name_bytes = data[cursor + 18:cursor + entry_length].split(b"\0", 1)[0]
            try:
                name = name_bytes.decode("utf-8")
            except UnicodeDecodeError:
                name = name_bytes.decode("utf-8", errors="replace")
            member_start = package_start + offset
            member_end = member_start + compressed_length
            if (
                member_start < package_start
                or member_end > toc_start
                or uncompressed_length > MAX_PYINSTALLER_MEMBER_BYTES
            ):
                valid = False
                break
            entries.append({
                "name": name,
                "typecode": typecode.decode("latin-1"),
                "compressed": bool(compressed),
                "compressed_length": compressed_length,
                "uncompressed_length": uncompressed_length,
                "start": member_start,
                "end": member_end,
            })
            cursor += entry_length
        if valid and cursor == toc_end and entries:
            return entries
    raise ValueError("PyInstaller archive metadata is malformed or outside inspection limits")


def _bounded_zlib_decompress(data: bytes, maximum: int) -> bytes:
    decompressor = zlib.decompressobj()
    output = decompressor.decompress(data, maximum + 1)
    if len(output) > maximum or decompressor.unconsumed_tail:
        raise ValueError("decompressed PyInstaller member exceeds inspection limit")
    output += decompressor.flush(maximum + 1 - len(output))
    if len(output) > maximum:
        raise ValueError("decompressed PyInstaller member exceeds inspection limit")
    return output


def _printable_strings(data: bytes) -> str:
    strings = [match.group().decode("latin-1") for match in re.finditer(rb"[ -~]{6,}", data)]
    return "\n".join(strings)


def _pyinstaller_findings(path: Path, display_path: str) -> tuple[list[dict], bool, bool]:
    try:
        data = path.read_bytes()
    except OSError:
        return [], True, False
    try:
        entries = _pyinstaller_entries(data)
    except ValueError:
        return [{
            "kind": "pyinstaller-unreadable",
            "severity": "info",
            "title": "PyInstaller bundle could not be inspected",
            "path": display_path,
            "detail": "Ward found a PyInstaller archive marker, but its bounded archive parser could not safely inventory the bundle.",
        }], True, True
    if entries is None:
        return [], False, False

    findings: list[dict] = []
    names = {entry["name"].lower() for entry in entries if entry["name"]}
    encrypted = sorted(name for name in names if Path(name).suffix in {".aes", ".enc", ".encrypted"})
    archivers = sorted(name for name in names if Path(name).name in {"7z.exe", "rar.exe", "winrar.exe"})
    key_material = sorted(name for name in names if Path(name).name in {"rarreg.key", "key.bin", "password.txt"})
    if encrypted and archivers:
        details = ["encrypted payload " + ", ".join(encrypted), "embedded archiver " + ", ".join(archivers)]
        if key_material:
            details.append("key material " + ", ".join(key_material))
        findings.append({
            "kind": "pyinstaller-encrypted-payload",
            "severity": "high",
            "title": "Packed executable bundles encrypted payload tooling",
            "path": display_path,
            "detail": "The PyInstaller bundle contains " + "; ".join(details) + ". This combination conceals bundled content and requires review; it is not alone proof of malware.",
        })

    budget = 2 * 1024 * 1024
    for entry in entries:
        if budget <= 0 or entry["compressed_length"] > 512 * 1024 or entry["uncompressed_length"] > 512 * 1024:
            continue
        if entry["typecode"] not in {"m", "M", "s", "x"}:
            continue
        member = data[entry["start"]:entry["end"]]
        try:
            if entry["compressed"]:
                member = _bounded_zlib_decompress(member, min(entry["uncompressed_length"], 512 * 1024))
        except (ValueError, zlib.error):
            continue
        budget -= len(member)
        text = _printable_strings(member)
        if text:
            name = entry["name"] or "entrypoint"
            findings.extend(_pattern_findings(text, f"{display_path}!{name}"))
    return findings, False, True


def inspect_tree(root: Path, *, indicators: dict | None = None, artifact_sink=None) -> dict:
    indicators = indicators or load_indicators(advisory_directory() / "indicators.json")
    known_hashes = {
        item["sha256"].lower(): item
        for item in indicators.get("indicators", [])
        if item.get("status") == "confirmed"
    }
    findings: list[dict] = []
    artifacts: list[dict] = []
    file_count = total_bytes = hashed_bytes = text_files = archives = executable_files = 0
    truncated = False
    coverage_incomplete = False
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts:
            continue
        if path.is_symlink():
            coverage_incomplete = True
            findings.append({"kind": "symlink-skipped", "severity": "info", "title": "Symbolic link was not followed",
                "path": path.relative_to(root).as_posix(), "detail": "Ward did not follow this link outside the scanned file inventory; target coverage is incomplete."})
            continue
        if not path.is_file():
            continue
        file_count += 1
        if file_count > MAX_FILES:
            truncated = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            coverage_incomplete = True
            continue
        total_bytes += size
        if total_bytes > MAX_REPOSITORY_BYTES:
            truncated = True
            break
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        prefix = b""
        read_error = False
        if size <= MAX_FILE_BYTES and hashed_bytes + size <= MAX_HASH_BYTES:
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    prefix = handle.read(4096)
                    digest.update(prefix)
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha256 = digest.hexdigest()
                hashed_bytes += size
                binary_kind = "pe" if prefix.startswith(b"MZ") else "elf" if prefix.startswith(b"\x7fELF") else "macho" if prefix[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"} else None
                if binary_kind:
                    executable_files += 1
                    artifacts.append({"path": relative, "sha256": sha256, "size": size, "format": binary_kind})
                    if artifact_sink is not None:
                        artifact_sink(relative, sha256, path)
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
                read_error = True
                coverage_incomplete = True
                findings.append({
                    "kind": "file-unreadable",
                    "severity": "info",
                    "title": "File could not be read",
                    "path": relative,
                    "detail": "Ward recorded the file but could not hash or inspect its bytes, so coverage is incomplete.",
                })
        else:
            coverage_incomplete = True
            findings.append({
                "kind": "file-unhashed",
                "severity": "info",
                "title": "File was outside hashing limits",
                "path": relative,
                "detail": "Ward recorded the file but did not hash its bytes because a per-file or scan-wide hashing limit was reached.",
            })
        if archive_kind(prefix, relative) and size <= MAX_FILE_BYTES and not read_error:
            try:
                archive_findings, archive_text, archive_count = inspect_archive(
                    path.read_bytes(), relative, lambda data, location: _content_findings(data, location, known_hashes))
                findings.extend(archive_findings)
                text_files += archive_text
                archives += archive_count
            except OSError:
                coverage_incomplete = True
        if prefix.startswith(b"MZ") and size <= MAX_FILE_BYTES and not read_error:
            packed_findings, packed_incomplete, packed_archive = _pyinstaller_findings(path, relative)
            findings.extend(packed_findings)
            if packed_archive:
                archives += 1
            if packed_incomplete:
                coverage_incomplete = True
        if size <= MAX_TEXT_BYTES and not read_error:
            try:
                text = _decode_text(path.read_bytes())
            except OSError:
                text = None
            if text is not None:
                text_files += 1
                if text.startswith("version https://git-lfs.github.com/spec/v1") or path.name == ".gitmodules":
                    coverage_incomplete = True
                    findings.append({"kind": "external-content-not-fetched", "severity": "info",
                        "title": "Referenced repository content was not fetched", "path": relative,
                        "detail": "This LFS pointer or submodule definition references content outside the cloned file inventory. That content was not inspected."})
                findings.extend(_pattern_findings(text, relative))
                source_findings = python_findings(text, relative) + lua_findings(text, relative)
                findings.extend(source_findings)
                if any(item['kind'] in {'python-source-limit', 'python-source-unparsed', 'lua-source-limit'} for item in source_findings):
                    coverage_incomplete = True
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
        elif size > MAX_TEXT_BYTES and _decode_text(prefix) is not None and prefix:
            coverage_incomplete = True
            findings.append({"kind": "text-inspection-limit", "severity": "info", "title": "Text file exceeded the source inspection limit",
                "path": relative, "detail": "The file was hashed when possible, but its full source was outside the bounded text-analysis budget."})
    rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(key=lambda item: (rank.get(item["severity"], 9), item.get("path", ""), item["title"]))
    archive_incomplete = any(
        item.get("kind") in {"archive-expansion", "archive-unreadable", "archive-encrypted", "archive-unsupported",
                             "archive-unsafe-entry", "archive-inspection-limit"}
        for item in findings
    )
    source_incomplete = any(item.get("kind") in {"python-source-limit", "python-source-unparsed", "lua-source-limit"} for item in findings)
    return {
        "files": min(file_count, MAX_FILES),
        "bytes": total_bytes,
        "hashed_bytes": hashed_bytes,
        "text_files": text_files,
        "archives": archives,
        "executable_files": executable_files,
        "truncated": truncated,
        "partial": truncated or archive_incomplete or source_incomplete or coverage_incomplete or len(findings) > 100,
        "archive_incomplete": archive_incomplete,
        "findings": findings[:100],
        "artifacts": artifacts,
    }


def scan_repository(value: str, ref: str | None = None, expected_commit: str | None = None, *, artifact_sink=None) -> dict:
    from . import __version__
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
        inspected = inspect_tree(checkout, artifact_sink=artifact_sink)
        if artifact_sink is not None:
            snapshot = temporary_path / "repository-snapshot.zip"
            selected = omitted = snapshot_bytes = 0
            with zipfile.ZipFile(snapshot, "w", compression=zipfile.ZIP_STORED) as archive:
                for source in sorted(checkout.rglob("*")):
                    if ".git" in source.relative_to(checkout).parts or source.is_symlink() or not source.is_file():
                        continue
                    relative_path = source.relative_to(checkout).as_posix()
                    entry_bytes = source.stat().st_size + 2 * len(relative_path.encode("utf-8")) + 256
                    if selected >= MAX_FILES or snapshot_bytes + entry_bytes > 31 * 1024 * 1024:
                        omitted += 1
                        continue
                    info = zipfile.ZipInfo(relative_path)
                    archive.writestr(info, source.read_bytes())
                    snapshot_bytes += entry_bytes
                    selected += 1
            snapshot_data = snapshot.read_bytes()
            snapshot_digest = hashlib.sha256(snapshot_data).hexdigest()
            inspected["artifacts"].append({"path": "@repository-snapshot.zip", "sha256": snapshot_digest,
                "size": len(snapshot_data), "format": "repository-snapshot", "members": selected, "omitted": omitted})
            artifact_sink("@repository-snapshot.zip", snapshot_digest, snapshot)
            if omitted:
                inspected["partial"] = True
                inspected["findings"].append({"kind": "repository-antivirus-limit", "severity": "info",
                    "title": "Repository antivirus snapshot is incomplete", "path": "@repository-snapshot.zip",
                    "detail": f"{omitted} files were outside the bounded antivirus snapshot; static file inspection remains separate."})
    warning = repository_warning(_github_target(url)) if _github_target(url) else None
    exact_matches = sum(1 for item in inspected["findings"] if item["kind"] == "known-malware-hash")
    if exact_matches:
        status = "Malicious"
    elif warning is not None:
        status = "Corroborated"
    elif any(item.get("evidence_type") == "source-behavior" for item in inspected["findings"]):
        status = "Suspicious"
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
        "scanner_version": __version__,
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
        "artifacts": inspected["artifacts"],
        "sources": sources,
        "verification": {
            "level": "partial" if inspected["partial"] else "inspected",
            "checks": [
                {"name": "revision-pinned", "status": "completed"},
                {"name": "file-inventory", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "sha256-inventory", "status": "partial" if inspected["truncated"] else "completed"},
                {"name": "known-indicators", "status": "completed"},
                {"name": "static-rules", "status": "partial" if inspected["partial"] else "completed"},
                {"name": "bounded-archive-inspection", "status": "partial" if inspected.get("archive_incomplete", inspected["partial"]) else "completed"},
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
