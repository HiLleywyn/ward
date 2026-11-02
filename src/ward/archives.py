"""Inspect bounded archive streams without extracting paths or executing members."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import PurePosixPath


MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 500
MAX_DEPTH = 3
ARCHIVE_SUFFIXES = {".zip", ".jar", ".whl", ".apk", ".xpi", ".vsix", ".nupkg", ".docx", ".xlsx", ".pptx",
                    ".tar", ".tgz", ".gz", ".bz2", ".xz", ".tbz2", ".txz", ".7z", ".rar"}


def archive_kind(data: bytes, path: str) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    for magic, kind in ((b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
                        (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar")):
        if data.startswith(magic):
            return kind
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    suffix = PurePosixPath(path.split("!")[-1]).suffix.lower()
    if suffix in ARCHIVE_SUFFIXES:
        return {".tgz": "gzip", ".gz": "gzip", ".bz2": "bzip2", ".tbz2": "bzip2", ".xz": "xz", ".txz": "xz",
                ".tar": "tar", ".7z": "7z", ".rar": "rar"}.get(suffix, "zip")
    return None


def inspect_archive(data: bytes, path: str, inspect_member) -> tuple[list[dict], int, int]:
    findings, text_count, archive_count = [], 0, 0
    remaining, members = MAX_EXPANDED_BYTES, 0

    def issue(kind, title, member_path, detail):
        findings.append({"kind": kind, "severity": "info", "title": title, "path": member_path, "detail": detail})

    def accept(content, member_path, depth):
        nonlocal remaining, members, text_count
        remaining -= len(content)
        members += 1
        detected, is_text = inspect_member(content, member_path)
        findings.extend(detected)
        text_count += int(is_text)
        if archive_kind(content, member_path):
            walk(content, member_path, depth + 1)

    def safe_name(name):
        parts = PurePosixPath(name.replace("\\", "/"))
        return not parts.is_absolute() and ".." not in parts.parts and not (parts.parts and ":" in parts.parts[0])

    def read_member(handle, declared_size, member_path, depth):
        if declared_size > remaining or members >= MAX_MEMBERS:
            issue("archive-inspection-limit", "Archive inspection limit reached", member_path,
                  "The member exceeded the shared expanded-byte or entry budget; coverage is incomplete.")
            return
        content = handle.read(remaining + 1)
        if len(content) > remaining:
            issue("archive-inspection-limit", "Archive expansion limit reached", member_path,
                  "Expanded content exceeded the shared byte budget; coverage is incomplete.")
            return
        accept(content, member_path, depth)

    def walk(content, member_path, depth):
        nonlocal archive_count
        archive_count += 1
        kind = archive_kind(content, member_path)
        if depth > MAX_DEPTH:
            issue("archive-inspection-limit", "Archive nesting limit reached", member_path,
                  "Nested archives exceeded the depth limit; coverage is incomplete.")
            return
        if kind in {"rar", "7z"}:
            issue("archive-unsupported", "Archive requires an additional unpacker", member_path,
                  f"The bounded in-process scanner cannot unpack {kind}. An isolated antivirus engine may inspect it; this scan does not claim member coverage.")
            return
        try:
            if kind == "zip":
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    entries = archive.infolist()
                    if len(entries) > MAX_MEMBERS:
                        issue("archive-inspection-limit", "Archive entry limit reached", member_path, "Not all entries could be inspected.")
                    for entry in entries[:MAX_MEMBERS]:
                        if entry.is_dir():
                            continue
                        location = member_path + "!" + entry.filename
                        if not safe_name(entry.filename) or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                            issue("archive-unsafe-entry", "Unsafe archive entry", location, "A traversal path or symbolic link was indexed without extraction.")
                            continue
                        if entry.flag_bits & 1:
                            issue("archive-encrypted", "Encrypted archive member", location, "The member could not be inspected without a password.")
                            continue
                        if entry.file_size / max(1, entry.compress_size) > 150:
                            issue("archive-expansion", "Archive expands unusually far", location, "The member's compression ratio exceeds the analysis limit.")
                            continue
                        with archive.open(entry) as handle:
                            read_member(handle, entry.file_size, location, depth)
            elif kind == "tar":
                with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
                    for index, entry in enumerate(archive):
                        if index >= MAX_MEMBERS or members >= MAX_MEMBERS:
                            issue("archive-inspection-limit", "Archive entry limit reached", member_path, "Not all entries could be inspected.")
                            break
                        if entry.isdir():
                            continue
                        location = member_path + "!" + entry.name
                        if not entry.isfile() or not safe_name(entry.name):
                            issue("archive-unsafe-entry", "Unsafe archive entry", location, "A link, special file, or traversal path was indexed without extraction.")
                            continue
                        with archive.extractfile(entry) as handle:
                            read_member(handle, entry.size, location, depth)
            elif kind == "xz":
                decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
                expanded = decoder.decompress(content, max_length=remaining + 1)
                if len(expanded) > remaining or not decoder.eof:
                    issue("archive-inspection-limit", "Archive expansion limit reached", member_path, "The XZ stream exceeded its memory or output budget, or was truncated.")
                else:
                    accept(expanded, member_path + "!decompressed", depth)
                    if decoder.unused_data:
                        issue("archive-inspection-limit", "Additional compressed stream was not inspected", member_path, "Concatenated XZ stream coverage is incomplete.")
            elif kind in {"gzip", "bzip2"}:
                opener = {"gzip": gzip.open, "bzip2": bz2.BZ2File}[kind]
                with opener(io.BytesIO(content), "rb") as handle:
                    read_member(handle, 0, member_path + "!decompressed", depth)
        except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, lzma.LZMAError):
            issue("archive-unreadable", "Archive could not be inspected", member_path,
                  "Malformed, encrypted, or unsupported content prevented complete archive inspection.")

    walk(data, path, 0)
    return findings, text_count, archive_count
