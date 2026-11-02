"""Inspect bounded archive streams without extracting paths or executing members."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import time
import zipfile
from pathlib import PurePosixPath


MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 500
MAX_DEPTH = 3
MAX_REPOSITORY_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_REPOSITORY_ARCHIVE_MEMBERS = 2_000
MAX_REPOSITORY_ARCHIVE_SECONDS = 15
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


class ArchiveBudget:
    """Shared by all root and nested archives in one repository inspection."""
    def __init__(self):
        self.bytes_left = MAX_REPOSITORY_EXPANDED_BYTES
        self.members_left = MAX_REPOSITORY_ARCHIVE_MEMBERS
        self.seconds_left = MAX_REPOSITORY_ARCHIVE_SECONDS


def inspect_archive(data: bytes, path: str, inspect_member, *, budget: ArchiveBudget | None = None) -> tuple[list[dict], int, int]:
    findings, text_count, archive_count = [], 0, 0
    remaining, members = MAX_EXPANDED_BYTES, 0
    budget = budget if budget is not None else ArchiveBudget()
    started = time.monotonic()
    deadline = started + budget.seconds_left

    def issue(kind, title, member_path, detail):
        findings.append({"kind": kind, "severity": "info", "title": title, "path": member_path, "detail": detail})

    def accept(content, member_path, depth, *, charged=False):
        nonlocal remaining, text_count
        if not charged:
            remaining -= len(content)
            budget.bytes_left -= len(content)
        detected, is_text = inspect_member(content, member_path)
        findings.extend(detected)
        text_count += int(is_text)
        if not time_available(member_path):
            return
        if archive_kind(content, member_path):
            walk(content, member_path, depth + 1)

    def time_available(member_path):
        if time.monotonic() >= deadline:
            issue("archive-inspection-limit", "Repository archive time limit reached", member_path,
                  "The repository's shared archive time budget was exhausted; remaining members were not inspected.")
            return False
        return True

    def take_entry(member_path):
        nonlocal members
        if not time_available(member_path):
            return False
        if budget.members_left <= 0 or budget.bytes_left <= 0:
            issue("archive-inspection-limit", "Repository archive limit reached", member_path,
                  "The repository's shared expanded-byte or entry budget was exhausted; remaining members were not inspected.")
            return False
        if members >= MAX_MEMBERS:
            issue("archive-inspection-limit", "Archive entry limit reached", member_path, "Not all entries could be inspected.")
            return False
        members += 1
        budget.members_left -= 1
        return True

    def safe_name(name):
        parts = PurePosixPath(name.replace("\\", "/"))
        return not parts.is_absolute() and ".." not in parts.parts and not (parts.parts and ":" in parts.parts[0])

    def read_member(handle, declared_size, member_path, depth):
        nonlocal remaining
        allowance = min(remaining, budget.bytes_left)
        if declared_size > allowance:
            issue("archive-inspection-limit", "Archive inspection limit reached", member_path,
                  "The member exceeded the per-archive or repository expanded-byte budget; coverage is incomplete.")
            return
        chunks, size = [], 0
        while size <= allowance:
            if not time_available(member_path):
                return
            chunk = handle.read(min(64 * 1024, allowance + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            remaining -= len(chunk)
            budget.bytes_left = max(0, budget.bytes_left - len(chunk))
        content = b"".join(chunks)
        if len(content) > allowance:
            issue("archive-inspection-limit", "Archive expansion limit reached", member_path,
                  "Expanded content exceeded the per-archive or repository byte budget; coverage is incomplete.")
            return
        accept(content, member_path, depth, charged=True)

    def walk(content, member_path, depth):
        nonlocal archive_count
        archive_count += 1
        if not time_available(member_path):
            return
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
                        if not take_entry(member_path):
                            break
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
                        if not take_entry(member_path):
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
                if not take_entry(member_path):
                    return
                decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
                allowance = min(remaining, budget.bytes_left)
                expanded = decoder.decompress(content, max_length=allowance + 1)
                if len(expanded) > allowance or not decoder.eof:
                    budget.bytes_left = max(0, budget.bytes_left - len(expanded))
                    issue("archive-inspection-limit", "Archive expansion limit reached", member_path, "The XZ stream exceeded its memory, per-archive or repository output budget, or was truncated.")
                else:
                    accept(expanded, member_path + "!decompressed", depth)
                    if decoder.unused_data:
                        issue("archive-inspection-limit", "Additional compressed stream was not inspected", member_path, "Concatenated XZ stream coverage is incomplete.")
            elif kind in {"gzip", "bzip2"}:
                if not take_entry(member_path):
                    return
                opener = {"gzip": gzip.open, "bzip2": bz2.BZ2File}[kind]
                with opener(io.BytesIO(content), "rb") as handle:
                    read_member(handle, 0, member_path + "!decompressed", depth)
        except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, lzma.LZMAError):
            issue("archive-unreadable", "Archive could not be inspected", member_path,
                  "Malformed, encrypted, or unsupported content prevented complete archive inspection.")

    try:
        walk(data, path, 0)
    finally:
        budget.seconds_left = max(0, budget.seconds_left - (time.monotonic() - started))
    return findings, text_count, archive_count
