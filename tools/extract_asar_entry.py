"""Extract one bounded embedded file from an Electron ASAR archive.

The extractor parses the archive header as data. It does not load Electron,
JavaScript, or any recovered application code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path, PurePosixPath


MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024


def extract_entry(data: bytes, entry_name: str) -> dict:
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive size is outside the supported range")
    if len(data) < 16:
        raise ValueError("ASAR header is truncated")
    payload_size, header_pickle_size, json_pickle_size, json_size = struct.unpack_from("<IIII", data)
    if payload_size != 4 or json_pickle_size < 4 or header_pickle_size < json_pickle_size:
        raise ValueError("ASAR pickle header is invalid")
    header_end = 16 + json_size
    data_offset = 8 + header_pickle_size
    if header_end > data_offset or data_offset > len(data):
        raise ValueError("ASAR header bounds are invalid")
    try:
        header = json.loads(data[16:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ASAR JSON header is invalid") from exc

    parts = PurePosixPath(entry_name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("entry path is invalid")
    node = header
    for part in parts:
        files = node.get("files") if isinstance(node, dict) else None
        if not isinstance(files, dict) or part not in files:
            raise ValueError("entry was not found in the ASAR header")
        node = files[part]
    if node.get("unpacked"):
        raise ValueError("entry is stored outside the ASAR archive")
    try:
        size = int(node["size"])
        offset = int(node["offset"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("entry metadata is invalid") from exc
    if size < 0 or size > MAX_ENTRY_BYTES or offset < 0:
        raise ValueError("entry bounds are outside the supported range")
    start = data_offset + offset
    end = start + size
    if start < data_offset or end > len(data):
        raise ValueError("entry data is truncated")
    content = data[start:end]
    digest = hashlib.sha256(content).hexdigest()
    integrity = node.get("integrity") if isinstance(node, dict) else None
    expected = integrity.get("hash") if isinstance(integrity, dict) else None
    if expected and expected.lower() != digest:
        raise ValueError("entry SHA-256 does not match the ASAR header")
    return {
        "content": content,
        "entry": "/".join(parts),
        "entry_offset": start,
        "entry_size": size,
        "entry_sha256": digest,
        "header_sha256": expected.lower() if expected else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("entry")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.input.read_bytes()
    result = extract_entry(source, args.entry)
    args.output.write_bytes(result.pop("content"))
    print(json.dumps({
        "input": str(args.input),
        "input_size": len(source),
        "input_sha256": hashlib.sha256(source).hexdigest(),
        **result,
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
