"""Decode bounded HTML carriers that XOR concatenated base64 DOM fragments.

The decoder treats the page as text and never evaluates its JavaScript or the
recovered document.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
DIV_RE = re.compile(
    rb'<div\s+id=["\'](?P<prefix>[A-Za-z0-9_-]*?)(?P<index>\d+)["\'][^>]*>(?P<data>[A-Za-z0-9+/=\s]+)</div>',
    re.IGNORECASE,
)
KEY_RE = re.compile(rb"atob\(['\"](?P<key>[A-Za-z0-9+/]+={0,2})['\"]\)")
URL_RE = re.compile(rb"https?://[^\s<>\"']+", re.IGNORECASE)


def decode_carrier(data: bytes) -> dict:
    if not data or len(data) > MAX_INPUT_BYTES:
        raise ValueError("input size is outside the supported range")
    key_match = KEY_RE.search(data)
    if key_match is None:
        raise ValueError("carrier key was not found")
    key = base64.b64decode(key_match.group("key"), validate=True)
    if not key:
        raise ValueError("carrier key is empty")

    groups: dict[bytes, list[tuple[int, bytes]]] = {}
    for match in DIV_RE.finditer(data):
        groups.setdefault(match.group("prefix"), []).append(
            (int(match.group("index")), re.sub(rb"\s+", b"", match.group("data")))
        )
    if not groups:
        raise ValueError("carrier fragments were not found")
    prefix, fragments = max(groups.items(), key=lambda item: len(item[1]))
    fragments.sort(key=lambda item: item[0])
    indexes = [index for index, _ in fragments]
    if indexes != list(range(len(indexes))):
        raise ValueError("carrier fragment indexes are not contiguous")
    encoded = b"".join(fragment for _, fragment in fragments)
    encrypted = base64.b64decode(encoded, validate=True)
    if len(encrypted) > MAX_OUTPUT_BYTES:
        raise ValueError("decoded carrier exceeds the output limit")
    payload = bytes(value ^ key[index % len(key)] for index, value in enumerate(encrypted))
    return {
        "prefix": prefix.decode("ascii", errors="replace"),
        "fragment_count": len(fragments),
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "payload": payload,
        "urls": sorted({match.decode("utf-8", errors="replace") for match in URL_RE.findall(payload)}),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    source = args.input.read_bytes()
    result = decode_carrier(source)
    if args.output:
        args.output.write_bytes(result["payload"])
    report = {
        "input": str(args.input),
        "input_size": len(source),
        "input_sha256": hashlib.sha256(source).hexdigest(),
        "fragment_prefix": result["prefix"],
        "fragment_count": result["fragment_count"],
        "key_sha256": result["key_sha256"],
        "payload_size": len(result["payload"]),
        "payload_sha256": hashlib.sha256(result["payload"]).hexdigest(),
        "urls": result["urls"],
        "output": str(args.output) if args.output else None,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
