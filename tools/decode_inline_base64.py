"""Recursively extract base64 literals without evaluating their container.

This helper is intentionally format-agnostic. It is useful for PowerShell and
JavaScript wrappers that pass quoted base64 text to a decoder, but it never
parses or executes the decoded program.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


BASE64_LITERAL = re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{64,}={0,2})(?![A-Za-z0-9+/=])")
MAX_LITERAL_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024


def text_likelihood(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(value in b"\t\n\r" or 32 <= value <= 126 for value in data)
    return printable / len(data)


def decode_layers(source: bytes, max_depth: int = 5) -> list[dict]:
    queue = [(0, source)]
    seen: set[str] = set()
    results: list[dict] = []
    total_bytes = 0

    while queue:
        depth, container = queue.pop(0)
        if depth >= max_depth:
            continue
        for match in BASE64_LITERAL.finditer(container):
            literal = match.group(1)
            if len(literal) > MAX_LITERAL_BYTES:
                continue
            try:
                decoded = base64.b64decode(literal, validate=True)
            except (ValueError, base64.binascii.Error):
                continue
            digest = hashlib.sha256(decoded).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            total_bytes += len(decoded)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("aggregate decoded-byte limit exceeded")
            likelihood = text_likelihood(decoded)
            results.append(
                {
                    "depth": depth + 1,
                    "offset": match.start(1),
                    "size": len(decoded),
                    "sha256": digest,
                    "text_likelihood": round(likelihood, 4),
                    "data": decoded,
                }
            )
            if likelihood >= 0.8:
                queue.append((depth + 1, decoded))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--max-depth", type=int, default=5)
    args = parser.parse_args()

    if not 1 <= args.max_depth <= 10:
        parser.error("--max-depth must be between 1 and 10")
    source = args.input.read_bytes()
    results = decode_layers(source, args.max_depth)
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for index, result in enumerate(results, start=1):
            suffix = ".txt" if result["text_likelihood"] >= 0.8 else ".bin"
            path = args.output_dir / f"layer-{index:03d}-d{result['depth']}{suffix}"
            path.write_bytes(result["data"])
            result["output"] = str(path)
    report = {
        "input": str(args.input),
        "input_sha256": hashlib.sha256(source).hexdigest(),
        "input_size": len(source),
        "decoded": [
            {key: value for key, value in result.items() if key != "data"}
            for result in results
        ],
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
