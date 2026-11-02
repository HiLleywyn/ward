"""Statically decode the X/Y tEXt payload layout used by PNG script carriers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_CHUNK_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def text_chunks(data: bytes) -> dict[str, str]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG file")
    offset = len(PNG_SIGNATURE)
    total = 0
    result: dict[str, str] = {}
    while offset + 12 <= len(data):
        size = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        start = offset + 8
        end = start + size
        if size > MAX_CHUNK_BYTES or end + 4 > len(data):
            raise ValueError("invalid or oversized PNG chunk")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("aggregate PNG chunk limit exceeded")
        if kind == b"tEXt":
            chunk = data[start:end]
            keyword, separator, value = chunk.partition(b"\x00")
            if separator and 1 <= len(keyword) <= 79:
                result[keyword.decode("latin-1")] = value.decode("latin-1")
        offset = end + 4
        if kind == b"IEND":
            break
    return result


def decode_payload(data: bytes) -> dict:
    chunks = text_chunks(data)
    metadata = json.loads(chunks["meta"])
    count_x = int(metadata["n"])
    count_y = int(metadata["m"])
    if not 0 <= count_x <= 100_000 or not 0 <= count_y <= 100_000:
        raise ValueError("metadata chunk count exceeds limit")
    stream_x = "".join(chunks[f"X{index:05d}"] for index in range(count_x))
    stream_y = "".join(chunks[f"Y{index:05d}"] for index in range(count_y))
    encoded = base64.b64decode(stream_x, validate=True)
    key = bytes.fromhex(str(metadata["key"]))
    if not key:
        raise ValueError("empty XOR key")
    payload = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
    source = base64.b64decode(stream_y, validate=True)
    return {"metadata": metadata, "payload": payload, "source": source, "chunks": chunks}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    data = args.input.read_bytes()
    decoded = decode_payload(data)
    report = {
        "input": str(args.input),
        "input_size": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "metadata": decoded["metadata"],
        "text_chunk_count": len(decoded["chunks"]),
        "payload_size": len(decoded["payload"]),
        "payload_sha256": hashlib.sha256(decoded["payload"]).hexdigest(),
        "source_size": len(decoded["source"]),
        "source_sha256": hashlib.sha256(decoded["source"]).hexdigest(),
    }
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        payload_path = args.output_dir / "payload.bin"
        source_path = args.output_dir / "embedded-source.txt"
        payload_path.write_bytes(decoded["payload"])
        source_path.write_bytes(decoded["source"])
        report["payload_output"] = str(payload_path)
        report["source_output"] = str(source_path)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
