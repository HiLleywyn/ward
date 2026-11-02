"""Statically reconstruct a strided, XOR-obfuscated PE section.

The tool reads bytes, validates PE bounds, and writes recovered artifacts only
when explicitly requested. It never loads or executes the input or output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


MAX_INPUT_BYTES = 1024 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_sections(image: bytes) -> list[dict[str, int | bytes]]:
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise ValueError("input is not a PE image")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if pe_offset + 24 > len(image) or image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signature is missing or out of bounds")
    section_count = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    if not section_count or table + section_count * 40 > len(image):
        raise ValueError("PE section table is invalid")

    sections: list[dict[str, int | bytes]] = []
    for index in range(section_count):
        header = table + index * 40
        name = image[header : header + 8].rstrip(b"\0")
        virtual_size, virtual_address = struct.unpack_from("<II", image, header + 8)
        raw_size, raw_offset = struct.unpack_from("<II", image, header + 16)
        if raw_offset + raw_size > len(image):
            raise ValueError(f"section {name!r} extends beyond the input")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "header_offset": header,
            }
        )
    return sections


def find_section(image: bytes, name: bytes) -> dict[str, int | bytes]:
    return next(
        (section for section in pe_sections(image) if section["name"] == name),
        None,
    ) or (_ for _ in ()).throw(ValueError(f"section {name!r} was not found"))


def rva_bytes(image: bytes, rva: int, size: int) -> bytes:
    if size <= 0:
        raise ValueError("RVA read size must be positive")
    for section in pe_sections(image):
        start = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        if start <= rva and rva + size <= start + raw_size:
            offset = int(section["raw_offset"]) + rva - start
            return image[offset : offset + size]
    raise ValueError(f"RVA {rva:#x} is not backed by raw section bytes")


def reconstruct(
    image: bytes,
    *,
    section_name: bytes,
    block_size: int,
    retained_size: int,
    key: bytes,
) -> dict[str, object]:
    if block_size <= 0 or retained_size <= 0 or retained_size > block_size:
        raise ValueError("retained size must be between one and block size")
    if not key:
        raise ValueError("XOR key is empty")
    section = find_section(image, section_name)
    raw_offset = int(section["raw_offset"])
    raw_size = int(section["raw_size"])
    carrier = image[raw_offset : raw_offset + raw_size]
    full_block_count = len(carrier) // block_size
    if not full_block_count:
        raise ValueError("carrier section contains no complete blocks")
    blocks = [
        carrier[offset : offset + block_size]
        for offset in range(0, full_block_count * block_size, block_size)
    ]
    compacted = b"".join(block[:retained_size] for block in blocks)
    runtime = bytes(value ^ key[index % len(key)] for index, value in enumerate(compacted))

    xored = bytes(value ^ key[index % len(key)] for index, value in enumerate(carrier))
    xored_blocks = [
        xored[offset : offset + block_size]
        for offset in range(0, full_block_count * block_size, block_size)
    ]
    filler = xored_blocks[0][retained_size:]
    filler_matches = sum(block[retained_size:] == filler for block in xored_blocks)
    return {
        "section": section,
        "carrier": carrier,
        "compacted": compacted,
        "runtime": runtime,
        "block_count": full_block_count,
        "trailing_bytes": len(carrier) - full_block_count * block_size,
        "post_xor_filler_hex": filler.hex(),
        "post_xor_filler_matches": filler_matches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--section", required=True, help="PE section name")
    parser.add_argument("--block-size", required=True, type=int)
    parser.add_argument("--retain", required=True, type=int)
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--key-hex")
    key_group.add_argument("--key-rva", type=lambda value: int(value, 0))
    parser.add_argument("--key-length", type=int, default=16)
    parser.add_argument("--output", type=Path, help="write reconstructed raw bytes")
    parser.add_argument(
        "--patched-pe",
        type=Path,
        help="write a non-executed PE copy with the section replaced for disassembly",
    )
    args = parser.parse_args()

    size = args.input.stat().st_size
    if size <= 0 or size > MAX_INPUT_BYTES:
        raise ValueError("input size is outside the supported range")
    image = args.input.read_bytes()
    key = bytes.fromhex(args.key_hex) if args.key_hex else rva_bytes(image, args.key_rva, args.key_length)
    result = reconstruct(
        image,
        section_name=args.section.encode("ascii"),
        block_size=args.block_size,
        retained_size=args.retain,
        key=key,
    )
    runtime = result["runtime"]
    assert isinstance(runtime, bytes)
    section = result["section"]
    assert isinstance(section, dict)
    if args.output:
        args.output.write_bytes(runtime)
    if args.patched_pe:
        raw_offset = int(section["raw_offset"])
        raw_size = int(section["raw_size"])
        if len(runtime) > raw_size:
            raise ValueError("reconstructed bytes exceed the original section")
        patched = bytearray(image)
        patched[raw_offset : raw_offset + raw_size] = runtime + bytes(raw_size - len(runtime))
        args.patched_pe.write_bytes(patched)

    report = {
        "input": str(args.input),
        "input_size": len(image),
        "input_sha256": sha256(image),
        "section": args.section,
        "section_size": len(result["carrier"]),
        "block_size": args.block_size,
        "retained_size": args.retain,
        "block_count": result["block_count"],
        "trailing_bytes": result["trailing_bytes"],
        "key_sha256": sha256(key),
        "post_xor_filler_hex": result["post_xor_filler_hex"],
        "post_xor_filler_matches": result["post_xor_filler_matches"],
        "runtime_size": len(runtime),
        "runtime_sha256": sha256(runtime),
        "output": str(args.output) if args.output else None,
        "patched_pe": str(args.patched_pe) if args.patched_pe else None,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
