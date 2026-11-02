from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import hmac
import json
import re
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_ROUNDS = 16

WRAPPER_PATTERN = re.compile(
    r"}\s*\(@\((?P<parts>.*?)\)\[(?P<order>[\d,\s]+)\]\s*"
    r"-join\s*''\)\s*(?P<rounds>\d+)\s+\$PSCommandPath\)",
    re.DOTALL,
)
STRING_PATTERN = re.compile(r"'([^']*)'")
BASE64_STRING_PATTERN = re.compile(rb"FromBase64String\('([A-Za-z0-9+/=]+)'\)")


def _decompress(data: bytes, codec: int) -> bytes:
    if codec == 0:
        decoded = gzip.decompress(data)
    elif codec == 1:
        try:
            decoded = zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            decoded = zlib.decompress(data)
    else:
        raise ValueError(f"unsupported compression codec: {codec}")
    if len(decoded) > MAX_OUTPUT_BYTES:
        raise ValueError("decoded layer exceeds the 64 MiB limit")
    return decoded


def _decode_layer(data: bytes) -> bytes:
    if len(data) < 128 or (len(data) - 112) % 16:
        raise ValueError("invalid encrypted layer length")
    encryption_key = data[:32]
    authentication_key = data[32:64]
    iv = data[64:80]
    expected_tag = data[80:112]
    ciphertext = data[112:]
    actual_tag = hmac.new(authentication_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, actual_tag):
        raise ValueError("encrypted layer integrity check failed")

    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    if len(plaintext) < 2:
        raise ValueError("decoded layer is empty")
    return _decompress(plaintext[1:], plaintext[0])


def decode_wrapper(text: str) -> tuple[bytes, int]:
    match = WRAPPER_PATTERN.search(text)
    if not match:
        raise ValueError("PSObfuscator wrapper was not recognized")
    parts = STRING_PATTERN.findall(match.group("parts"))
    order = [int(value) for value in match.group("order").split(",")]
    rounds = int(match.group("rounds"))
    if not parts or sorted(order) != list(range(len(parts))):
        raise ValueError("wrapper part order is incomplete or duplicated")
    if not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError("wrapper round count exceeds the limit")
    data = base64.b64decode("".join(parts[index] for index in order), validate=True)
    for _ in range(rounds):
        data = _decode_layer(data)
    return data, rounds


def unwrap_nested_powershell_command(decoded: bytes) -> bytes | None:
    for value in BASE64_STRING_PATTERN.findall(decoded):
        try:
            first = base64.b64decode(value, validate=True).decode("utf-16-le").strip()
            command = base64.b64decode(first, validate=True)
        except (UnicodeDecodeError, ValueError):
            continue
        if command and len(command) <= MAX_OUTPUT_BYTES:
            return command
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Statically decode a bounded PSObfuscator wrapper without executing PowerShell."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--command-output", type=Path)
    args = parser.parse_args()

    raw = args.input.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the 4 MiB limit")
    decoded, rounds = decode_wrapper(raw.decode("utf-8-sig"))
    if args.output:
        args.output.write_bytes(decoded)
    command = unwrap_nested_powershell_command(decoded)
    if args.command_output:
        if command is None:
            raise ValueError("no nested UTF-16/base64 PowerShell command was recognized")
        args.command_output.write_bytes(command)
    print(
        json.dumps(
            {
                "rounds": rounds,
                "decoded_bytes": len(decoded),
                "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                "output": str(args.output) if args.output else None,
                "command_bytes": len(command) if command is not None else None,
                "command_sha256": hashlib.sha256(command).hexdigest() if command is not None else None,
                "command_output": str(args.command_output) if args.command_output else None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
