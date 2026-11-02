"""Decrypt a bounded AES-CBC blob with an explicit key and prefixed IV.

This is a static recovery helper. It writes plaintext bytes but never imports,
evaluates, or executes them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def decrypt_blob(data: bytes, key: bytes, *, iv_size: int = 16) -> bytes:
    if not data or len(data) > MAX_INPUT_BYTES:
        raise ValueError("input size is outside the supported range")
    if len(key) not in {16, 24, 32}:
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    if iv_size != 16 or len(data) <= iv_size:
        raise ValueError("AES-CBC requires a 16-byte prefixed IV")
    iv, ciphertext = data[:iv_size], data[iv_size:]
    if len(ciphertext) % 16:
        raise ValueError("ciphertext length is not a multiple of the AES block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding = plaintext[-1]
    if not 1 <= padding <= 16 or plaintext[-padding:] != bytes([padding]) * padding:
        raise ValueError("plaintext does not contain valid PKCS7 padding")
    plaintext = plaintext[:-padding]
    if len(plaintext) > MAX_OUTPUT_BYTES:
        raise ValueError("plaintext exceeds the output limit")
    return plaintext


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--key-hex", required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.input.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if args.expected_sha256 and digest != args.expected_sha256.lower():
        raise ValueError("input SHA-256 does not match --expected-sha256")
    try:
        key = bytes.fromhex(args.key_hex)
    except ValueError as exc:
        raise ValueError("--key-hex is not valid hexadecimal") from exc
    plaintext = decrypt_blob(source, key)
    args.output.write_bytes(plaintext)
    print(json.dumps({
        "input": str(args.input),
        "input_size": len(source),
        "input_sha256": digest,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "plaintext_size": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
