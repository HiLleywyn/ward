from __future__ import annotations

import base64
import importlib.util
import json
import struct
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "decode_png_text_payload.py"
SPEC = importlib.util.spec_from_file_location("decode_png_text_payload", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


class DecodePngTextPayloadTests(unittest.TestCase):
    def test_decodes_xor_payload_and_embedded_source(self):
        key = bytes.fromhex("10203040")
        payload = b"bounded binary fixture"
        encoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(payload))
        source = b"public class Fixture { }"
        metadata = json.dumps({"n": 1, "m": 1, "key": key.hex(), "fn": "Fixture"}).encode()
        png = MODULE.PNG_SIGNATURE + b"".join(
            [
                chunk(b"tEXt", b"meta\x00" + metadata),
                chunk(b"tEXt", b"X00000\x00" + base64.b64encode(encoded)),
                chunk(b"tEXt", b"Y00000\x00" + base64.b64encode(source)),
                chunk(b"IEND", b""),
            ]
        )

        result = MODULE.decode_payload(png)

        self.assertEqual(payload, result["payload"])
        self.assertEqual(source, result["source"])
        self.assertEqual("Fixture", result["metadata"]["fn"])

    def test_rejects_non_png_input(self):
        with self.assertRaisesRegex(ValueError, "not a PNG"):
            MODULE.decode_payload(b"not a png")


if __name__ == "__main__":
    unittest.main()
