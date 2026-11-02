from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "extract_pe_stride_xor.py"
SPEC = importlib.util.spec_from_file_location("extract_pe_stride_xor", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def fixture_pe(section_data: bytes, key: bytes) -> bytes:
    image = bytearray(0x600)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x86, 2)
    struct.pack_into("<H", image, 0x94, 0xE0)
    first = 0x178
    image[first : first + 8] = b".carrier"
    struct.pack_into("<IIII", image, first + 8, len(section_data), 0x1000, len(section_data), 0x200)
    second = first + 40
    image[second : second + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", image, second + 8, 0x100, 0x2000, 0x100, 0x500)
    image[0x200 : 0x200 + len(section_data)] = section_data
    image[0x510 : 0x510 + len(key)] = key
    return bytes(image)


class ExtractPeStrideXorTests(unittest.TestCase):
    def test_reconstructs_retained_bytes_and_reports_repeated_filler(self):
        key = bytes.fromhex("10203040")
        plaintext = b"MZpayload-123456"
        encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(plaintext))
        filler = bytes.fromhex("aabbccddeeff0011")
        carrier = b"".join(
            encrypted[offset : offset + 4] + filler
            for offset in range(0, len(encrypted), 4)
        )
        image = fixture_pe(carrier, key)

        result = MODULE.reconstruct(
            image,
            section_name=b".carrier",
            block_size=12,
            retained_size=4,
            key=key,
        )

        self.assertEqual(plaintext, result["runtime"])
        self.assertEqual(4, result["block_count"])
        self.assertEqual(4, result["post_xor_filler_matches"])

    def test_reads_key_from_bounded_rva(self):
        key = b"bounded-key"
        image = fixture_pe(bytes(24), key)
        self.assertEqual(key, MODULE.rva_bytes(image, 0x2010, len(key)))
        with self.assertRaisesRegex(ValueError, "not backed"):
            MODULE.rva_bytes(image, 0x3000, 4)

    def test_rejects_invalid_stride(self):
        image = fixture_pe(bytes(24), b"key")
        with self.assertRaisesRegex(ValueError, "retained size"):
            MODULE.reconstruct(
                image,
                section_name=b".carrier",
                block_size=4,
                retained_size=5,
                key=b"key",
            )


if __name__ == "__main__":
    unittest.main()
