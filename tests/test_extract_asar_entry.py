from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "extract_asar_entry.py"
SPEC = importlib.util.spec_from_file_location("extract_asar_entry", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def fixture(entry: bytes) -> bytes:
    digest = hashlib.sha256(entry).hexdigest()
    header = json.dumps({"files": {"main.js": {
        "size": len(entry), "offset": "0",
        "integrity": {"algorithm": "SHA256", "hash": digest},
    }}}).encode()
    padding = b"\0" * ((4 - len(header) % 4) % 4)
    json_pickle_size = 4 + len(header) + len(padding)
    header_pickle_size = 4 + json_pickle_size
    return struct.pack("<IIII", 4, header_pickle_size, json_pickle_size, len(header)) + header + padding + entry


class ExtractAsarEntryTests(unittest.TestCase):
    def test_extracts_hash_bound_entry_without_loading_javascript(self):
        content = b"console.log('fixture only');\n"
        result = MODULE.extract_entry(fixture(content), "main.js")
        self.assertEqual(content, result["content"])
        self.assertEqual(hashlib.sha256(content).hexdigest(), result["entry_sha256"])

    def test_rejects_missing_entry(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            MODULE.extract_entry(fixture(b"fixture"), "missing.js")


if __name__ == "__main__":
    unittest.main()
