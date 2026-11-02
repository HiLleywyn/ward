from __future__ import annotations

import base64
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "decode_inline_base64.py"
SPEC = importlib.util.spec_from_file_location("decode_inline_base64", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DecodeInlineBase64Tests(unittest.TestCase):
    def test_recursively_decodes_text_literals_without_execution(self):
        payload = b"Write-Output 'bounded fixture that is deliberately long enough for extraction'"
        inner = base64.b64encode(payload)
        outer = base64.b64encode(b"decode('" + inner + b"')")

        results = MODULE.decode_layers(b"wrapper('" + outer + b"')")

        self.assertEqual([1, 2], [item["depth"] for item in results])
        self.assertEqual(b"decode('" + inner + b"')", results[0]["data"])
        self.assertEqual(payload, results[1]["data"])

    def test_rejects_invalid_base64(self):
        self.assertEqual([], MODULE.decode_layers(b"'A' * 128"))


if __name__ == "__main__":
    unittest.main()
