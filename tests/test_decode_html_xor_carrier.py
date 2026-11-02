from __future__ import annotations

import base64
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "decode_html_xor_carrier.py"
SPEC = importlib.util.spec_from_file_location("decode_html_xor_carrier", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DecodeHtmlXorCarrierTests(unittest.TestCase):
    def test_decodes_contiguous_dom_fragments_without_javascript_execution(self):
        key = b"bounded-key"
        payload = b'<a href="https://example.test/payload">fixture</a>'
        encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(payload))
        encoded = base64.b64encode(encrypted)
        midpoint = len(encoded) // 2
        html = b"".join(
            [
                b'<div id="carrier0" style="display:none">' + encoded[:midpoint] + b"</div>",
                b'<div id="carrier1" style="display:none">' + encoded[midpoint:] + b"</div>",
                b"<script>const key=atob('" + base64.b64encode(key) + b"');</script>",
            ]
        )

        result = MODULE.decode_carrier(html)

        self.assertEqual(payload, result["payload"])
        self.assertEqual(2, result["fragment_count"])
        self.assertEqual(["https://example.test/payload"], result["urls"])

    def test_rejects_missing_key(self):
        with self.assertRaisesRegex(ValueError, "key"):
            MODULE.decode_carrier(b'<div id="carrier0">QUJD</div>')


if __name__ == "__main__":
    unittest.main()
