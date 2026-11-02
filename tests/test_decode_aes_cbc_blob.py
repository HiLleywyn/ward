from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SCRIPT = Path(__file__).parents[1] / "tools" / "decode_aes_cbc_blob.py"
SPEC = importlib.util.spec_from_file_location("decode_aes_cbc_blob", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DecodeAesCbcBlobTests(unittest.TestCase):
    def test_decrypts_prefixed_iv_and_pkcs7_without_executing_plaintext(self):
        key = bytes(range(32))
        iv = bytes(range(16))
        plaintext = b"static fixture payload"
        padding = 16 - len(plaintext) % 16
        padded = plaintext + bytes([padding]) * padding
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = iv + encryptor.update(padded) + encryptor.finalize()
        self.assertEqual(plaintext, MODULE.decrypt_blob(blob, key))

    def test_rejects_invalid_padding(self):
        with self.assertRaisesRegex(ValueError, "padding"):
            MODULE.decrypt_blob(bytes(32), bytes(32))


if __name__ == "__main__":
    unittest.main()
