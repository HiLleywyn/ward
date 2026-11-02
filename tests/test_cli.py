import unittest

from ward.cli import build_parser


class WardCliTests(unittest.TestCase):
    def test_cli_uses_ward_as_its_public_name(self):
        parser = build_parser()

        self.assertEqual(parser.prog, "ward")
        self.assertIn("usage: ward", parser.format_help())


if __name__ == "__main__":
    unittest.main()
