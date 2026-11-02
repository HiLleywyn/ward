import gzip
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ward.scanner import inspect_tree


def archive(content=b'12345678', name='payload.txt'):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as value:
        value.writestr(name, content)
    return stream.getvalue()


class ArchiveBudgetTests(unittest.TestCase):
    def inspect(self, files):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in files.items():
                (Path(directory) / name).write_bytes(content)
            return inspect_tree(Path(directory), indicators={'indicators': []})

    def test_all_root_archives_share_expansion_bytes(self):
        with patch('ward.archives.MAX_REPOSITORY_EXPANDED_BYTES', 10):
            result = self.inspect({'one.zip': archive(), 'two.zip': archive()})
        self.assertTrue(result['archive_incomplete'])
        self.assertTrue(result['partial'])
        self.assertEqual(result['text_files'], 1)
        self.assertTrue(any('repository' in item['detail'].lower() for item in result['findings']))

    def test_all_root_archives_share_entry_budget_including_unsafe_names(self):
        with patch('ward.archives.MAX_REPOSITORY_ARCHIVE_MEMBERS', 1):
            result = self.inspect({'one.zip': archive(name='../unsafe.txt'), 'two.zip': archive()})
        self.assertTrue(result['partial'])
        self.assertEqual(result['text_files'], 0)
        self.assertIn('archive-inspection-limit', {item['kind'] for item in result['findings']})

    def test_nested_and_compressed_members_share_repository_budget(self):
        zipped = archive()
        with patch('ward.archives.MAX_REPOSITORY_EXPANDED_BYTES', len(zipped) + 9):
            result = self.inspect({'one.gz': gzip.compress(zipped), 'two.zip': archive()})
        self.assertTrue(result['partial'])
        self.assertEqual(result['text_files'], 1)

    def test_archive_time_budget_covers_multiple_roots(self):
        from ward.archives import ArchiveBudget, inspect_archive
        clock = [0.0]
        inspected = []
        def member(content, path):
            inspected.append(path)
            clock[0] += 0.75
            return [], True
        with patch('ward.archives.MAX_REPOSITORY_ARCHIVE_SECONDS', 1), \
             patch('ward.archives.time.monotonic', side_effect=lambda: clock[0]):
            budget = ArchiveBudget()
            inspect_archive(archive(), 'one.zip', member, budget=budget)
            findings, _, _ = inspect_archive(archive(), 'two.zip', member, budget=budget)
            skipped, _, _ = inspect_archive(archive(), 'three.zip', member, budget=budget)
        self.assertEqual(len(inspected), 2)
        self.assertTrue(any(item['kind'] == 'archive-inspection-limit' for item in findings + skipped))
        self.assertTrue(any('time' in item['detail'] for item in findings + skipped))

    def test_per_archive_limits_still_apply_below_global_limit(self):
        with patch('ward.archives.MAX_EXPANDED_BYTES', 4):
            result = self.inspect({'one.zip': archive()})
        self.assertTrue(result['partial'])
        self.assertEqual(result['text_files'], 0)

    def test_small_archives_are_complete(self):
        result = self.inspect({'one.zip': archive(), 'two.zip': archive()})
        self.assertFalse(result['partial'])
        self.assertEqual(result['text_files'], 2)
