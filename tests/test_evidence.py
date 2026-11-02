import tempfile
import unittest
from pathlib import Path

from ward.analyze import assess_file, assess_repository, parse_repository_target
from ward.evidence import ResultStore, repository_warning


class EvidenceTests(unittest.TestCase):
    def test_renamed_repo_with_known_asset_digest_is_detected(self):
        from ward.github import RepositorySnapshot
        digest = 'a' * 64
        snapshot = RepositorySnapshot(
            {'full_name':'unrelated/tool','name':'tool','size':1000}, {},
            [{'assets':[{'name':'tool.zip','digest':'sha256:'+digest}]}], '')
        indicators = {'indicators':[{'sha256':digest,'status':'confirmed','source_url':'https://example.test/report'}]}
        result = assess_repository(snapshot, indicators=indicators)
        self.assertTrue(result.exact_indicator_match)
        self.assertEqual(result.verdict,'confirmed-malicious-asset')
        indicators['indicators'][0]['status'] = 'false-positive'
        self.assertFalse(assess_repository(snapshot, indicators=indicators).exact_indicator_match)

    def test_primary_repository_warning_works_without_network(self):
        result = repository_warning('https://github.com/A1phaD3v/Oringo-Client/releases/tag/test')
        self.assertTrue(result.exact_indicator_match)
        self.assertIn('Check Point', result.signals[0].message)

    def test_unlisted_repo_is_unknown(self):
        self.assertIsNone(repository_warning('innocent/project'))

    def test_reports_and_scans_persist_without_promoting_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ResultStore(Path(temp) / 'results.db')
            first = store.report('someone/project', 'https://example.org/evidence', 'Please review')
            store.record_assessment(repository_warning('Dipo17/battle'))
            rows = ResultStore(store.path).history()
            self.assertEqual([row['status'] for row in rows], ['FAIL', 'UNKNOWN'])
            self.assertEqual(rows[1]['id'], first)
            with self.assertRaises(ValueError):
                store.record('someone/project', {}, kind='community-report', status='FAIL')

    def test_withdrawn_hash_does_not_trigger(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture'
            path.write_bytes(b'fixture')
            item = {'sha256': hashlib.sha256(b'fixture').hexdigest(), 'status': 'false-positive'}
            self.assertFalse(assess_file(path, {'indicators':[item]}).exact_indicator_match)

    def test_rejects_url_path_manipulation(self):
        for target in ('owner/..', 'https://github.com/owner/%2e%2e', 'https://github.com@evil.example/a/b', 'owner/repo?token=x'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_repository_target(target)
