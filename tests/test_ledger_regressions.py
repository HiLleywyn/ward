import tempfile
import unittest
from pathlib import Path

from ward.evidence import ResultStore
from ward.views import badge_state


class RepositoryIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ResultStore(Path(self.temp.name) / 'state.db')

    def scan(self, url, *, status='Malicious', branch='main', commit='a' * 40, findings=None):
        job, _ = self.store.create_scan_job(kind='repository', target=url, request_hash='a' * 64,
            idempotency_key=None, cancel_token_hash='b' * 64, requested_ref=branch)
        self.store.start_scan_job(job['id'])
        self.store.complete_scan_job(job['id'], {'repository': url, 'repository_url': url,
            'branch': branch, 'commit': commit, 'status': status, 'findings': findings or [],
            'scanned_at': job['created_at']})
        return self.store.scan_job(job['id'])

    def test_hosts_never_share_latest_badge_or_history(self):
        self.scan('https://gitlab.com/repro/project.git')
        for target in ('repro/project', 'https://github.com/repro/project.git', 'https://example.org/repro/project'):
            with self.subTest(target=target):
                self.assertIsNone(self.store.latest_repository_scan(target))
                self.assertEqual(self.store.repository_history(target)['scans'], [])
                self.assertEqual(badge_state(self.store.latest_repository_scan(target))[1], 'not scanned')

    def test_github_shorthand_case_suffix_and_trailing_slash_aliases(self):
        job = self.scan('https://github.com/Repro/Project.git')
        for target in ('repro/project', 'REPRO/PROJECT', 'https://GITHUB.COM:443/repro/project.git/',
                       'https://github.com/repro/project/'):
            with self.subTest(target=target):
                self.assertEqual(self.store.latest_repository_scan(target)['id'], job['id'])
                self.assertEqual(len(self.store.repository_history(target)['scans']), 1)

    def test_generic_paths_preserve_case_and_host_qualified_labels(self):
        job = self.scan('https://git.example.org/Team/Project.git')
        self.assertIsNone(self.store.latest_repository_scan('https://git.example.org/team/project.git'))
        self.assertEqual(self.store.latest_repository_scan('git.example.org/Team/Project')['id'], job['id'])
        self.assertEqual(self.store.latest_repository_scan('https://GIT.EXAMPLE.ORG/Team/Project.git/')['id'], job['id'])

    def test_gateway_suffix_aliases_do_not_guess_repository_ownership(self):
        url = 'https://git.lley.cat/r/b60252cb-df6f-478f-8cb7-d18f4cdd316b'
        job = self.scan(url + '.git')
        self.assertEqual(self.store.latest_repository_scan(url)['id'], job['id'])
        self.assertIsNone(self.store.latest_repository_scan('https://git.lley.cat/lleywyn/ward'))

    def test_query_credentials_and_custom_ports_are_not_aliases(self):
        self.scan('https://github.com/repro/project')
        for target in ('https://github.com/repro/project?other=1', 'https://user@github.com/repro/project',
                       'https://github.com:444/repro/project', 'https://github.com/repro/project#other'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.store.latest_repository_scan(target)
