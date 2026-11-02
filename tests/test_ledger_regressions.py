import hashlib
import tempfile
import unittest
from pathlib import Path

from ward.evidence import ResultStore
from ward.analysis import result_digest
from ward.api import report_for_job
from ward.views import badge_state


class LedgerStoreCase(unittest.TestCase):
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


class RepositoryIdentityTests(LedgerStoreCase):
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


class LedgerAssessmentTests(LedgerStoreCase):
    def test_antivirus_evidence_reaches_history_comparison_and_ledger(self):
        from ward.views import repository_ledger_page
        url = 'https://github.com/repro/project'
        base = self.scan(url, status='Unverified')
        data = b'harmless fixture'
        digest = hashlib.sha256(data).hexdigest()
        head, _ = self.store.create_scan_job(kind='repository', target=url, request_hash='a' * 64,
            idempotency_key=None, cancel_token_hash='b' * 64, requested_ref='main')
        self.store.start_scan_job(head['id'])
        original = {'repository': 'repro/project', 'repository_url': url, 'branch': 'main',
            'commit': 'b' * 40, 'status': 'Unverified', 'scanned_at': head['created_at'], 'findings': [],
            'artifacts': [{'path': 'sample.exe', 'sha256': digest}]}
        original['evidence_digest'] = result_digest(original)
        self.store.complete_scan_job(head['id'], original)
        analysis_id = self.store.analyses.enqueue(head['id'], 'sample.exe', digest, data)
        self.assertEqual(self.store.compare_repository_scans(base['id'], head['id'])['assessment'], 'no_finding_change')
        claimed = self.store.analyses.claim('remnux')
        evidence = {'sha256': digest, 'coverage': 'partial', 'engines': [
            {'name': 'clamav', 'status': 'partial', 'detections': ['Test.Signature']}]}
        evidence['evidence_digest'] = result_digest(evidence)
        self.store.analyses.finish(analysis_id, claimed['claim_token'], result=evidence)

        history = self.store.repository_history(url)
        self.assertEqual(history['scans'][-1]['status'], 'Malicious')
        self.assertEqual(history['scans'][-1]['static_status'], 'Unverified')
        self.assertEqual(history['scans'][-1]['static_evidence_digest'], original['evidence_digest'])
        self.assertNotIn('evidence_digest', history['scans'][-1])
        self.assertEqual(history['scans'][-1]['analysis_evidence'][0]['evidence_digest'], evidence['evidence_digest'])
        self.assertEqual(history['transitions'][0]['to_status'], 'Malicious')
        comparison = self.store.compare_repository_scans(base['id'], head['id'])
        self.assertEqual(comparison['assessment'], 'new_findings_detected')
        self.assertEqual(comparison['new_findings'][0]['analysis_id'], analysis_id)
        self.assertEqual(comparison['new_findings'][0]['sha256'], digest)
        self.assertEqual(comparison['head']['status'], 'Malicious')
        self.assertIn('Malicious', repository_ledger_page(history).decode())
        job = self.store.scan_job(head['id'])
        self.assertEqual(job['result'], original)
        self.assertEqual(report_for_job(job)['verdict']['status'], 'malicious')
        self.assertEqual(badge_state(job)[1], 'malware detected')
