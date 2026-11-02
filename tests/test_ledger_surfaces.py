import hashlib
import json
import unittest
from pathlib import Path

import test_api
import test_ledger_regressions
from ward.analysis import result_digest
from ward.evidence import ResultStore


class LedgerSurfaceTests(unittest.TestCase):
    tearDown = test_api.WardAPITests.tearDown
    request = test_api.WardAPITests.request
    scan = test_ledger_regressions.LedgerStoreCase.scan

    def setUp(self):
        test_api.WardAPITests.setUp(self)
        self.store = ResultStore(Path(self.temp.name) / 'results.sqlite3')

    def mcp(self, name, arguments):
        _, _, result = self.request('/mcp', method='POST', body={
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}})
        self.assertNotIn('error', result)
        self.assertFalse(result['result'].get('isError'))
        return result['result']['structuredContent']

    def text(self, path):
        with test_api.urlopen(self.base + path, timeout=3) as response:
            return response.read().decode()

    def test_host_identity_is_consistent_across_rest_mcp_badges_and_ledger(self):
        self.scan('https://gitlab.com/repro/project')
        _, _, history = self.request('/api/v1/repositories/history?target=repro%2Fproject')
        self.assertEqual(history['scans'], [])
        self.assertEqual(self.mcp('ward_repository_history', {'repository': 'repro/project'})['scans'], [])
        self.assertIsNone(self.mcp('ward_get_badge', {'repository': 'repro/project'})['scan'])
        self.assertIn('not scanned', self.text('/api/v1/badges/repro/project.svg'))
        self.assertIn('No scans recorded.', self.text('/repositories/repro/project'))

    def test_antivirus_history_comparison_and_failed_refresh_across_surfaces(self):
        url = 'https://github.com/repro/project'
        base = self.scan(url, status='Unverified')
        data = b'harmless fixture'
        digest = hashlib.sha256(data).hexdigest()
        head, _ = self.store.create_scan_job(kind='repository', target=url, request_hash='a' * 64,
            idempotency_key=None, cancel_token_hash='b' * 64, requested_ref='main')
        self.store.start_scan_job(head['id'])
        self.store.complete_scan_job(head['id'], {'repository': 'repro/project', 'repository_url': url,
            'status': 'Unverified', 'commit': 'b' * 40, 'branch': 'main', 'scanned_at': head['created_at'],
            'findings': [], 'artifacts': [{'path': 'fixture.bin', 'sha256': digest}]})
        self.store.analyses.enqueue(head['id'], 'fixture.bin', digest, data)
        claimed = self.store.analyses.claim('remnux')
        result = {'sha256': digest, 'coverage': 'partial', 'engines': [
            {'name': 'clamav', 'status': 'partial', 'detections': ['Test.Signature']}]}
        result['evidence_digest'] = result_digest(result)
        self.store.analyses.finish(claimed['id'], claimed['claim_token'], result=result)
        _, _, history = self.request('/api/v1/repositories/history?target=repro%2Fproject')
        self.assertEqual(history['scans'][-1]['status'], 'Malicious')
        self.assertEqual(self.mcp('ward_repository_history', {'repository': 'repro/project'})['scans'], history['scans'])
        _, _, comparison = self.request(f'/api/v1/comparisons?base_scan={base["id"]}&head_scan={head["id"]}')
        self.assertEqual(comparison['assessment'], 'new_findings_detected')
        self.assertEqual(self.mcp('ward_compare_scans', {'base_scan_id': base['id'], 'head_scan_id': head['id']}), comparison)
        self.assertIn('Malicious', self.text('/repositories/repro/project'))
        self.assertIn('malware detected', self.text('/api/v1/badges/repro/project.svg'))
        refresh, _ = self.store.create_scan_job(kind='repository', target=url, request_hash='c' * 64,
            idempotency_key=None, cancel_token_hash='b' * 64, requested_ref='main')
        self.store.fail_scan_job(refresh['id'], 'fixture', 'Fixture failure')
        scan = self.mcp('ward_get_badge', {'repository': 'repro/project', 'branch': 'main'})['scan']
        self.assertEqual(scan['status'], 'failed')
        self.assertEqual(scan['last_completed_scan']['id'], head['id'])
        self.assertIn('previous: malware detected; refresh incomplete', self.text('/api/v1/badges/repro/project.svg?branch=main'))
        self.assertIn('/scans/' + head['id'], self.text('/scans/' + refresh['id']))
