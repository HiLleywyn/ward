import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from ward.web import BoundedHTTPServer, _handler

# This test client addresses only loopback fixture servers, never external URLs.
urlopen = build_opener(ProxyHandler({})).open


class PublicWebTests(unittest.TestCase):
    def test_public_history_hidden_and_known_warning_works_without_github(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'WARD_PUBLIC':'1','WARD_STATE_DIR':temp}):
            with patch('ward.web.GitHubClient.snapshot', side_effect=AssertionError('No live call expected')):
                server = BoundedHTTPServer(('127.0.0.1',0), _handler())
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                base = f'http://127.0.0.1:{server.server_port}'
                try:
                    def get(path):
                        with urlopen(base + path, timeout=3) as response:
                            return json.load(response)
                    request = Request(base + '/api/check-repo', data=json.dumps({'target':'Dipo17/battle'}).encode(), headers={'Content-Type':'application/json'})
                    with urlopen(request,timeout=3) as response:
                        self.assertEqual(json.load(response)['status'], 'FAIL')
                    self.assertEqual(get('/api/history'), {'observations':[]})
                    reviewed = get('/api/reviewed')
                    self.assertEqual(
                        {
                            'gpt-5-6/gpt-5-6.github.io',
                            'gpt-6-astra/gpt-6-astra.github.io',
                            'opus-5-0/opus-5-0.github.io',
                            'lehhlass/Fluxus-Roblox-Executor',
                            'hanneshow/Fluxus-Roblox-Executor',
                            'sjyjoghkkjj/Discord-Nitro-Generator',
                        },
                        {item['repository'] for item in reviewed['records']},
                    )
                    self.assertNotIn('repositories', reviewed)
                    record = get('/api/record?repository=gpt-5-6%2Fgpt-5-6.github.io')
                    self.assertEqual(record['artifact'], 'sol-setup.zip')
                    self.assertEqual(record['malicious_path'], 'sol-setup.zip / winmm.dll')
                    with self.assertRaises(HTTPError) as missing:
                        get('/api/record?repository=anyps-5%2FAnyPS5-Github')
                    self.assertEqual(missing.exception.code, 404)
                    for data in (b'[]', b'null', b'{"target":"owner/.."}'):
                        with self.subTest(data=data), self.assertRaises(HTTPError):
                            urlopen(Request(base+'/api/check-repo',data=data,headers={'Content-Type':'application/json'}),timeout=3)
                    with self.assertRaises(HTTPError):
                        urlopen(Request(base+'/api/check-repo',data=b'{}',headers={'Origin':'https://attacker.test'}),timeout=3)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()

    def test_repository_scan_is_persisted_and_returned(self):
        result = {
            'id': 'scan-fixture',
            'repository': 'owner/repository',
            'repository_url': 'https://github.com/owner/repository',
            'commit': 'a' * 40,
            'status': 'Unverified',
            'scanned_at': '2026-11-01T12:00:00+00:00',
            'duration_ms': 125,
            'summary': {'files': 2, 'bytes': 30, 'hashed_bytes': 30, 'text_files': 1, 'archives': 0, 'executable_files': 0, 'truncated': False},
            'findings': [],
            'sources': [],
            'limitations': ['No match does not prove safety.'],
        }
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'WARD_PUBLIC':'1','WARD_STATE_DIR':temp}):
            with patch('ward.web.normalize_repository_url', return_value='https://github.com/owner/repository.git'):
                with patch('ward.web.scan_repository', return_value=result):
                    server = BoundedHTTPServer(('127.0.0.1',0), _handler())
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    base = f'http://127.0.0.1:{server.server_port}'
                    try:
                        request = Request(
                            base + '/api/scan-repo',
                            data=json.dumps({'target':'https://github.com/owner/repository'}).encode(),
                            headers={'Content-Type':'application/json'},
                        )
                        with urlopen(request, timeout=3) as response:
                            self.assertEqual(json.load(response)['id'], 'scan-fixture')
                        with urlopen(base + '/api/scans', timeout=3) as response:
                            scans = json.load(response)['scans']
                        self.assertEqual([item['id'] for item in scans], ['scan-fixture'])
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join()
