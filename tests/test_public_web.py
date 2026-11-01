import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from emuwatch.web import BoundedHTTPServer, _handler


class PublicWebTests(unittest.TestCase):
    def test_public_history_hidden_and_known_warning_works_without_github(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'EMUWATCH_PUBLIC':'1','EMUWATCH_STATE_DIR':temp}):
            with patch('emuwatch.web.GitHubClient.snapshot', side_effect=AssertionError('No live call expected')):
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
                    self.assertEqual(len(get('/api/reviewed')['repositories']),25)
                    for data in (b'[]', b'null', b'{"target":"owner/.."}'):
                        with self.subTest(data=data), self.assertRaises(HTTPError):
                            urlopen(Request(base+'/api/check-repo',data=data,headers={'Content-Type':'application/json'}),timeout=3)
                    with self.assertRaises(HTTPError):
                        urlopen(Request(base+'/api/check-repo',data=b'{}',headers={'Origin':'https://attacker.test'}),timeout=3)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()
