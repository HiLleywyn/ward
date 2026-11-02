import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ward.evidence import ResultStore


class WorkerHeartbeatTests(unittest.TestCase):
    def test_active_analysis_renews_heartbeat_and_stops_on_exit(self):
        from ward.analysis_worker import analysis_heartbeat
        with tempfile.TemporaryDirectory() as directory:
            store = ResultStore(Path(directory) / 'state.db')
            renewed = threading.Event()
            original = store.analyses.heartbeat
            calls = []
            def heartbeat(engine):
                original(engine)
                calls.append(engine)
                if len(calls) > 1:
                    renewed.set()
            with patch.object(store.analyses, 'heartbeat', side_effect=heartbeat):
                with analysis_heartbeat(store.analyses, interval=0.01):
                    self.assertTrue(renewed.wait(1))
                    self.assertTrue(store.analyses.workers()['remnux']['available'])
                count = len(calls)
                self.assertGreaterEqual(count, 2)
                # A dead controller must expire, even if its previous job remains running.
                with store.connect() as connection:
                    connection.execute("UPDATE analysis_workers SET seen_at='2000-01-01T00:00:00+00:00'")
                self.assertFalse(store.analyses.workers()['remnux']['available'])
                self.assertEqual(len(calls), count)

    def test_heartbeat_has_a_deadline_even_if_analyzer_hangs(self):
        from ward.analysis_worker import analysis_heartbeat
        from unittest.mock import Mock
        queue = Mock()
        # Zero lifetime exercises the fail-closed deadline without waiting 200 seconds.
        with analysis_heartbeat(queue, interval=0.001, lifetime=0):
            pass
        self.assertEqual(queue.heartbeat.call_count, 1)

    def test_worker_wraps_claimed_analysis_and_stops_on_failure(self):
        from ward.analysis_worker import run_worker
        from unittest.mock import Mock
        store, keeper = Mock(), Mock()
        job = {'id': 'fixture', 'data': b'fixture', 'sha256': 'a' * 64, 'claim_token': 'claim'}
        store.analyses.claim.return_value = job
        def analyze(data, **kwargs):
            if data != job['data']:
                return {'sha256': kwargs['expected_sha256'], 'isolation': {'sample_executed': False}}
            self.assertTrue(keeper.__enter__.called)
            raise ValueError('fixture timeout')
        from unittest.mock import MagicMock
        keeper = MagicMock()
        with patch('ward.analysis_worker.default_store', return_value=store), \
             patch('ward.analysis_worker.analyze_remnux', side_effect=analyze), \
             patch('ward.analysis_worker.analysis_heartbeat', return_value=keeper):
            run_worker(once=True)
        keeper.__exit__.assert_called_once()
        store.analyses.finish.assert_called_once_with('fixture', 'claim', error='fixture timeout')
