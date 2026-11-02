import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(sys.platform.startswith('linux'), 'Worker runs inside Linux REMnux')
class RemnuxOutputTests(unittest.TestCase):
    def test_nonzero_exit_keeps_stdout_and_stderr_separate(self):
        from ward.remnux_worker import run_tool
        result = run_tool('clamav', [sys.executable, '-c',
            "import sys; print('sample: Test.Signature FOUND'); print('parser warning',file=sys.stderr); sys.exit(1)"], 5)
        self.assertEqual(result['exit_code'], 1)
        self.assertIn('Test.Signature FOUND', result['output'])
        self.assertEqual(result['warnings'], 'parser warning')

    def test_matches_survive_warnings_errors_and_output_limits(self):
        from ward.remnux_worker import analyze, run_tool
        for exit_code, limit in ((1, 1024), (2, 1024), (1, 64)):
            with self.subTest(exit_code=exit_code, limit=limit), tempfile.TemporaryDirectory() as directory:
                database = Path(directory) / 'fixture.cvd'
                database.write_bytes(b'ClamAV-VDB:02 Nov 2026:1:10:')
                def tool(name, command, timeout):
                    if name != 'clamav':
                        return {'name': name, 'status': 'completed', 'output': 'text'}
                    return run_tool(name, [sys.executable, '-c',
                        f"import sys; print('sample: Test.Signature FOUND'); print('x'*100); print('parser warning',file=sys.stderr); sys.exit({exit_code})"], 5)
                with patch('ward.remnux_worker.Path.glob', return_value=[database]), \
                     patch('ward.remnux_worker.Path.write_bytes'), \
                     patch('ward.remnux_worker.run_tool', side_effect=tool), \
                     patch('ward.remnux_worker.MAX_OUTPUT', limit):
                    report = analyze(b'harmless fixture')
                engine = next(item for item in report['engines'] if item['name'] == 'clamav')
                self.assertEqual(engine['detections'], ['Test.Signature'])
                self.assertEqual(engine['status'], 'partial')
                self.assertEqual(engine['exit_code'], exit_code)
                self.assertEqual(report['coverage'], 'partial')

    def test_no_match_with_error_remains_a_failure(self):
        from ward.remnux_worker import analyze
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'fixture.cvd'
            database.write_bytes(b'ClamAV-VDB:02 Nov 2026:1:10:')
            with patch('ward.remnux_worker.Path.glob', return_value=[database]), \
                 patch('ward.remnux_worker.Path.write_bytes'), \
                 patch('ward.remnux_worker.run_tool', side_effect=lambda name, *args: {
                     'name': name, 'status': 'failed', 'exit_code': 2, 'output': '', 'warnings': 'parser error'}):
                report = analyze(b'harmless fixture')
        engine = next(item for item in report['engines'] if item['name'] == 'clamav')
        self.assertEqual(engine['detections'], [])
        self.assertEqual(engine['status'], 'failed')
