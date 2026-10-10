import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('summary', Path(__file__).with_name('summarize-test-results.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('capture-tests.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class SafeTestEvidence(unittest.TestCase):
    def collect(self, content):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text(content)
            return summary.summarize(root, {'crates/vera-e2e/tests/case.rs': 100})

    def test_capture_preserves_argv_exit_code_and_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'fixture.py'
            runner.write_text('import sys\nprint("private-output")\n'
                              'assert sys.argv[1:] == ["--", "--exact", "case with spaces"]\n'
                              'sys.exit(101)\n')
            command = [sys.executable, str(runner), '--', '--exact', 'case with spaces']
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('capture-tests.py')),
                                     '--logs', str(root / 'logs'), *command],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 101)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr, '')
            self.assertEqual((root / 'logs/test-exit-code').read_text(), '101\n')
            self.assertEqual((root / 'logs/test-output.log').read_text(), 'private-output\n')
            self.assertEqual((root / 'logs/test-output.log').stat().st_mode & 0o777, 0o600)
            evidence = summary.summarize(root / 'logs', {})
            self.assertEqual(evidence['runner_exit_code'], 101)
            self.assertNotIn('private-output', json.dumps(evidence))

    def test_capture_rejects_redirected_output_before_running_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            retained = root / 'retained'
            retained.write_text('private material')
            (root / 'test-output.log').symlink_to(retained)
            with patch.object(capture.subprocess, 'run') as run:
                with self.assertRaises(OSError):
                    capture.capture(root, ['fixture-runner'])
                run.assert_not_called()
            self.assertEqual(retained.read_text(), 'private material')

    def test_capture_maps_signal_exit_without_publishing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(capture.subprocess, 'run', return_value=subprocess.CompletedProcess([], -9)):
                self.assertEqual(capture.capture(root, ['fixture-runner']), 137)
            self.assertEqual((root / 'test-exit-code').read_text(), '137\n')

    def test_counts_and_known_locations_exclude_private_messages(self):
        evidence = self.collect("thread 'private_actor' panicked at crates/vera-e2e/tests/case.rs:23:4:\n"
                                "private_key=secret-value endpoint=http://private.example\n"
                                "test result: FAILED. 2 passed; 1 failed; 3 ignored;\n")
        self.assertEqual(evidence['source_locations'], [{'file': 'crates/vera-e2e/tests/case.rs', 'line': 23, 'column': 4}])
        self.assertEqual(evidence['test_results'], [{'passed': 2, 'failed': 1, 'ignored': 3, 'success': False}])
        public = json.dumps(evidence)
        for secret in ('private_actor', 'secret-value', 'private.example', 'private_key'):
            self.assertNotIn(secret, public)

    def test_unknown_paths_and_impossible_positions_are_not_exported(self):
        evidence = self.collect('/secret/key.rs:1:1 crates/private/key.rs:1:1\n'
                                'crates/vera-e2e/tests/case.rs:101:1\n'
                                'crates/vera-e2e/tests/case.rs:0:1\n'
                                'crates/vera-e2e/tests/case.rs:1:0\n')
        self.assertEqual(evidence['source_locations'], [])

    def test_locations_are_deduplicated_and_bounded(self):
        evidence = self.collect('crates/vera-e2e/tests/case.rs:1:1\n' * 200 +
                                ''.join(f'crates/vera-e2e/tests/case.rs:{n}:1\n' for n in range(2, 30)))
        self.assertEqual(len(evidence['source_locations']), summary.MAX_LOCATIONS)
        self.assertTrue(evidence['location_limit_reached'])

    def test_only_log_files_are_read_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text('test result: ok. 1 passed; 0 failed; 0 ignored;\n')
            (root / 'validator.key').write_text('secret-key')
            (root / 'secrets.json').write_text('secret-dkg')
            logs = root / 'node0/logs'
            logs.mkdir(parents=True)
            (logs / 'stdout.log').symlink_to(root / 'validator.key')
            (logs / 'stderr.log').write_text('private plaintext\n')
            evidence = summary.summarize(root, {})
            self.assertEqual(evidence['files_read'], 2)
            self.assertEqual(evidence['files_unreadable'], 1)
            self.assertNotIn('secret', json.dumps(evidence))

    def test_tail_limits_keep_complete_recent_lines(self):
        with patch.object(summary, 'TAIL_BYTES', 96):
            evidence = self.collect('discarded private data\n' * 100 +
                                    'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n')
        self.assertEqual(evidence['tails_truncated'], 1)
        self.assertEqual(evidence['test_results'][0]['failed'], 1)

    def test_result_and_file_limits_are_explicit(self):
        with patch.object(summary, 'MAX_FILES', 1), patch.object(summary, 'MAX_RESULTS', 2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'test-output.log').write_text('test result: ok. 1 passed; 0 failed; 0 ignored;\n' * 3)
                logs = root / 'node0/logs'
                logs.mkdir(parents=True)
                (logs / 'stdout.log').write_text('private\n')
                evidence = summary.summarize(root, {})
                self.assertEqual(len(evidence['test_results']), 2)
                self.assertTrue(evidence['result_limit_reached'])
                self.assertTrue(evidence['file_limit_reached'])

    def test_exit_code_is_numeric_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text('')
            for value in ('0\n', '101\n', '255'):
                (root / 'test-exit-code').write_text(value)
                self.assertEqual(summary.summarize(root, {})['runner_exit_code'], int(value))
            for value in ('secret', '256', '-1', '0\nprivate'):
                (root / 'test-exit-code').write_text(value)
                evidence = summary.summarize(root, {})
                self.assertIsNone(evidence['runner_exit_code'])
                self.assertEqual(evidence['files_unreadable'], 1)

    def test_color_and_absolute_prefix_do_not_escape_path_filter(self):
        evidence = self.collect('\x1b[31m/private/operator/crates/vera-e2e/tests/case.rs:4:2\x1b[0m\n')
        self.assertEqual(evidence['source_locations'], [{'file': 'crates/vera-e2e/tests/case.rs', 'line': 4, 'column': 2}])
        self.assertNotIn('/private', json.dumps(evidence))


    def test_recovery_rpc_failure_evidence_is_closed_and_does_not_export_messages(self):
        evidence = self.collect('recovery_rpc_failure phase=restored kind=finality-unavailable replica=3\n'
                                'private key and endpoint information\n'
                                'recovery_rpc_failure phase=private kind=rpc-internal replica=0\n'
                                'recovery_rpc_failure phase=initial kind=private replica=0\n'
                                'recovery_rpc_failure phase=initial kind=rpc-internal replica=4\n'
                                'recovery_rpc_failure phase=initial kind=rpc-internal replica=30\n')
        self.assertEqual(evidence['recovery_rpc_failures'], [
            {'phase': 'restored', 'kind': 'finality-unavailable', 'replica': 3}])
        self.assertNotIn('private', json.dumps(evidence))

    def test_recovery_rpc_failure_evidence_deduplicates_and_bounds_records(self):
        with patch.object(summary, 'MAX_RPC_FAILURES', 1):
            evidence = self.collect('recovery_rpc_failure phase=initial kind=rpc-internal replica=0\n' * 2 +
                                    'recovery_rpc_failure phase=restored kind=rpc-internal replica=3\n')
            self.assertEqual(len(evidence['recovery_rpc_failures']), 1)
            self.assertTrue(evidence['recovery_rpc_failure_limit_reached'])



if __name__ == '__main__':
    unittest.main()
