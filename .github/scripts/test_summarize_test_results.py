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
    def collect(self, content, function_names=frozenset()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text(content)
            return summary.summarize(root, {'crates/vera-e2e/tests/case.rs': 100}, function_names)

    def test_netem_coverage_keeps_bounded_counts_without_private_suffixes(self):
        evidence = self.collect(
            'netem_coverage active=3 installed=4 uncovered=1\n'
            'netem_coverage active=3 installed=4 uncovered=1\n'
            'netem_coverage active=2 installed=4 uncovered=3\n'
            'netem_coverage active=4097 installed=4 uncovered=1\n'
            'netem_coverage active=3 installed=0 uncovered=1\n'
            'netem_coverage active=3 installed=4 uncovered=1 private-key\n')
        self.assertEqual(evidence['netem_coverage'], [{'active': 3, 'installed': 4, 'uncovered': 1}])
        self.assertNotIn('private-key', json.dumps(evidence))

    def test_netem_coverage_is_limited_and_excludes_node_log_text(self):
        evidence = self.collect(''.join(
            f'netem_coverage active={i + 1} installed=4 uncovered=1\n'
            for i in range(summary.MAX_NETEM_SAMPLES + 1)))
        self.assertEqual(len(evidence['netem_coverage']), summary.MAX_NETEM_SAMPLES)
        self.assertTrue(evidence['netem_coverage_limit_reached'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text('')
            logs = root / 'node0/logs'
            logs.mkdir(parents=True)
            (logs / 'stderr.log').write_text('netem_coverage active=3 installed=4 uncovered=1\n')
            self.assertEqual(summary.summarize(root, {})['netem_coverage'], [])

    def test_admission_progress_retains_only_bounded_numeric_runner_samples(self):
        evidence = self.collect(
            'native_admission_progress replica=0 nonce=2048 elapsed_ms=120001\n'
            'native_admission_progress replica=2 nonce=unavailable elapsed_ms=120003\n'
            'native_admission_progress replica=4 nonce=1 elapsed_ms=1\n'
            'native_admission_progress replica=0 nonce=18446744073709551616 elapsed_ms=1\n'
            'native_admission_progress replica=0 nonce=1 elapsed_ms=900001\n'
            'native_admission_progress replica=0 nonce=1 elapsed_ms=1 private-secret\n')
        self.assertEqual(evidence['admission_progress'], [
            {'replica': 0, 'native_nonce': 2048, 'elapsed_ms': 120001},
            {'replica': 2, 'native_nonce': None, 'elapsed_ms': 120003}])
        self.assertNotIn('private-secret', json.dumps(evidence))

    def test_admission_progress_is_bounded_and_excludes_application_logs(self):
        with patch.object(summary, 'MAX_ADMISSION_SAMPLES', 2):
            evidence = self.collect(''.join(
                f'native_admission_progress replica=0 nonce={nonce} elapsed_ms=1\n'
                for nonce in (1, 1, 2, 3)))
        self.assertEqual(len(evidence['admission_progress']), 2)
        self.assertTrue(evidence['admission_progress_limit_reached'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text('')
            logs = root / 'node0/logs'
            logs.mkdir(parents=True)
            (logs / 'stdout.log').write_text(
                'native_admission_progress replica=0 nonce=100 elapsed_ms=1\n')
            self.assertEqual(summary.summarize(root, {})['admission_progress'], [])

    def test_worker_progress_retains_worker_without_accepting_private_suffixes(self):
        evidence = self.collect(
            'native_admission_progress replica=1 nonce=1024 elapsed_ms=120002 worker=3\n'
            'native_admission_progress replica=2 nonce=unavailable elapsed_ms=120003 worker=0\n'
            'native_admission_progress replica=1 nonce=1 elapsed_ms=1 worker=4\n'
            'native_admission_progress replica=1 nonce=1 elapsed_ms=1 worker=0 private-key\n')
        self.assertEqual(evidence['admission_progress'], [
            {'replica': 1, 'worker': 3, 'native_nonce': 1024, 'elapsed_ms': 120002},
            {'replica': 2, 'worker': 0, 'native_nonce': None, 'elapsed_ms': 120003}])
        self.assertNotIn('private-key', json.dumps(evidence))

    def test_admission_state_keeps_unknowns_and_rejects_invalid_or_private_fields(self):
        valid = ('native_admission_state replica=2 worker=0 height=100 epoch=0 '
                 'view=101 peers=2 backfilling=false elapsed_ms=120001\n')
        unknown = ('native_admission_state replica=0 worker=3 height=unavailable epoch=unavailable '
                   'view=unavailable peers=unavailable backfilling=unavailable elapsed_ms=120004\n')
        evidence = self.collect(valid + unknown +
            valid.replace('height=100', 'height=18446744073709551616') +
            valid.replace('replica=2', 'replica=4') +
            valid.replace('worker=0', 'worker=4') +
            valid.replace('elapsed_ms=120001', 'elapsed_ms=900001') +
            valid.replace('backfilling=false', 'backfilling=private-key') +
            valid.rstrip() + ' private-key\n')
        self.assertEqual(evidence['admission_state'], [
            {'replica': 2, 'worker': 0, 'finalized_height': 100, 'finalized_epoch': 0,
             'current_view': 101, 'peer_count': 2, 'backfilling': False, 'elapsed_ms': 120001},
            {'replica': 0, 'worker': 3, 'finalized_height': None, 'finalized_epoch': None,
             'current_view': None, 'peer_count': None, 'backfilling': None, 'elapsed_ms': 120004}])
        with patch.object(summary, 'MAX_ADMISSION_SAMPLES', 1):
            bounded = self.collect(valid + valid + unknown)
        self.assertEqual(len(bounded['admission_state']), 1)
        self.assertTrue(bounded['admission_state_limit_reached'])
        self.assertNotIn('private-key', json.dumps(evidence))

    def test_cases_export_only_source_names_without_private_prefixes_or_reasons(self):
        evidence = self.collect('test private_actor::restores_revocations ... ok\n'
                                'test rejected_proof ... FAILED\n'
                                'test excluded_case ... ignored, private endpoint and key\n'
                                'test secret_value ... ok\n',
                                {'restores_revocations', 'rejected_proof', 'excluded_case'})
        self.assertEqual(evidence['test_cases'], [
            {'name': 'restores_revocations', 'status': 'ok'},
            {'name': 'rejected_proof', 'status': 'FAILED'},
            {'name': 'excluded_case', 'status': 'ignored'}])
        public = json.dumps(evidence)
        for private in ('private_actor', 'private endpoint', 'secret_value'):
            self.assertNotIn(private, public)

    def test_case_records_are_bounded_and_do_not_guess_interleaved_outcomes(self):
        with patch.object(summary, 'MAX_CASES', 2):
            evidence = self.collect('test known_case ... ok\n' * 3 +
                                    'test known_case ... private tracing output\nok\n', {'known_case'})
        self.assertEqual(len(evidence['test_cases']), 2)
        self.assertTrue(evidence['case_limit_reached'])
        evidence = self.collect('test known_case ... private tracing output\nok\n', {'known_case'})
        self.assertEqual(evidence['test_cases'], [])
        self.assertFalse(evidence['case_limit_reached'])

    def test_application_logs_cannot_add_runner_case_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test-output.log').write_text('test first_case ... ok\n')
            logs = root / 'node0/logs'
            logs.mkdir(parents=True)
            (logs / 'stdout.log').write_text('test other_case ... FAILED\n')
            evidence = summary.summarize(root, {}, {'first_case', 'other_case'})
            self.assertEqual(evidence['test_cases'], [{'name': 'first_case', 'status': 'ok'}])

    def test_source_name_inventory_does_not_read_untracked_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'case.rs'
            source.write_text('async fn actual_case() {}\nfn generic_case<T>() {}\n')
            (root / 'validator.key').write_text('fn private_secret() {}')
            names = summary.source_function_names(root, {'case.rs': 2})
            self.assertEqual(names, {'actual_case', 'generic_case'})

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

    def test_admission_page_failures_keep_only_static_classes(self):
        evidence = self.collect(
            'recovery_rpc_failure phase=admission-pages kind=server-capacity replica=0\n'
            'recovery_rpc_failure phase=admission-receipts kind=proof-invalid replica=1\n'
            'recovery_rpc_failure phase=admission-pages kind=private replica=2\n'
            'private proof bytes and endpoint information\n')
        self.assertEqual(evidence['recovery_rpc_failures'], [
            {'phase': 'admission-pages', 'kind': 'server-capacity', 'replica': 0},
            {'phase': 'admission-receipts', 'kind': 'proof-invalid', 'replica': 1}])
        self.assertNotIn('private', json.dumps(evidence))



if __name__ == '__main__':
    unittest.main()
