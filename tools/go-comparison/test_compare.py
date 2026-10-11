import copy
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from compare import PROOF_CASES, TAGS, compare
from paired import command, proof_cases


class MatchedRegistrationEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.host = {'comparison_id': 'a' * 32, 'github_run_id': '123', 'github_job': 'fixture',
                     'platform': 'Linux fixture', 'architecture': 'x86_64', 'logical_cpus': 4,
                     'runner_image': 'fixture-image'}
        self.identity = dict(self.host, format_version=1, count=2, rate=20, order=list(TAGS),
                             go={'source': '1' * 40, 'node_sha256': '2' * 64, 'driver_sha256': '3' * 64},
                             rust={'source': '4' * 40, 'node_sha256': '5' * 64, 'runner_sha256': '6' * 64})
        self.write('comparison.json', self.identity)
        for tag in TAGS:
            (self.root / tag).mkdir()
            side = 'go' if tag.startswith('go') else 'rust'
            manifest = dict(self.host, **self.identity[side])
            if side == 'go':
                manifest.update(status='passed', completed=2, count=2, worker_accounts=2, nodes=4,
                                arrivals_per_second=20, max_outstanding=128, permission_reads_per_write=0,
                                history='goleveldb', commit_timeout_ms=200, certified_execution_p95_ms=400,
                                duration_seconds=.4, completed_per_second=5,
                                reconciliation='all four replicas before and after all-node SIGKILL restart')
                self.lines(tag + '/observations.jsonl', [
                    dict(index=index, owner=f'did:example:{index}', status='completed', object=str(index),
                         hash='ab' * 32, height=1, certified_execution_ms=value)
                    for index, value in enumerate((300, 400))])
                self.write(tag + '/verification.json', {'passed': 14, 'cases': sorted(PROOF_CASES)})
                self.lines(tag + '/resources.jsonl', [{'at': 1, 'processes': [
                    {'pid': pid, 'rss_bytes': 1024 * 1024} for pid in range(100, 104)]}])
            else:
                manifest.update(exit_code=0, dirty=False, runner_dirty=False, runner_source='4' * 40, history='regolith')
                self.lines(tag + '/workload.jsonl', [
                    dict(kind='configuration', format_version=2, count=2, signer_count=2, nodes=4,
                         arrivals_per_second=20, max_outstanding=128, permission_reads_per_write=0,
                         fixed_update_objects=0, preset='Normal', runner_debug_assertions=False,
                         revisions_per_epoch=192, receipt_poll_ms=50, workload='certified_native_registrations',
                         simplex={'optimistic_views': 4, 'stall_timeout_ms': 5000, 'term_length': 16},
                         proposal_batch_wait_ms=100, pruning={'maintenance_interval': 64,
                             'retained_consensus_revisions': 256, 'retained_state_revisions': 0}),
                    dict(kind='summary', offered=2, completed_workflows=2, confirmed=2, verification_failures=0,
                         unknown=0, rejected=0, reverted=0, not_sent=0, confirmed_incomplete_workflows=0,
                         completed_workflows_per_second=5, elapsed_seconds=.4,
                         scheduled_to_certified_receipt_ms={'p95': 200}),
                    *[dict(kind='observation', index=index, object_id=str(index), outcome='confirmed',
                           verification_failure=False, error=None, scheduled_to_certified_receipt_ms=value)
                      for index, value in enumerate((100, 200))],
                    dict(kind='verification', verified=2, unresolved=0, replicas=4),
                    dict(kind='recovery', inspected_operations=2, receipt_mismatches=0, state_mismatches=0),
                    dict(kind='resource_configuration', node_pids=list(range(100, 104))),
                    dict(kind='resources', elapsed_seconds=1, sample={'rows': '\n'.join(
                         f'{pid} 1024 00:00:01' for pid in range(100, 104))}),
                ])
            self.write(tag + '/manifest.json', manifest)

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def lines(self, name, values):
        (self.root / name).write_text('\n'.join(json.dumps(value) for value in values))

    def change_manifest(self, tag, key, value):
        path = tag + '/manifest.json'
        manifest = json.loads((self.root / path).read_text())
        manifest[key] = value
        self.write(path, manifest)

    def test_all_four_passes_use_validated_raw_measurements(self):
        result = compare(self.root)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['observed_go_over_rust_p95_ratio'], 2)
        self.assertEqual(result['medians']['go']['completed_per_second'], 5)
        self.assertIn('not maximum capacity', result['scope'])

    def test_host_source_or_binary_mismatch_cannot_be_compared(self):
        original = json.loads((self.root / 'go2/manifest.json').read_text())
        for key, value in (('comparison_id', 'b' * 32), ('github_run_id', '999'),
                           ('logical_cpus', 8), ('source', '7' * 40), ('node_sha256', '8' * 64)):
            with self.subTest(key=key):
                self.write('go2/manifest.json', {**original, key: value})
                with self.assertRaises(ValueError):
                    compare(self.root)

    def test_actor_count_and_go_configuration_must_match(self):
        original = json.loads((self.root / 'go1/manifest.json').read_text())
        for key, value in (('worker_accounts', 1), ('arrivals_per_second', 10),
                           ('permission_reads_per_write', 1), ('commit_timeout_ms', 5000)):
            with self.subTest(key=key):
                self.write('go1/manifest.json', {**original, key: value})
                with self.assertRaisesRegex(ValueError, 'logical workload'):
                    compare(self.root)

    def test_failed_or_duplicate_raw_go_observation_overrides_success_summary(self):
        path = 'go1/observations.jsonl'
        original = [json.loads(line) for line in (self.root / path).read_text().splitlines()]
        for key, value in (('status', 'unconfirmed'), ('index', 1), ('owner', original[1]['owner']),
                           ('certified_execution_ms', float('nan'))):
            with self.subTest(key=key):
                rows = copy.deepcopy(original)
                rows[0][key] = value
                self.lines(path, rows)
                with self.assertRaises(ValueError):
                    compare(self.root)

    def test_forged_go_rate_or_latency_summary_cannot_override_observations(self):
        original = json.loads((self.root / 'go1/manifest.json').read_text())
        for key, value in (('duration_seconds', 1), ('completed_per_second', 500),
                           ('certified_execution_p95_ms', 1)):
            with self.subTest(key=key):
                self.write('go1/manifest.json', {**original, key: value})
                with self.assertRaises(ValueError):
                    compare(self.root)

    def test_missing_go_negative_proof_case_and_rust_recovery_fail(self):
        cases = sorted(PROOF_CASES)
        self.write('go1/verification.json', {'passed': 14, 'cases': cases[:-1] + [cases[0]]})
        with self.assertRaisesRegex(ValueError, 'proof rejection'):
            compare(self.root)
        self.write('go1/verification.json', {'passed': 14, 'cases': cases})
        rows = [json.loads(line) for line in (self.root / 'rust2/workload.jsonl').read_text().splitlines()]
        next(row for row in rows if row['kind'] == 'recovery')['state_mismatches'] = 1
        self.lines('rust2/workload.jsonl', rows)
        with self.assertRaisesRegex(ValueError, 'Rust fixture failed'):
            compare(self.root)

    def test_missing_signer_count_or_different_simplex_configuration_fails(self):
        path = 'rust1/workload.jsonl'
        original = [json.loads(line) for line in (self.root / path).read_text().splitlines()]
        for key, value in (('signer_count', None), ('simplex', {}), ('pruning', {})):
            with self.subTest(key=key):
                rows = copy.deepcopy(original)
                rows[0][key] = value
                self.lines(path, rows)
                with self.assertRaises(ValueError):
                    compare(self.root)

    def test_missing_or_changed_resource_participants_fail(self):
        self.lines('go2/resources.jsonl', [])
        with self.assertRaisesRegex(ValueError, 'missing Go resource'):
            compare(self.root)


class PairedProcessControl(unittest.TestCase):
    def test_proof_case_parser_requires_each_real_negative_case_without_duplicates(self):
        content = '\n'.join(f'--- PASS: TestCertifiedExecution/{name} (0.00s)' for name in PROOF_CASES)
        self.assertEqual(set(proof_cases(content)), PROOF_CASES)
        for invalid in ('', content + '\n--- PASS: TestCertifiedExecution/wrong_network (0.00s)'):
            with self.assertRaises(ValueError):
                proof_cases(invalid)

    def test_deadline_kills_the_owned_group_and_reaps_it(self):
        with tempfile.TemporaryDirectory() as directory:
            process = Mock(pid=42)
            process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 3), 0]
            with patch('paired.subprocess.Popen', return_value=process) as start, \
                    patch('paired.os.killpg') as kill:
                with self.assertRaises(subprocess.TimeoutExpired):
                    command(['fixture'], Path(directory), {}, Path(directory) / 'private.log', 3)
                self.assertTrue(start.call_args.kwargs['start_new_session'])
                kill.assert_called_once_with(42, signal.SIGKILL)
                self.assertEqual(process.wait.call_count, 2)


if __name__ == '__main__':
    unittest.main()
