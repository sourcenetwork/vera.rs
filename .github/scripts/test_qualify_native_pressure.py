import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'pressure', Path(__file__).with_name('qualify-native-pressure.py'))
pressure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pressure)
runner_spec = importlib.util.spec_from_file_location(
    'pressure_runner', Path(__file__).with_name('run-native-pressure.py'))
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


def fixture():
    pids = [11, 12, 13, 14]
    rows = [{'kind': 'resource_configuration', 'node_pids': pids,
             'process_io_source': 'linux_proc_io'}]
    rows.extend({'kind': 'pressure_phase', 'phase': phase, 'elapsed_seconds': time}
                for phase, time in zip(pressure.PHASES, (.1, 1, 31, 39.5)))
    for time in range(40):
        rows.append({'kind': 'resources', 'elapsed_seconds': time,
                     'sample': {'rows': '\n'.join(
                         f'{pid} {12000 + time} 00:00:{time:02}' for pid in pids[:2]),
                                'process_io': [
                                    {'pid': pid, 'availability': 'complete',
                                     'read_bytes': time * 100, 'write_bytes': time * 200,
                                     'cancelled_write_bytes': 0, 'private': 'do-not-export'}
                                    for pid in pids[:2]]}})
    rows.extend({'kind': 'storage', 'phase': phase, 'node': node,
                 'logical_bytes': 1000, 'allocated_file_bytes': 4096,
                 'regular_files': 2, 'error': None}
                for phase in pressure.STORAGE_PHASES for node in range(4))
    rows.append({'kind': 'pressure_result', 'admitted': 4096, 'confirmed': 4097,
                 'workers': 1, 'worker_recoveries': [
                     {'worker': 0, 'confirmed': 4096, 'backlog_tail_observed_ms': 500}],
                 'rejected': 1200, 'reconciled_replicas': 4,
                 'pending_wire_bytes': 2 * 1024 * 1024, 'recovery_ms': 8500,
                 'rejection_ms': [1.5] * 1200, 'final_node_pids': [11, 12, 15, 16]})
    return rows


class PressureQualification(unittest.TestCase):
    def test_multiworker_tail_coverage_and_counts(self):
        rows = fixture()
        rows[-1].update(workers=4, worker_recoveries=[
            {'worker': worker, 'confirmed': 1024, 'backlog_tail_observed_ms': 500 + 10 * worker}
            for worker in range(4)])
        result = pressure.qualify(rows, pressure.MULTIWORKER_CASE)
        self.assertEqual(result['workers'], 4)
        self.assertEqual(result['backlog_tail_spread_ms'], 30)
        self.assertEqual(sum(row['confirmed'] for row in result['worker_recoveries']), 4096)
        with self.assertRaises(ValueError):
            pressure.qualify(rows)
        for change in ('missing', 'duplicate', 'short', 'late', 'boolean'):
            records = json.loads(json.dumps(rows))
            workers = records[-1]['worker_recoveries']
            if change == 'missing': workers.pop()
            elif change == 'duplicate': workers[-1]['worker'] = 0
            elif change == 'short': workers[-1]['confirmed'] = 1023
            elif change == 'late': workers[-1]['backlog_tail_observed_ms'] = 8501
            else: workers[-1]['worker'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                pressure.qualify(records, pressure.MULTIWORKER_CASE)

    def test_reports_only_survivors_with_explicit_scope_and_numeric_data(self):
        result = pressure.qualify(fixture())
        self.assertTrue(result['qualified'])
        self.assertEqual(len(result['resources']['saturated']['process']['members']), 2)
        self.assertEqual(result['resources']['saturated']['process']['members'][0]['samples'], 30)
        self.assertEqual(result['rejection_ms']['p95'], 1.5)
        self.assertNotIn('do-not-export', json.dumps(result))
        self.assertEqual(len(result['storage']), 12)

    def test_rejects_partial_outcomes_and_invalid_timing(self):
        for field, value in [('confirmed', 4096), ('rejected', 1199),
                             ('admitted', True), ('reconciled_replicas', 3),
                             ('pending_wire_bytes', (64 << 20) + 1),
                             ('rejection_ms', [float('nan')] * 1200)]:
            rows = fixture()
            rows[-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pressure.qualify(rows)

    def test_rejects_missing_short_or_sparse_saturation(self):
        for change in ('missing', 'short', 'sparse'):
            rows = fixture()
            if change == 'missing':
                rows = [row for row in rows if row.get('phase') != 'saturated']
            elif change == 'short':
                rows[3]['elapsed_seconds'] = 10
            else:
                rows = [row for row in rows if row['kind'] != 'resources'
                        or row['elapsed_seconds'] % 5 == 0]
            with self.subTest(change=change), self.assertRaises(ValueError):
                pressure.qualify(rows)

    def test_rejects_survivor_restart_missing_sample_and_io_regression(self):
        for change in ('restart', 'missing', 'io'):
            rows = fixture()
            if change == 'restart':
                rows[-1]['final_node_pids'][0] = 99
            elif change == 'missing':
                rows[10]['sample']['rows'] = '11 10000 00:00:05'
            else:
                rows[10]['sample']['process_io'][0]['write_bytes'] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                pressure.qualify(rows)

    def test_fast_recovery_keeps_unobserved_cpu_and_io_explicit(self):
        rows = [row for row in fixture() if row['kind'] != 'resources'
                or row['elapsed_seconds'] < 32]
        rows[4]['elapsed_seconds'] = 32
        rows[-1]['recovery_ms'] = 1000
        result = pressure.qualify(rows)
        member = result['resources']['recovery']['process']['members'][0]
        self.assertEqual(member['samples'], 1)
        self.assertIsNone(member['observed_window'])
        self.assertIsNone(result['resources']['recovery']['io']['members'][0]['observed_window'])

    def test_accepts_only_the_exact_libtest_prefix_without_private_output(self):
        rows = pressure.records((f'test {pressure.CASE} ... '
                                 '{"kind":"pressure_phase","phase":"filling"}\n'
                                 'private-key=do-not-export\n'
                                 'test unknown_case ... {"kind":"pressure_result"}\n').encode())
        self.assertEqual(rows, [{'kind': 'pressure_phase', 'phase': 'filling'}])

    def test_late_provenance_failure_cannot_publish_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            node, runner, output = (root / name for name in ('node', 'runner', 'evidence.json'))
            node.write_bytes(b'node')
            runner.write_bytes(b'runner')
            manifest = {'exit_code': 0, 'source': 'a' * 40, 'runner_source': 'a' * 40,
                        'dirty': False, 'runner_dirty': False, 'history': 'regolith',
                        'trace_span_close': False,
                        'rust_log': 'warn,vera_storage=info',
                        'arguments': [pressure.CASE, '--exact', '--nocapture', '--test-threads=1'],
                        'node_sha256': hashlib.sha256(b'node').hexdigest(),
                        'runner_sha256': hashlib.sha256(b'runner').hexdigest(),
                        'platform': 'Linux', 'architecture': 'x86_64', 'logical_cpus': 4,
                        'cpu_model': ''}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            (root / 'workload.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in fixture()))
            with patch.object(sys, 'argv', ['qualify', '--directory', str(root),
                                           '--node', str(node), '--runner', str(runner),
                                           '--output', str(output)]), \
                    patch.object(pressure.subprocess, 'check_output', return_value='a' * 40):
                with self.assertRaises(SystemExit) as exit_code:
                    pressure.main()
            self.assertEqual(exit_code.exception.code, 1)
            self.assertEqual(json.loads(output.read_text()),
                             {'qualified': False, 'failure_stage': 'validation'})


class CargoExecutableSelection(unittest.TestCase):
    def test_setup_failure_retains_an_explicit_unqualified_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            metadata, output = root / 'build.jsonl', root / 'evidence.json'
            metadata.write_text('')
            with patch.object(sys, 'argv', ['run', '--build-metadata', str(metadata),
                                           '--directory', str(root / 'measurement'),
                                           '--logs', str(root / 'logs'),
                                           '--output', str(output)]), self.assertRaises(ValueError):
                runner.main()
            self.assertEqual(json.loads(output.read_text()),
                             {'qualified': False, 'failure_stage': 'setup', 'case': pressure.CASE})

    def test_selects_the_reported_release_fixture_and_ignores_other_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / 'target/release/deps/native_pressure-123'
            target.parent.mkdir(parents=True)
            target.write_bytes(b'fixture')
            row = {'reason': 'compiler-artifact', 'target': {'name': 'native_pressure'},
                   'profile': {'test': True}, 'executable': str(target)}
            metadata = root / 'build.jsonl'
            metadata.write_text(json.dumps({'reason': 'build-finished'}) + '\n' + json.dumps(row))
            self.assertEqual(runner.executable(metadata, root), target)

    def test_rejects_missing_ambiguous_and_foreign_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            targets = [root / 'target/release/deps/native_pressure-123',
                       root / 'target/release/deps/native_pressure-456', root / 'foreign']
            targets[0].parent.mkdir(parents=True)
            for target in targets:
                target.write_bytes(b'fixture')
            def row(path):
                return {'reason': 'compiler-artifact', 'target': {'name': 'native_pressure'},
                        'profile': {'test': True}, 'executable': str(path)}
            metadata = root / 'build.jsonl'
            for selection in ([], targets[:2], targets[2:]):
                metadata.write_text('\n'.join(json.dumps(row(path)) for path in selection))
                with self.subTest(selection=selection), self.assertRaises(ValueError):
                    runner.executable(metadata, root)


if __name__ == '__main__':
    unittest.main()
