"""Storage attribution preserves timing boundaries and never exports raw traces."""
import io
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from storage_attribution import closed_blob_span, closed_span, span_summary, syscall_summary, summarize_run


APPLY = '2026-10-06T00:00:00Z DEBUG vera_publication_diagnostics: finalized state apply height=12 database_apply_us=12000 publication_us=10\n'
START = '2026-10-06T00:00:01Z DEBUG vera_publication_diagnostics: finalized state synchronization started height=Some(12) sync_start_us=100000\n'
FINALIZE = 'stateful.db.finalize{index=3}: commonware_glue::stateful::db: close time.busy=2ms time.idle=10ms\n'
ANY = ('stateful.db.finalize{index=3}:qmdb.current.db.start_sync:'
       'qmdb.any.db.start_sync{db_size=3}: commonware_storage::qmdb::any::db: close '
       'time.busy=100ns time.idle=12µs\n')
WRITE = 'utils.rwlock.write{lock="stateful.db.3"}: commonware_utils::sync: close time.busy=3us time.idle=1s\n'

BLOB_WRITE = ('runtime.storage.blob.write_at{partition=/private/secret bytes=32 options=DONT_CACHE}: '
              'commonware_runtime::storage::metered: close time.busy=5µs time.idle=3ms\n')
BLOB_START = ('runtime.storage.blob.start_sync{partition=private-payload}: '
              'commonware_runtime::storage::metered: close time.busy=2us time.idle=100ns\n')
BLOB_COMPLETE = ('runtime.storage.blob.start_sync{partition=private-payload}:'
                 'runtime.storage.blob.sync{partition=private-payload}: '
                 'commonware_runtime::storage::metered: close time.busy=1ms time.idle=2s\n')


class StorageAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.descriptor = self.root / 'clusters' / 'run' / 'node0' / 'private-payload'

    def call(self, pid, syscall, seconds, result='0', path=None):
        return f'{pid} 1791244800.000001 {syscall}(17<{path or self.descriptor}>) = {result} <{seconds}>\n'

    def test_complete_execution_windows_exclude_bootstrap_and_incomplete_revisions(self):
        other_start = START.replace('Some(12)', 'Some(13)')
        result = span_summary(io.StringIO(FINALIZE + APPLY + FINALIZE + ANY + WRITE + START
                                         + APPLY + FINALIZE + other_start + APPLY + FINALIZE))
        self.assertEqual(result['completed_finalization_windows'], 1)
        self.assertEqual(result['discarded_windows'], 2)
        self.assertEqual(result['spans_outside_windows'], 1)
        groups = {row['operation']: row for row in result['groups']}
        self.assertEqual(set(groups), {'write', 'finalize', 'start_sync'})
        self.assertEqual(groups['finalize']['elapsed'], {'count': 1, 'p50_ms': 12, 'p95_ms': 12,
                                                       'p99_ms': 12, 'max_ms': 12})
        self.assertAlmostEqual(groups['start_sync']['elapsed']['p50_ms'], .0121)
        self.assertAlmostEqual(groups['write']['elapsed']['p50_ms'], 1000.003)
        self.assertEqual(groups['write']['partition'], 'acp')

    def test_retained_completion_children_expose_missing_finalize_window_coverage(self):
        persistent = ''.join(FINALIZE.replace('index=3', f'index={index}') for index in range(7))
        first = APPLY + persistent + START
        complete = span_summary(io.StringIO(first))
        self.assertTrue(complete['persistent_finalize_window_coverage_complete'])
        self.assertEqual(complete['persistent_finalize_window_samples'], 7)
        self.assertEqual(complete['incomplete_persistent_finalize_windows'], 0)
        # Persistent parents close after the window when returned completion children retain them.
        second = APPLY + FINALIZE.replace('index=3', 'index=7') + START + BLOB_COMPLETE + persistent
        retained = span_summary(io.StringIO(first + second))
        self.assertEqual(retained['completed_finalization_windows'], 2)
        self.assertFalse(retained['persistent_finalize_window_coverage_complete'])
        self.assertEqual(retained['incomplete_persistent_finalize_windows'], 1)
        self.assertEqual(retained['persistent_finalize_window_samples'], 7)
        self.assertEqual(retained['spans_outside_windows'], 7)
        self.assertEqual(retained['blob_groups'][0]['operation'], 'sync')

    def test_child_close_is_not_double_counted_and_bad_units_fail(self):
        current = ('stateful.db.finalize{index=3}:qmdb.current.db.start_sync: '
                   'commonware_storage::qmdb::current::db: close time.busy=1ms time.idle=2ms\n')
        self.assertIsNone(closed_span(current))
        self.assertEqual(closed_span(ANY)[0], 'start_sync')
        with self.assertRaises(ValueError):
            closed_span(WRITE.replace('1s', '1fortnight'))
        with self.assertRaises(ValueError):
            closed_span(WRITE.replace('time.idle=1s', 'time.busy=1s'))

    def test_blob_spans_cover_bootstrap_and_late_completion_outside_revision_windows(self):
        result = span_summary([BLOB_WRITE, APPLY, FINALIZE, BLOB_START, START, BLOB_COMPLETE])
        self.assertEqual(result['completed_finalization_windows'], 1)
        groups = {row['operation']: row for row in result['blob_groups']}
        self.assertEqual(set(groups), {'write_at', 'start_sync', 'sync'})
        for row in groups.values():
            self.assertEqual(row['elapsed']['count'], 1)
            self.assertEqual(set(row), {'operation', 'elapsed', 'busy', 'idle'})
        self.assertAlmostEqual(groups['write_at']['elapsed']['p50_ms'], 3.005)
        self.assertAlmostEqual(groups['start_sync']['elapsed']['p50_ms'], .0021)
        self.assertEqual(groups['sync']['elapsed']['p50_ms'], 2001)
        self.assertEqual([row['operation'] for row in result['groups']], ['finalize'])
        self.assertNotIn('private', json.dumps(result))

    def test_blob_close_matches_only_emitting_operation_and_target(self):
        self.assertEqual(closed_blob_span(BLOB_COMPLETE)[0], 'sync')
        fieldless = ('runtime.storage.blob.sync: commonware_runtime::storage::metered: '
                     'close time.busy=1µs time.idle=2ms\n')
        self.assertEqual(closed_blob_span(fieldless), ('sync', .001, 2))
        for line in (BLOB_COMPLETE.replace('::metered:', '::tokio:'),
                     BLOB_COMPLETE.replace('runtime.storage.blob.sync{', 'some.child{'),
                     BLOB_WRITE.replace('.write_at{', '.resize{')):
            self.assertIsNone(closed_blob_span(line))
        for line in (BLOB_WRITE.replace('3ms', 'NaNms'),
                     BLOB_COMPLETE.replace('time.idle=2s', 'time.busy=2s')):
            with self.assertRaises(ValueError):
                closed_blob_span(line)

    def test_publication_scalars_are_separate_from_spans_and_duplicate_target(self):
        durable = ('DEBUG vera_publication_diagnostics: finalized state durability completed '
                   'height=Some(12) durable=true wait_us=2000 since_finalize_us=150000\n')
        published = ('DEBUG vera_publication_diagnostics: finalized revision publication '
                     'height=12 transactions=2 lookup_us=3000 history_us=17000 index_us=500\n')
        completed = ('DEBUG vera_publication_diagnostics: finalized sink completed '
                     'height=12 total_us=23000\n')
        lines = [APPLY, FINALIZE, START, published, durable, completed]
        result = span_summary(lines + [line.replace('vera_publication_diagnostics:', 'vera_diagnostics:')
                                       for line in lines if 'vera_publication_diagnostics:' in line])
        self.assertEqual(result['completed_finalization_windows'], 1)
        self.assertFalse(result['persistent_finalize_window_coverage_complete'])
        self.assertTrue(all(count == 1 for count in result['publication_event_counts'].values()))
        fields = {row['field']: row for row in result['publication_groups']}
        expected = {'database_apply_us': 12, 'publication_us': .01, 'sync_start_us': 100,
                    'wait_us': 2, 'since_finalize_us': 150, 'lookup_us': 3, 'history_us': 17,
                    'index_us': .5, 'total_us': 23}
        self.assertEqual(set(fields), set(expected))
        for name, value in expected.items():
            self.assertEqual(fields[name]['count'], 1)
            self.assertEqual(fields[name]['p50_ms'], value)
        self.assertEqual(result['durability_outcomes'], {'durable': 1, 'not_durable': 0})

    def test_failed_durability_and_missing_events_are_not_successes_or_zero_latency(self):
        prefix = 'DEBUG vera_publication_diagnostics: finalized state durability completed '
        result = span_summary([
            prefix + 'height=Some(12) durable=true wait_us=1000 since_finalize_us=4000\n',
            prefix + 'height=None durable=false wait_us=9000 since_finalize_us=12000\n',
        ])
        self.assertEqual(result['durability_outcomes'], {'durable': 1, 'not_durable': 1})
        self.assertEqual(result['publication_unknown_height_events'], 1)
        self.assertEqual(result['publication_event_counts']['synchronization_started'], 0)
        groups = {(row['field'], row['outcome']): row for row in result['publication_groups']}
        self.assertEqual(groups['wait_us', 'durable']['p50_ms'], 1)
        self.assertEqual(groups['wait_us', 'not_durable']['p50_ms'], 9)
        self.assertNotIn(('sync_start_us', 'observed'), groups)
        empty = span_summary([])
        self.assertEqual(empty['publication_groups'], [])
        self.assertFalse(empty['persistent_finalize_window_coverage_complete'])

    def test_malformed_publication_fields_fail_without_echoing_private_values(self):
        bad = [START.replace(' sync_start_us=100000', ''),
               START.replace('sync_start_us=100000', 'sync_start_us=1 sync_start_us=2'),
               START.replace('Some(12)', 'Some(18446744073709551616)'),
               START.replace('Some(12)', '12'),
               START.replace('sync_start_us=100000', 'sync_start_us= sync_start_us=2'),
               APPLY.replace('height=12', 'height=None')]
        for value in ('NaN', 'inf', '-1', '1.5', '1ms', '1e3', str(1 << 128), '/private/secret'):
            bad.append(START.replace('100000', value))
        bad.append('DEBUG vera_publication_diagnostics: finalized state durability completed '
                   'height=Some(12) durable=unknown wait_us=0 since_finalize_us=1\n')
        for line in bad:
            with self.subTest(line=line), self.assertRaises(ValueError) as raised:
                span_summary([line])
            self.assertNotIn('/private/secret', str(raised.exception))

    def test_interleaved_resumed_syscalls_use_total_seconds_and_preserve_failures(self):
        lines = [f'31 1791244800.1 fdatasync(17<{self.descriptor}> <unfinished ...>\n',
                 self.call(32, 'fsync', '0.000020'),
                 '31 1791244800.2 <... fdatasync resumed>) = 0 <0.123456>\n',
                 self.call(31, 'fdatasync', '1.000000', '-1 EIO (Input/output error)'),
                 f'32 1791244801.0 fsync(17<{self.descriptor} (deleted)> <unfinished ...>\n']
        result = syscall_summary(lines, self.root)
        groups = {(r['syscall'], r['outcome']): r for r in result['groups']}
        self.assertAlmostEqual(groups['fdatasync', 'success']['p50_ms'], 123.456)
        self.assertAlmostEqual(groups['fsync', 'success']['p50_ms'], .020)
        self.assertEqual(groups['fdatasync', 'error']['max_ms'], 1000)
        self.assertEqual(result['failed_calls'], 1)
        self.assertEqual(result['unfinished_calls'], 1)
        self.assertNotIn('private-payload', json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_resumed_descriptor_and_interrupted_result_are_preserved(self):
        lines = ['31 1791244800.1 fsync(17 <unfinished ...>\n',
                 f'31 1791244800.2 <... fsync resumed> <{self.descriptor}>) = ? ERESTARTSYS (To be restarted) <0.100000>\n']
        result = syscall_summary(lines, self.root)
        self.assertEqual(result['interrupted_calls'], 1)
        self.assertEqual(result['failed_calls'], 0)
        self.assertEqual(result['unattributed_calls'], 0)
        self.assertEqual(result['groups'][0]['outcome'], 'interrupted')
        self.assertEqual(result['groups'][0]['max_ms'], 100)
        lines[1] = lines[1].replace(str(self.descriptor), str(self.root.parent / 'foreign'))
        with self.assertRaises(ValueError):
            syscall_summary(lines, self.root)

    def test_directory_syncs_within_private_root_are_valid(self):
        node = self.root / 'clusters' / 'run' / 'node0'
        lines = [self.call(31, 'fsync', '0.001', path=node),
                 self.call(31, 'fsync', '0.002', path=node.parent),
                 self.call(31, 'fsync', '0.003', path=self.root)]
        result = syscall_summary(lines, self.root)
        groups = {row['node']: row for row in result['groups']}
        self.assertEqual(groups[0]['count'], 1)
        self.assertEqual(groups[0]['p50_ms'], 1)
        self.assertEqual(groups[None]['count'], 2)
        self.assertEqual(result['unattributed_calls'], 2)
        self.assertEqual(result['failed_calls'], 0)

    def test_orphan_wrong_resume_and_missing_duration_are_not_successful_samples(self):
        for lines in [
            ['31 1791244800.2 <... fsync resumed>) = 0 <0.2>\n'],
            [f'31 1791244800.1 fsync(17<{self.descriptor}> <unfinished ...>\n',
             '31 1791244800.2 <... fdatasync resumed>) = 0 <0.2>\n'],
            [self.call(31, 'fsync', 'NaN')],
        ]:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                syscall_summary(lines, self.root)
        unknown = syscall_summary(['31 1791244800.2 fsync(17) = 0 <0.2>\n'], self.root)
        self.assertEqual(unknown['unattributed_calls'], 1)
        self.assertIsNone(unknown['groups'][0]['node'])

    def test_descriptor_paths_cannot_escape_run_root_even_on_unfinished_calls(self):
        paths = [self.root.parent / 'foreign', self.root / 'clusters' / '..' / 'foreign']
        external = self.root / 'external'
        external.symlink_to(self.root.parent, target_is_directory=True)
        paths.append(external / 'foreign')
        for path in paths:
            for suffix in (' = 0 <0.001>', ' <unfinished ...>'):
                line = f'31 1791244800.1 fsync(17<{path}>){suffix}\n'
                with self.subTest(path=path, suffix=suffix), self.assertRaises(ValueError):
                    syscall_summary([line], self.root)

    def publication_run(self):
        events = [APPLY, START,
                  'DEBUG vera_publication_diagnostics: finalized state durability completed '
                  'height=Some(12) durable=true wait_us=2000 since_finalize_us=150000\n',
                  'DEBUG vera_publication_diagnostics: finalized revision publication '
                  'height=12 lookup_us=3000 history_us=17000 index_us=500\n',
                  'DEBUG vera_publication_diagnostics: finalized sink completed height=12 total_us=23000\n']
        for node in range(4):
            path = self.root / 'clusters' / 'run' / f'node{node}' / 'logs' / 'stdout.log'
            path.parent.mkdir(parents=True)
            path.write_text('untrusted /private/secret\n' + ''.join(events))
        return events

    def test_publication_only_cli_accepts_events_without_claiming_span_or_syscall_evidence(self):
        self.publication_run()
        output = self.root / 'summary.json'
        command = [sys.executable, str(Path(__file__).with_name('storage_attribution.py')),
                   '--publication-only', '--run-root', str(self.root), '--output', str(output)]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(output.read_text())
        self.assertEqual(result['summary_scope'], 'publication_only')
        self.assertIsNone(result['syscalls'])
        self.assertEqual(set(result['private_input_sha256']), {f'node{node}_stdout' for node in range(4)})
        for node in result['nodes']:
            self.assertTrue(all(count == 1 for count in node['publication_event_counts'].values()))
            self.assertEqual(node['durability_outcomes'], {'durable': 1, 'not_durable': 0})
            self.assertEqual(node['completed_finalization_windows'], 1)
            for field in ('groups', 'blob_groups', 'spans_outside_windows',
                          'persistent_finalize_window_samples', 'incomplete_persistent_finalize_windows',
                          'persistent_finalize_window_coverage_complete'):
                self.assertIsNone(node[field])
            timing = next(row for row in node['publication_groups'] if row['field'] == 'wait_us')
            self.assertEqual(timing['p50_ms'], 2)
        for private in ('untrusted', '/private/secret', str(self.root)):
            self.assertNotIn(private, output.read_text())

    def test_publication_only_requires_each_lifecycle_event_on_each_node(self):
        events = self.publication_run()
        path = self.root / 'clusters/run/node3/logs/stdout.log'
        for excluded in range(len(events)):
            path.write_text(''.join(event for index, event in enumerate(events) if index != excluded))
            with self.subTest(excluded=excluded), self.assertRaises(ValueError):
                summarize_run(self.root, publication_only=True)
        path.unlink()
        with self.assertRaises(ValueError):
            summarize_run(self.root, publication_only=True)

    def test_default_mode_still_rejects_missing_syscalls_with_complete_publication_events(self):
        self.publication_run()
        output = self.root / 'summary.json'
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name('storage_attribution.py')),
             '--run-root', str(self.root), '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(output.exists())
        self.assertNotIn(str(self.root), completed.stderr)

    def create_run(self):
        for node in range(4):
            path = self.root / 'clusters' / 'run' / f'node{node}' / 'logs' / 'stdout.log'
            path.parent.mkdir(parents=True)
            path.write_text('untrusted text and /private/secret/config\n' + FINALIZE
                            + APPLY + FINALIZE + ANY + WRITE + START + BLOB_COMPLETE)
        (self.root / 'syscalls.log').write_text(self.call(31, 'fsync', '0.001'))

    def test_summary_has_numeric_observations_and_hashes_but_no_arbitrary_log_text(self):
        self.create_run()
        result = summarize_run(self.root)
        encoded = json.dumps(result)
        self.assertEqual(len(result['nodes']), 4)
        self.assertEqual(len(result['private_input_sha256']), 5)
        self.assertEqual(result['nodes'][0]['blob_groups'][0]['operation'], 'sync')
        for private in ('private-payload', '/private/secret', 'untrusted', str(self.root)):
            self.assertNotIn(private, encoded)

    def test_symlinked_log_or_trace_outside_run_root_is_rejected(self):
        self.create_run()
        for name in ('clusters/run/node0/logs/stdout.log', 'syscalls.log'):
            path = self.root / name
            original = path.read_text()
            path.unlink()
            path.symlink_to(self.root.parent / 'foreign')
            with self.subTest(name=name), self.assertRaises(ValueError):
                summarize_run(self.root)
            path.unlink()
            path.write_text(original)


if __name__ == '__main__':
    unittest.main()
