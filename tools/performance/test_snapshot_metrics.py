import contextlib
import datetime
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import snapshot_metrics as metrics


START = datetime.datetime(2026, 10, 9, 10, tzinfo=datetime.timezone.utc)


def snapshot(second=0, labels=''):
    return (
        '2026-10-09T10:00:%02d.000Z DEBUG vera_diagnostics: node resource snapshot '
        'runtime_metrics=# HELP buffer_bytes Resident buffer\n'
        '# TYPE buffer_bytes gauge\n'
        'buffer_bytes%s 4096\n'
        'counter_total 18446744073709551615\n'
        'elapsed_seconds 1.25e-3\n'
        '# EOF\n'
        ' history_memory_bytes={"block_cache": Some(2048), "memtables": Some(512), "table_readers": None} '
        'durable_height=42 '
        'index=IndexStats { cached_bytes: 8192, block_count: 21 } '
        'proofs=LightBlockStats { finalizations: 21 }\n'
    ) % (second, labels)


class SnapshotParser(unittest.TestCase):
    def test_multiline_prometheus_and_debug_fields(self):
        record = metrics.parse_snapshot(snapshot())
        self.assertEqual(record['durable_height'], 42)
        self.assertEqual(record['runtime_metrics.buffer_bytes'], 4096)
        self.assertEqual(record['runtime_metrics.counter_total'], 18446744073709551615)
        self.assertEqual(record['runtime_metrics.elapsed_seconds'], 0.00125)
        self.assertEqual(record['history_memory_bytes.block_cache'], 2048)
        self.assertIsNone(record['history_memory_bytes.table_readers'])
        self.assertEqual(record['index.cached_bytes'], 8192)
        self.assertEqual(record['proofs.finalizations'], 21)

    def test_distinct_labelled_series_do_not_export_label_values(self):
        labels = '{partition="private-partition"}'
        event = snapshot(labels=labels).replace('counter_total ', 'buffer_bytes{partition="other"} 1024\ncounter_total ')
        record = metrics.parse_snapshot(event)
        key = 'runtime_metrics.buffer_bytes.' + hashlib.sha256(labels.encode()).hexdigest()
        self.assertEqual(record[key], 4096)
        self.assertEqual(len([key for key in record if key.startswith('runtime_metrics.buffer_bytes.')]), 2)
        self.assertNotIn('private-partition', json.dumps(record))

    def test_missing_fields_invalid_metrics_and_non_finite_values_fail(self):
        for event in (snapshot().replace('durable_height=42 ', ''),
                      snapshot().replace('elapsed_seconds 1.25e-3', 'elapsed_seconds NaN'),
                      snapshot().replace('elapsed_seconds 1.25e-3', 'elapsed_seconds invalid'),
                      snapshot().replace('buffer_bytes 4096', 'buffer_bytes 4096\nbuffer_bytes 2048')):
            with self.subTest(event=event), self.assertRaises(ValueError):
                metrics.parse_snapshot(event)

    def test_unrelated_lines_are_ignored(self):
        self.assertIsNone(metrics.parse_snapshot('INFO unrelated: durable_height=5'))

    def test_allocator_counters_are_separate_from_backend_memory(self):
        event = snapshot().rstrip() + (
            ' allocator_memory_bytes={"arena_reserved": Some(1024), '
            '"arena_in_use": Some(768), "arena_free": Some(256), '
            '"direct_mapped": Some(4096)}\n')
        record = metrics.parse_snapshot(event)
        self.assertEqual(record['allocator_memory_bytes.arena_reserved'], 1024)
        self.assertEqual(record['allocator_memory_bytes.arena_in_use'], 768)
        self.assertEqual(record['allocator_memory_bytes.arena_free'], 256)
        self.assertEqual(record['allocator_memory_bytes.direct_mapped'], 4096)
        self.assertEqual(record['history_memory_bytes.block_cache'], 2048)

    def test_unsupported_allocator_counters_remain_absent_values(self):
        event = snapshot().rstrip() + (
            ' allocator_memory_bytes={"arena_reserved": None, "arena_in_use": None, '
            '"arena_free": None, "direct_mapped": None}\n')
        record = metrics.parse_snapshot(event)
        counters = {key: value for key, value in record.items() if key.startswith('allocator_memory_bytes.')}
        self.assertEqual(len(counters), 4)
        self.assertTrue(all(value is None for value in counters.values()))

    def test_incomplete_or_partial_allocator_counters_fail(self):
        for counters in (
                '{"arena_reserved": Some(1024)}',
                '{"arena_reserved": None, "arena_in_use": Some(768), '
                '"arena_free": Some(256), "direct_mapped": Some(4096)}',
                '{"arena_reserved": Some(1024), "arena_in_use": Some(-1), '
                '"arena_free": Some(256), "direct_mapped": Some(4096)}'):
            with self.subTest(counters=counters), self.assertRaises(ValueError):
                metrics.parse_snapshot(snapshot().rstrip() + ' allocator_memory_bytes=' + counters + '\n')


class RetainedCluster(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / 'nodes'
        self.output = self.root / 'recording'
        self.output.mkdir()
        (self.output / 'manifest.json').write_text(json.dumps({'started_at': START.isoformat()}))
        for member in range(4):
            directory = self.logs / 'run-one' / ('node%d' % member) / 'logs'
            directory.mkdir(parents=True)
            (directory / 'stdout.log').write_text(snapshot() + snapshot(30))
        (self.output / 'stderr.log').write_text('workload runner has no node snapshots\n')

    def arguments(self):
        return [str(self.output), '--node-logs', str(self.logs), '--minimum-samples', '2']

    def test_real_node_layout_retains_member_and_actual_timestamp(self):
        records = metrics.collect(self.logs, START, 4, 2)
        self.assertEqual(len(records), 8)
        self.assertEqual({row['member'] for row in records}, {'node0', 'node1', 'node2', 'node3'})
        self.assertEqual(records[1]['recording_elapsed_seconds'], 30)
        self.assertEqual(records[1]['sample_index'], 1)
        self.assertEqual(records[1]['recorded_at'], '2026-10-09T10:00:30.000Z')

    def test_cli_reads_nodes_and_exports_only_numeric_evidence(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(metrics.main(self.arguments()), 0)
        rows = [json.loads(line) for line in (self.output / 'diagnostics.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[-1]['index.cached_bytes'], 8192)
        self.assertNotIn(str(self.logs), json.dumps(rows))

    def test_empty_member_fails_and_removes_stale_success(self):
        output = self.output / 'diagnostics.jsonl'
        output.write_text('stale success\n')
        (self.logs / 'run-one/node2/logs/stdout.log').write_text('')
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(metrics.main(self.arguments()), 1)
        self.assertFalse(output.exists())
        self.assertNotIn(str(self.logs), error.getvalue())

    def test_one_missing_member_is_not_a_successful_cluster(self):
        (self.logs / 'run-one/node3/logs/stdout.log').unlink()
        with self.assertRaises(ValueError):
            metrics.collect(self.logs, START, 4, 1)

    def test_stale_second_cluster_and_foreign_members_fail(self):
        (self.logs / 'stale-run').mkdir()
        with self.assertRaises(ValueError):
            metrics.collect(self.logs, START, 4, 1)
        (self.logs / 'stale-run').rmdir()
        (self.logs / 'run-one/node4').mkdir()
        with self.assertRaises(ValueError):
            metrics.collect(self.logs, START, 4, 1)

    def test_ansi_and_unrelated_events_do_not_merge_snapshots(self):
        log = self.logs / 'run-one/node0/logs/stdout.log'
        log.write_text('\x1b[32m' + snapshot() + '\x1b[0m' +
                       '2026-10-09T10:00:10.000Z INFO unrelated event secret=private\n' + snapshot(30))
        records = metrics.collect(self.logs, START, 4, 2)
        self.assertEqual(len(records), 8)
        self.assertNotIn('private', json.dumps(records))

    def test_non_monotonic_snapshot_time_fails(self):
        (self.logs / 'run-one/node0/logs/stdout.log').write_text(snapshot(30) + snapshot())
        with self.assertRaises(ValueError):
            metrics.collect(self.logs, START, 4, 2)

    def test_single_snapshot_cannot_qualify_requested_coverage(self):
        (self.logs / 'run-one/node0/logs/stdout.log').write_text(snapshot())
        with self.assertRaises(ValueError):
            metrics.collect(self.logs, START, 4, 2)


if __name__ == '__main__':
    unittest.main()
