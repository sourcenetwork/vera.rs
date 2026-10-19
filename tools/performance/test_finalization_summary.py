import datetime
import unittest

import finalization_summary as summary


CONFIG = {'node_pids': [11, 12, 13, 14], 'started_at_unix_ms': 1_800_000_000_000}


def samples():
    for pid in CONFIG['node_pids']:
        for second in (20, 80):
            row = {'process_id': pid, 'recorded_at': datetime.datetime.fromtimestamp(
                CONFIG['started_at_unix_ms'] / 1000 + second, datetime.timezone.utc).isoformat()}
            for suffix in summary.STAGES.values():
                row['runtime_metrics.node_' + suffix + '_count'] = second
                row['runtime_metrics.node_' + suffix + '_sum'] = second / 100
            row['history_wal_statistics.count'] = second
            row['history_wal_statistics.sum'] = second * 1000
            yield row


class FinalizationSummary(unittest.TestCase):
    def test_clock_aligned_stage_and_wal_deltas(self):
        result = summary.summarize(samples(), CONFIG, 100)
        self.assertEqual(len(result['members']), 4)
        member = result['members'][0]
        self.assertEqual(member['observed_seconds'], 60)
        self.assertEqual(member['stages']['callback']['samples'], 60)
        self.assertAlmostEqual(member['stages']['callback']['mean_ms'], 10)
        self.assertAlmostEqual(member['stages']['wal_write_and_sync']['mean_ms'], 1)
        self.assertAlmostEqual(member['stages']['callback']['elapsed_share'], .01)

    def test_counter_reset_missing_histogram_and_unsupported_wal_fail(self):
        for mutate in (
                lambda row: row.update({'runtime_metrics.node_finalization_callback_seconds_count': 0}),
                lambda row: row.pop('runtime_metrics.node_finalization_callback_seconds_sum'),
                lambda row: row.update({'history_wal_statistics.sum': None})):
            rows = list(samples())
            mutate(rows[-1])
            with self.assertRaises(ValueError):
                summary.summarize(rows, CONFIG, 100)

    def test_excludes_other_processes_and_samples_outside_workload(self):
        rows = list(samples())
        rows.append({'process_id': 99, 'recorded_at': rows[0]['recorded_at']})
        rows.append({'process_id': 11, 'recorded_at': '2030-01-01T00:00:00+00:00'})
        self.assertEqual(len(summary.summarize(rows, CONFIG, 100)['members']), 4)
        with self.assertRaises(ValueError):
            summary.summarize(samples(), CONFIG, 30)

    def test_nonfinite_values_and_duplicate_clocks_fail(self):
        for invalid in (float('inf'), float('nan'), -1, True):
            rows = list(samples())
            rows[-1]['runtime_metrics.node_finalization_callback_seconds_sum'] = invalid
            with self.assertRaises(ValueError):
                summary.summarize(rows, CONFIG, 100)
        rows = list(samples())
        rows.insert(1, rows[0].copy())
        with self.assertRaises(ValueError):
            summary.summarize(rows, CONFIG, 100)


if __name__ == '__main__':
    unittest.main()
