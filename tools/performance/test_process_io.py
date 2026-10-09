import json
from pathlib import Path
import tempfile
import unittest

from process_io import summarize_io


class ProcessIoTests(unittest.TestCase):
    def parse(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'workload.jsonl'
            path.write_text('\n'.join(json.dumps(row) + '\n' for row in records))
            return summarize_io(path)

    def config(self, source='linux_proc_io'):
        return {'kind': 'resource_configuration', 'node_pids': [1, 2], 'process_io_source': source}

    def sample(self, elapsed, values):
        return {'kind': 'resources', 'elapsed_seconds': elapsed, 'sample': {'process_io': values}}

    def counters(self, pid, written=0, cancelled=0):
        return {'pid': pid, 'availability': 'complete', 'read_bytes': 0,
                'write_bytes': written, 'cancelled_write_bytes': cancelled}

    def test_observed_intervals_keep_cancellations_separate_and_zero_real(self):
        result = self.parse([self.config(), self.sample(2, [self.counters(1, 100, 50), self.counters(2)]),
                             self.sample(9, [self.counters(1, 200, 300), self.counters(2)])])
        first, second = result['members']
        self.assertEqual(first['samples'], 2)
        self.assertEqual(first['observed_window'], {'start_elapsed_seconds': 2, 'end_elapsed_seconds': 9,
                         'duration_seconds': 7, 'read_bytes_delta': 0, 'write_bytes_delta': 100,
                         'cancelled_write_bytes_delta': 250})
        self.assertEqual(second['observed_window']['write_bytes_delta'], 0)

    def test_missing_unavailable_and_single_sample_are_not_zero_deltas(self):
        result = self.parse([self.config(), self.sample(0, []), self.sample(1, [self.counters(1),
                             {'pid': 2, 'availability': 'read_error'}])])
        first, second = result['members']
        self.assertEqual(first['missing_samples'], 1)
        self.assertIsNone(first['observed_window'])
        self.assertEqual(second['unavailable_samples'], 1)
        self.assertIsNone(second['observed_window'])

    def test_legacy_and_unsupported_reports_have_no_invented_counters(self):
        for source in ('unavailable', 'unsupported'):
            result = self.parse([self.config(source), self.sample(0, [])])
            self.assertEqual(result['source'], source)
            self.assertEqual(result['members'], [])

    def test_invalid_or_regressing_counters_fail(self):
        for value in (-1, 1 << 64, 1.5, True, None):
            row = self.counters(1)
            row['write_bytes'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse([self.config(), self.sample(0, [row])])
        with self.assertRaisesRegex(ValueError, 'regressed'):
            self.parse([self.config(), self.sample(1, [self.counters(1, 100)]),
                        self.sample(2, [self.counters(1, 99)])])

    def test_invalid_timestamps_and_member_selection_fail(self):
        for elapsed in (-1, float('inf'), float('nan'), True, '1'):
            with self.subTest(elapsed=elapsed), self.assertRaises(ValueError):
                self.parse([self.config(), self.sample(elapsed, [self.counters(1)])])
        for samples in ([self.counters(3)], [self.counters(1), self.counters(1)]):
            with self.assertRaises(ValueError):
                self.parse([self.config(), self.sample(0, samples)])
        with self.assertRaisesRegex(ValueError, 'regressed'):
            self.parse([self.config(), self.sample(2, [self.counters(1)]), self.sample(1, [self.counters(1)])])

    def test_configuration_rejects_duplicate_or_invalid_members(self):
        for pids in ([1, 1], [True], [], [[1]], [1 << 32]):
            row = self.config()
            row['node_pids'] = pids
            with self.subTest(pids=pids), self.assertRaises(ValueError):
                self.parse([row])
        with self.assertRaises(ValueError):
            self.parse([self.config(), self.config()])

    def test_zero_duration_and_u64_counters_preserve_precision(self):
        result = self.parse([self.config(), self.sample(0, [self.counters(1, (1 << 64) - 2)]),
                             self.sample(0, [self.counters(1, (1 << 64) - 1)])])
        self.assertIsNone(result['members'][0]['observed_window'])
        result = self.parse([self.config(), self.sample(0, [self.counters(1, (1 << 64) - 2)]),
                             self.sample(1, [self.counters(1, (1 << 64) - 1)])])
        self.assertEqual(result['members'][0]['observed_window']['write_bytes_delta'], 1)


if __name__ == '__main__':
    unittest.main()
