import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import storage_summary as storage

ANCHOR = 1_791_947_321_749
CONFIG = {'node_pids': [11, 12, 13, 14], 'started_at_unix_ms': ANCHOR}


def sample(pid, elapsed, increment):
    timestamp = datetime.datetime.fromtimestamp(ANCHOR / 1000 + elapsed, datetime.timezone.utc)
    return {'process_id': pid, 'recorded_at': timestamp.isoformat(),
            **{key: increment for key in storage.FIELDS},
            'private_response': 'do-not-export'}


def fixture():
    return [sample(pid, elapsed, increment) for pid in CONFIG['node_pids']
            for elapsed, increment in [(5, 100), (35, 200), (65, 300)]]


class StorageSummary(unittest.TestCase):
    def test_intervals_and_counters_exclude_setup_restart_and_post_workload(self):
        records = [sample(11, -5, 90), sample(99, 30, 999), *fixture(), sample(11, 95, 400)]
        result = storage.summarize(records, CONFIG, 90)
        self.assertEqual(len(result['members']), 4)
        for member in result['members']:
            self.assertEqual(member['samples'], 3)
            self.assertEqual(member['observed_seconds'], {'start': 5, 'end': 65})
            self.assertEqual(member['history_counter_deltas']['batch_input_bytes'], 200)
            self.assertEqual(member['history_encoded_output_per_input'], 3)
            self.assertEqual(member['commonware_requested_write_bytes'], 200)
        self.assertNotIn('do-not-export', str(result))

    def test_counter_reset_cannot_be_hidden_by_a_later_larger_value(self):
        records = fixture()
        records[1][storage.RUNTIME[0]] = 50
        with self.assertRaises(ValueError):
            storage.summarize(records, CONFIG, 90)

    def test_missing_member_invalid_clock_and_zero_input_fail(self):
        cases = [fixture()[3:], [sample(pid, 5, 100) for pid in CONFIG['node_pids']], fixture()]
        for row in cases[-1]:
            row['history_write_statistics.batch_input_bytes'] = 0
        for records in cases:
            with self.subTest(records=len(records)), self.assertRaises(ValueError):
                storage.summarize(records, CONFIG, 90)
        for duration in [0, -1, True, float('nan')]:
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                storage.summarize(fixture(), CONFIG, duration)

    def test_gauge_eviction_is_allowed_but_missing_and_boolean_counters_fail(self):
        records = fixture()
        records[1][storage.MEMORY[0]] = 50
        result = storage.summarize(records, CONFIG, 90)
        self.assertEqual(result['members'][0]['retained_resources'][storage.MEMORY[0]]['last'], 300)
        for value in [None, True, -1]:
            invalid = fixture()
            invalid[0][storage.RUNTIME[0]] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                storage.summarize(invalid, CONFIG, 90)

    def test_duplicate_time_and_naive_timestamp_fail(self):
        records = fixture()
        records[1]['recorded_at'] = records[0]['recorded_at']
        with self.assertRaises(ValueError):
            storage.summarize(records, CONFIG, 90)
        records[0]['recorded_at'] = '2026-10-14T03:09:00'
        with self.assertRaises(ValueError):
            storage.summarize(records, CONFIG, 90)

    def test_failed_or_incomplete_run_removes_stale_success_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / 'storage-summary.json'
            for report in [{'status': 'failed', 'manifest': {'exit_code': 0}},
                           {'status': 'passed', 'manifest': {'exit_code': 1}},
                           {'status': 'passed', 'manifest': {'exit_code': 0},
                            'summary': {'elapsed_seconds': 90}}]:
                (directory / 'report.json').write_text(json.dumps(report))
                (directory / 'workload.jsonl').write_text('')
                output.write_text('stale success')
                with patch.object(sys, 'argv', ['storage_summary.py', str(directory)]):
                    with self.assertRaisesRegex(SystemExit, 'storage measurement qualification failed'):
                        storage.main()
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
