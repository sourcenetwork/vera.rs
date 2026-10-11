"""Account for worker scheduling without inventing node queue measurements."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from worker_progress import summarize_worker_progress


class WorkerProgressTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'workload.jsonl'
        self.rows = [
            dict(kind='configuration', fixed_update_objects=2, count=4, arrivals_per_second=1,
                 arrival_model='scheduled_wait_for_previous_per_object'),
            dict(kind='summary', elapsed_seconds=5, offered=4, confirmed=4, completed_workflows=4,
                 unknown=0, rejected=0, reverted=0, not_sent=0, confirmed_incomplete_workflows=0,
                 verification_failures=0),
        ]
        for index, (latency, lag) in enumerate(((3000, 0), (100, 0), (2000, 1000), (100, 0))):
            self.rows.append(dict(kind='observation', index=index, object_id=str(index % 2),
                                  outcome='confirmed', verification_failure=False, error=None,
                                  scheduled_to_workflow_ms=latency, schedule_lag_ms=lag,
                                  hash='private submission identity'))

    def summarize(self):
        self.path.write_text('\n'.join(json.dumps(row) for row in self.rows))
        return summarize_worker_progress(self.path, True)

    def test_slow_worker_and_scheduling_backlog_are_visible(self):
        result = self.summarize()
        self.assertEqual(result['status'], 'measured')
        self.assertEqual(result['minimum_worker_workflow_p95_ms'], 100)
        self.assertEqual(result['maximum_worker_workflow_p95_ms'], 3000)
        self.assertEqual(result['peak_scheduled_incomplete'], 2)
        self.assertEqual(result['peak_not_started'], 1)
        self.assertAlmostEqual(result['time_weighted_scheduled_incomplete'], 1.04)
        self.assertAlmostEqual(result['time_weighted_not_started'], .2)
        self.assertEqual([row['completed'] for row in result['workers']], [2, 2])
        self.assertNotIn('private submission', json.dumps(result))

    def test_record_order_does_not_change_the_result(self):
        expected = self.summarize()
        self.rows.reverse()
        self.assertEqual(self.summarize(), expected)

    def test_simultaneous_completion_and_arrival_do_not_inflate_backlog(self):
        for row in self.rows[2:]:
            row.update(scheduled_to_workflow_ms=1000, schedule_lag_ms=0)
        result = self.summarize()
        self.assertEqual(result['peak_scheduled_incomplete'], 1)
        self.assertEqual(result['peak_not_started'], 0)

    def test_failed_workload_is_unavailable_without_reading_raw_data(self):
        self.assertEqual(summarize_worker_progress(self.path, False),
                         dict(status='unavailable', reason='workload_not_qualified'))

    def test_one_operation_per_signer_is_not_a_repeated_worker_measurement(self):
        self.rows[0]['fixed_update_objects'] = 0
        self.assertEqual(self.summarize(), dict(status='not_applicable', reason='one_operation_per_signer'))

    def test_invalid_coverage_identity_or_timing_is_rejected(self):
        original = copy.deepcopy(self.rows)
        changes = [('index', 0), ('index', True), ('object_id', 'private'),
                   ('scheduled_to_workflow_ms', None), ('scheduled_to_workflow_ms', float('nan')),
                   ('scheduled_to_workflow_ms', True), ('scheduled_to_workflow_ms', 5000),
                   ('schedule_lag_ms', -1), ('schedule_lag_ms', 3000),
                   ('outcome', 'unknown'), ('verification_failure', True)]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.rows = copy.deepcopy(original)
                self.rows[-2][field] = value
                with self.assertRaises(ValueError):
                    self.summarize()
        self.rows = original[:-1]
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.summarize()

    def test_untrusted_success_summary_and_duplicate_headers_are_rejected(self):
        original = copy.deepcopy(self.rows)
        for field, value in [('offered', 3), ('not_sent', 1), ('unknown', False),
                             ('elapsed_seconds', 0), ('elapsed_seconds', float('inf'))]:
            with self.subTest(field=field):
                self.rows = copy.deepcopy(original)
                self.rows[1][field] = value
                with self.assertRaises(ValueError):
                    self.summarize()
        for index in (0, 1):
            self.rows = copy.deepcopy(original)
            self.rows.append(self.rows[index])
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.summarize()

    def test_unsupported_arrival_model_or_worker_count_is_rejected(self):
        original = copy.deepcopy(self.rows)
        for field, value in [('arrival_model', 'scheduled_drop_when_full'),
                             ('fixed_update_objects', True), ('fixed_update_objects', 1025),
                             ('count', 100001), ('arrivals_per_second', 0)]:
            with self.subTest(field=field):
                self.rows = copy.deepcopy(original)
                self.rows[0][field] = value
                with self.assertRaises(ValueError):
                    self.summarize()

    def test_long_fixed_run_reports_every_completed_worker(self):
        count = 100_001
        configuration = dict(self.rows[0], count=count, arrivals_per_second=50)
        summary = dict(self.rows[1], offered=count, confirmed=count,
                       completed_workflows=count, elapsed_seconds=2001)

        def records():
            yield configuration
            yield summary
            for index in range(count):
                yield dict(self.rows[2], index=index, object_id=str(index % 2),
                           scheduled_to_workflow_ms=12, schedule_lag_ms=1)

        with patch('worker_progress._records', side_effect=lambda _: records()):
            result = summarize_worker_progress(self.path, True)
        self.assertEqual([worker['completed'] for worker in result['workers']], [50_001, 50_000])
        self.assertEqual(result['maximum_worker_workflow_p95_ms'], 12)
        self.assertEqual(result['peak_scheduled_incomplete'], 1)
        self.assertNotIn('private submission', json.dumps(result))

    def test_growing_runs_keep_the_registration_count_bound(self):
        self.rows[0].update(fixed_update_objects=0, count=100_001)
        with self.assertRaisesRegex(ValueError, 'count'):
            self.summarize()

    def test_oversized_raw_record_is_rejected(self):
        self.path.write_bytes(b' ' * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            summarize_worker_progress(self.path, True)


if __name__ == '__main__':
    unittest.main()
