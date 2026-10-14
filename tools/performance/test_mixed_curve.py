import copy
import unittest

from mixed_curve import RATES, backlog, compare, markdown


def case(rate, lag_seconds=0):
    observations = [
        {'workflow': index, 'elapsed_ms': 500,
         'schedule_lag_ms': index * lag_seconds * 1000,
         'scheduled_to_complete_ms': 500 + index * lag_seconds * 1000}
        for index in range(256)
    ]
    duration = 255 / rate + 255 * lag_seconds + .5
    return {
        'format_version': 2, 'qualified': True, 'profile': f'curve-{rate}',
        'offered_workflows_per_second': rate, 'workflows': 256,
        'source_revision': 'a' * 40, 'node_sha256': 'b' * 64, 'runner_sha256': 'c' * 64,
        'hardware': {'logical_cpus': 4, 'cpu_model': 'fixture CPU'},
        'timed_seconds': duration,
        'timed_counts': {'certified_successes': 1280, 'issued_native_submissions': 1280,
                         'certified_embedded_mutations': 3328, 'issued_embedded_mutations': 3328,
                         'verified_permission_checks': 15360, 'throttled_requests': 0},
        'replica_phases': ['after_workload', 'remove_member', 'reintroduce_member',
                          'after_explicit_regrant', 'after_hard_restart'],
        'scheduled_workflow_ms': {'p50': 500, 'p95': 500, 'p99': 500},
        'schedule_lag_ms': {'p50': 0, 'p95': 0, 'p99': 0},
        'workflow_observations': observations,
        'resource_usage': {
            'source': 'ps_rss_and_cpu_time',
            'members': [{'member': member, 'samples': 2, 'missing_samples': 0,
                         'rss_mib': {'first': 10, 'last': 20, 'peak': 20},
                         'observed_window': {'average_cpu_cores': .1}}
                        for member in range(4)],
        },
        'resources': {'storage': []},
        'process_io': {'source': 'linux_proc_io',
                       'members': [{'samples': 2, 'missing_samples': 0, 'unavailable_samples': 0,
                                    'observed_window': {'write_bytes_delta': 1024}}
                                   for _ in range(4)]},
        'restart_ms': 1000,
    }


class MixedCurveTests(unittest.TestCase):
    def test_throughput_excludes_setup_and_later_policy_edits(self):
        result = compare([case(rate) for rate in RATES])
        row = result['cases'][0]
        self.assertEqual(row['certified_native_submissions_per_second'], 1280 / 255.5)
        self.assertEqual(row['certified_embedded_mutations_per_second'], 3328 / 255.5)
        self.assertIn('bounded client', result['scope'])
        self.assertIn('Certified submissions/s', markdown(result))

    def test_delayed_starts_show_backlog_even_when_every_workflow_completes(self):
        fixture = case(8, .25)
        result = backlog(fixture['workflow_observations'], 8, fixture['timed_seconds'])
        self.assertGreater(result['peak_not_started'], 100)
        self.assertGreater(result['average_not_started'], 0)
        immediate = case(8)
        self.assertEqual(backlog(immediate['workflow_observations'], 8,
                                 immediate['timed_seconds'])['peak_not_started'], 0)

    def test_comparisons_reject_source_hardware_and_binary_changes(self):
        for key, changed in (('source_revision', 'd' * 40), ('node_sha256', 'd' * 64),
                             ('runner_sha256', 'd' * 64), ('hardware', {'logical_cpus': 8})):
            cases = [case(rate) for rate in RATES]
            cases[2][key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare(cases)

    def test_missing_reordered_failed_or_incomplete_cases_cannot_pass(self):
        for change in ('missing', 'reordered', 'failed', 'recovery', 'resources', 'io', 'counts', 'percentile'):
            cases = [case(rate) for rate in RATES]
            if change == 'missing':
                cases.pop()
            elif change == 'reordered':
                cases.reverse()
            elif change == 'failed':
                cases[0]['qualified'] = False
            elif change == 'recovery':
                cases[0]['replica_phases'].pop()
            elif change == 'resources':
                cases[0]['resource_usage']['members'][0]['missing_samples'] = 1
            elif change == 'io':
                cases[0]['process_io']['members'][0]['unavailable_samples'] = 1
            elif change == 'percentile':
                cases[0]['scheduled_workflow_ms']['p95'] = 499
            else:
                cases[0]['timed_counts']['certified_successes'] -= 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                compare(cases)

    def test_timestamp_and_concurrency_violations_cannot_hide_backlog(self):
        for change in ('duplicate', 'boolean', 'nan', 'end_before_start', 'after_end', 'concurrency'):
            fixture = case(8)
            observations = copy.deepcopy(fixture['workflow_observations'])
            if change == 'duplicate':
                observations[1]['workflow'] = 0
            elif change == 'boolean':
                observations[0]['workflow'] = False
            elif change == 'nan':
                observations[0]['schedule_lag_ms'] = float('nan')
            elif change == 'end_before_start':
                observations[0]['schedule_lag_ms'] = 600
            elif change == 'after_end':
                observations[-1]['scheduled_to_complete_ms'] += 1000
            else:
                for row in observations:
                    row['scheduled_to_complete_ms'] = 2000
            with self.subTest(change=change), self.assertRaises(ValueError):
                backlog(observations, 8, fixture['timed_seconds'])


if __name__ == '__main__':
    unittest.main()
