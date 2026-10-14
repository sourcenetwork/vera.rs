import copy
import unittest

from resource_envelope import qualify


def fixture():
    report = dict(status='passed', manifest=dict(exit_code=0, history='regolith', dirty=False,
        runner_dirty=False, trace_span_close=False, source='a' * 40, node_sha256='b' * 64,
        runner_sha256='c' * 64), configuration=dict(count=90000, fixed_update_objects=0,
        workload='certified_native_registrations', nodes=4, arrivals_per_second=50,
        max_outstanding=128, permission_reads_per_write=1, preset='Normal',
        proposal_batch_wait_ms=100, revisions_per_epoch=192, runner_debug_assertions=False,
        pruning=dict(retained_consensus_revisions=256, retained_state_revisions=0)),
        summary=dict(confirmed=90000, completed_workflows=90000),
        verification=dict(verified=90000, unresolved=0, replicas=4),
        recovery=dict(inspected_operations=90000, receipt_mismatches=0, state_mismatches=0),
        resource_usage=dict(source='ps_rss_and_cpu_time', members=[dict(member=i, samples=1801,
            missing_samples=0, rss_mib=dict(peak=800), observed_window=dict(duration_seconds=1800))
            for i in range(4)]))
    storage = [dict(kind='storage', phase='after', node=i, error=None,
                    allocated_file_bytes=320 * 1024 * 1024) for i in range(4)]
    return report, storage


class EnvelopeTests(unittest.TestCase):
    def test_fixed_profile_requires_its_full_two_hour_window(self):
        report, storage = fixture()
        report['configuration'].update(count=360000, fixed_update_objects=128,
                                      workload='certified_native_object_updates')
        report['summary'].update(confirmed=360000, completed_workflows=360000)
        report['verification']['verified'] = 360000
        report['recovery']['inspected_operations'] = 360000
        with self.assertRaises(ValueError):
            qualify(report, storage, 'fixed-360k')
        for member in report['resource_usage']['members']:
            member.update(samples=7201, observed_window=dict(duration_seconds=7200))
        self.assertEqual(qualify(report, storage, 'fixed-360k')['status'], 'passed')

    def test_measured_headroom_and_exact_budget_boundary(self):
        report, storage = fixture()
        report['resource_usage']['members'][0]['rss_mib']['peak'] = 1024
        storage[0]['allocated_file_bytes'] = 512 * 1024 * 1024
        result = qualify(report, storage, 'growing-90k')
        self.assertEqual(result['members'][0]['rss_budget_unused_fraction'], 0)
        self.assertEqual(result['members'][0]['file_budget_unused_fraction'], 0)
        self.assertGreater(result['members'][1]['rss_budget_unused_fraction'], .2)

    def test_missing_wrong_or_failed_workloads_cannot_qualify(self):
        report, storage = fixture()
        for key, value in [('status', 'failed'), ('manifest', {**report['manifest'], 'dirty': True}),
                           ('recovery', {**report['recovery'], 'receipt_mismatches': 1}),
                           ('configuration', {**report['configuration'], 'count': 3000}),
                           ('resource_usage', {**report['resource_usage'], 'members': []})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                qualify({**report, key: value}, storage, 'growing-90k')

    def test_member_gaps_invalid_numbers_short_windows_and_excess_memory_fail(self):
        report, storage = fixture()
        for key, value in [('missing_samples', 1), ('samples', 12),
                           ('observed_window', dict(duration_seconds=30)),
                           ('rss_mib', dict(peak=float('nan'))), ('rss_mib', dict(peak=1024.01))]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                candidate = copy.deepcopy(report)
                candidate['resource_usage']['members'][0][key] = value
                qualify(candidate, storage, 'growing-90k')

    def test_disk_overflow_missing_duplicate_and_failed_scans_fail(self):
        report, storage = fixture()
        for candidate in [storage[1:], storage + [storage[0]],
                          [{**storage[0], 'error': 'read_error'}] + storage[1:],
                          [{**storage[0], 'allocated_file_bytes': 512 * 1024 * 1024 + 1}] + storage[1:]]:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                qualify(report, candidate, 'growing-90k')


if __name__ == '__main__':
    unittest.main()
