import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mixed', Path(__file__).with_name('qualify-mixed-policy.py'))
mixed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mixed)


def complete_run():
    records = [dict(kind='configuration', schema_version=1, workflows=2, validators=4, epoch_revisions=192,
                    scheduled_arrivals_per_second=2, maximum_outstanding_workflows=8,
                    whole_run_deadline_seconds=900, request_deadline_seconds=30, workflow_deadline_seconds=120,
                    objects_per_workflow=4, readers=2, outsiders=1, verification_concurrency_per_replica=8,
                    timing='normal', pipelined=True, debug_assertions=False, daemon='/private/daemon'),
               dict(kind='artifacts', node_directories=['private fixture material'])]
    for index in range(2):
        records.append(dict(kind='workflow_completed', workflow=index, finalized_revision=10,
                            elapsed_ms=500, scheduled_to_complete_ms=600, schedule_lag_ms=100))
        for phase in mixed.WORKFLOW_PHASES:
            records.append(dict(kind='workflow_phase', phase=phase, workflow=index, permission_checks=12,
                                minimum_revision=10, elapsed_ms=100, failure_kind=None, error=None))
    submissions = [(phase, index) for phase in mixed.WORKFLOW_PHASES + ('restore_current_grants',) for index in range(2)]
    submissions += [(phase, None) for phase in ('policy_setup', 'remove_member', 'reintroduce_member')]
    for sequence, (phase, workflow) in enumerate(submissions, 1):
        row = dict(phase=phase, workflow=workflow, id=f'0x{sequence:064x}',
                   embedded_mutations={'initial_grants': 9, 'restore_current_grants': 4}.get(phase, 1))
        records.append(dict(row, kind='submission_started'))
        records.append(dict(row, kind='submission', revision=10, elapsed_ms=100, accepted_ms=1,
                            failure_kind=None, error=None))
    for phase in mixed.REPLICA_PHASES:
        records.append(dict(kind='replica_verification', phase=phase, replicas=4, workflows=2,
                            permission_checks=96, minimum_revision=20, elapsed_ms=50))
        for replica in range(4):
            for workflow in range(2):
                records.append(dict(kind='replica_check', phase=phase, replica=replica, workflow=workflow,
                                    permission_checks=12, owner_checks=4, minimum_revision=20,
                                    failure_kind=None, error=None))
    before = dict(issued_native_submissions=1, issued_embedded_mutations=1, certified_embedded_mutations=1,
                  submission_attempts=1, certified_successes=1, verified_permission_checks=0,
                  verified_owners=0, throttled_requests=0)
    after = dict(issued_native_submissions=11, issued_embedded_mutations=27, certified_embedded_mutations=27,
                 submission_attempts=11, certified_successes=11, verified_permission_checks=120,
                 verified_owners=0, throttled_requests=0)
    counts = dict(issued_native_submissions=15, issued_embedded_mutations=37, certified_embedded_mutations=37,
                  submission_attempts=15, certified_successes=15, verified_permission_checks=600,
                  verified_owners=160, throttled_requests=0)
    records.extend([dict(kind='workload_summary', scheduled_workflows=2, completed_workflows=2,
                         failed_workflows=0, failures=[], elapsed_seconds=1, counts_before=before, counts_after=after),
                    dict(kind='restart', replica=3, verified_workflows=2, minimum_revision=20, elapsed_ms=1000),
                    dict(kind='result', success=True, counts=counts, failure_kind=None, error=None),
                    dict(kind='resource_configuration', node_pids=[101, 102, 103, 104])])
    records.append(dict(kind='resources', elapsed_seconds=.5, sample={
        'rows': '101 512 0:00\n102 512 0:00\n103 512 0:00\n104 512 0:00\n',
        'rss_breakdown': [dict(pid=pid, availability='complete', vm_rss_kib=512,
                               rss_anon_kib=384, rss_file_kib=128, rss_shmem_kib=0) for pid in range(101, 105)]}))
    for phase in ('before_workload', 'after_workload', 'after_verification'):
        for node in range(4):
            records.append(dict(kind='storage', phase=phase, node=node, logical_bytes=100,
                                allocated_file_bytes=4096, regular_files=1, error=None))
    return records


class QualificationTests(unittest.TestCase):
    def sustained_run(self):
        records = complete_run()
        config = next(row for row in records if row['kind'] == 'configuration')
        config.update(scheduled_arrivals_per_second=1, whole_run_deadline_seconds=5400)
        next(row for row in records if row['kind'] == 'workload_summary')['elapsed_seconds'] = 1801
        sample = next(row for row in records if row['kind'] == 'resources')
        records.remove(sample)
        for second in range(1801):
            record = copy.deepcopy(sample)
            record['elapsed_seconds'] = second
            records.append(record)
        return records

    def test_sustained_profile_exports_closed_memory_series_and_storage(self):
        result = mixed.qualify(self.sustained_run(), 2, 1, 5400, 1800)
        self.assertEqual(len(result['resources']['member_rss_series']), 1801)
        self.assertEqual(result['resources']['member_rss_series'][-1],
                         {'elapsed_seconds': 1800, 'rss_mib': [.5] * 4})
        self.assertEqual(len(result['resources']['storage']), 12)
        for private in ('/private', 'private fixture material', 'node_pids'):
            self.assertNotIn(private, json.dumps(result))

    def test_observations_allow_recomputation_without_private_fields(self):
        records = complete_run()
        completed = [row for row in records if row['kind'] == 'workflow_completed']
        completed[0].update(elapsed_ms=300, scheduled_to_complete_ms=350, schedule_lag_ms=50,
                            request='private fixture material')
        completed[1].update(elapsed_ms=700, scheduled_to_complete_ms=800, schedule_lag_ms=100)
        submissions = [row for row in records if row['kind'] == 'submission']
        for index, row in enumerate(submissions):
            row.update(elapsed_ms=index + 1, accepted_ms=0.5, request='private fixture material')
        result = mixed.qualify(records, 2)
        self.assertEqual(result['format_version'], 2)
        observations = result['workflow_observations']
        self.assertEqual([row['workflow'] for row in observations], [0, 1])
        for field, metric in (('elapsed_ms', 'workflow_ms'),
                              ('scheduled_to_complete_ms', 'scheduled_workflow_ms'),
                              ('schedule_lag_ms', 'schedule_lag_ms')):
            values = sorted(row[field] for row in observations)
            self.assertEqual(result[metric], {'p50': values[0], 'p95': values[1], 'p99': values[1]})
        observed = result['submission_observations']
        self.assertEqual(len(observed), 15)
        self.assertEqual(sorted(row['elapsed_ms'] for row in observed), list(range(1, 16)))
        self.assertEqual(result['certified_submission_ms'], {'p50': 8, 'p95': 15, 'p99': 15})
        self.assertTrue(all(set(row) == {'phase', 'workflow', 'revision', 'embedded_mutations',
                                        'elapsed_ms', 'accepted_ms'} for row in observed))
        for private in ('private fixture material', '0x', '/private', 'node_pids'):
            self.assertNotIn(private, json.dumps(result))

    def test_raw_observations_reject_invalid_admission_timing_and_counts(self):
        for field, value in (('accepted_ms', True), ('accepted_ms', -1),
                             ('accepted_ms', float('nan')), ('accepted_ms', 900_001), ('accepted_ms', 100.1),
                             ('embedded_mutations', True)):
            records = complete_run()
            row = next(row for row in records if row['kind'] == 'submission' and row['embedded_mutations'] == 1)
            row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(mixed.InvalidEvidence):
                mixed.qualify(records, 2)

    def test_hardware_export_is_closed_and_bounded(self):
        manifest = {'platform': 'Linux-6.11-x86_64-with-glibc2.39', 'architecture': 'x86_64',
                    'logical_cpus': 4, 'cpu_model': 'Intel(R) Xeon(R)',
                    'private_field': 'private fixture material'}
        expected = {key: manifest[key] for key in ('platform', 'architecture', 'logical_cpus', 'cpu_model')}
        self.assertEqual(mixed.hardware_manifest(manifest), expected)
        for field, value in (('logical_cpus', True), ('logical_cpus', 0), ('logical_cpus', 4097),
                             ('cpu_model', 'x' * 257), ('cpu_model', 'private\nlog'),
                             ('architecture', '/private/host'), ('platform', None)):
            with self.subTest(field=field), self.assertRaises(mixed.InvalidEvidence):
                mixed.hardware_manifest({**manifest, field: value})

    def test_short_load_cannot_be_promoted_to_sustained_qualification(self):
        records = self.sustained_run()
        next(row for row in records if row['kind'] == 'workload_summary')['elapsed_seconds'] = 1799
        with self.assertRaisesRegex(mixed.InvalidEvidence, '^timing$'):
            mixed.qualify(records, 2, 1, 5400, 1800)

    def test_sustained_resources_require_full_time_coverage(self):
        for mode in ('gap', 'missing-tail', 'duplicate-time'):
            with self.subTest(mode=mode):
                records = self.sustained_run()
                if mode == 'gap':
                    records = [row for row in records if row['kind'] != 'resources'
                               or not 800 <= row['elapsed_seconds'] <= 820]
                elif mode == 'missing-tail':
                    records = [row for row in records if row['kind'] != 'resources'
                               or row['elapsed_seconds'] <= 1700]
                else:
                    resources = [row for row in records if row['kind'] == 'resources']
                    resources[1]['elapsed_seconds'] = resources[0]['elapsed_seconds']
                with self.assertRaisesRegex(mixed.InvalidEvidence, '^resources$'):
                    mixed.qualify(records, 2, 1, 5400, 1800)

    def test_complete_run_exports_only_closed_counts_and_timings(self):
        result = mixed.qualify(complete_run(), 2)
        self.assertTrue(result['qualified'])
        self.assertEqual(result['counts']['verified_permission_checks'], 600)
        self.assertEqual(result['resources']['peak_member_rss_mib'], [.5] * 4)
        self.assertEqual(result['scheduled_workflow_ms']['p95'], 600)
        public = json.dumps(result)
        self.assertNotIn('private', public)
        self.assertNotIn('/private/daemon', public)
        self.assertNotIn('0x', public)
        self.assertNotIn('node_pids', public)

    def test_missing_revocation_replica_and_duplicate_workflow_are_rejected(self):
        for kind, phase in [('replica_check', 'reintroduce_member'), ('workflow_phase', 'member_revoke')]:
            records = complete_run()
            removed = next(row for row in records if row.get('kind') == kind and row.get('phase') == phase)
            records.remove(removed)
            with self.assertRaises(mixed.InvalidEvidence):
                mixed.qualify(records, 2)
        records = complete_run()
        completed = [row for row in records if row['kind'] == 'workflow_completed']
        completed[1]['workflow'] = completed[0]['workflow']
        with self.assertRaises(mixed.InvalidEvidence):
            mixed.qualify(records, 2)

    def test_uncertified_submissions_and_mixed_revisions_are_rejected(self):
        for kind, field, value in [('result', 'success', False), ('submission', 'error', 'private server message'),
                                    ('replica_check', 'minimum_revision', 19)]:
            records = complete_run()
            next(row for row in records if row['kind'] == kind)[field] = value
            with self.assertRaises(mixed.InvalidEvidence):
                mixed.qualify(records, 2)
        records = complete_run()
        next(row for row in records if row['kind'] == 'result')['counts']['certified_successes'] -= 1
        with self.assertRaises(mixed.InvalidEvidence):
            mixed.qualify(records, 2)

    def test_debug_build_invalid_numbers_and_missing_resources_are_rejected(self):
        for kind, field, value in [('configuration', 'debug_assertions', True), ('workflow_completed', 'elapsed_ms', float('nan')),
                                    ('workflow_completed', 'workflow', True), ('restart', 'verified_workflows', 1)]:
            records = complete_run()
            next(row for row in records if row['kind'] == kind)[field] = value
            with self.assertRaises(mixed.InvalidEvidence):
                mixed.qualify(records, 2)
        records = complete_run()
        next(row for row in records if row['kind'] == 'resources')['sample']['rows'] = '101 512 0:00\n'
        with self.assertRaises(mixed.InvalidEvidence):
            mixed.qualify(records, 2)

    def test_failed_provenance_exports_no_private_manifest_content(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'manifest.json').write_text(json.dumps({
                'source': 'a' * 40, 'runner_source': 'a' * 40, 'dirty': True,
                'private_field': 'private fixture material'}))
            output = root / 'evidence.json'
            arguments = ['gate', '--directory', str(root), '--node', str(root / 'node'),
                         '--runner', str(root / 'runner'), '--output', str(output)]
            with patch('sys.argv', arguments), patch.object(mixed.subprocess, 'check_output', return_value='a' * 40):
                with self.assertRaises(SystemExit):
                    mixed.main()
            public = json.loads(output.read_text())
            self.assertFalse(public['qualified'])
            self.assertEqual(public['failure_stage'], 'provenance')
            self.assertNotIn('private', output.read_text())

    def test_bounded_reader_rejects_symlinks_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / 'target'
            target.write_text('private fixture material')
            link = root / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                mixed.read_bounded(link)
            with target.open('wb') as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(mixed.InvalidEvidence):
                mixed.read_bounded(target)


if __name__ == '__main__':
    unittest.main()
