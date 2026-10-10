import importlib.util
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
