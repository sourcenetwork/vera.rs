import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import qualify_snapshots as qualification
from test_snapshot_metrics import snapshot


def allocator_snapshot(second=0, supported=True):
    values = [1024, 768, 256, 4096]
    fields = ', '.join('"%s": %s' % (name, 'Some(%d)' % value if supported else 'None')
                       for name, value in zip(qualification.COUNTERS, values))
    return snapshot(second, '{private_label="do-not-export"}').rstrip() + (
        ' allocator_memory_bytes={' + fields + '}\n')


class Qualification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / 'private-clusters'
        self.cluster = self.logs / 'private-test-name'
        for index in range(4):
            directory = self.cluster / ('node%d' % index) / 'logs'
            directory.mkdir(parents=True)
            (directory / 'stdout.log').write_text(allocator_snapshot() + allocator_snapshot(30))

    def log(self, index=0):
        return self.cluster / ('node%d' % index) / 'logs/stdout.log'

    def test_actual_parser_qualifies_members_without_exporting_private_fields(self):
        self.log().write_text(allocator_snapshot() + allocator_snapshot(30)
                              .replace('Some(1024)', 'Some(2048)')
                              .replace('Some(256)', 'Some(1280)'))
        report = qualification.qualify(self.logs)
        self.assertEqual(report['allocator'], 'glibc')
        self.assertEqual(len(report['clusters']), 1)
        members = report['clusters'][0]['members']
        self.assertEqual([row['samples'] for row in members], [2] * 4)
        self.assertEqual(members[0]['bytes']['arena_free'],
                         {'minimum': 256, 'maximum': 1280, 'last': 1280})
        encoded = json.dumps(report)
        for private in ('private-test-name', 'do-not-export', 'runtime_metrics', str(self.root)):
            self.assertNotIn(private, encoded)

    def test_restart_process_count_requires_identity_on_every_sample(self):
        first = allocator_snapshot().rstrip() + ' process_id=11\n'
        second = allocator_snapshot(30).rstrip() + ' process_id=29\n'
        self.log().write_text(first + second)
        members = qualification.qualify(self.logs)['clusters'][0]['members']
        self.assertEqual(members[0]['processes'], 2)
        self.assertIsNone(members[1]['processes'])
        self.log().write_text(first + allocator_snapshot(30))
        members = qualification.qualify(self.logs)['clusters'][0]['members']
        self.assertIsNone(members[0]['processes'])

    def test_required_process_identity_rejects_old_and_mixed_samples(self):
        with self.assertRaisesRegex(ValueError, 'process ID'):
            qualification.qualify(self.logs, require_process_id=True)
        for index in range(4):
            content = allocator_snapshot().rstrip() + ' process_id=%d\n' % (index + 1)
            self.log(index).write_text(content)
        members = qualification.qualify(self.logs, require_process_id=True)['clusters'][0]['members']
        self.assertEqual([member['processes'] for member in members], [1] * 4)
        output = self.root / 'identified-evidence.json'
        args = ['--logs', str(self.logs), '--output', str(output), '--require-process-id']
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(qualification.main(args), 0)
        with self.log().open('a') as output:
            output.write(allocator_snapshot(30))
        with self.assertRaisesRegex(ValueError, 'process ID'):
            qualification.qualify(self.logs, require_process_id=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(qualification.main(args), 1)
        self.assertFalse((self.root / 'identified-evidence.json').exists())

    def test_missing_unsupported_malformed_and_inconsistent_snapshots_fail(self):
        for content in ('ordinary private log\n', snapshot(), allocator_snapshot(supported=False),
                        allocator_snapshot().replace('Some(256)', 'Some(257)'),
                        allocator_snapshot().replace('Some(768)', 'Some(-1)')):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.log().write_text(content)
                qualification.qualify(self.logs)

    def test_missing_and_oversized_member_sets_fail(self):
        missing = self.cluster / 'node1'
        missing.rename(self.cluster / 'retained-node1')
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)
        (self.cluster / 'retained-node1').rename(missing)
        for index in range(4, qualification.MAX_MEMBERS + 1):
            (self.cluster / ('node%d' % index)).mkdir()
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)

    def test_multiple_clusters_and_the_four_member_coverage_requirement(self):
        second = self.logs / 'second-private-cluster' / 'node0/logs'
        second.mkdir(parents=True)
        (second / 'stdout.log').write_text(allocator_snapshot())
        report = qualification.qualify(self.logs)
        self.assertEqual([len(row['members']) for row in report['clusters']], [4, 1])
        self.cluster.rename(self.root / 'outside-retained-root')
        with self.assertRaisesRegex(ValueError, 'four-member cluster'):
            qualification.qualify(self.logs)

    def test_symlinked_logs_and_directories_fail(self):
        self.log().rename(self.root / 'original.log')
        self.log().symlink_to(self.root / 'original.log')
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)
        self.log().unlink()
        (self.root / 'original.log').rename(self.log())
        self.cluster.rename(self.root / 'retained-cluster')
        self.cluster.symlink_to(self.root / 'retained-cluster', target_is_directory=True)
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)

    def test_sample_and_file_limits_fail(self):
        self.log().write_text(allocator_snapshot() * (qualification.MAX_SNAPSHOTS + 1))
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)
        with self.log().open('wb') as stream:
            stream.truncate(qualification.MAX_LOG_BYTES + 1)
        with self.assertRaises(ValueError):
            qualification.qualify(self.logs)

    def test_failed_collection_removes_stale_evidence_and_hides_log_content(self):
        output = self.root / 'evidence.json'
        output.write_text('stale success')
        self.log().write_text('private-do-not-export\n')
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(qualification.main(['--logs', str(self.logs), '--output', str(output)]), 1)
        self.assertFalse(output.exists())
        self.assertEqual(errors.getvalue(), 'allocator snapshot qualification failed\n')


if __name__ == '__main__':
    unittest.main()
