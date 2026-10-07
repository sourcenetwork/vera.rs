"""The report must not present incomplete or unverifiable runs as successful."""
import json
from pathlib import Path
import tempfile
import unittest

from report import load_run


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        (self.path / 'manifest.json').write_text(json.dumps({'exit_code': 0}))
        self.rows = [
            {'kind': 'configuration', 'format_version': 2, 'count': 1, 'nodes': 1},
            dict(kind='summary', offered=1, completed_workflows=1, confirmed=1,
                 verification_failures=0, unknown=0, rejected=0, reverted=0,
                 not_sent=0, confirmed_incomplete_workflows=0),
            dict(kind='observation', index=0, outcome='confirmed', verification_failure=False,
                 error=None, scheduled_to_certified_receipt_ms=12),
            dict(kind='verification', verified=1, unresolved=0, replicas=1),
            dict(kind='recovery', inspected_operations=1, receipt_mismatches=0, state_mismatches=0),
            dict(kind='resource_configuration', node_pids=[42]),
            dict(kind='resources', elapsed_seconds=1, sample={'error': 'unavailable'}),
        ]

    def load(self):
        (self.path / 'workload.jsonl').write_text('\n'.join(json.dumps(row) for row in self.rows))
        return load_run(self.path)

    def test_missing_resources_are_not_zero_samples(self):
        result = self.load()
        self.assertTrue(result[3])
        self.assertEqual(result[5], {42: []})
        self.assertEqual(result[6], 1)

    def test_rss_breakdown_preserves_legacy_report_and_missing_ps_samples(self):
        self.rows[-1]['sample'] = {'rows': '42 2048 00:00:01\n'}
        legacy = self.load()
        self.assertEqual(legacy[5], {42: [(1, 2.0)]})
        for source, availability, values in [
                ('linux_proc_status', 'complete', [2048, 1536, 512, 0]),
                ('linux_proc_status', 'partial', [2048, None, 512, None]),
                ('unsupported', 'unsupported', [None] * 4),
                ('linux_proc_status', 'read_error', [None] * 4)]:
            with self.subTest(availability=availability):
                self.rows[-2]['rss_breakdown_source'] = source
                self.rows[-1]['sample']['rss_breakdown'] = [dict(
                    pid=42, availability=availability,
                    vm_rss_kib=values[0], rss_anon_kib=values[1],
                    rss_file_kib=values[2], rss_shmem_kib=values[3])]
                self.assertEqual(self.load(), legacy)
        # Component measurements never fill a missing legacy ps observation.
        del self.rows[-1]['sample']['rows']
        self.rows[-1]['sample']['rss_breakdown'][0].update(
            availability='complete', vm_rss_kib=2048, rss_anon_kib=1536,
            rss_file_kib=512, rss_shmem_kib=0)
        result = self.load()
        self.assertEqual(result[5], {42: []})
        self.assertEqual(result[6], 1)

    def test_missing_recovery_cannot_pass(self):
        self.rows = [row for row in self.rows if row['kind'] != 'recovery']
        result = self.load()
        self.assertFalse(result[3])
        self.assertEqual(result[-1], {})

    def test_missing_replica_verification_cannot_pass(self):
        self.rows = [row for row in self.rows if row['kind'] != 'verification']
        result = self.load()
        self.assertFalse(result[3])
        self.assertEqual(result[-2], {})

    def test_duplicate_recovery_is_rejected(self):
        self.rows.append(dict(self.rows[4]))
        with self.assertRaisesRegex(ValueError, 'expected one recovery'):
            self.load()

    def test_observation_failure_overrides_success_summary(self):
        self.rows[2]['verification_failure'] = True
        self.assertFalse(self.load()[3])

    def test_restart_mismatch_fails_report(self):
        self.rows[4]['state_mismatches'] = 1
        self.assertFalse(self.load()[3])

    def test_invalid_latency_is_rejected(self):
        self.rows[2]['scheduled_to_certified_receipt_ms'] = float('nan')
        with self.assertRaisesRegex(ValueError, 'latency'):
            self.load()


if __name__ == '__main__':
    unittest.main()
