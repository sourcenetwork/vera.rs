import json
from pathlib import Path
import tempfile
import unittest

from resource_usage import cpu_seconds, markdown_resources, summarize_resources


class ResourceUsageTests(unittest.TestCase):
    def summarize(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'workload.jsonl'
            path.write_text('\n'.join(json.dumps(row) for row in rows))
            return summarize_resources(path)

    def config(self):
        return {'kind': 'resource_configuration', 'node_pids': [7, 9]}

    def sample(self, elapsed, rows):
        return {'kind': 'resources', 'elapsed_seconds': elapsed, 'sample': {'rows': rows}}

    def test_cpu_clock_formats_preserve_units(self):
        for raw, expected in [('0:13.25', 13.25), ('03:01', 181),
                              ('01:02:03', 3723), ('1-01:02:03', 90123)]:
            with self.subTest(raw=raw):
                self.assertEqual(cpu_seconds(raw), expected)
        for raw in ['NaN', '-1:00', '00:60', '01:60:00', '1-24:00:00', '1-01:02']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                cpu_seconds(raw)

    def test_memory_peak_and_cpu_use_observed_interval(self):
        result = self.summarize([
            self.config(), self.sample(10, '7 1024 00:00:10\n9 2048 00:00:00'),
            self.sample(310, '7 4096 00:01:10\n9 6144 00:02:00'),
            self.sample(610, '7 3072 00:02:10\n9 5120 00:04:00')])
        first, second = result['members']
        self.assertEqual(first['rss_mib'], {'first': 1, 'last': 3, 'peak': 4})
        self.assertEqual(first['observed_window']['cpu_seconds'], 120)
        self.assertEqual(first['observed_window']['duration_seconds'], 600)
        self.assertEqual(first['observed_window']['average_cpu_cores'], .2)
        self.assertEqual(second['observed_window']['average_cpu_cores'], .4)
        self.assertEqual(second['rss_mib']['peak'], 6)
        self.assertEqual(first['late_rss_growth']['delta_mib'], 2)
        self.assertEqual(first['late_rss_growth']['observed_seconds'], 600)
        self.assertIn('| 0 | 4.00 | 0.20 | 2.00 | 0 |', markdown_resources(result))

    def test_missing_samples_do_not_become_zero_usage(self):
        result = self.summarize([
            self.config(), self.sample(10, '7 1024 00:00:10'),
            self.sample(15, ''), self.sample(20, '7 1024 00:00:10')])
        measured, absent = result['members']
        self.assertEqual(measured['missing_samples'], 1)
        self.assertEqual(measured['observed_window']['average_cpu_cores'], 0)
        self.assertEqual(measured['rss_mib']['last'], 1)
        self.assertEqual(absent['missing_samples'], 3)
        self.assertIsNone(absent['rss_mib'])
        self.assertIsNone(absent['observed_window'])
        self.assertIn('| 1 | unavailable | unavailable | unavailable | 3 |', markdown_resources(result))

    def test_member_order_follows_configuration_not_ps_output(self):
        result = self.summarize([
            {'kind': 'resource_configuration', 'node_pids': [9, 7]},
            self.sample(10, '7 1024 00:00:01\n9 2048 00:00:02')])
        self.assertEqual(result['members'][0]['rss_mib']['peak'], 2)
        self.assertEqual(result['members'][1]['rss_mib']['peak'], 1)

    def test_short_runs_and_single_samples_have_no_late_growth(self):
        for rows in [[self.sample(1, '7 1024 00:00:00')],
                     [self.sample(1, '7 1024 00:00:00'), self.sample(2, '7 2048 00:00:01')]]:
            result = self.summarize([self.config(), *rows])
            self.assertIsNone(result['members'][0]['late_rss_growth'])
        result = self.summarize([self.config(), self.sample(1, '7 1024 00:00:00')])
        self.assertIsNone(result['members'][0]['observed_window'])

    def test_malformed_or_reset_counters_cannot_produce_a_report(self):
        initial = self.sample(10, '7 1024 00:00:10')
        for final in [self.sample(20, '7 1024 00:00:09'),
                      self.sample(20, '8 1024 00:00:11'),
                      self.sample(20, '7 -1 00:00:11'),
                      self.sample(20, '7 1024 00:00:11\n7 1024 00:00:11'),
                      self.sample(20, '7 1024 NaN'), self.sample(10, '7 1024 00:00:11'),
                      self.sample(True, '7 1024 00:00:11')]:
            with self.subTest(final=final), self.assertRaises(ValueError):
                self.summarize([self.config(), initial, final])
        with self.assertRaises(ValueError):
            self.summarize([initial, self.config()])
        with self.assertRaises(ValueError):
            self.summarize([self.config(), self.config()])


if __name__ == '__main__':
    unittest.main()
