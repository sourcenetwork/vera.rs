"""Trust and timing boundaries of the offline measurement replay."""
import json
from pathlib import Path
import re
import tempfile
import unittest

from replay import build_replay, render


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.manifest = {'exit_code': 0, 'source': 'recorded-source'}
        self.rows = [
            dict(kind='configuration', format_version=2, count=2, nodes=2,
                 arrival_model='scheduled_drop_when_full', arrivals_per_second=2),
            dict(kind='summary', offered=2, completed_workflows=2, confirmed=2,
                 elapsed_seconds=1, verification_failures=0, unknown=0, rejected=0,
                 reverted=0, not_sent=0, confirmed_incomplete_workflows=0),
            dict(kind='observation', index=1, outcome='confirmed', verification_failure=False,
                 error=None, scheduled_to_certified_receipt_ms=100, scheduled_to_workflow_ms=150),
            dict(kind='observation', index=0, outcome='confirmed', verification_failure=False,
                 error=None, scheduled_to_certified_receipt_ms=200, scheduled_to_workflow_ms=250),
            dict(kind='verification', verified=2, unresolved=0, replicas=2),
            dict(kind='recovery', inspected_operations=2, receipt_mismatches=0, state_mismatches=0),
            dict(kind='resource_configuration', node_pids=[41, 42]),
            dict(kind='resources', elapsed_seconds=.1, sample={'rows': '41 2048 00:00:01\n42 4096 00:00:01'}),
            dict(kind='resources', elapsed_seconds=.7, sample={'rows': '41 3072 00:00:01'}),
        ]

    def load(self):
        (self.path / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.path / 'workload.jsonl').write_text('\n'.join(json.dumps(row) for row in self.rows))
        return build_replay(self.path)

    def test_schedule_plus_measured_latency_and_missing_rss(self):
        for model in ('scheduled_drop_when_full', 'scheduled_wait_for_previous_per_object'):
            with self.subTest(model=model):
                self.rows[0]['arrival_model'] = model
                result = self.load()
                self.assertEqual(result['status'], 'passed')
                self.assertEqual([(e['index'], e['at'], e['completed_at']) for e in result['events']],
                                 [(0, .2, .25), (1, .6, .65)])
                self.assertEqual(result['duration'], 1)
                self.assertEqual(result['members'][1]['rss_mib'], [4, None])
                self.assertEqual(result['missing_member_samples'], 1)
                self.assertEqual(result['manifest']['source'], 'recorded-source')

    def test_untrusted_labels_round_trip_without_script_breakout(self):
        attack = '</script><img src=x onerror=alert(1)>&\u2028\u2029'
        self.manifest['source'] = attack
        self.manifest['run_url'] = 'javascript:alert(1)'
        html = render(self.load())
        self.assertNotIn(attack, html)
        self.assertNotIn('<img src=x', html)
        embedded = re.search(r'<script id="replay-data" type="application/json">(.*?)</script>', html, re.S).group(1)
        self.assertEqual(json.loads(embedded)['manifest']['source'], attack)
        self.assertEqual(html.count('</script>'), 2)
        script = Path(__file__).with_name('replay').joinpath('script.js').read_text()
        self.assertNotIn('innerHTML', script)
        self.assertNotIn('setAttribute(\'href\'', script)

    def test_failed_or_missing_recovery_never_passes(self):
        for failure in ('exit', 'observation', 'recovery', 'missing'):
            with self.subTest(failure=failure):
                original = json.loads(json.dumps(self.rows))
                self.manifest['exit_code'] = 1 if failure == 'exit' else 0
                if failure == 'observation': self.rows[2]['verification_failure'] = True
                if failure == 'recovery': self.rows[5]['state_mismatches'] = 1
                if failure == 'missing': self.rows = [r for r in self.rows if r['kind'] != 'recovery']
                self.assertEqual(self.load()['status'], 'failed')
                self.rows = original

    def test_incomplete_stream_and_invalid_timestamps_have_no_charts(self):
        self.rows = [r for r in self.rows if r['kind'] != 'summary']
        result = self.load()
        self.assertEqual(result['status'], 'unavailable')
        self.assertFalse(result['events'])
        self.assertEqual(result['manifest']['source'], 'recorded-source')
        self.assertIn('expected one summary', result['issue'])

    def test_wrong_json_shapes_still_render_unavailable_evidence(self):
        self.manifest = []
        result = self.load()
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['manifest'], {})
        self.assertIn('must be JSON objects', result['issue'])
        self.assertIn('replay-data', render(result))
        self.manifest = {'exit_code': 0}
        self.rows.append([])
        self.assertEqual(self.load()['status'], 'unavailable')

    def test_nested_resource_shape_cannot_escape_unavailable_report(self):
        for sample in (None, [], {'rows': []}):
            with self.subTest(sample=sample):
                self.rows[-1]['sample'] = sample
                result = self.load()
                self.assertEqual(result['status'], 'unavailable')
                self.assertFalse(result['members'])
                self.assertIn('resource sample', result['issue'])
                self.assertIn('replay-data', render(result))

    def test_no_invented_event_time_for_missing_receipt_or_unknown_schedule(self):
        self.rows[2]['scheduled_to_certified_receipt_ms'] = None
        result = self.load()
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(result['untimed_observations'], 1)
        self.rows[0]['arrival_model'] = 'unrecognized-model'
        result = self.load()
        self.assertFalse(result['timeline_available'])
        self.assertEqual(result['events'], [])
        self.assertEqual(result['untimed_observations'], 2)

    def test_impossible_derived_time_and_nonfinite_resource_time_are_rejected(self):
        self.rows[2]['scheduled_to_workflow_ms'] = 2000
        self.assertEqual(self.load()['status'], 'unavailable')
        self.rows[2]['scheduled_to_workflow_ms'] = 150
        self.rows[-1]['elapsed_seconds'] = float('nan')
        self.assertEqual(self.load()['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
