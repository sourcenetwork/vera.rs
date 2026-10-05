"""PR comparisons must preserve failures and distinguish noise from direction."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from compare_pr import COMPONENTS, LIFECYCLE_COMPONENTS, TAGS, change, compare, components


class CompareTests(unittest.TestCase):
    def test_direction_and_noise(self):
        self.assertEqual(change([100, 101], [110, 111])[1], 'regression signal')
        self.assertEqual(change([100, 101], [110, 111], lower=False)[1], 'improvement signal')
        self.assertEqual(change([100, 120], [110, 130])[1], 'inconclusive (pass ranges overlap)')
        self.assertEqual(change([100, 101], [102, 103])[1], 'within threshold')
        self.assertEqual(change([100, 101], [80, 81])[1], 'improvement signal')
        self.assertEqual(change([100, 101], [110, 150])[1], 'inconclusive (pass variability)')

    def test_invalid_timings(self):
        for values in ([0, 1], [float('nan'), 1], [float('inf'), 1], [1]):
            with self.assertRaises(ValueError):
                change(values, [1, 2])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.identity = {s: dict(source=s, node_sha256=s, runner_sha256=s, components=True) for s in ('head', 'base')}
        self.write_identity()
        self.rows = [dict(format_version=1, fixture_version=1, kind='configuration', samples=9, sample_ms=100, warmup_ms=200)]
        self.rows += [dict(name=n, unit='ns/op', samples=[100] * 9, iterations=[10] * 9) for n in COMPONENTS]
        for tag in TAGS:
            (self.root / tag).mkdir()
            (self.root / tag / 'components.jsonl').write_text('\n'.join(json.dumps(r) for r in self.rows))

    def write_identity(self):
        (self.root / 'comparison.json').write_text(json.dumps(self.identity))

    def run_fixture(self, path):
        side = path.parent.name.rstrip('12')
        manifest = dict(source=side, dirty=False, node_sha256=side, runner_sha256=side)
        summary = dict(completed_workflows_per_second=20)
        for metric in ('scheduled_to_certified_receipt_ms', 'permission_read_ms', 'scheduled_to_workflow_ms'):
            summary[metric] = dict(p95=10)
        return manifest, dict(count=600), summary, True, [], {1: [(1, 100)]}, 0, {}, {}

    def test_correctness_failure_never_becomes_speedup(self):
        def bad(path):
            run = list(self.run_fixture(path))
            if path.parent.name == 'head2':
                run[3] = False
            return run
        with patch('compare_pr.load_run', side_effect=bad):
            self.assertTrue(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(len(result['errors']), 2)
        self.assertTrue(all('ns/op' in r['metric'] for r in result['metrics']))

    def test_source_and_binary_mismatch_fail(self):
        for key in ('source', 'node_sha256', 'runner_sha256'):
            def bad(path):
                run = self.run_fixture(path)
                run[0][key] = 'wrong'
                return run
            with patch('compare_pr.load_run', side_effect=bad):
                self.assertTrue(compare(self.root))

    def test_configuration_changes_suppress_deltas(self):
        def changed(path):
            run = self.run_fixture(path)
            run[1]['queue'] = 128 if path.parent.name.startswith('head') else 0
            return run
        with patch('compare_pr.load_run', side_effect=changed):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(len(result['configuration_differences']), 2)
        self.assertTrue(all(r['change_percent'] is None for r in result['metrics'] if 'ns/op' not in r['metric']))

    def test_new_component_is_explicit_not_zero_baseline(self):
        self.identity['base']['components'] = False
        self.write_identity()
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(result['metrics'][-1]['verdict'], 'new benchmark; no baseline')
        self.assertIsNone(result['metrics'][-1]['change_percent'])

    def write_lifecycle(self, tag, value=100):
        rows = [dict(self.rows[0], fixture_version=2)] + self.rows[1:]
        rows += [dict(name=n, unit='ns/op', samples=[value] * 9, iterations=[3] * 9)
                 for n in LIFECYCLE_COMPONENTS]
        (self.root / tag / 'components.jsonl').write_text('\n'.join(json.dumps(r) for r in rows))

    def test_new_lifecycle_metrics_preserve_existing_comparisons(self):
        for tag in ('head1', 'head2'):
            self.write_lifecycle(tag)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        metrics = {row['metric']: row for row in result['metrics']}
        for name in COMPONENTS:
            self.assertEqual(metrics[f'{name}: ns/op']['change_percent'], 0)
        for name in LIFECYCLE_COMPONENTS:
            row = metrics[f'{name}: ns/op']
            self.assertIsNone(row['change_percent'])
            self.assertEqual(row['base'], [])
            self.assertEqual(row['verdict'], 'new benchmark; no baseline')

    def test_lifecycle_regressions_are_reported(self):
        for tag in TAGS:
            self.write_lifecycle(tag, 120 if tag.startswith('head') else 100)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        metrics = {row['metric']: row for row in result['metrics']}
        for name in LIFECYCLE_COMPONENTS:
            self.assertEqual(metrics[f'{name}: ns/op']['verdict'], 'regression signal')

    def test_missing_lifecycle_measurement_fails(self):
        self.write_lifecycle('head1')
        path = self.root / 'head1' / 'components.jsonl'
        path.write_text('\n'.join(path.read_text().splitlines()[:-1]))
        with self.assertRaisesRegex(ValueError, 'missing component'):
            components(path)

    def test_component_fixture_must_match_between_passes(self):
        self.write_lifecycle('head1')
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertTrue(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(result['errors'], ['components: component fixture changed between head passes'])

    def test_removed_component_measurements_fail(self):
        for tag in ('base1', 'base2'):
            self.write_lifecycle(tag)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertTrue(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(result['errors'], ['components: head removed a component measurement'])

    def test_missing_component_fails(self):
        path = self.root / 'head1' / 'components.jsonl'
        path.write_text('\n'.join(json.dumps(r) for r in self.rows[:-1]))
        with self.assertRaisesRegex(ValueError, 'missing component'):
            components(path)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertTrue(compare(self.root))


if __name__ == '__main__':
    unittest.main()
