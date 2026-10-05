"""PR comparisons must preserve failures and distinguish noise from direction."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from protocol import SCHEMAS, unavailable
from compare_pr import COMPONENTS, LIFECYCLE_COMPONENTS, LOGICAL_EDIT_COMPONENTS, TAGS, change, compare, components


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

    def shared_driver(self):
        self.identity['format_version'] = 2
        for side in ('head', 'base'):
            self.identity[side].update(runner_source='head', runner_sha256='shared-driver')
        self.write_identity()

    def shared_run_fixture(self, path):
        run = self.run_fixture(path)
        run[0].update(format_version=2, runner_source='head', runner_sha256='shared-driver', runner_dirty=False)
        return run

    def test_shared_driver_accepts_distinct_node_revisions(self):
        self.shared_driver()
        with patch('compare_pr.load_run', side_effect=self.shared_run_fixture):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertFalse(result['errors'])
        self.assertTrue(any('workflows/s' in row['metric'] for row in result['metrics']))
        self.assertIn('Shared workload runner source `head`', (self.root / 'comparison.md').read_text())

    def incompatible_driver(self):
        self.shared_driver()
        self.identity['head']['proof_schema'] = dict(SCHEMAS['relationship/v4/'])
        self.identity['base']['proof_schema'] = dict(SCHEMAS['relationship/v3/'])
        self.write_identity()
        for tag in ('base1', 'base2'):
            for objects in (0, 32):
                directory = self.root / tag / f'objects-{objects}'
                directory.mkdir(exist_ok=True)
                (directory / 'unavailable.json').write_text(json.dumps(unavailable(self.identity, objects)))

    def test_incompatible_schema_reports_head_only_without_baseline_success_or_delta(self):
        self.incompatible_driver()
        with patch('compare_pr.load_run', side_effect=self.shared_run_fixture) as load:
            self.assertFalse(compare(self.root))
        self.assertEqual({call.args[0].parent.name for call in load.call_args_list}, {'head1', 'head2'})
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(len(result['non_comparable_baselines']), 2)
        for metric in result['metrics']:
            if 'ns/op' not in metric['metric']:
                self.assertEqual(metric['base'], [])
                self.assertEqual(len(metric['head']), 2)
                self.assertIsNone(metric['change_percent'])
                self.assertIn('baseline not run', metric['verdict'])
        self.assertIn('no baseline success or regression claim', (self.root / 'comparison.md').read_text())

    def test_incompatible_baseline_still_requires_each_valid_head_pass(self):
        self.incompatible_driver()
        for failure in ('missing', 'failed', 'provenance'):
            with self.subTest(failure=failure):
                def bad(path):
                    run = list(self.shared_run_fixture(path))
                    if path.parent.name == 'head2':
                        if failure == 'missing':
                            raise FileNotFoundError('head2 missing')
                        if failure == 'failed':
                            run[3] = False
                        else:
                            run[0]['runner_sha256'] = 'wrong'
                    return run
                with patch('compare_pr.load_run', side_effect=bad):
                    self.assertTrue(compare(self.root))
                result = json.loads((self.root / 'comparison-report.json').read_text())
                self.assertEqual(len(result['errors']), 2)
                self.assertTrue(all('ns/op' in row['metric'] for row in result['metrics']))

    def test_unknown_or_incomplete_schema_metadata_fails(self):
        self.incompatible_driver()
        for schema in (None, {}, {'relationship_namespace': 'relationship/v5/', 'policy_generations': 'required'}):
            self.identity['base']['proof_schema'] = schema
            self.write_identity()
            with patch('compare_pr.load_run', side_effect=self.shared_run_fixture):
                self.assertTrue(compare(self.root))
        del self.identity['base']['proof_schema']
        self.write_identity()
        with patch('compare_pr.load_run', side_effect=self.shared_run_fixture):
            self.assertTrue(compare(self.root))

    def test_incompatible_baseline_requires_exact_not_run_evidence(self):
        self.incompatible_driver()
        directory = self.root / 'base1' / 'objects-0'
        (directory / 'unavailable.json').write_text('{}')
        with patch('compare_pr.load_run', side_effect=self.shared_run_fixture):
            self.assertTrue(compare(self.root))
        (directory / 'unavailable.json').write_text(json.dumps(unavailable(self.identity, 0)))
        (directory / 'manifest.json').write_text('{"exit_code":101}')
        with patch('compare_pr.load_run', side_effect=self.shared_run_fixture):
            self.assertTrue(compare(self.root))

    def test_shared_driver_rejects_missing_dirty_or_misattributed_manifests(self):
        self.shared_driver()
        for key, value in [('runner_source', 'base'), ('runner_dirty', True), ('format_version', 1),
                           ('runner_source', None), ('runner_dirty', None)]:
            with self.subTest(key=key, value=value):
                def bad(path):
                    run = self.shared_run_fixture(path)
                    if value is None:
                        run[0].pop(key)
                    else:
                        run[0][key] = value
                    return run
                with patch('compare_pr.load_run', side_effect=bad):
                    self.assertTrue(compare(self.root))
                result = json.loads((self.root / 'comparison-report.json').read_text())
                self.assertEqual(len(result['errors']), 2)
                self.assertTrue(all('ns/op' in row['metric'] for row in result['metrics']))

    def test_shared_driver_requires_boolean_clean_flags(self):
        self.shared_driver()
        for key in ('dirty', 'runner_dirty'):
            for value in (None, 0, '', [], {}):
                with self.subTest(key=key, value=value):
                    def bad(path):
                        run = self.shared_run_fixture(path)
                        run[0][key] = value
                        return run
                    with patch('compare_pr.load_run', side_effect=bad):
                        self.assertTrue(compare(self.root))
                    result = json.loads((self.root / 'comparison-report.json').read_text())
                    self.assertEqual(len(result['errors']), 2)
                    self.assertTrue(all('ns/op' in row['metric'] for row in result['metrics']))

    def test_version_two_manifests_cannot_use_historical_comparison_rules(self):
        self.shared_driver()
        for version in (None, 1):
            with self.subTest(version=version):
                if version is None:
                    self.identity.pop('format_version')
                else:
                    self.identity['format_version'] = version
                self.write_identity()
                def bad(path):
                    run = self.shared_run_fixture(path)
                    run[0]['runner_dirty'] = True
                    return run
                with patch('compare_pr.load_run', side_effect=bad):
                    self.assertTrue(compare(self.root))
                result = json.loads((self.root / 'comparison-report.json').read_text())
                self.assertTrue(all('mixed comparison provenance versions' in error for error in result['errors']))

    def test_shared_driver_rejects_two_runners_even_with_matching_side_manifests(self):
        for key, value in [('runner_source', 'base'), ('runner_sha256', 'old-driver')]:
            with self.subTest(key=key):
                self.shared_driver()
                self.identity['base'][key] = value
                self.write_identity()
                def bad(path):
                    run = self.shared_run_fixture(path)
                    if path.parent.name.startswith('base'):
                        run[0][key] = value
                    return run
                with patch('compare_pr.load_run', side_effect=bad):
                    self.assertTrue(compare(self.root))
                result = json.loads((self.root / 'comparison-report.json').read_text())
                self.assertTrue(all('one head-built workload runner' in error for error in result['errors']))

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

    def write_logical_edit(self, tag, small=100, large=200):
        self.write_lifecycle(tag)
        path = self.root / tag / 'components.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['fixture_version'] = 3
        rows += [dict(name=name, unit='ns/op', samples=[value] * 9, iterations=[3] * 9)
                 for name, value in zip(LOGICAL_EDIT_COMPONENTS, (small, large))]
        path.write_text('\n'.join(json.dumps(row) for row in rows))

    def test_logical_edit_v3_accepts_both_old_baselines_and_reports_head_ratios(self):
        for old_version in (1, 2):
            with self.subTest(old_version=old_version):
                for tag in ('base1', 'base2'):
                    if old_version == 2:
                        self.write_lifecycle(tag)
                self.write_logical_edit('head1', 100, 200)
                self.write_logical_edit('head2', 200, 600)
                with patch('compare_pr.load_run', side_effect=self.run_fixture):
                    self.assertFalse(compare(self.root))
                result = json.loads((self.root / 'comparison-report.json').read_text())
                self.assertEqual(result['logical_edit_2048_to_32_ratio'], {'head1': 2, 'head2': 3})
                metrics = {row['metric']: row for row in result['metrics']}
                for name in LOGICAL_EDIT_COMPONENTS:
                    self.assertEqual(metrics[f'{name}: ns/op']['verdict'], 'new benchmark; no baseline')
                    self.assertIsNone(metrics[f'{name}: ns/op']['change_percent'])
                self.assertEqual(metrics['native_bls_verify: ns/op']['change_percent'], 0)

    def test_logical_edit_v3_requires_both_sizes_and_matching_head_passes(self):
        self.write_logical_edit('head1')
        path = self.root / 'head1' / 'components.jsonl'
        lines = path.read_text().splitlines()
        path.write_text('\n'.join(lines[:-1]))
        with self.assertRaisesRegex(ValueError, 'missing component'):
            components(path)
        self.write_logical_edit('head1')
        self.write_lifecycle('head2')
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertTrue(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        self.assertEqual(result['errors'], ['components: component fixture changed between head passes'])
        self.assertEqual(result['logical_edit_2048_to_32_ratio'], {})

    def test_logical_edit_v3_same_fixture_keeps_timing_comparisons(self):
        for tag in TAGS:
            self.write_logical_edit(tag, large=240 if tag.startswith('head') else 200)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertFalse(compare(self.root))
        result = json.loads((self.root / 'comparison-report.json').read_text())
        metrics = {row['metric']: row for row in result['metrics']}
        self.assertEqual(metrics[f'{LOGICAL_EDIT_COMPONENTS[1]}: ns/op']['verdict'], 'regression signal')
        self.assertAlmostEqual(metrics[f'{LOGICAL_EDIT_COMPONENTS[1]}: ns/op']['change_percent'], 20)

    def test_missing_component_fails(self):
        path = self.root / 'head1' / 'components.jsonl'
        path.write_text('\n'.join(json.dumps(r) for r in self.rows[:-1]))
        with self.assertRaisesRegex(ValueError, 'missing component'):
            components(path)
        with patch('compare_pr.load_run', side_effect=self.run_fixture):
            self.assertTrue(compare(self.root))


if __name__ == '__main__':
    unittest.main()
