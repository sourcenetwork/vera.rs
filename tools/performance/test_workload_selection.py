"""Workload selection must preserve bounded modes and reject costly combinations."""

import unittest

from workload_selection import FLAGS, selection


def choose(*names):
    return selection(dict.fromkeys(names, 'true'))


class SelectionTests(unittest.TestCase):
    def test_default_runs_both_short_cases_without_allocator_override(self):
        self.assertEqual(choose(), {
            'count': 3000, 'objects': [0, 128], 'arenas': ['default'],
            'controlled_arenas': False, 'timeout_seconds': 900,
            'memory': False, 'archive': False,
        })

    def test_archive_retains_its_single_case_and_numeric_snapshots(self):
        result = choose('ARCHIVE_RETENTION')
        self.assertEqual((result['count'], result['objects']), (6000, [128]))
        self.assertTrue(result['memory'] and result['archive'])

    def test_existing_sustained_modes_keep_count_and_deadline(self):
        for name, objects in [('SUSTAINED_FIXED_STATE', [128]), ('SUSTAINED_GROWING_STATE', [0])]:
            with self.subTest(name=name):
                result = choose(name)
                self.assertEqual((result['count'], result['objects'], result['timeout_seconds']),
                                 (90000, objects, 7200))
                self.assertFalse(result['controlled_arenas'] or result['memory'])

    def test_comparison_runs_both_existing_arenas_and_collects_snapshots(self):
        result = choose('ALLOCATOR_COMPARISON')
        self.assertEqual((result['count'], result['objects'], result['arenas']),
                         (90000, [128], ['default', '2']))
        self.assertTrue(result['controlled_arenas'] and result['memory'])

    def test_extended_mode_has_one_case_and_time_for_reconciliation(self):
        result = choose('EXTENDED_FIXED_STATE')
        self.assertEqual(result, {
            'count': 360000, 'objects': [128], 'arenas': ['2'],
            'controlled_arenas': True, 'timeout_seconds': 10800,
            'memory': True, 'archive': False,
        })
        self.assertGreater(result['timeout_seconds'], result['count'] / 50)

    def test_conflicting_modes_fail_before_builds(self):
        for flags in [
            ('ARCHIVE_RETENTION', 'EXTENDED_FIXED_STATE'),
            ('EXTENDED_FIXED_STATE', 'SUSTAINED_GROWING_STATE'),
            ('EXTENDED_FIXED_STATE', 'STORAGE_ATTRIBUTION'),
            ('EXTENDED_FIXED_STATE', 'ALLOCATOR_COMPARISON'),
            ('SUSTAINED_FIXED_STATE', 'SUSTAINED_GROWING_STATE'),
            ('SUSTAINED_MEMORY_ATTRIBUTION',),
        ]:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                choose(*flags)

    def test_flags_cannot_be_arbitrary_strings_or_boolean_objects(self):
        for name in FLAGS:
            for value in ['1', 'TRUE', '90000; command', True, None]:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    selection({name: value})


if __name__ == '__main__':
    unittest.main()
