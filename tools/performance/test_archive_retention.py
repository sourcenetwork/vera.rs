import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import archive_retention as retention


def samples():
    for member in range(4):
        for height in (0, 192, 384, 576):
            record = {'member': 'node%d' % member, 'durable_height': height}
            for archive in retention.ARCHIVES:
                prefix = 'runtime_metrics.' + archive + '_'
                record.update({prefix + 'index_items': min(height, 384),
                               prefix + 'index_keys': min(height, 384),
                               prefix + 'items_tracked': min(height, 384)})
            yield record


class ArchiveRetention(unittest.TestCase):
    def test_bounded_indices_cover_all_members_and_multiple_prune_windows(self):
        result = retention.audit(samples())
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['members']), 4)
        self.assertEqual(result['members']['node0']['archives']['finalized_blocks']['maximum_items'], 384)

    def test_lookup_growth_is_rejected_even_when_primary_archive_is_bounded(self):
        rows = list(samples())
        rows[-1]['runtime_metrics.finalized_blocks_index_items'] = 15000
        with self.assertRaisesRegex(ValueError, 'lookup entries'):
            retention.audit(rows)

    def test_observation_skew_is_explicit_and_bounded(self):
        rows = list(samples())
        key = 'runtime_metrics.finalizations_by_height_index_items'
        rows[-1][key] += 64
        self.assertTrue(retention.audit(rows)['passed'])
        rows[-1][key] += 1
        with self.assertRaises(ValueError):
            retention.audit(rows)

    def test_missing_samples_metrics_and_actual_pruning_progress_fail(self):
        for rows in ([row for row in samples() if row['member'] != 'node3'],
                     list(samples())[:-1]):
            with self.assertRaises(ValueError):
                retention.audit(rows)
        rows = list(samples())
        rows[-1]['durable_height'] = 384
        with self.assertRaisesRegex(ValueError, 'finalization'):
            retention.audit(rows)
        rows = list(samples())
        del rows[-1]['runtime_metrics.finalized_blocks_index_items']
        with self.assertRaises(KeyError):
            retention.audit(rows)

    def test_invalid_gauges_and_stale_success_are_rejected(self):
        for value in (-1, 1.5, True):
            rows = list(samples())
            rows[-1]['runtime_metrics.finalized_blocks_index_items'] = value
            with self.assertRaises(ValueError):
                retention.audit(rows)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / 'archive-retention.json'
            output.write_text('stale success')
            (root / 'diagnostics.jsonl').write_text(json.dumps(next(samples())) + '\n')
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(retention.main([str(root)]), 1)
            self.assertFalse(output.exists())
            self.assertNotIn(str(root), error.getvalue())


if __name__ == '__main__':
    unittest.main()
