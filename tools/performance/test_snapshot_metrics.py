import tempfile
import unittest
from pathlib import Path

import snapshot_metrics


class ParseSections(unittest.TestCase):
    LINE = (
        '2026-10-09T10:00:00.000Z DEBUG vera_diagnostics: node resource snapshot '
        'runtime_metrics=counter_one: 7 counter_two: 9 '
        'history_memory_bytes={"block_cache": Some(2048), "memtables": Some(512), "table_readers": None} '
        'durable_height=42 '
        'index=IndexStats { cached_bytes: 4096, block_count: 21, head_block_number: 42 } '
        'proofs=LightBlockStats { finalizations: 21 }'
    )

    def test_sections_split_top_level_fields(self):
        found = snapshot_metrics.sections(self.LINE)
        self.assertEqual(
            set(found),
            {'runtime_metrics', 'history_memory_bytes', 'durable_height', 'index', 'proofs'},
        )
        self.assertEqual(found['durable_height'].strip(), '42')

    def test_snapshot_flattens_numeric_leaves(self):
        record = snapshot_metrics.parse_snapshot(self.LINE)
        self.assertEqual(record['durable_height'], 42)
        self.assertEqual(record['runtime_metrics.counter_one'], 7)
        self.assertEqual(record['history_memory_bytes.block_cache'], 2048)
        self.assertIsNone(record['history_memory_bytes.table_readers'])
        self.assertEqual(record['index.cached_bytes'], 4096)
        self.assertEqual(record['proofs.finalizations'], 21)

    def test_non_snapshot_lines_are_ignored(self):
        self.assertIsNone(
            snapshot_metrics.parse_snapshot('DEBUG vera_diagnostics: resource snapshot failed error=x')
        )
        self.assertIsNone(snapshot_metrics.parse_snapshot('INFO unrelated: durable_height=5'))


class ExtractFile(unittest.TestCase):
    def test_records_cadence_aligned_samples(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            line = (
                'DEBUG vera_diagnostics: node resource snapshot durable_height=3 '
                'index=IndexStats { block_count: 3 }'
            )
            (directory / 'stderr.log').write_text('noise\n%s\n%s\n' % (line, line))
            samples = snapshot_metrics.parse_stderr(directory / 'stderr.log')
            self.assertEqual(len(samples), 2)
            self.assertEqual(samples[1]['sample_index'], 1)
            self.assertEqual(samples[1]['index.block_count'], 3)


if __name__ == '__main__':
    unittest.main()
