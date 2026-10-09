import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from heap_profile import demangle_stacks, heap_timeline, retained_sites, rust_demangler, source_location

LAUNCHER = Path(__file__).resolve().parents[2] / '.github/scripts/profiled-verad.sh'


class HeapEvidence(unittest.TestCase):
    def test_retained_sites_charge_each_allocation_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('tokio::spawn;vera_app::apply (/private/crates/vera-app/src/app.rs:12);'
                            'alloc::alloc (/private/storage/src/cache.rs:24); 64\n'
                            'private_secret (/secret/key.rs:1); 8\n')
            self.assertEqual(retained_sites(path), {'storage/src/cache.rs:24': 64, 'unresolved': 8})

    def test_source_names_do_not_expose_private_paths(self):
        self.assertEqual(source_location('private_secret (/secret/credentials.rs:1)'), 'unresolved')
        self.assertEqual(source_location('tokio::spawn (/home/operator/project.rs:9)'), 'tokio::spawn')

    def test_heaptrack_basename_frames_identify_component_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('tokio::spawn (task.rs);commonware_storage::qmdb::Store (mod.rs);alloc::alloc (alloc.rs); 64\n'
                            'commonware_storage::qmdb::Store (mod.rs);alloc::alloc (alloc.rs); 32\n')
            self.assertEqual(retained_sites(path), {'commonware_storage::qmdb::Store (mod.rs)': 96})

    def test_timeline_requires_live_heap_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'massif'
            path.write_text('time_unit: ms\nsnapshot=0\ntime=10\nmem_heap_B=100\nheap_tree=detailed\n'
                            'n1: 100 secret_frame (/secret/key.rs:1)\nsnapshot=1\ntime=20\nmem_heap_B=200\n')
            self.assertEqual(heap_timeline(path), [{'milliseconds': 10, 'interval_peak_heap_bytes': 100},
                                                  {'milliseconds': 20, 'interval_peak_heap_bytes': 200}])
            path.write_text('time_unit: ms\nsnapshot=0\ntime=10\n')
            with self.assertRaises(ValueError):
                heap_timeline(path)

    def test_heaptrack_seconds_are_normalized_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'massif'
            path.write_text('desc: heaptrack\ncmd: private command\ntime_unit: s\n'
                            'snapshot=0\ntime=0.01\nmem_heap_B=100\n'
                            'snapshot=1\ntime=300.125\nmem_heap_B=200\n')
            self.assertEqual(heap_timeline(path), [{'milliseconds': 10, 'interval_peak_heap_bytes': 100},
                                                  {'milliseconds': 300125, 'interval_peak_heap_bytes': 200}])

    def test_timeline_rejects_unknown_units_nonfinite_and_regressing_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'massif'
            for text in ('time_unit: i\nsnapshot=0\ntime=10\nmem_heap_B=100\n',
                         'time_unit: s\nsnapshot=0\ntime=NaN\nmem_heap_B=100\n',
                         'time_unit: s\nsnapshot=0\ntime=-1\nmem_heap_B=100\n',
                         'time_unit: s\nsnapshot=0\ntime=0.0001\nmem_heap_B=100\n',
                         'time_unit: s\nsnapshot=0\ntime=10\nmem_heap_B=-1\n',
                         'time_unit: s\nsnapshot=0\ntime=10\nmem_heap_B=100\n'
                         'snapshot=1\ntime=9\nmem_heap_B=200\n'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    heap_timeline(path)

    def test_unsupported_rust_decoder_fails_before_profiling(self):
        response = subprocess.CompletedProcess([], 0, stdout='_RNvC6_123foo3bar\n')
        with patch('heap_profile.subprocess.run', return_value=response), \
                patch('heap_profile.subprocess.check_output') as version:
            with self.assertRaises(ValueError):
                rust_demangler()
            version.assert_not_called()

    def test_decoded_symbols_preserve_weights_and_private_frame_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            symbol = b'_RNvNtC18commonware_storage4qmdb5Store'
            raw.write_bytes(symbol + b' (mod.rs); 64\n'
                            b'private_secret (/secret/credentials.rs:1); 8\n')

            def decode(command, **options):
                options['stdout'].write(options['stdin'].read().replace(
                    symbol, b'commonware_storage::qmdb::Store'))
                return subprocess.CompletedProcess(command, 0)

            with patch('heap_profile.subprocess.run', side_effect=decode):
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            before, after = retained_sites(raw), retained_sites(decoded)
            self.assertEqual(sum(before.values()), sum(after.values()))
            self.assertEqual(before['unresolved'], 72)
            self.assertEqual(after, {'commonware_storage::qmdb::Store (mod.rs)': 64,
                                     'unresolved': 8})
            self.assertNotIn('/secret', json.dumps(after))

    def test_decoder_failure_is_propagated(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('unresolved; 64\n')
            with patch('heap_profile.subprocess.run', side_effect=subprocess.CalledProcessError(1, ['decoder'])):
                with self.assertRaises(subprocess.CalledProcessError):
                    demangle_stacks(raw, decoded, ['fixture-decoder'])

    def test_launcher_execs_only_selected_first_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'node'
            binary.write_text('#!/usr/bin/env python3\nimport json,os\n'
                              'os.write(int(os.environ["TEST_DESCRIPTOR_FD"]), b"kept")\n'
                              'print(json.dumps({"pid":os.getpid(),"profile":os.getenv("DUMP_HEAPTRACK_OUTPUT")}))\n')
            binary.chmod(0o700)
            environment = dict(os.environ, VERA_PROFILE_BINARY=str(binary), VERA_PROFILE_ROOT=str(root),
                               VERA_PROFILE_LIBRARY='')
            for member, selected in [('node2', False), ('node3', True), ('node3', False)]:
                reader, writer = os.pipe()
                try:
                    process = subprocess.Popen(['bash', str(LAUNCHER), '--data-dir', '/data/' + member],
                                               stdout=subprocess.PIPE, text=True, pass_fds=(writer,),
                                               env=dict(environment, TEST_DESCRIPTOR_FD=str(writer)))
                    os.close(writer)
                    writer = None
                    output, _ = process.communicate()
                    self.assertEqual(os.read(reader, 5), b'kept')
                finally:
                    os.close(reader)
                    if writer is not None:
                        os.close(writer)
                self.assertEqual(process.returncode, 0)
                row = json.loads(output)
                self.assertEqual(row['pid'], process.pid)
                self.assertEqual(row['profile'] is not None, selected)


if __name__ == '__main__':
    unittest.main()
