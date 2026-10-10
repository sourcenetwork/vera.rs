import collections
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from heap_profile import demangle_stacks, heap_timeline, profile_settings, profile_workload, retained_sites, rust_demangler, source_location

LAUNCHER = Path(__file__).resolve().parents[2] / '.github/scripts/profiled-verad.sh'


class HeapEvidence(unittest.TestCase):
    def test_sustained_profile_covers_the_measured_late_window(self):
        count, rate, deadline, arena = profile_workload('sustained')
        self.assertEqual((count, rate, arena), (90000, 50, '2'))
        self.assertEqual(count / rate, 1800)
        self.assertGreater(deadline, count / rate)
        self.assertEqual(profile_workload('startup'), (6000, 20, 1200, None))
        with self.assertRaises(ValueError):
            profile_workload('unbounded')

    def test_profile_build_flags_are_explicit_and_not_overridden(self):
        environment = {'CARGO_PROFILE_RELEASE_DEBUG': 'full',
                       'CARGO_PROFILE_RELEASE_STRIP': 'none',
                       'RUSTFLAGS': '-C force-frame-pointers=yes'}
        self.assertEqual(profile_settings(environment), {
            'release_debug': 'full', 'release_strip': 'none',
            'rustflags': '-C force-frame-pointers=yes'})
        for key in environment:
            for value in (None, '', 'private_value'):
                changed = dict(environment)
                if value is None:
                    changed.pop(key)
                else:
                    changed[key] = value
                with self.assertRaisesRegex(ValueError, '^unsupported allocation build settings$'):
                    profile_settings(changed)
        for value in ('', '-Cprivate'):
            with self.assertRaises(ValueError):
                profile_settings(dict(environment, CARGO_ENCODED_RUSTFLAGS=value))

    def test_allocator_symbol_does_not_establish_component_attribution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('std::alloc::System (unix.rs);??; 64\n'
                            'vera_app::apply (app.rs);std::alloc::System (unix.rs); 32\n'
                            'rocksdb::Arena::AllocateNewBlock (arena.cc); 16\n'
                            'private_secret (/secret/key.rs:1); 8\n')
            attribution = collections.Counter()
            sites = retained_sites(path, attribution=attribution)
            self.assertEqual(attribution, {'allocator_only': 64, 'vera_commonware_caller': 32,
                                          'library_caller': 16, 'unresolved': 8})
            self.assertEqual(sum(sites.values()), sum(attribution.values()))
            self.assertNotIn('private', json.dumps(attribution))

    def test_attribution_includes_callers_outside_the_display_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text(''.join('vera_app::site%d (app.rs); 1\n' % index for index in range(60)) +
                            'std::alloc::System (unix.rs); 2\n')
            attribution = collections.Counter()
            sites = retained_sites(path, attribution=attribution)
            self.assertEqual(attribution, {'vera_commonware_caller': 60, 'allocator_only': 2})
            self.assertEqual(sum(sites.values()), 62)
            self.assertLess(sum(amount for _, amount in sites.most_common(50)), sum(attribution.values()))

    def test_retained_sites_charge_each_allocation_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('tokio::spawn;vera_app::apply (/private/crates/vera-app/src/app.rs:12);'
                            'alloc::alloc (/private/storage/src/cache.rs:24); 64\n'
                            'private_secret (/secret/key.rs:1); 8\n')
            self.assertEqual(retained_sites(path), {'storage/src/cache.rs:24': 64, 'unresolved': 8})

    def test_unknown_leaf_does_not_discard_known_allocator_frames(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('rocksdb::Arena::AllocateNewBlock (arena.cc);??; 64\n'
                            'alloc::raw_vec::RawVecInner (mod.rs);private_secret; 32\n')
            self.assertEqual(retained_sites(path), {
                'rocksdb::Arena::AllocateNewBlock': 64,
                'alloc::raw_vec::RawVecInner (mod.rs)': 32,
            })

    def test_unresolved_formats_retain_weights_without_private_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stacks'
            path.write_text('??;0x123; 64\n_Rprivate_secret; 32\n'
                            'private_secret (/secret/key.rs:1); 16\n 8\n')
            details = collections.Counter()
            self.assertEqual(retained_sites(path, details), {'unresolved': 120})
            self.assertEqual(details, {'missing_symbols': 64, 'mangled_symbols': 32,
                                       'unrecognized_symbols': 16, 'missing_stack': 8})
            self.assertNotIn('secret', json.dumps(details))

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
                self.assertEqual(options['input'], symbol.decode() + '\n')
                return subprocess.CompletedProcess(command, 0, stdout='commonware_storage::qmdb::Store\n')

            with patch('heap_profile.subprocess.run', side_effect=decode):
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            before, after = retained_sites(raw), retained_sites(decoded)
            self.assertEqual(sum(before.values()), sum(after.values()))
            self.assertEqual(before['unresolved'], 72)
            self.assertEqual(after, {'commonware_storage::qmdb::Store (mod.rs)': 64,
                                     'unresolved': 8})
            self.assertNotIn('/secret', json.dumps(after))

    def test_repeated_symbols_are_decoded_once_without_changing_frames_or_weights(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text(('_RNvC6_123foo3bar (foo.rs);_RNvC6_123foo3bar (bar.rs); 7\n') * 2000)
            response = subprocess.CompletedProcess([], 0, stdout='commonware_storage::cache::Entry\n')
            with patch('heap_profile.subprocess.run', return_value=response) as run:
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['input'], '_RNvC6_123foo3bar\n')
            self.assertEqual(decoded.read_text(),
                             ('commonware_storage::cache::Entry (foo.rs);'
                              'commonware_storage::cache::Entry (bar.rs); 7\n') * 2000)
            self.assertEqual(sum(retained_sites(raw).values()), sum(retained_sites(decoded).values()))

    def test_symbol_batches_are_bounded_and_array_types_preserve_frame_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text(''.join('_RNvC6_fixture%d (mod.rs); 1\n' % index for index in range(257)))

            def decode(command, **options):
                count = len(options['input'].splitlines())
                self.assertLessEqual(count, 256)
                return subprocess.CompletedProcess(command, 0,
                                                   stdout='commonware_storage::cache::Entry<[u8; 32]>\n' * count)

            with patch('heap_profile.subprocess.run', side_effect=decode) as run:
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            self.assertEqual(run.call_count, 2)
            self.assertEqual(sum(retained_sites(decoded).values()), 257)
            self.assertTrue(all(line.count(';') == 1 for line in decoded.read_text().splitlines()))

    def test_llvm_suffixed_symbols_are_decoded_and_plain_frames_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('_RNvC6_123foo3bar.llvm.123ABC (foo.rs);??; 64\n'
                           'std::alloc::System (unix.rs); 8\n')
            response = subprocess.CompletedProcess([], 0, stdout='commonware_storage::cache::Entry\n')
            with patch('heap_profile.subprocess.run', return_value=response) as run:
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            self.assertEqual(run.call_args.kwargs['input'], '_RNvC6_123foo3bar.llvm.123ABC\n')
            self.assertEqual(decoded.read_text(),
                             'commonware_storage::cache::Entry (foo.rs);??; 64\n'
                             'std::alloc::System (unix.rs); 8\n')

    def test_decoder_only_replaces_complete_frame_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('plain (_RNvC6_123foo3bar.rs);_RNvC6_123foo3bar (foo.rs);'
                           '_RNvC6_123foo3bar extra;_RNvC6_123foo3bar; 17\n')
            response = subprocess.CompletedProcess([], 0, stdout='commonware_storage::cache::Entry\n')
            with patch('heap_profile.subprocess.run', return_value=response) as run:
                demangle_stacks(raw, decoded, ['fixture-decoder'])
            self.assertEqual(run.call_args.kwargs['input'], '_RNvC6_123foo3bar\n')
            self.assertEqual(decoded.read_text(),
                             'plain (_RNvC6_123foo3bar.rs);commonware_storage::cache::Entry (foo.rs);'
                             '_RNvC6_123foo3bar extra;commonware_storage::cache::Entry; 17\n')

    def test_decoder_rejects_missing_or_extra_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('_RNvC6_123foo3bar; 64\n')
            for output in ('', '\n', 'first\nsecond\n'):
                response = subprocess.CompletedProcess([], 0, stdout=output)
                with patch('heap_profile.subprocess.run', return_value=response):
                    with self.assertRaisesRegex(ValueError, 'symbol count'):
                        demangle_stacks(raw, decoded, ['fixture-decoder'])

    def test_decoder_budget_and_deadline_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('_R' + 'x' * 65536 + '; 1\n')
            with patch('heap_profile.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'budget'):
                    demangle_stacks(raw, decoded, ['fixture-decoder'])
                run.assert_not_called()
            raw.write_text('_RNvC6_123foo3bar; 64\n')
            with patch('heap_profile.time.monotonic', side_effect=[0, 0, 121]), \
                    patch('heap_profile.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    demangle_stacks(raw, decoded, ['fixture-decoder'])
                run.assert_not_called()

    def test_decoder_failure_is_propagated(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, decoded = (Path(directory) / name for name in ('raw', 'decoded'))
            raw.write_text('_RNvC6_123foo3bar; 64\n')
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
