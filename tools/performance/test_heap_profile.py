import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from heap_profile import heap_timeline, retained_sites, source_location

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
            self.assertEqual(heap_timeline(path), [{'milliseconds': 10, 'live_heap_bytes': 100},
                                                  {'milliseconds': 20, 'live_heap_bytes': 200}])
            path.write_text('time_unit: ms\nsnapshot=0\ntime=10\n')
            with self.assertRaises(ValueError):
                heap_timeline(path)

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
