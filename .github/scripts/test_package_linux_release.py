import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'release', Path(__file__).with_name('package-linux-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class LinuxReleaseBundle(unittest.TestCase):
    def test_archive_is_reproducible_and_contains_only_binary_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'verad'
            executable = bytearray(64)
            executable[:6] = b'\x7fELF\x02\x01'
            executable[18:20] = b'\x3e\x00'
            binary.write_bytes(executable)
            (root / 'validator.key').write_text('private material')
            metadata = {'source_commit': 'a' * 40, 'features': []}
            first = release.package(binary, root / 'first', metadata)
            binary.touch()
            second = release.package(binary, root / 'second', metadata)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            expected = f'{hashlib.sha256(first.read_bytes()).hexdigest()}  {first.name}\n'
            self.assertEqual((first.parent / 'SHA256SUMS').read_text(), expected)
            with tarfile.open(first) as archive:
                self.assertEqual(archive.getnames(), ['verad', 'build.json'])
                self.assertEqual(archive.extractfile('verad').read(), executable)
                manifest = json.load(archive.extractfile('build.json'))
                self.assertEqual(manifest['binary_sha256'], hashlib.sha256(executable).hexdigest())
                self.assertEqual(manifest['source_commit'], 'a' * 40)
                for entry in archive.getmembers():
                    self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0))
                self.assertEqual(archive.getmember('verad').mode, 0o755)
                self.assertEqual(archive.getmember('build.json').mode, 0o644)
            self.assertEqual(metadata, {'source_commit': 'a' * 40, 'features': []})
            with self.assertRaises(FileExistsError):
                release.package(binary, first.parent, metadata)
            self.assertEqual((first.parent / 'SHA256SUMS').read_text(), expected)

    def test_other_inputs_fail_before_creating_an_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'verad'
            output = root / 'output'
            for content in (b'private material', b'\x7fELF\x01\x01' + bytes(64),
                            b'\x7fELF\x02\x02' + bytes(64), b'\x7fELF\x02\x01' + bytes(64)):
                binary.write_bytes(content)
                with self.assertRaises(ValueError):
                    release.package(binary, output, {})
                self.assertFalse(output.exists())

    def test_runtime_dependencies_are_names_without_loader_paths(self):
        dynamic = (' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n'
                   ' 0x0000000000000001 (NEEDED) Shared library: [libstdc++.so.6]\n'
                   ' 0x000000000000001d (RUNPATH) Library runpath: [/private/build]\n')
        self.assertEqual(release.shared_libraries(dynamic), ['libc.so.6', 'libstdc++.so.6'])
        for invalid in ('', '(NEEDED) Shared library: [/private/build/libc.so.6]'):
            with self.assertRaises(ValueError):
                release.shared_libraries(invalid)

    def test_modified_source_or_wrong_host_cannot_supply_provenance(self):
        with patch.object(release, 'checked_output', return_value=' M Cargo.toml') as command:
            with self.assertRaisesRegex(ValueError, 'unchanged tracked source'):
                release.provenance(Path('.'))
            self.assertEqual(command.call_count, 1)
        with patch.object(release, 'checked_output', side_effect=['', 'host: aarch64-apple-darwin']):
            with self.assertRaisesRegex(ValueError, 'qualified Linux'):
                release.provenance(Path('.'))


if __name__ == '__main__':
    unittest.main()
