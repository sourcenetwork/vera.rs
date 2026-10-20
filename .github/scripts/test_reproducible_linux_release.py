import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


reproduction = module('reproduction', 'reproducible-linux-release.py')
release = module('release', 'package-linux-release.py')
SOURCE = 'a' * 40
ELF = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + bytes(44)
METADATA = {
    'format_version': 1, 'source_commit': SOURCE, 'source_tree': 'b' * 40,
    'history_backend': 'regolith', 'target': 'x86_64-unknown-linux-gnu',
    'features': [], 'profile': 'release', 'build_command': release.BUILD_COMMAND,
    'cargo_lock_sha256': 'c' * 64, 'toolchain_file_sha256': 'd' * 64,
    'rustc': 'host: x86_64-unknown-linux-gnu', 'required_shared_libraries': ['libc.so.6'],
}


class IndependentReleaseEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def bundle(self, name, builder, metadata=None, executable=ELF, environment=None):
        binary = self.root / (name + '.elf')
        binary.write_bytes(executable)
        destination = self.root / name
        release.package(binary, destination, METADATA if metadata is None else metadata)
        (destination / 'compilation.json').write_text(json.dumps({
            'builder': builder,
            'environment': {'packages': 'libc6\t2.39', 'source_path': '/candidate'}
            if environment is None else environment,
        }))
        return destination

    def test_equal_independent_builds_preserve_the_measured_binary_and_source(self):
        first = self.bundle('first', '1')
        second = self.bundle('second', '2')
        result = reproduction.compare(first, second, SOURCE)
        self.assertEqual(result['binary_sha256'], hashlib.sha256(ELF).hexdigest())
        self.assertEqual(result['source_commit'], SOURCE)
        self.assertEqual(result['source_tree'], METADATA['source_tree'])
        self.assertEqual(result['builders'], ['1', '2'])

    def test_distinct_binary_or_build_provenance_fails(self):
        first = self.bundle('first', '1')
        for index, (metadata, executable) in enumerate((
            (METADATA, ELF + b'changed'),
            ({**METADATA, 'source_tree': 'e' * 40}, ELF),
            ({**METADATA, 'cargo_lock_sha256': 'e' * 64}, ELF),
        )):
            with self.subTest(index=index):
                second = self.bundle('second' + str(index), '2', metadata, executable)
                with self.assertRaisesRegex(ValueError, 'compilations differ'):
                    reproduction.compare(first, second, SOURCE)

    def test_wrong_source_features_profile_and_command_fail(self):
        first = self.bundle('first', '1')
        for key, value in (('source_commit', 'f' * 40), ('features', ['fault-injection']),
                           ('profile', 'dev'), ('build_command', ['cargo', 'build'])):
            with self.subTest(key=key):
                second = self.bundle(key, '2', {**METADATA, key: value})
                with self.assertRaisesRegex(ValueError, 'provenance differs'):
                    reproduction.compare(first, second, SOURCE)

    def test_environment_drift_and_duplicate_builder_fail(self):
        first = self.bundle('first', '1')
        drift = self.bundle('drift', '2', environment={'packages': 'libc6\tother'})
        with self.assertRaisesRegex(ValueError, 'environments differ'):
            reproduction.compare(first, drift, SOURCE)
        duplicate = self.bundle('duplicate', '1')
        with self.assertRaisesRegex(ValueError, 'independent builders'):
            reproduction.compare(first, duplicate, SOURCE)

    def test_package_drift_names_the_changed_build_tool_without_relaxing_equality(self):
        first = self.bundle('first', '1', environment={
            'packages': 'libc6\t2.39\nprotobuf-compiler\t3.21.12-8.2ubuntu0.4',
            'source_path': '/candidate',
        })
        second = self.bundle('second', '2', environment={
            'packages': 'libc6\t2.39\nprotobuf-compiler\t3.21.12-8.2ubuntu0.3',
            'source_path': '/candidate',
        })
        with self.assertRaises(ValueError) as failure:
            reproduction.compare(first, second, SOURCE)
        detail = str(failure.exception)
        self.assertIn('environments differ: packages', detail)
        self.assertIn('builder-1/packages', detail)
        self.assertIn('builder-2/packages', detail)
        self.assertIn('-protobuf-compiler\t3.21.12-8.2ubuntu0.4', detail)
        self.assertIn('+protobuf-compiler\t3.21.12-8.2ubuntu0.3', detail)

    def test_package_drift_output_is_bounded(self):
        first = self.bundle('first', '1', environment={'packages': 'old\n' * 100})
        second = self.bundle('second', '2', environment={'packages': 'new\n' * 100})
        with self.assertRaises(ValueError) as failure:
            reproduction.compare(first, second, SOURCE)
        self.assertLessEqual(len(str(failure.exception).splitlines()), 26)
        self.assertIn('package diff truncated', str(failure.exception))

    def test_changed_archive_or_claimed_binary_hash_fails(self):
        first = self.bundle('first', '1')
        (first / 'SHA256SUMS').write_text('0' * 64 + '  ' + reproduction.ARCHIVE + '\n')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            reproduction.bundle(first, SOURCE)
        forged = self.bundle('forged', '1')
        actual_load = reproduction.json.load
        with patch.object(reproduction.json, 'load', side_effect=lambda stream: {
            **actual_load(stream), 'binary_sha256': '0' * 64,
        }):
            with self.assertRaisesRegex(ValueError, 'provenance differs'):
                reproduction.bundle(forged, SOURCE)

    def test_oversized_members_are_rejected_from_their_headers(self):
        first = self.bundle('oversized', '1')
        archive = first / reproduction.ARCHIVE
        pristine = gzip.decompress(archive.read_bytes())
        for name, size, prefix in (
                ('verad', reproduction.MAX_BINARY_BYTES + 1, b''),
                ('build.json', reproduction.MAX_MANIFEST_BYTES + 1, pristine[:1024])):
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.size = size
                entry.mode = 0o755 if name == 'verad' else 0o644
                archive.write_bytes(gzip.compress(prefix + entry.tobuf(format=tarfile.USTAR_FORMAT)))
                with self.assertRaisesRegex(ValueError, 'comparison bounds'):
                    reproduction.release_members(archive)

    def test_extension_links_and_unexpected_first_members_are_rejected(self):
        archive = self.root / 'unexpected.tar.gz'
        for kind, name in ((tarfile.XHDTYPE, 'extended'), (tarfile.GNUTYPE_LONGNAME, '././@LongLink'),
                           (tarfile.SYMTYPE, 'verad'), (tarfile.LNKTYPE, 'verad'),
                           (tarfile.REGTYPE, '../verad'), (tarfile.REGTYPE, 'validator.key')):
            with self.subTest(kind=kind, name=name):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = reproduction.MAX_BINARY_BYTES + 1
                archive.write_bytes(gzip.compress(entry.tobuf(format=tarfile.USTAR_FORMAT)))
                with self.assertRaisesRegex(ValueError, 'unexpected release archive members'):
                    reproduction.release_members(archive)

    def test_truncation_nonzero_padding_and_extra_members_fail(self):
        first = self.bundle('damaged', '1')
        archive = first / reproduction.ARCHIVE
        pristine = gzip.decompress(archive.read_bytes())
        nonzero_padding = bytearray(pristine)
        nonzero_padding[512 + len(ELF)] = 1
        extra = tarfile.TarInfo('verad').tobuf(format=tarfile.USTAR_FORMAT)
        for index, damaged in enumerate((pristine[:511], pristine[:550], pristine[:-1],
                                        nonzero_padding, pristine + b'\0',
                                        pristine[:2048] + extra + pristine[2560:])):
            with self.subTest(index=index):
                archive.write_bytes(gzip.compress(damaged))
                with self.assertRaises((ValueError, tarfile.HeaderError)):
                    reproduction.release_members(archive)

    def test_archive_size_is_checked_before_hashing_or_decompression(self):
        first = self.bundle('compressed-limit', '1')
        with patch.object(reproduction, 'MAX_BINARY_BYTES', 0), \
                patch.object(reproduction, 'MAX_MANIFEST_BYTES', 0), \
                patch.object(reproduction, 'digest') as hash_archive:
            with (first / reproduction.ARCHIVE).open('ab') as archive:
                archive.write(bytes(1024 * 1024))
            with self.assertRaisesRegex(ValueError, 'comparison bounds'):
                reproduction.bundle(first, SOURCE)
            hash_archive.assert_not_called()

    def test_source_cannot_be_mutable_or_an_argument(self):
        for value in ('main', '--upload-pack=command', 'a' * 39, 'A' * 40, SOURCE + '\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                reproduction.validate_source(value)

    def test_nonclean_target_and_build_overrides_stop_before_compilation(self):
        (self.root / 'target').mkdir()
        with patch.object(reproduction, 'output', return_value=SOURCE), \
                patch.object(reproduction.subprocess, 'run') as compile_command:
            with self.assertRaisesRegex(ValueError, 'absent target'):
                reproduction.build(self.root, self.root / 'out', SOURCE, '1')
            compile_command.assert_not_called()
        (self.root / 'target').rmdir()
        for key in ('CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTC_WRAPPER',
                    'CARGO_PROFILE_RELEASE_LTO', 'CARGO_INCREMENTAL'):
            with self.subTest(key=key), patch.dict(reproduction.os.environ, {key: 'override'}, clear=True), \
                    patch.object(reproduction, 'output', return_value=SOURCE), \
                    patch.object(reproduction.subprocess, 'run') as compile_command:
                with self.assertRaisesRegex(ValueError, 'build override'):
                    reproduction.build(self.root, self.root / 'out', SOURCE, '1')
                compile_command.assert_not_called()

    def test_toolchain_can_disable_incremental_compilation_but_cannot_enable_it(self):
        reproduction.validate_build_environment({'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2'})
        for value in ('1', '', 'false', 'override'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'CARGO_INCREMENTAL'):
                reproduction.validate_build_environment({'CARGO_INCREMENTAL': value})


if __name__ == '__main__':
    unittest.main()
