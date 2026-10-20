import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(filename):
    spec = importlib.util.spec_from_file_location('daemon_release', Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('prepare-daemon-release.py')
package = load('package-linux-release.py')
ELF = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + bytes(44)


class TaggedDaemonRelease(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / '.github').mkdir()
        (self.root / '.github/release-packages.json').write_text(json.dumps({'packages': ['vera-client']}))
        (self.root / 'Cargo.lock').write_text('fixture lockfile\n')
        (self.root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.98.0"\n')
        self.git('init', '--quiet')
        self.git('add', '.')
        self.git('-c', 'user.name=Release test', '-c', 'user.email=release@example.com',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Fixture')
        self.source = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v0.1.0')
        self.metadata = {'workspace_members': ['verad', 'vera-client'], 'packages': [
            {'id': name, 'name': name, 'version': '0.1.0'} for name in ('verad', 'vera-client')]}
        actual_output = release.output

        def output(root, command):
            if command[0] == 'cargo':
                return json.dumps(self.metadata)
            return actual_output(root, command)

        replacement = patch.object(release, 'output', side_effect=output)
        replacement.start()
        self.addCleanup(replacement.stop)

    def git(self, *arguments):
        return subprocess.check_output(['git', *arguments], cwd=self.root, text=True).strip()

    def bundle(self, name, member, change=None):
        metadata = {
            'format_version': 1, 'source_commit': self.source,
            'source_tree': self.git('rev-parse', 'HEAD^{tree}'),
            'history_backend': 'regolith', 'target': 'x86_64-unknown-linux-gnu',
            'features': [], 'profile': 'release', 'build_command': package.BUILD_COMMAND,
            'cargo_lock_sha256': hashlib.sha256((self.root / 'Cargo.lock').read_bytes()).hexdigest(),
            'toolchain_file_sha256': hashlib.sha256((self.root / 'rust-toolchain.toml').read_bytes()).hexdigest(),
        }
        metadata.update(change or {})
        binary = self.root / 'verad.elf'
        binary.write_bytes(ELF)
        destination = self.root / name
        package.package(binary, destination, metadata)
        (destination / 'compilation.json').write_text(json.dumps({
            'builder': member, 'environment': {'source_path': '/candidate'},
        }))
        return destination

    def test_matching_tag_prepares_source_bound_assets_and_checksums(self):
        first, second = self.bundle('first', '1'), self.bundle('second', '2')
        destination = self.root / 'release'
        release.prepare(self.root, self.source, 'v0.1.0', first, second, destination)
        evidence = json.loads((destination / 'release.json').read_text())
        self.assertEqual(evidence['source_commit'], self.source)
        self.assertEqual((evidence['version'], evidence['tag']), ('0.1.0', 'v0.1.0'))
        self.assertEqual(evidence['builders'], ['1', '2'])
        for line in (destination / 'SHA256SUMS').read_text().splitlines():
            digest, filename = line.split('  ')
            self.assertEqual(hashlib.sha256((destination / filename).read_bytes()).hexdigest(), digest)
        self.assertEqual((destination / release.REPRODUCTION['ARCHIVE']).read_bytes(),
                         (first / release.REPRODUCTION['ARCHIVE']).read_bytes())
        self.assertIn(self.source, (destination / 'release-notes.md').read_text())

    def test_annotated_tags_resolve_to_the_source_commit(self):
        self.git('tag', '--delete', 'v0.1.0')
        self.git('-c', 'user.name=Release test', '-c', 'user.email=release@example.com',
                 '-c', 'tag.gpgsign=false', 'tag', '--annotate', 'v0.1.0', '--message', 'Release')
        self.assertEqual(release.validate(self.root, self.source, 'v0.1.0'), '0.1.0')

    def test_malformed_tags_fail_before_git_or_cargo(self):
        for tag in ('main', '--draft', 'v0.1', 'v00.1.0', 'v0.1.0\n', 'v0.1.0/other'):
            with self.subTest(tag=tag), patch.object(release, 'output') as command:
                with self.assertRaisesRegex(ValueError, 'release tag'):
                    release.validate(self.root, self.source, tag)
                command.assert_not_called()

    def test_tag_and_checkout_must_both_select_the_requested_commit(self):
        with self.assertRaisesRegex(ValueError, 'checkout differs'):
            release.validate(self.root, 'a' * 40, 'v0.1.0')
        (self.root / 'Cargo.lock').write_text('new lockfile\n')
        self.git('add', 'Cargo.lock')
        self.git('-c', 'user.name=Release test', '-c', 'user.email=release@example.com',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'New source')
        with self.assertRaisesRegex(ValueError, 'tag differs'):
            release.validate(self.root, self.git('rev-parse', 'HEAD'), 'v0.1.0')

    def test_dirty_source_and_wrong_or_missing_package_versions_fail(self):
        for packages in ([{'id': 'verad', 'name': 'verad', 'version': '0.2.0'}],
                         [{'id': 'verad', 'name': 'verad', 'version': '0.1.0'}]):
            self.metadata['packages'] = packages
            with self.subTest(packages=packages), self.assertRaisesRegex(ValueError, 'version differs'):
                release.validate(self.root, self.source, 'v0.1.0')
        (self.root / 'Cargo.lock').write_text('uncommitted\n')
        with self.assertRaisesRegex(ValueError, 'unchanged tracked source'):
            release.validate(self.root, self.source, 'v0.1.0')

    def test_consistently_forged_build_metadata_still_fails_against_checkout(self):
        for index, field in enumerate(('source_tree', 'cargo_lock_sha256', 'toolchain_file_sha256')):
            with self.subTest(field=field):
                first = self.bundle(f'first-{index}', '1', {field: '0' * 64})
                second = self.bundle(f'second-{index}', '2', {field: '0' * 64})
                destination = self.root / f'out-{index}'
                with self.assertRaisesRegex(ValueError, 'provenance differs from checkout'):
                    release.prepare(self.root, self.source, 'v0.1.0', first, second, destination)
                self.assertFalse(destination.exists())

    def test_existing_assets_are_never_overwritten(self):
        first, second = self.bundle('first', '1'), self.bundle('second', '2')
        destination = self.root / 'release'
        destination.mkdir()
        (destination / 'release.json').write_text('existing evidence')
        with self.assertRaises(FileExistsError):
            release.prepare(self.root, self.source, 'v0.1.0', first, second, destination)
        self.assertEqual((destination / 'release.json').read_text(), 'existing evidence')


if __name__ == '__main__':
    unittest.main()
