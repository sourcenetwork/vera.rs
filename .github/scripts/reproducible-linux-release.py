#!/usr/bin/env python3
"""Build and compare independent normal Linux release bundles."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tarfile


ARCHIVE = 'verad-x86_64-unknown-linux-gnu-regolith.tar.gz'
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(chunk)
    return result.hexdigest()


def validate_source(value):
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('source must be an immutable commit')
    return value


def output(command, root):
    return subprocess.check_output(command, cwd=root, text=True, timeout=60).strip()


def validate_build_environment(environment):
    for key in environment:
        if key == 'CARGO_INCREMENTAL' and environment[key] == '0':
            continue
        if (key.startswith(('CARGO_PROFILE_', 'CARGO_TARGET_'))
                or (key.startswith('CARGO_BUILD_') and key != 'CARGO_BUILD_JOBS')
                or key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC',
                           'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_INCREMENTAL',
                           'RUSTC_BOOTSTRAP', 'CC', 'CXX')):
            raise ValueError(f'release compilation has a build override: {key}')


def build(root, destination, source, member):
    validate_source(source)
    if member not in ('1', '2'):
        raise ValueError('unknown independent builder')
    if output(['git', 'rev-parse', 'HEAD'], root) != source:
        raise ValueError('checkout differs from selected source')
    if (root / 'target').exists():
        raise ValueError('clean compilation requires an absent target directory')
    validate_build_environment(os.environ)
    package = runpy.run_path(str(root / '.github/scripts/package-linux-release.py'))
    environment = {
        'runner_image': os.environ.get('ImageVersion'),
        'runner_os': os.environ.get('ImageOS'),
        'os_release': Path('/etc/os-release').read_text(),
        'packages': output(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n'], root),
        'gcc': output(['gcc', '--version'], root),
        'linker': output(['ld', '--version'], root),
        'build_jobs': os.environ.get('CARGO_BUILD_JOBS'),
        'incremental': os.environ.get('CARGO_INCREMENTAL'),
        'source_path': str(root.resolve()),
    }
    subprocess.run(package['BUILD_COMMAND'], cwd=root, check=True)
    metadata = package['provenance'](root)
    package['package'](root / 'target/release/verad', destination, metadata)
    evidence = {'builder': member, 'environment': environment}
    (destination / 'compilation.json').write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n')


def read_exact(stream, size):
    content = stream.read(size)
    if len(content) != size:
        raise ValueError('truncated release archive')
    return content


def release_members(archive):
    # Inspect fixed USTAR headers before reading payloads or extension records.
    consumed = 0
    with gzip.open(archive, 'rb') as stream:
        for name, mode, minimum, maximum in (
                ('verad', 0o755, 64, MAX_BINARY_BYTES),
                ('build.json', 0o644, 2, MAX_MANIFEST_BYTES)):
            header = read_exact(stream, tarfile.BLOCKSIZE)
            entry = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            if entry.name != name or entry.type != tarfile.REGTYPE:
                raise ValueError('unexpected release archive members')
            if not minimum <= entry.size <= maximum:
                raise ValueError('release archive exceeds comparison bounds')
            if (entry.mode != mode or entry.uid or entry.gid or entry.mtime
                    or entry.uname or entry.gname or entry.linkname
                    or header[257:265] != tarfile.POSIX_MAGIC):
                raise ValueError('release archive metadata is not canonical')
            if name == 'verad':
                executable_header = read_exact(stream, 64)
                if (executable_header[:6] != b'\x7fELF\x02\x01'
                        or executable_header[18:20] != b'\x3e\x00'):
                    raise ValueError('release executable is not Linux x86-64')
                binary = hashlib.sha256(executable_header)
                remaining = entry.size - len(executable_header)
                while remaining:
                    chunk = read_exact(stream, min(remaining, 1024 * 1024))
                    binary.update(chunk)
                    remaining -= len(chunk)
                binary_sha = binary.hexdigest()
            else:
                metadata = json.load(io.BytesIO(read_exact(stream, entry.size)))
            padding = (-entry.size) % tarfile.BLOCKSIZE
            if any(read_exact(stream, padding)):
                raise ValueError('release archive metadata is not canonical')
            consumed += tarfile.BLOCKSIZE + entry.size + padding
        trailer_size = (-consumed) % tarfile.RECORDSIZE
        if trailer_size < 2 * tarfile.BLOCKSIZE:
            trailer_size += tarfile.RECORDSIZE
        trailer = read_exact(stream, trailer_size)
        if any(trailer) or stream.read(1):
            raise ValueError('unexpected release archive members')
    return metadata, binary_sha


def bundle(directory, source):
    archive = directory / ARCHIVE
    with archive.open('rb') as stream:
        if os.fstat(stream.fileno()).st_size > MAX_BINARY_BYTES + MAX_MANIFEST_BYTES + 1024 * 1024:
            raise ValueError('release archive exceeds comparison bounds')
        archive_sha = digest(stream)
    if (directory / 'SHA256SUMS').read_text() != f'{archive_sha}  {ARCHIVE}\n':
        raise ValueError('archive checksum mismatch')
    metadata, binary_sha = release_members(archive)
    if (metadata['source_commit'] != source or metadata['binary_sha256'] != binary_sha
            or metadata['format_version'] != 1 or metadata['history_backend'] != 'regolith'
            or metadata['target'] != 'x86_64-unknown-linux-gnu'
            or metadata['features'] != [] or metadata['profile'] != 'release'
            or metadata['build_command'] != ['cargo', 'build', '--frozen', '--release',
                                             '--no-default-features', '-p', 'verad']):
        raise ValueError('release provenance differs from selected native build')
    compilation = json.loads((directory / 'compilation.json').read_text())
    return metadata, compilation, archive_sha


def compare(first, second, source):
    validate_source(source)
    left, left_build, left_archive = bundle(first, source)
    right, right_build, right_archive = bundle(second, source)
    if left_build['builder'] != '1' or right_build['builder'] != '2':
        raise ValueError('comparison requires both independent builders')
    if left_build['environment'] != right_build['environment']:
        raise ValueError('independent compilation environments differ')
    if left != right or left_archive != right_archive:
        raise ValueError('independent release compilations differ')
    return {'source_commit': source, 'source_tree': left['source_tree'],
            'binary_sha256': left['binary_sha256'], 'archive_sha256': left_archive,
            'builders': ['1', '2'], 'environment': left_build['environment'],
            'scope': 'Two clean hosted builds at the same source path and recorded environment; '
                     'does not establish cross-toolchain reproducibility or runtime correctness.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=validate_source)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('validate')
    compile_command = commands.add_parser('build')
    compile_command.add_argument('--root', type=Path, required=True)
    compile_command.add_argument('--output', type=Path, required=True)
    compile_command.add_argument('--member', choices=('1', '2'), required=True)
    comparison = commands.add_parser('compare')
    comparison.add_argument('--first', type=Path, required=True)
    comparison.add_argument('--second', type=Path, required=True)
    comparison.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'validate':
        return
    if args.command == 'build':
        build(args.root, args.output, args.source, args.member)
    else:
        result = compare(args.first, args.second, args.source)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
