#!/usr/bin/env python3
"""Bundle the normal Linux release binary with source provenance and checksums."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile


BUILD_COMMAND = ['cargo', 'build', '--frozen', '--release', '--no-default-features', '-p', 'verad']


def checked_output(root, command):
    return subprocess.run(command, cwd=root, check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


def provenance(root):
    if checked_output(root, ['git', 'status', '--porcelain', '--untracked-files=no']):
        raise ValueError('release packaging requires unchanged tracked source')
    compiler = checked_output(root, ['rustc', '-vV'])
    if 'host: x86_64-unknown-linux-gnu' not in compiler.splitlines():
        raise ValueError('release packaging supports the qualified Linux x86-64 host only')
    return {
        'format_version': 1,
        'source_commit': checked_output(root, ['git', 'rev-parse', 'HEAD']),
        'source_tree': checked_output(root, ['git', 'rev-parse', 'HEAD^{tree}']),
        'cargo_lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest(),
        'toolchain_file_sha256': hashlib.sha256((root / 'rust-toolchain.toml').read_bytes()).hexdigest(),
        'rustc': compiler,
        'target': 'x86_64-unknown-linux-gnu',
        'history_backend': 'rocksdb',
        'features': [],
        'profile': 'release',
        'build_command': BUILD_COMMAND,
        'required_shared_libraries': shared_libraries(checked_output(
            root, ['readelf', '--dynamic', '--wide', 'target/release/verad'])),
    }


def shared_libraries(dynamic_section):
    libraries = re.findall(r'\(NEEDED\).*Shared library: \[([^\]]+)\]', dynamic_section)
    if not libraries or any(not re.fullmatch(r'[A-Za-z0-9_+.-]{1,128}', name)
                            for name in libraries):
        raise ValueError('cannot identify release runtime libraries')
    return sorted(set(libraries))


def package(binary, output, metadata):
    executable = binary.read_bytes()
    # ELF64, little endian, x86-64. The hosted lifecycle test executes this binary.
    if (len(executable) < 64 or executable[:6] != b'\x7fELF\x02\x01'
            or executable[18:20] != b'\x3e\x00'):
        raise ValueError('release input is not a Linux x86-64 executable')
    metadata = dict(metadata, binary_sha256=hashlib.sha256(executable).hexdigest())
    manifest = (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode()
    name = 'verad-x86_64-unknown-linux-gnu-rocksdb.tar.gz'
    output.mkdir(parents=True, exist_ok=True)
    archive = output / name
    with archive.open('xb') as destination:
        with gzip.GzipFile(filename='', fileobj=destination, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
                for filename, content, mode in [('verad', executable, 0o755),
                                                ('build.json', manifest, 0o644)]:
                    entry = tarfile.TarInfo(filename)
                    entry.size = len(content)
                    entry.mode = mode
                    bundle.addfile(entry, io.BytesIO(content))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with (output / 'SHA256SUMS').open('x') as checksums:
        checksums.write(f'{digest}  {name}\n')
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    package(root / 'target/release/verad', args.output, provenance(root))


if __name__ == '__main__':
    main()
