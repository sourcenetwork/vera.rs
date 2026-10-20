#!/usr/bin/env python3
"""Bind independently reproduced daemon assets to an existing version tag."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess


REPRODUCTION = runpy.run_path(str(Path(__file__).with_name('reproducible-linux-release.py')))


def validate_tag(tag):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('release tag must be vMAJOR.MINOR.PATCH')
    return tag[1:]


def output(root, command):
    return subprocess.check_output(command, cwd=root, text=True, timeout=60).strip()


def validate(root, source, tag):
    REPRODUCTION['validate_source'](source)
    version = validate_tag(tag)
    if output(root, ['git', 'status', '--porcelain', '--untracked-files=no']):
        raise ValueError('release preparation requires unchanged tracked source')
    if output(root, ['git', 'rev-parse', 'HEAD']) != source:
        raise ValueError('checkout differs from release source')
    if output(root, ['git', 'rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}']) != source:
        raise ValueError('release tag differs from release source')
    metadata = json.loads(output(root, ['cargo', 'metadata', '--offline', '--no-deps',
                                        '--format-version', '1']))
    config = json.loads((root / '.github/release-packages.json').read_text())
    members = set(metadata['workspace_members'])
    versions = {package['name']: package['version'] for package in metadata['packages']
                if package['id'] in members}
    for name in ['verad'] + config['packages']:
        if versions.get(name) != version:
            raise ValueError(f'{name} version differs from release tag')
    return version


def prepare(root, source, tag, first, second, destination):
    version = validate(root, source, tag)
    evidence = REPRODUCTION['compare'](first, second, source)
    metadata, _, _ = REPRODUCTION['bundle'](first, source)
    if metadata['source_tree'] != output(root, ['git', 'rev-parse', 'HEAD^{tree}']):
        raise ValueError('release provenance differs from checkout tree')
    for filename, field in (('Cargo.lock', 'cargo_lock_sha256'),
                            ('rust-toolchain.toml', 'toolchain_file_sha256')):
        if metadata[field] != hashlib.sha256((root / filename).read_bytes()).hexdigest():
            raise ValueError('release provenance differs from checkout ' + filename)
    destination.mkdir(parents=True, exist_ok=False)
    archive = REPRODUCTION['ARCHIVE']
    shutil.copyfile(first / archive, destination / archive)
    evidence.update(version=version, tag=tag)
    (destination / 'release.json').write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n')
    checksums = []
    for filename in (archive, 'release.json'):
        with (destination / filename).open('rb') as stream:
            checksums.append(f"{REPRODUCTION['digest'](stream)}  {filename}\n")
    (destination / 'SHA256SUMS').write_text(''.join(checksums))
    (destination / 'release-notes.md').write_text(
        f'Vera {tag}\n\nSource: `{source}`\n\n'
        'Linux x86-64 daemon with Regolith history. The archive includes the executable '
        'and its build provenance. Verify SHA256SUMS before extracting. '
        'release.json records the two clean-build comparison.\n\n'
        'Client and verifier crates are published separately by the maintainer.\n\n'
        'This release excludes the pending DKG boundary-retry fix, four-host WAN '
        'qualification and qualification of the unmerged Orbis service stack. '
        'DKG bootstrap and resharing remain enabled; boundary recovery can require '
        'a restart from a fresh certified target.\n\n'
        f'[Scope, operating limits and recovery instructions](https://github.com/'
        f'sourcenetwork/vera.rs/blob/{source}/docs/release-qualification.md).\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--root', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('validate')
    bundle = commands.add_parser('prepare')
    bundle.add_argument('--first', type=Path, required=True)
    bundle.add_argument('--second', type=Path, required=True)
    bundle.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'validate':
        validate(args.root, args.source, args.tag)
    else:
        prepare(args.root, args.source, args.tag, args.first, args.second, args.output)


if __name__ == '__main__':
    main()
