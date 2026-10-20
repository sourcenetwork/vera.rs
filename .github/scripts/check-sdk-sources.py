#!/usr/bin/env python3
"""Verify that independent Git SDK consumers resolve the qualified dependency sources."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def metadata(root, *arguments):
    result = subprocess.run(
        ['cargo', 'metadata', '--format-version', '1', *arguments],
        cwd=root, check=True, capture_output=True, text=True, timeout=120)
    return json.loads(result.stdout)


def commonware_sources(data):
    sources = defaultdict(set)
    for package in data['packages']:
        if package['name'].startswith('commonware-'):
            sources[package['name']].add(package['source'])
    return {name: sorted(values) for name, values in sorted(sources.items())}


def check(root):
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root):
        raise ValueError('SDK source qualification requires unchanged tracked source')
    config = json.loads((root / '.github/release-packages.json').read_text())
    expected = commonware_sources(metadata(root, '--offline', '--locked'))
    with tempfile.TemporaryDirectory(prefix='vera-sdk-sources-') as temporary:
        consumer = Path(temporary)
        (consumer / 'src').mkdir()
        (consumer / 'src/lib.rs').write_text('')
        dependencies = '\n'.join(
            f'{name} = {{ git = {json.dumps(root.as_uri())}, rev = {json.dumps(source)} }}'
            for name in config['roots'])
        (consumer / 'Cargo.toml').write_text(
            '[package]\nname = "vera-sdk-source-check"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n\n[workspace]\n\n[dependencies]\n' + dependencies + '\n')
        shutil.copyfile(root / 'Cargo.lock', consumer / 'Cargo.lock')
        resolved = metadata(root, '--manifest-path', str(consumer / 'Cargo.toml'))
        actual = commonware_sources(resolved)
        mismatches = {name: dict(expected=expected.get(name), actual=actual.get(name))
                      for name in sorted(expected.keys() | actual.keys())
                      if expected.get(name) != actual.get(name)}
        return dict(source_commit=source, ready=not mismatches, roots=config['roots'],
                    commonware=actual, mismatches=mismatches,
                    scope='Independent Git dependency resolution without consumer workspace patches; '
                          'does not replace compilation or runtime checks.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(ROOT)
    except subprocess.CalledProcessError as error:
        parser.exit(1, error.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if not result['ready']:
        print('SDK consumer dependency sources differ: ' + ', '.join(result['mismatches']))
        return 1
    print('SDK Git consumer resolves all qualified Commonware sources without workspace patches.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
