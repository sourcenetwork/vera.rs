#!/usr/bin/env python3
"""Measure prebuilt node revisions with one head workload driver and no intervening builds."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from compare_pr import TAGS, compare
from record import digest
from protocol import baseline_incompatible, source_schema, unavailable


def supports_rpc_listener(node):
    help_text = subprocess.run([str(node), 'validator', '--help'], check=True,
                               capture_output=True, text=True, timeout=10).stdout
    return any(line.split()[:1] == ['--rpc-listener-fd'] for line in help_text.splitlines())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', required=True, type=Path)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--binaries', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--count', type=int, default=600)
    parser.add_argument('--rate', type=int, default=20)
    parser.add_argument('--consensus', choices=['pipelined', 'classic'], default='pipelined')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    sources = {'head': args.head.resolve(), 'base': args.base.resolve()}
    binaries = args.binaries.resolve()
    runner = binaries / 'head' / 'operation_baseline'
    runner_sha256 = digest(runner)
    revisions = {side: subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
                 for side, source in sources.items()}
    identity = {'format_version': 2}
    for side in sources:
        identity[side] = {
            'source': revisions[side],
            'proof_schema': source_schema(sources[side], revisions[side]),
            'runner_source': revisions['head'],
            'node_sha256': digest(binaries / side / 'verad'),
            'runner_sha256': runner_sha256,
            'components': (binaries / side / 'component_baseline').is_file(),
            'supports_rpc_listener_fd': supports_rpc_listener(binaries / side / 'verad'),
        }
        if identity[side]['components']:
            identity[side]['component_sha256'] = digest(binaries / side / 'component_baseline')
    if not identity['head']['components']:
        raise ValueError('head component benchmark is required')
    inherit_rpc_listener = all(identity[side]['supports_rpc_listener_fd'] for side in sources)
    identity['inherit_rpc_listener'] = inherit_rpc_listener
    incompatible = baseline_incompatible(identity)
    (output / 'comparison.json').write_text(json.dumps(identity, indent=2) + '\n')
    pipelined = args.consensus == 'pipelined'
    epoch, retained = ('192', '256') if pipelined else ('20', '32')
    failed = False
    for tag in TAGS:
        side = tag.rstrip('12')
        destination = output / tag
        destination.mkdir()
        print(f'Measuring {tag}', flush=True)
        if identity[side]['components']:
            with (destination / 'components.jsonl').open('w') as out, (destination / 'components.stderr').open('w') as err:
                subprocess.run([str(binaries / side / 'component_baseline')], cwd=sources[side],
                               stdout=out, stderr=err, check=True, timeout=120)
        for objects in (0, 32):
            if side == 'base' and incompatible:
                skipped = destination / f'objects-{objects}'
                skipped.mkdir()
                (skipped / 'unavailable.json').write_text(json.dumps(unavailable(identity, objects), indent=2) + '\n')
                print(f'{tag}/objects-{objects}: incompatible ACP proof schema; baseline not run', flush=True)
                continue
            command = [sys.executable, str(scripts / 'record.py'), '--node', str(binaries / side / 'verad'),
                       '--runner', str(runner), '--runner-source', str(sources['head']), '--history', 'regolith',
                       '--output', str(destination / f'objects-{objects}'), str(args.count), str(args.rate),
                       '128', '1', 'normal', '100', epoch, '0', str(objects), retained,
                       '1' if pipelined else '0', '1' if inherit_rpc_listener else '0']
            environment = dict(os.environ, VERA_E2E_KEEP='0')
            failed |= subprocess.run(command, cwd=sources[side], env=environment, check=False).returncode != 0
    # Render only after every timed pass has finished.
    for tag in TAGS:
        if tag.startswith('base') and incompatible:
            continue
        for objects in (0, 32):
            failed |= subprocess.run([sys.executable, str(scripts / 'report.py'),
                                      str(output / tag / f'objects-{objects}')], check=False).returncode != 0
    failed |= compare(output)
    raise SystemExit(int(failed))


if __name__ == '__main__':
    main()
