#!/usr/bin/env python3
"""Run the exact prebuilt admission fixture with source and binary provenance."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

CASES = ('pipelined_admission_preserves_work_when_quorum_recovers',
         'pipelined_multiworker_admission_preserves_each_sequence_when_quorum_recovers')


def executable(metadata, workspace):
    candidates = set()
    for line in metadata.read_text().splitlines():
        row = json.loads(line)
        if (row.get('reason') == 'compiler-artifact'
                and row['target']['name'] == 'native_pressure'
                and row['profile']['test'] and row.get('executable')):
            candidates.add(Path(row['executable']).resolve(strict=True))
    if len(candidates) != 1:
        raise ValueError('one native pressure executable is required')
    result = candidates.pop()
    if result.parent != workspace / 'target/release/deps':
        raise ValueError('pressure fixture must use the release build')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-metadata', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--logs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', choices=CASES, default=CASES[0])
    args = parser.parse_args()
    args.output.write_text(json.dumps({'qualified': False, 'failure_stage': 'setup'}) + '\n')
    workspace = Path.cwd().resolve()
    runner = executable(args.build_metadata, workspace)
    node = workspace / 'target/release/verad'
    code = subprocess.run([
        sys.executable, 'tools/performance/record.py', '--node', str(node),
        '--runner', str(runner), '--output', str(args.directory),
        '--history', 'regolith', '--rust-log', 'warn,vera_storage=info',
        '--timeout-seconds', '840', '--',
        args.case,
        '--exact', '--nocapture', '--test-threads=1',
    ]).returncode
    args.logs.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(args.logs / 'test-output.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        for name in ('workload.jsonl', 'stderr.log'):
            output.write((args.directory / name).read_bytes())
    (args.logs / 'test-exit-code').write_text(str(code) + '\n')
    if code:
        args.output.write_text(json.dumps({
            'qualified': False, 'failure_stage': 'process', 'runner_exit_code': code,
        }) + '\n')
        raise SystemExit(code)
    subprocess.run([
        sys.executable, '.github/scripts/qualify-native-pressure.py',
        '--directory', str(args.directory), '--node', str(node),
        '--runner', str(runner), '--output', str(args.output),
        '--case', args.case,
    ], check=True)


if __name__ == '__main__':
    main()
