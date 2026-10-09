#!/usr/bin/env python3
"""Export bounded test counts and tracked source locations, never log contents."""
import argparse
import itertools
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_FILES = 128
TAIL_BYTES = 256 * 1024
MAX_LOCATIONS = 16
MAX_RESULTS = 32
LOCATION = re.compile(r'((?:crates|bin)/[A-Za-z0-9_./-]+\.rs):(\d{1,7}):(\d{1,4})')
RESULT = re.compile(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def source_inventory(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', '*.rs'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=10)
    inventory = {}
    for raw in result.stdout.split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if name.startswith(('crates/', 'bin/')):
            inventory[name] = len((root / name).read_bytes().splitlines())
    return inventory


def read_tail(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('test evidence input must be a regular file')
        truncated = metadata.st_size > TAIL_BYTES
        stream.seek(max(0, metadata.st_size - TAIL_BYTES))
        content = stream.read(TAIL_BYTES).decode('utf-8', errors='replace')
        if truncated:
            content = content.partition('\n')[2]
        return content, truncated


def summarize(root, inventory):
    evidence = {'format_version': 1, 'files_read': 0, 'files_unreadable': 0,
                'tails_truncated': 0, 'file_limit_reached': False,
                'location_limit_reached': False, 'result_limit_reached': False,
                'runner_exit_code': None, 'source_locations': [], 'test_results': []}
    exit_path = root / 'test-exit-code'
    if exit_path.exists() or exit_path.is_symlink():
        try:
            content, truncated = read_tail(exit_path)
            if truncated or not re.fullmatch(r'\d{1,3}\n?', content) or int(content) > 255:
                raise ValueError('invalid test exit code')
            evidence['runner_exit_code'] = int(content)
        except (OSError, ValueError):
            evidence['files_unreadable'] += 1

    candidates = iter([root / 'test-output.log'])
    cluster_logs = root.glob('**/logs/*.log')
    candidates = itertools.chain(candidates, cluster_logs)
    for index, path in enumerate(candidates):
        if index >= MAX_FILES:
            evidence['file_limit_reached'] = True
            break
        try:
            content, truncated = read_tail(path)
        except (OSError, ValueError):
            evidence['files_unreadable'] += 1
            continue
        evidence['files_read'] += 1
        evidence['tails_truncated'] += int(truncated)
        for raw in content.splitlines():
            if len(raw) > 16384:
                continue
            line = ANSI.sub('', raw)
            for match in LOCATION.finditer(line):
                name, row, column = match.groups()
                row, column = int(row), int(column)
                if name not in inventory or not 1 <= row <= inventory[name] or column < 1:
                    continue
                location = {'file': name, 'line': row, 'column': column}
                if location in evidence['source_locations']:
                    continue
                if len(evidence['source_locations']) == MAX_LOCATIONS:
                    evidence['location_limit_reached'] = True
                else:
                    evidence['source_locations'].append(location)
            for match in RESULT.finditer(line):
                outcome, passed, failed, ignored = match.groups()
                counts = [int(passed), int(failed), int(ignored)]
                if any(count > 100000 for count in counts):
                    continue
                if len(evidence['test_results']) == MAX_RESULTS:
                    evidence['result_limit_reached'] = True
                else:
                    evidence['test_results'].append({'passed': counts[0], 'failed': counts[1],
                                                     'ignored': counts[2], 'success': outcome == 'ok'})
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = summarize(args.logs, source_inventory(Path.cwd()))
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True,
                                           stderr=subprocess.DEVNULL, timeout=10).strip()
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('invalid source revision')
        evidence['source_revision'] = revision
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + '\n')
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Unable to collect bounded test evidence') from None


if __name__ == '__main__':
    main()
