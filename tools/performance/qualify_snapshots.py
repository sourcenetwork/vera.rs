#!/usr/bin/env python3
"""Qualify allocator snapshots without exporting node paths, labels or logs."""
import argparse
import json
from pathlib import Path
import re
import stat
import sys

from snapshot_metrics import parse_snapshot, snapshots


COUNTERS = ('arena_reserved', 'arena_in_use', 'arena_free', 'direct_mapped')
MAX_CLUSTERS = 64
MAX_MEMBERS = 16
MAX_LOG_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOTS = 256


def directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError('snapshot directory must be a real directory')


def member_summary(node, require_process_id=False):
    directory(node)
    directory(node / 'logs')
    log = node / 'logs/stdout.log'
    metadata = log.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_LOG_BYTES:
        raise ValueError('snapshot log is not a bounded regular file')
    values = {name: [] for name in COUNTERS}
    processes = set()
    identified = 0
    for event in snapshots(log):
        record = parse_snapshot(event)
        if require_process_id and 'process_id' not in record:
            raise ValueError('snapshot process ID must be present')
        if 'process_id' in record:
            processes.add(record['process_id'])
            identified += 1
        current = {name: record.get('allocator_memory_bytes.' + name) for name in COUNTERS}
        if any(type(value) is not int or value < 0 for value in current.values()):
            raise ValueError('GNU/Linux allocator counters must be present')
        if current['arena_reserved'] != current['arena_in_use'] + current['arena_free']:
            raise ValueError('allocator arena accounting is inconsistent')
        for name, value in current.items():
            values[name].append(value)
        if len(values[COUNTERS[0]]) > MAX_SNAPSHOTS:
            raise ValueError('snapshot sample limit exceeded')
    count = len(values[COUNTERS[0]])
    if count == 0:
        raise ValueError('member has no allocator snapshots')
    return {'samples': count, 'processes': len(processes) if identified == count else None, 'bytes': {
        name: {'minimum': min(series), 'maximum': max(series), 'last': series[-1]}
        for name, series in values.items()}}


def qualify(logs, require_process_id=False):
    directory(logs)
    clusters = []
    for run in sorted(logs.iterdir()):
        if not run.is_dir():
            continue
        directory(run)
        members = {int(path.name[4:]): path for path in run.iterdir()
                   if re.fullmatch(r'node(?:0|[1-9][0-9]?)', path.name)}
        if not members:
            continue
        if not 1 <= len(members) <= MAX_MEMBERS or set(members) != set(range(len(members))):
            raise ValueError('retained member set is incomplete or oversized')
        clusters.append({'members': [member_summary(members[index], require_process_id)
                                     for index in range(len(members))]})
        if len(clusters) > MAX_CLUSTERS:
            raise ValueError('snapshot cluster limit exceeded')
    if not any(len(cluster['members']) >= 4 for cluster in clusters):
        raise ValueError('missing allocator coverage from a four-member cluster')
    return {'format_version': 1, 'allocator': 'glibc', 'clusters': clusters}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-process-id', action='store_true')
    args = parser.parse_args(argv)
    args.output.unlink(missing_ok=True)
    try:
        result = qualify(args.logs, args.require_process_id)
    except (OSError, KeyError, TypeError, ValueError):
        print('allocator snapshot qualification failed', file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print('%d clusters have checked allocator snapshots' % len(result['clusters']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
