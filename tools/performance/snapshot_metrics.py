#!/usr/bin/env python3
"""Extract timestamped numeric snapshots from retained per-member node logs."""
import argparse
import datetime
import hashlib
import json
import math
import re
import sys
from pathlib import Path

SNAPSHOT_MARK = 'node resource snapshot'
TIMESTAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+')
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
FIELD_START = re.compile(r'\s+(runtime_metrics|history_memory_bytes|durable_height|index|proofs|allocator_memory_bytes|process_id)=')
LEAF_STRUCT = re.compile(r'([a-z_0-9]+): (\d+)')
LEAF_OPTION = re.compile(r'"([a-z_0-9]+)": (?:Some\((\d+)\)|(None))')
METRIC = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([^\s]+)(?:\s+#.*)?$')


def sections(event):
    found = {}
    matches = list(FIELD_START.finditer(event))
    for current, following in zip(matches, matches[1:]):
        found[current.group(1)] = event[current.end():following.start()]
    if matches:
        found[matches[-1].group(1)] = event[matches[-1].end():]
    return found


def leaves(section):
    values = {name: int(value) for name, value in LEAF_STRUCT.findall(section)}
    for name, present, absent in LEAF_OPTION.findall(section):
        values.setdefault(name, None if absent else int(present))
    return values


def runtime_metrics(section):
    values = {}
    for line in section.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = METRIC.fullmatch(line)
        if match is None:
            raise ValueError('invalid runtime metric')
        name, labels, raw = match.groups()
        value = int(raw) if re.fullmatch(r'[+-]?\d+', raw) else float(raw)
        if not math.isfinite(value):
            raise ValueError('non-finite runtime metric')
        if labels:
            # Keep labelled series separate without exporting private label values.
            name += '.' + hashlib.sha256(labels.encode()).hexdigest()
        if name in values:
            raise ValueError('duplicate runtime metric')
        values[name] = value
    if not values:
        raise ValueError('missing runtime metrics')
    return values


def parse_snapshot(event):
    if SNAPSHOT_MARK not in event:
        return None
    fields = sections(event)
    required = {'runtime_metrics', 'history_memory_bytes', 'durable_height', 'index', 'proofs'}
    if not required <= set(fields) <= required | {'allocator_memory_bytes', 'process_id'}:
        raise ValueError('incomplete node resource snapshot')
    record = {'durable_height': int(fields['durable_height'].strip())}
    if 'process_id' in fields:
        process = fields['process_id'].strip()
        if not re.fullmatch(r'[1-9][0-9]{0,9}', process) or int(process) > 0xffffffff:
            raise ValueError('invalid snapshot process ID')
        record['process_id'] = int(process)
    for section in ('runtime_metrics', 'history_memory_bytes', 'index', 'proofs'):
        parser = runtime_metrics if section == 'runtime_metrics' else leaves
        for name, value in parser(fields[section]).items():
            record[section + '.' + name] = value
    if 'allocator_memory_bytes' in fields:
        values = leaves(fields['allocator_memory_bytes'])
        if set(values) != {'arena_reserved', 'arena_in_use', 'arena_free', 'direct_mapped'}:
            raise ValueError('incomplete allocator memory snapshot')
        if any(value is None for value in values.values()) and any(value is not None for value in values.values()):
            raise ValueError('partially supported allocator memory snapshot')
        for name, value in values.items():
            record['allocator_memory_bytes.' + name] = value
    return record


def snapshots(log):
    event = []
    with log.open() as handle:
        for raw in handle:
            line = ANSI.sub('', raw)
            if TIMESTAMP.match(line):
                if event:
                    yield ''.join(event)
                event = [line] if SNAPSHOT_MARK in line else []
            elif event:
                event.append(line)
    if event:
        yield ''.join(event)


def timestamp(value):
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))


def collect(node_logs, started_at, members, minimum_samples):
    runs = [path for path in node_logs.iterdir() if path.is_dir()]
    if len(runs) != 1:
        raise ValueError('expected exactly one retained cluster')
    expected = {'node%d' % member for member in range(members)}
    actual = {path.name for path in runs[0].glob('node*') if path.is_dir()}
    if actual != expected:
        raise ValueError('retained member set differs from expected members')
    records = []
    for member in sorted(expected):
        log = runs[0] / member / 'logs/stdout.log'
        if not log.is_file():
            raise ValueError('missing member stdout log')
        count = 0
        previous = None
        for event in snapshots(log):
            observed_at = TIMESTAMP.match(event).group(1)
            observed = timestamp(observed_at)
            if observed < started_at or (previous is not None and observed < previous):
                raise ValueError('member snapshot timestamp is out of order')
            previous = observed
            records.append({
                'member': member,
                'sample_index': count,
                'recorded_at': observed_at,
                'recording_elapsed_seconds': (observed - started_at).total_seconds(),
                **parse_snapshot(event),
            })
            count += 1
        if count < minimum_samples:
            raise ValueError('member snapshot coverage is incomplete')
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Recorded workload directory.')
    parser.add_argument('--node-logs', required=True, type=Path, help='Private retained cluster parent.')
    parser.add_argument('--members', type=int, default=4)
    parser.add_argument('--minimum-samples', type=int, default=1)
    args = parser.parse_args(argv)
    if args.members < 1 or args.minimum_samples < 1:
        parser.error('member and sample counts must be positive')
    output = args.directory / 'diagnostics.jsonl'
    output.unlink(missing_ok=True)
    try:
        manifest = json.loads((args.directory / 'manifest.json').read_text())
        records = collect(args.node_logs, timestamp(manifest['started_at']),
                          args.members, args.minimum_samples)
    except (OSError, KeyError, TypeError, ValueError):
        print('diagnostic evidence validation failed', file=sys.stderr)
        return 1
    with output.open('w') as handle:
        for record in records:
            handle.write(json.dumps(record, allow_nan=False) + '\n')
    print('%d snapshots from %d members' % (len(records), args.members))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
