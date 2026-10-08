#!/usr/bin/env python3
"""Extract numeric node diagnostics from a recorded workload's stderr log.

The opt-in `vera_diagnostics` target emits one resource snapshot every 30
seconds while the node runs. Raw logs stay private; this tool flattens each
snapshot into numeric records only, aligned to the sampler cadence because
the subscriber does not timestamp lines.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SNAPSHOT_MARK = 'node resource snapshot'
FIELD_START = re.compile(r' (runtime_metrics|history_memory_bytes|durable_height|index|proofs)=')
LEAF_STRUCT = re.compile(r'([a-z_0-9]+): (\d+)')
LEAF_OPTION = re.compile(r'"([a-z_0-9]+)": (?:Some\((\d+)\)|(None))')
CADENCE_SECONDS = 30


def sections(line):
    """Split one tracing line into its top-level diagnostic fields."""
    found = {}
    matches = list(FIELD_START.finditer(line))
    for current, following in zip(matches, matches[1:]):
        found[current.group(1)] = line[current.end():following.start()]
    if matches:
        found[matches[-1].group(1)] = line[matches[-1].end():]
    return found


def leaves(section):
    """Flatten one Debug/Display section into numeric leaf values."""
    values = {}
    for name, value in LEAF_STRUCT.findall(section):
        values.setdefault(name, int(value))
    for name, present, absent in LEAF_OPTION.findall(section):
        if name not in values:
            values[name] = None if absent else int(present)
    return values


def parse_snapshot(line):
    """Flatten one snapshot line into numeric leaves keyed by field path."""
    if SNAPSHOT_MARK not in line:
        return None
    record = {}
    for name, section in sections(line).items():
        if name == 'durable_height':
            record[name] = int(section)
            continue
        for leaf, value in leaves(section).items():
            record['%s.%s' % (name, leaf)] = value
    return record or None


def parse_stderr(log):
    """Read every snapshot in publishing order as numeric records."""
    samples = []
    with log.open() as handle:
        for line in handle:
            flattened = parse_snapshot(line)
            if flattened is None:
                continue
            samples.append({'sample_index': len(samples), **flattened})
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path,
                        help='record.py output directory containing stderr.log')
    parser.add_argument('--cadence-seconds', type=int, default=CADENCE_SECONDS)
    args = parser.parse_args()

    log = args.directory / 'stderr.log'
    if not log.is_file():
        print('missing %s' % log, file=sys.stderr)
        return 1

    samples = parse_stderr(log)
    output = args.directory / 'diagnostics.jsonl'
    with output.open('w') as handle:
        for sample in samples:
            sample['elapsed_seconds'] = sample['sample_index'] * args.cadence_seconds
            handle.write(json.dumps(sample) + '\n')
    print('%d snapshots -> %s' % (len(samples), output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
