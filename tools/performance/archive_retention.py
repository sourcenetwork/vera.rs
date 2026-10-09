#!/usr/bin/env python3
"""Check archive lookup retention using numeric snapshots from a real workload."""
import argparse
import json
import sys
from pathlib import Path

ARCHIVES = ('finalized_blocks', 'finalizations_by_height')


def count(record, key):
    value = record[key]
    if type(value) is not int or value < 0:
        raise ValueError('invalid archive gauge')
    return value


def audit(records, members=4, minimum_samples=4, minimum_finalized_span=512, max_excess=64):
    expected = {'node%d' % member for member in range(members)}
    summaries = {}
    for record in records:
        member = record['member']
        if member not in expected:
            raise ValueError('unexpected member')
        summary = summaries.setdefault(member, {'samples': 0, 'minimum_height': None,
                                                'maximum_height': 0, 'archives': {}})
        height = count(record, 'durable_height')
        summary['samples'] += 1
        summary['minimum_height'] = height if summary['minimum_height'] is None else min(summary['minimum_height'], height)
        summary['maximum_height'] = max(summary['maximum_height'], height)
        for archive in ARCHIVES:
            prefix = 'runtime_metrics.' + archive + '_'
            items = count(record, prefix + 'index_items')
            keys = count(record, prefix + 'index_keys')
            retained = count(record, prefix + 'items_tracked')
            # Gauges are read separately; tolerate one declared sync cadence of observation skew.
            if keys > items + max_excess or abs(items - retained) > max_excess:
                raise ValueError('lookup entries differ from retained archive')
            result = summary['archives'].setdefault(archive, {'maximum_items': 0,
                                                            'maximum_retained': 0,
                                                            'maximum_excess': 0})
            result['maximum_items'] = max(result['maximum_items'], items)
            result['maximum_retained'] = max(result['maximum_retained'], retained)
            result['maximum_excess'] = max(result['maximum_excess'], items - retained)
    if set(summaries) != expected:
        raise ValueError('missing member evidence')
    for summary in summaries.values():
        if summary['samples'] < minimum_samples:
            raise ValueError('insufficient archive samples')
        if summary['maximum_height'] - summary['minimum_height'] < minimum_finalized_span:
            raise ValueError('insufficient finalization to exercise pruning')
    return {'passed': True, 'members': summaries, 'minimum_samples': minimum_samples,
            'minimum_finalized_span': minimum_finalized_span, 'max_excess': max_excess}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--members', type=int, default=4)
    parser.add_argument('--minimum-samples', type=int, default=4)
    parser.add_argument('--minimum-finalized-span', type=int, default=512)
    parser.add_argument('--max-excess', type=int, default=64)
    args = parser.parse_args(argv)
    if min(args.members, args.minimum_samples, args.minimum_finalized_span) < 1 or args.max_excess < 0:
        parser.error('member, sample and finalization counts must be positive; excess must be nonnegative')
    output = args.directory / 'archive-retention.json'
    output.unlink(missing_ok=True)
    try:
        with (args.directory / 'diagnostics.jsonl').open() as stream:
            result = audit((json.loads(line) for line in stream), args.members, args.minimum_samples,
                           args.minimum_finalized_span, args.max_excess)
        output.write_text(json.dumps(result, indent=2) + '\n')
    except (OSError, KeyError, TypeError, ValueError):
        print('archive retention evidence validation failed', file=sys.stderr)
        return 1
    print('Archive lookup retention verified for %d members.' % args.members)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
