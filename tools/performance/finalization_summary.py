#!/usr/bin/env python3
"""Attribute finalized publication work from numeric in-workload snapshots."""
import argparse
import datetime
import json
import math
from pathlib import Path

from storage_summary import rows

STAGES = {
    'callback': 'finalization_callback_seconds',
    'artifact_lookup': 'finalization_lookup_seconds',
    'blocking_queue': 'finalization_blocking_queue_seconds',
    'history_append': 'finalization_history_append_seconds',
    'history_preparation': 'finalization_history_prepare_seconds',
    'history_lock': 'finalization_history_lock_seconds',
    'history_batch': 'finalization_history_batch_seconds',
    'qmdb_apply': 'state_database_apply_seconds',
    'qmdb_durability_wait': 'state_durability_wait_seconds',
    'qmdb_durability_completion': 'state_durability_completion_seconds',
}


def histogram(row, suffix):
    result = {}
    for field in ('sum', 'count'):
        ending = suffix + '_' + field
        values = [value for key, value in row.items()
                  if key.startswith('runtime_metrics.') and
                  (key == 'runtime_metrics.' + ending or key.endswith('_' + ending))]
        if not values or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0
                             for v in values):
            raise ValueError('missing or invalid finalization histogram')
        if field == 'count' and any(v != int(v) for v in values):
            raise ValueError('invalid histogram count')
        result[field] = sum(values)
    return result


def summarize(records, configuration, duration):
    pids, anchor = configuration['node_pids'], configuration['started_at_unix_ms']
    if (len(pids) != 4 or len(set(pids)) != 4
            or any(type(pid) is not int or pid <= 0 for pid in pids)
            or type(anchor) is not int or anchor <= 0
            or type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0):
        raise ValueError('invalid workload configuration')
    samples = {pid: [] for pid in pids}
    for row in records:
        pid = row['process_id']
        clock = datetime.datetime.fromisoformat(row['recorded_at'].replace('Z', '+00:00'))
        if clock.tzinfo is None:
            raise ValueError('diagnostic clock has no timezone')
        elapsed = clock.timestamp() - anchor / 1000
        if pid not in samples or not 0 <= elapsed <= duration:
            continue
        values = {stage: histogram(row, suffix) for stage, suffix in STAGES.items()}
        wal = {name: row['history_wal_statistics.' + name] for name in ('count', 'sum')}
        if any(type(v) is not int or v < 0 for v in wal.values()):
            raise ValueError('missing or invalid WAL timing')
        values['wal_write_and_sync'] = {'count': wal['count'], 'sum': wal['sum'] / 1_000_000}
        if samples[pid]:
            previous = samples[pid][-1]
            if elapsed <= previous[0] or any(values[stage][field] < previous[1][stage][field]
                                            for stage in values for field in ('count', 'sum')):
                raise ValueError('timing counters or clock regressed')
        samples[pid].append((elapsed, values))
        if len(samples[pid]) > 4096:
            raise ValueError('too many timing samples')
    members = []
    for member, pid in enumerate(pids):
        series = samples[pid]
        if len(series) < 2:
            raise ValueError('missing in-workload member coverage')
        first, last = series[0], series[-1]
        observed = last[0] - first[0]
        stages = {}
        for stage in last[1]:
            count = last[1][stage]['count'] - first[1][stage]['count']
            seconds = last[1][stage]['sum'] - first[1][stage]['sum']
            stages[stage] = {'samples': count, 'total_seconds': seconds,
                             'mean_ms': seconds * 1000 / count if count else None,
                             'elapsed_share': seconds / observed}
        if stages['callback']['samples'] <= 0:
            raise ValueError('no completed callbacks in measured interval')
        members.append({'member': member, 'observed_seconds': observed, 'stages': stages})
    return {'format_version': 1, 'members': members, 'limits': [
        'Counters are sampled independently and intervals exclude setup and restart.',
        'Nested and overlapping stage durations must not be added as independent time.',
        'WAL timing includes append and synchronization; it does not isolate fsync syscall time.',
        'Means are per stage observation, not per transaction or consensus finality latency.',
    ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    output = args.directory / 'finalization-summary.json'
    output.unlink(missing_ok=True)
    try:
        report = json.loads((args.directory / 'report.json').read_text())
        if report['status'] != 'passed' or report['manifest']['exit_code'] != 0:
            raise ValueError('workload failed')
        configurations = [row for row in rows(args.directory / 'workload.jsonl')
                          if row.get('kind') == 'resource_configuration']
        if len(configurations) != 1:
            raise ValueError('ambiguous workload configuration')
        result = summarize(rows(args.directory / 'diagnostics.jsonl'), configurations[0],
                           report['summary']['elapsed_seconds'])
        result['source'] = report['manifest']['source']
        result['node_sha256'] = report['manifest']['node_sha256']
        result['runner_sha256'] = report['manifest']['runner_sha256']
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        raise SystemExit('finalization measurement qualification failed') from None
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print('Clock-aligned finalization measurements recorded for four validators.')


if __name__ == '__main__':
    main()
