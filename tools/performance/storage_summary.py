#!/usr/bin/env python3
"""Report clock-aligned storage counters and retained resources from a checked run."""
import argparse
import datetime
import json
import math
from pathlib import Path

HISTORY = ('batch_input_bytes', 'wal_bytes', 'flush_bytes', 'compaction_bytes',
           'wal_syncs', 'admitted_stall_us')
RUNTIME = ('runtime_metrics.runtime_storage_write_bytes_total',
           'runtime_metrics.runtime_storage_syncs_total')
MEMORY = ('history_memory_bytes.block_cache', 'history_memory_bytes.memtables',
          'history_memory_bytes.arena_pool', 'index.cached_bytes',
          'proofs.finalization_bytes', 'proofs.epoch_bytes')
RETENTION = ('index.block_count', 'index.transaction_count', 'index.receipt_count',
             'proofs.finalizations', 'proofs.epochs')
FIELDS = tuple('history_write_statistics.' + name for name in HISTORY) + RUNTIME + MEMORY + RETENTION


def rows(path):
    with path.open('rb') as stream:
        for line in stream:
            if len(line) > 2 * 1024 * 1024:
                raise ValueError('measurement record exceeds the byte limit')
            if line.strip():
                yield json.loads(line)


def summarize(records, configuration, duration):
    pids = configuration['node_pids']
    anchor = configuration['started_at_unix_ms']
    if (type(anchor) is not int or anchor <= 0 or len(pids) != 4 or len(set(pids)) != 4
            or any(type(pid) is not int or pid <= 0 for pid in pids)
            or type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0):
        raise ValueError('invalid workload clock or member configuration')
    samples = {pid: [] for pid in pids}
    for row in records:
        clock, pid = row['recorded_at'], row['process_id']
        if (not isinstance(clock, str) or len(clock) > 64
                or type(pid) is not int or pid <= 0):
            raise ValueError('invalid diagnostic clock or process identity')
        timestamp = datetime.datetime.fromisoformat(clock.replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            raise ValueError('diagnostic clock has no timezone')
        elapsed = timestamp.timestamp() - anchor / 1000
        if pid not in samples or not 0 <= elapsed <= duration:
            continue
        if any(type(row.get(key)) is not int or row[key] < 0 for key in FIELDS):
            raise ValueError('missing or invalid storage measurement')
        if samples[pid] and elapsed <= samples[pid][-1]['elapsed_seconds']:
            raise ValueError('member diagnostic clock regressed')
        samples[pid].append({'elapsed_seconds': elapsed, **{key: row[key] for key in FIELDS}})
        if len(samples[pid]) > 4096:
            raise ValueError('member diagnostic sample limit exceeded')
    members = []
    for member, pid in enumerate(pids):
        series = samples[pid]
        if len(series) < 2:
            raise ValueError('missing in-workload member coverage')
        counter_keys = FIELDS[:len(HISTORY) + len(RUNTIME)]
        for first, last in zip(series, series[1:]):
            if any(last[key] < first[key] for key in counter_keys):
                raise ValueError('storage counter regressed within one process')
        first, last = series[0], series[-1]
        history = {name: last['history_write_statistics.' + name] - first['history_write_statistics.' + name]
                   for name in HISTORY}
        if history['batch_input_bytes'] == 0:
            raise ValueError('no measured history input bytes')
        output = sum(history[name] for name in ('wal_bytes', 'flush_bytes', 'compaction_bytes'))
        members.append({
            'member': member, 'samples': len(series),
            'observed_seconds': {'start': first['elapsed_seconds'], 'end': last['elapsed_seconds']},
            'history_counter_deltas': history,
            'history_encoded_output_per_input': output / history['batch_input_bytes'],
            'commonware_requested_write_bytes': last[RUNTIME[0]] - first[RUNTIME[0]],
            'commonware_sync_requests': last[RUNTIME[1]] - first[RUNTIME[1]],
            'retained_resources': {key: {'first': first[key], 'last': last[key],
                                       'peak_sampled': max(row[key] for row in series)}
                                   for key in MEMORY + RETENTION},
        })
    return {'format_version': 1, 'members': members,
            'definitions': {
                'history_encoded_output_per_input': 'Regolith encoded WAL, flush and compaction output divided by submitted batch key/value bytes over the same sampled interval.',
                'commonware_requested_write_bytes': 'Requested Commonware storage bytes, including QMDB and consensus archives. Its counter increments before the storage operation returns; failed attempts can be included.',
                'resources': 'Sampled cache/history payload and index/proof retention, not a whole-process memory bound.'},
            'limits': ['Intervals exclude setup, post-workload inspection and restarted processes. Periodic samples can miss transient peaks.',
                       'Encoded output and requested bytes are not physical-device write amplification; they exclude filesystem/device accounting.',
                       'Memory scopes can overlap; do not sum them as independent RSS components.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    output = args.directory / 'storage-summary.json'
    output.unlink(missing_ok=True)
    try:
        report = json.loads((args.directory / 'report.json').read_text())
        if report['status'] != 'passed' or report['manifest']['exit_code'] != 0:
            raise ValueError('workload qualification failed')
        configurations = [row for row in rows(args.directory / 'workload.jsonl')
                          if row.get('kind') == 'resource_configuration']
        if len(configurations) != 1:
            raise ValueError('ambiguous resource configuration')
        result = summarize(rows(args.directory / 'diagnostics.jsonl'), configurations[0],
                           report['summary']['elapsed_seconds'])
        result['source'] = report['manifest']['source']
        result['node_sha256'] = report['manifest']['node_sha256']
        result['runner_sha256'] = report['manifest']['runner_sha256']
        result['hardware'] = {key: report['manifest'][key] for key in
                              ('platform', 'architecture', 'logical_cpus', 'cpu_model')}
    except (OSError, KeyError, TypeError, ValueError):
        raise SystemExit('storage measurement qualification failed') from None
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print('Clock-aligned storage measurements recorded for four validators.')


if __name__ == '__main__':
    main()
