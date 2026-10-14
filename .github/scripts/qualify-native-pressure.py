#!/usr/bin/env python3
"""Validate numeric admission-pressure evidence without exporting private logs."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location(
    'mixed_qualification', Path(__file__).with_name('qualify-mixed-policy.py'))
mixed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mixed)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/performance'))
from resource_usage import summarize_resources
from process_io import summarize_io

CASE = 'pipelined_admission_preserves_work_when_quorum_recovers'
MULTIWORKER_CASE = 'pipelined_multiworker_admission_preserves_each_sequence_when_quorum_recovers'
CASES = {CASE: 1, MULTIWORKER_CASE: 4}
PHASES = ('filling', 'saturated', 'recovering', 'reconciled')
STORAGE_PHASES = ('before_pending', 'saturated', 'after_reconciliation')
require = mixed.require
integer = mixed.integer


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 900


def records(content, case=CASE):
    result = []
    for line in content.decode().splitlines():
        prefix = f'test {case} ... '
        if line.startswith(prefix):
            line = line[len(prefix):]
        if not line.startswith('{'):
            continue
        require(len(line) <= 128 * 1024, 'input')
        row = json.loads(line)
        if row.get('kind') in ('pressure_phase', 'pressure_result', 'resources',
                               'resource_configuration', 'storage'):
            result.append(row)
    return result


def qualify(rows, case=CASE):
    require(case in CASES, 'case')
    workers = CASES[case]
    phases = [row for row in rows if row['kind'] == 'pressure_phase']
    require([row['phase'] for row in phases] == list(PHASES), 'phases')
    times = [row['elapsed_seconds'] for row in phases]
    require(all(number(value) for value in times)
            and all(b > a for a, b in zip(times, times[1:])), 'phases')
    require(29 <= times[2] - times[1] <= 180, 'saturation-duration')
    results = [row for row in rows if row['kind'] == 'pressure_result']
    require(len(results) == 1, 'result')
    result = results[0]
    for field, expected in (('admitted', 4096), ('rejected', 1200),
                            ('confirmed', 4097), ('reconciled_replicas', 4)):
        require(type(result[field]) is int and result[field] == expected, 'outcomes')
    require(integer(result['pending_wire_bytes'], 1)
            and result['pending_wire_bytes'] <= 64 << 20, 'pending-bytes')
    latencies = result['rejection_ms']
    require(isinstance(latencies, list) and len(latencies) == 1200, 'rejections')
    rejection = mixed.distribution(latencies, maximum=120000)
    recovery_ms = mixed.timing(result['recovery_ms'])
    require(abs(recovery_ms - (times[3] - times[2]) * 1000) <= 2000, 'recovery-duration')
    require(type(result.get('workers')) is int and result['workers'] == workers, 'workers')
    observed = result.get('worker_recoveries')
    require(isinstance(observed, list) and len(observed) == workers, 'workers')
    mixed.unique(observed, ('worker',), {(worker,) for worker in range(workers)})
    per_worker = 4096 // workers
    worker_results = []
    for row in sorted(observed, key=lambda row: row['worker']):
        require(type(row['confirmed']) is int and row['confirmed'] == per_worker, 'workers')
        tail = mixed.timing(row['backlog_tail_observed_ms'], maximum=recovery_ms)
        worker_results.append({'worker': row['worker'], 'confirmed': row['confirmed'],
                               'backlog_tail_observed_ms': tail})

    configs = [row for row in rows if row['kind'] == 'resource_configuration']
    require(len(configs) == 1, 'resources')
    config = configs[0]
    pids = config['node_pids']
    require(isinstance(pids, list) and len(pids) == len(set(pids)) == 4
            and all(integer(pid, 1) and pid <= 0xffffffff for pid in pids), 'resources')
    final = result['final_node_pids']
    require(isinstance(final, list) and len(final) == len(set(final)) == 4
            and all(integer(pid, 1) and pid <= 0xffffffff for pid in final)
            and final[:2] == pids[:2] and not set(final[2:]) & set(pids), 'process-identity')
    require(config['process_io_source'] == 'linux_proc_io', 'process-io')
    samples = [row for row in rows if row['kind'] == 'resources']
    require(1 <= len(samples) <= 900, 'resources')
    elapsed = [row['elapsed_seconds'] for row in samples]
    require(all(number(value) for value in elapsed)
            and all(0 < b - a <= 3 for a, b in zip(elapsed, elapsed[1:]))
            and elapsed[0] <= 2 and elapsed[-1] >= times[-1] - 3, 'sampling-coverage')
    saturated = [row for row in samples if times[1] <= row['elapsed_seconds'] < times[2]]
    require(len(saturated) >= 20 and saturated[0]['elapsed_seconds'] <= times[1] + 3
            and saturated[-1]['elapsed_seconds'] >= times[2] - 3, 'sampling-coverage')
    selected = []
    for row in samples:
        sample = row['sample']
        require('error' not in sample, 'resources')
        entries = []
        seen = set()
        for line in sample['rows'].splitlines():
            fields = line.split()
            require(len(fields) == 3 and fields[0].isdecimal()
                    and fields[1].isdecimal(), 'resources')
            pid = int(fields[0])
            require(pid in pids and pid not in seen, 'resources')
            seen.add(pid)
            if pid in pids[:2]:
                entries.append(line)
        require(set(pids[:2]) <= seen, 'resources')
        io = [{field: entry[field] for field in
               ('pid', 'availability', 'read_bytes', 'write_bytes', 'cancelled_write_bytes')}
              for entry in sample['process_io'] if entry['pid'] in pids[:2]]
        require(len(io) == 2 and {entry['pid'] for entry in io} == set(pids[:2])
                and all(entry['availability'] == 'complete' for entry in io), 'process-io')
        selected.append({'kind': 'resources', 'elapsed_seconds': row['elapsed_seconds'],
                         'sample': {'rows': '\n'.join(entries), 'process_io': io}})

    storage = [row for row in rows if row['kind'] == 'storage']
    mixed.unique(storage, ('phase', 'node'),
                 {(phase, node) for phase in STORAGE_PHASES for node in range(4)})
    require(all(type(row['node']) is int and 0 <= row['node'] < 4
                and row['error'] is None and all(integer(row[field]) for field in
                ('logical_bytes', 'allocated_file_bytes', 'regular_files')) for row in storage), 'storage')
    usage = {}
    for phase, start, end in [('complete_run', 0, 900),
                              ('saturated', times[1], times[2]),
                              ('recovery', times[2], times[3])]:
        observations = [row for row in selected if start <= row['elapsed_seconds'] < end]
        minimum = 0 if phase == 'recovery' and end - start < 3 else 2
        require(len(observations) >= minimum, 'sampling-coverage')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'resources.jsonl'
            filtered_config = {**config, 'node_pids': pids[:2]}
            path.write_text(''.join(json.dumps(row) + '\n' for row in
                                    [filtered_config, *observations]))
            usage[phase] = {'process': summarize_resources(path, late_window_seconds=10),
                            'io': summarize_io(path)}
        require(all(member['missing_samples'] == 0 for member in usage[phase]['process']['members']), 'resources')
    return {'qualified': True, 'case': case, 'workers': workers,
            'worker_recoveries': worker_results,
            'backlog_tail_spread_ms': max(row['backlog_tail_observed_ms'] for row in worker_results)
                                      - min(row['backlog_tail_observed_ms'] for row in worker_results),
            'admitted': 4096, 'confirmed': 4097,
            'rejected': 1200, 'pending_wire_bytes': result['pending_wire_bytes'],
            'rejection_ms': rejection, 'recovery_and_reconciliation_ms': recovery_ms,
            'phases': [{field: row[field] for field in ('phase', 'elapsed_seconds')} for row in phases],
            'resources': usage, 'numeric_observations': selected,
            'rejection_latency_samples_ms': latencies,
            'storage': [{field: row[field] for field in
                         ('phase', 'node', 'logical_bytes', 'allocated_file_bytes', 'regular_files')}
                        for row in storage],
            'scope': 'Four local validators; two stable surviving processes sampled during admission saturation and recovery. Restored process memory is outside this series. Kernel dirtying is not physical-device write amplification. No maximum capacity, steady-state memory bound or WAN claim.'}


def provenance(manifest, node, runner, case):
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    require(case in CASES and manifest['source'] == manifest['runner_source'] == revision
            and manifest['dirty'] is False and manifest['runner_dirty'] is False
            and manifest['history'] == 'regolith' and manifest['trace_span_close'] is False
            and manifest['rust_log'] == 'warn,vera_storage=info', 'provenance')
    require(manifest['arguments'] == [case, '--exact', '--nocapture', '--test-threads=1'], 'provenance')
    require(manifest['node_sha256'] == mixed.digest(node)
            and manifest['runner_sha256'] == mixed.digest(runner), 'provenance')
    return {'source_revision': revision, 'node_sha256': manifest['node_sha256'],
            'runner_sha256': manifest['runner_sha256'], 'hardware': mixed.hardware_manifest(manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, default=CASE)
    args = parser.parse_args()
    qualified = {'qualified': False, 'failure_stage': 'validation'}
    try:
        manifest = json.loads(mixed.read_bounded(args.directory / 'manifest.json', 65536))
        require(manifest['exit_code'] == 0, 'provenance')
        identity = provenance(manifest, args.node, args.runner, args.case)
        result = qualify(records(mixed.read_bounded(args.directory / 'workload.jsonl', 8 * 1024 * 1024), args.case), args.case)
        result.update(identity)
        qualified = result
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    args.output.write_text(json.dumps(qualified, indent=2) + '\n')
    raise SystemExit(0 if qualified['qualified'] else 1)


if __name__ == '__main__':
    main()
