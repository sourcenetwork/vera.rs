#!/usr/bin/env python3
"""Qualify a mixed-policy run and export only bounded counts and timings."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess

WORKFLOW_PHASES = ('initial_grants', 'member_revoke', 'member_regrant', 'blocked_deny', 'unblock')
REPLICA_PHASES = ('after_workload', 'remove_member', 'reintroduce_member', 'after_explicit_regrant', 'after_hard_restart')
COUNT_FIELDS = ('issued_native_submissions', 'issued_embedded_mutations', 'certified_embedded_mutations',
                'submission_attempts', 'certified_successes', 'verified_permission_checks',
                'verified_owners', 'throttled_requests')


class InvalidEvidence(ValueError):
    pass


def require(condition, stage):
    if not condition:
        raise InvalidEvidence(stage)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 10**9


def timing(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 960_000, 'timing')
    return value


def unique(rows, fields, expected):
    keys = [tuple(row[field] for field in fields) for row in rows]
    for key in keys:
        require(all(type(value) is str if field == 'phase' else integer(value)
                    or (value is None and any(item[index] is None for item in expected))
                    for index, (field, value) in enumerate(zip(fields, key))), 'coverage')
    require(len(keys) == len(set(keys)) and set(keys) == expected, 'coverage')


def distribution(values):
    values = sorted(timing(value) for value in values)
    require(bool(values), 'timing')
    return {name: values[max(0, math.ceil(len(values) * fraction) - 1)]
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))}


def resource_summary(records):
    config = [row for row in records if row.get('kind') == 'resource_configuration']
    require(len(config) == 1, 'resources')
    pids = config[0]['node_pids']
    require(len(pids) == len(set(pids)) == 4 and all(integer(pid, 1) for pid in pids), 'resources')
    peaks = {pid: 0 for pid in pids}
    samples = [row for row in records if row.get('kind') == 'resources']
    require(bool(samples), 'resources')
    for sample in samples:
        require('error' not in sample['sample'], 'resources')
        found = {}
        for row in sample['sample']['rows'].splitlines():
            pid, rss, _ = row.split()
            pid, rss = int(pid), int(rss)
            require(pid in peaks and pid not in found and integer(rss), 'resources')
            found[pid] = rss
            peaks[pid] = max(peaks[pid], rss)
        require(set(found) == set(pids), 'resources')
        breakdown = sample['sample']['rss_breakdown']
        require(len(breakdown) == 4 and {row['pid'] for row in breakdown} == set(pids), 'resources')
        require(all(row['availability'] == 'complete' and all(integer(row[field]) for field in
                    ('vm_rss_kib', 'rss_anon_kib', 'rss_file_kib', 'rss_shmem_kib')) for row in breakdown), 'resources')
    storage = [row for row in records if row.get('kind') == 'storage']
    unique(storage, ('phase', 'node'), {(phase, node) for phase in
           ('before_workload', 'after_workload', 'after_verification') for node in range(4)})
    require(all(row['error'] is None and all(integer(row[field]) for field in
                ('logical_bytes', 'allocated_file_bytes', 'regular_files')) for row in storage), 'resources')
    return {'sample_count': len(samples), 'peak_member_rss_mib': [peaks[pid] / 1024 for pid in pids]}


def qualify(records, workflows=16):
    def rows(kind):
        return [row for row in records if row.get('kind') == kind]

    def one(kind):
        found = rows(kind)
        require(len(found) == 1, 'coverage')
        return found[0]

    config, result, summary, restart = (one(kind) for kind in ('configuration', 'result', 'workload_summary', 'restart'))
    expected_config = {'schema_version': 1, 'workflows': workflows, 'validators': 4, 'epoch_revisions': 192,
                       'scheduled_arrivals_per_second': 2, 'maximum_outstanding_workflows': 8,
                       'whole_run_deadline_seconds': 900, 'request_deadline_seconds': 30,
                       'workflow_deadline_seconds': 120, 'objects_per_workflow': 4, 'readers': 2, 'outsiders': 1,
                       'verification_concurrency_per_replica': 8, 'timing': 'normal',
                       'pipelined': True, 'debug_assertions': False}
    require(all(type(config.get(key)) is type(value) and config[key] == value
                for key, value in expected_config.items()), 'configuration')
    require(result['success'] is True and result['failure_kind'] is None and result['error'] is None, 'driver')
    require(summary['scheduled_workflows'] == summary['completed_workflows'] == workflows
            and summary['failed_workflows'] == 0 and summary['failures'] == [], 'workflows')
    require(type(summary['elapsed_seconds']) in (int, float)
            and math.isfinite(summary['elapsed_seconds']) and 0 < summary['elapsed_seconds'] <= 900, 'timing')
    counts = result['counts']
    require(all(integer(counts[field]) for field in COUNT_FIELDS), 'counts')
    expected_counts = {'issued_native_submissions': 6 * workflows + 3, 'certified_successes': 6 * workflows + 3,
                       'issued_embedded_mutations': 17 * workflows + 3, 'certified_embedded_mutations': 17 * workflows + 3,
                       'verified_permission_checks': 300 * workflows, 'verified_owners': 80 * workflows}
    require(all(counts[key] == value for key, value in expected_counts.items()), 'counts')
    require(counts['submission_attempts'] >= counts['issued_native_submissions'], 'counts')
    for field, expected in (('issued_native_submissions', 5 * workflows), ('certified_successes', 5 * workflows),
                            ('issued_embedded_mutations', 13 * workflows), ('certified_embedded_mutations', 13 * workflows),
                            ('verified_permission_checks', 60 * workflows), ('verified_owners', 0)):
        before, after = summary['counts_before'][field], summary['counts_after'][field]
        require(integer(before) and integer(after) and after - before == expected, 'counts')
    completed = rows('workflow_completed')
    unique(completed, ('workflow',), {(index,) for index in range(workflows)})
    require(all(integer(row['workflow']) and integer(row['finalized_revision'], 1) for row in completed), 'workflows')
    phases = rows('workflow_phase')
    unique(phases, ('phase', 'workflow'), {(phase, index) for phase in WORKFLOW_PHASES for index in range(workflows)})
    require(all(row['permission_checks'] == 12 and integer(row['minimum_revision'], 1)
                and row['failure_kind'] is None and row['error'] is None for row in phases), 'permissions')
    submissions = rows('submission')
    keys = {(phase, index) for phase in WORKFLOW_PHASES + ('restore_current_grants',) for index in range(workflows)}
    keys |= {(phase, None) for phase in ('policy_setup', 'remove_member', 'reintroduce_member')}
    unique(submissions, ('phase', 'workflow'), keys)
    started = rows('submission_started')
    unique(started, ('phase', 'workflow'), keys)
    identities = {row['id'] for row in submissions}
    require(len(identities) == len(submissions)
            and all(type(value) is str and re.fullmatch(r'0x[0-9a-f]{64}', value) for value in identities), 'submissions')
    require({(row['phase'], row['workflow'], row['id']) for row in started}
            == {(row['phase'], row['workflow'], row['id']) for row in submissions}, 'submissions')
    mutations = {'initial_grants': 9, 'restore_current_grants': 4}
    require(all(row['embedded_mutations'] == mutations.get(row['phase'], 1)
                and row['failure_kind'] is None and row['error'] is None
                and integer(row['revision'], 1) for row in submissions), 'submissions')
    verified = rows('replica_verification')
    unique(verified, ('phase',), {(phase,) for phase in REPLICA_PHASES})
    require(all(row['replicas'] == 4 and row['workflows'] == workflows
                and row['permission_checks'] == 48 * workflows and integer(row['minimum_revision'], 1)
                for row in verified), 'replicas')
    targets = {row['phase']: row['minimum_revision'] for row in verified}
    checks = rows('replica_check')
    unique(checks, ('phase', 'replica', 'workflow'),
           {(phase, replica, index) for phase in REPLICA_PHASES for replica in range(4) for index in range(workflows)})
    require(all(row['permission_checks'] == 12 and row['owner_checks'] == 4
                and row['minimum_revision'] == targets[row['phase']]
                and row['failure_kind'] is None and row['error'] is None for row in checks), 'replicas')
    require(restart['replica'] == 3 and restart['verified_workflows'] == workflows
            and restart['minimum_revision'] == targets['after_hard_restart'], 'restart')
    return {'format_version': 1, 'qualified': True, 'workflows': workflows,
            'timed_seconds': summary['elapsed_seconds'], 'completed_workflows_per_second': workflows / summary['elapsed_seconds'],
            'counts': {field: counts[field] for field in COUNT_FIELDS}, 'replica_phases': list(REPLICA_PHASES),
            'workflow_ms': distribution([row['elapsed_ms'] for row in completed]),
            'scheduled_workflow_ms': distribution([row['scheduled_to_complete_ms'] for row in completed]),
            'schedule_lag_ms': distribution([row['schedule_lag_ms'] for row in completed]),
            'certified_submission_ms': distribution([row['elapsed_ms'] for row in submissions]),
            'restart_ms': timing(restart['elapsed_ms']), 'resources': resource_summary(records)}


def read_bounded(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 16 * 1024 * 1024, 'input')
        content = stream.read(16 * 1024 * 1024 + 1)
        require(len(content) <= 16 * 1024 * 1024, 'input')
        return content


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evidence = {'format_version': 1, 'qualified': False, 'failure_stage': 'input'}
    try:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        require(bool(re.fullmatch(r'[0-9a-f]{40}', revision)), 'provenance')
        evidence['source_revision'] = revision
        manifest = json.loads(read_bounded(args.directory / 'manifest.json'))
        require(manifest['source'] == manifest['runner_source'] == revision
                and manifest['dirty'] is False and manifest['runner_dirty'] is False
                and manifest['exit_code'] == 0 and manifest['history'] == 'regolith'
                and manifest['arguments'] == ['16', '2', '8', '900']
                and manifest['trace_span_close'] is False and manifest['rust_log'] == 'warn', 'provenance')
        require(manifest['node_sha256'] == digest(args.node)
                and manifest['runner_sha256'] == digest(args.runner), 'provenance')
        lines = read_bounded(args.directory / 'workload.jsonl').splitlines()
        require(bool(lines) and all(len(line) <= 64 * 1024 for line in lines), 'input')
        records = [json.loads(line) for line in lines if line.strip()]
        require(all(type(row) is dict for row in records), 'input')
        configurations = [row for row in records if row.get('kind') == 'configuration']
        require(len(configurations) == 1 and configurations[0]['daemon'] == str(args.node.resolve()), 'provenance')
        evidence = qualify(records)
        evidence.update(source_revision=revision, node_sha256=manifest['node_sha256'], runner_sha256=manifest['runner_sha256'])
    except InvalidEvidence as error:
        evidence['failure_stage'] = str(error)
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        pass
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, allow_nan=False, indent=2) + '\n')
    if not evidence['qualified']:
        raise SystemExit('Mixed-policy evidence failed qualification')


if __name__ == '__main__':
    main()
