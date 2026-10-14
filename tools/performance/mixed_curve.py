"""Compare bounded mixed-policy loads on one host and one normal release build."""

import argparse
from itertools import groupby
import json
import math
from pathlib import Path
import re

RATES = (1, 2, 4, 8)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            'invalid observation')
    return value


def percentiles(values):
    values = sorted(number(value) for value in values)
    require(bool(values), 'empty timing observations')
    return {name: values[max(0, math.ceil(len(values) * fraction) - 1)]
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))}


def backlog(observations, rate, duration):
    require(len(observations) == 256, 'missing workflow observations')
    require(all(type(row['workflow']) is int for row in observations)
            and {row['workflow'] for row in observations} == set(range(256)),
            'duplicate or missing workflow')
    events = []
    for row in observations:
        scheduled = row['workflow'] / rate
        started = scheduled + number(row['schedule_lag_ms']) / 1000
        ended = scheduled + number(row['scheduled_to_complete_ms']) / 1000
        require(started <= ended <= duration + .01, 'inconsistent workflow timestamps')
        events.extend(((scheduled, 1, 1), (started, 0, -1), (ended, -1, 0)))
    incomplete = waiting = peak_incomplete = peak_waiting = 0
    incomplete_area = waiting_area = previous = 0
    for timestamp, at in groupby(sorted(events), key=lambda event: event[0]):
        incomplete_area += incomplete * (timestamp - previous)
        waiting_area += waiting * (timestamp - previous)
        at = list(at)
        incomplete += sum(event[1] for event in at)
        waiting += sum(event[2] for event in at)
        require(0 <= waiting <= incomplete and incomplete - waiting <= 8,
                'workflow concurrency differs from the fixed limit')
        peak_incomplete = max(peak_incomplete, incomplete)
        peak_waiting = max(peak_waiting, waiting)
        previous = timestamp
    require(incomplete == waiting == 0, 'unfinished workflows')
    return {'peak_scheduled_incomplete': peak_incomplete, 'peak_not_started': peak_waiting,
            'average_scheduled_incomplete': incomplete_area / duration,
            'average_not_started': waiting_area / duration}


def compare(cases):
    require(len(cases) == len(RATES), 'missing load case')
    first = cases[0]
    for key in ('source_revision', 'node_sha256', 'runner_sha256'):
        length = 40 if key == 'source_revision' else 64
        require(type(first.get(key)) is str and re.fullmatch(f'[0-9a-f]{{{length}}}', first[key]),
                'invalid source or binary hash')
    rows = []
    for rate, case in zip(RATES, cases):
        require(case.get('qualified') is True and case.get('format_version') == 2
                and case.get('profile') == f'curve-{rate}'
                and case.get('offered_workflows_per_second') == rate
                and case.get('workflows') == 256, 'unqualified or reordered load case')
        for key in ('source_revision', 'node_sha256', 'runner_sha256', 'hardware'):
            require(case.get(key) == first[key], 'cases use different hardware, sources or binaries')
        duration = number(case['timed_seconds'])
        require(duration >= 255 / rate, 'workload ends before scheduled arrivals')
        counts = case['timed_counts']
        require(counts['certified_successes'] == counts['issued_native_submissions'] == 1280
                and counts['certified_embedded_mutations'] == counts['issued_embedded_mutations'] == 3328
                and counts['verified_permission_checks'] == 15360, 'timed operation counts differ')
        require(case['replica_phases'] == ['after_workload', 'remove_member', 'reintroduce_member',
                                         'after_explicit_regrant', 'after_hard_restart'],
                'recovery phases missing')
        resource = case['resource_usage']
        require(resource['source'] == 'ps_rss_and_cpu_time' and len(resource['members']) == 4,
                'per-member resources unavailable')
        require(all(member['missing_samples'] == 0 and member['samples'] >= 2
                    and member['observed_window'] is not None for member in resource['members']),
                'incomplete resource observations')
        io = case['process_io']
        require(io['source'] == 'linux_proc_io' and len(io['members']) == 4
                and all(member['samples'] >= 2 and member['missing_samples'] == 0
                        and member['unavailable_samples'] == 0 and member['observed_window'] is not None
                        for member in io['members']), 'incomplete process I/O observations')
        observations = case['workflow_observations']
        scheduled_ms = percentiles(row['scheduled_to_complete_ms'] for row in observations)
        lag_ms = percentiles(row['schedule_lag_ms'] for row in observations)
        require(case['scheduled_workflow_ms'] == scheduled_ms and case['schedule_lag_ms'] == lag_ms,
                'timing summary differs from observations')
        rows.append({
            'offered_workflows_per_second': rate, 'timed_seconds': duration,
            'completed_workflows_per_second': 256 / duration,
            'certified_native_submissions_per_second': counts['certified_successes'] / duration,
            'certified_embedded_mutations_per_second': counts['certified_embedded_mutations'] / duration,
            'scheduled_workflow_ms': scheduled_ms,
            'schedule_lag_ms': lag_ms,
            'client_backlog': backlog(observations, rate, duration),
            'timed_throttled_requests': counts['throttled_requests'],
            'resources': resource, 'process_io': io,
            'storage': case['resources']['storage'], 'restart_ms': case['restart_ms'],
        })
    return {'format_version': 1, 'status': 'passed', 'source_revision': first['source_revision'],
            'node_sha256': first['node_sha256'], 'runner_sha256': first['runner_sha256'],
            'hardware': first['hardware'], 'cases': rows,
            'scope': 'Four local validators; 256 workflows and eight concurrent workers per case. '
                     'Each timed workflow has five certified submissions, thirteen embedded mutations '
                     'and sixty verified permission checks. Setup, later policy edits and reconciliation '
                     'are excluded from timed throughput. Backlog measures the bounded client, not validator '
                     'queues. No maximum-capacity, memory-ceiling, WAN or whole-gateway claim.'}


def markdown(report):
    lines = ['# Mixed-policy load curve', '',
             '| Offered workflows/s | Completed workflows/s | Certified submissions/s | Workflow p95 (ms) | Peak waiting workflows | Peak validator RSS (MiB) |',
             '| ---: | ---: | ---: | ---: | ---: | ---: |']
    for case in report['cases']:
        peak = max(m['rss_mib']['peak'] for m in case['resources']['members'])
        lines.append(f"| {case['offered_workflows_per_second']} | {case['completed_workflows_per_second']:.3f} | "
                     f"{case['certified_native_submissions_per_second']:.3f} | "
                     f"{case['scheduled_workflow_ms']['p95']:.2f} | "
                     f"{case['client_backlog']['peak_not_started']} | {peak:.2f} |")
    return '\n'.join(lines) + '\n\n' + report['scope'] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    cases = []
    for rate in RATES:
        path = args.directory / f'curve-{rate}.json'
        require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, 'case file unavailable or too large')
        cases.append(json.loads(path.read_text()))
    result = compare(cases)
    (args.directory / 'report.json').write_text(json.dumps(result, allow_nan=False, indent=2) + '\n')
    (args.directory / 'report.md').write_text(markdown(result))


if __name__ == '__main__':
    main()
