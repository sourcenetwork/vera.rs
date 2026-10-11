"""Derive fixed-object worker progress from successful scheduled observations."""
import json
import math
from pathlib import Path


def _number(value, name, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError('invalid worker progress ' + name)
    return value


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid worker progress ' + name)
    return value


def _percentiles(values):
    ordered = sorted(values)
    return {name: ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))}


def _records(path):
    with Path(path).open('rb') as stream:
        while True:
            line = stream.readline(1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 1024 * 1024:
                raise ValueError('worker progress record exceeds byte limit')
            if line.strip():
                yield json.loads(line)


def summarize_worker_progress(path, qualified):
    """Report useful progress, not internal node queues or consensus fairness."""
    if not qualified:
        return {'status': 'unavailable', 'reason': 'workload_not_qualified'}
    config = summary = None
    observations = []
    for row in _records(path):
        kind = row.get('kind')
        if kind == 'configuration':
            if config is not None:
                raise ValueError('duplicate worker progress configuration')
            config = row
        elif kind == 'summary':
            if summary is not None:
                raise ValueError('duplicate worker progress summary')
            summary = row
        elif kind == 'observation':
            if len(observations) == 100_000:
                raise ValueError('worker progress observation limit exceeded')
            observations.append(row)
    if config is None or summary is None:
        raise ValueError('missing worker progress configuration or summary')
    objects = _integer(config.get('fixed_update_objects', 0), 'workers', 0, 1024)
    if objects == 0:
        return {'status': 'not_applicable', 'reason': 'one_operation_per_signer'}
    if config.get('arrival_model') != 'scheduled_wait_for_previous_per_object':
        raise ValueError('unsupported worker progress arrival model')
    count = _integer(config.get('count'), 'count', objects, 100_000)
    rate = _integer(config.get('arrivals_per_second'), 'rate', 1, 10_000)
    elapsed = _number(summary.get('elapsed_seconds'), 'elapsed', 86_400)
    if elapsed == 0 or len(observations) != count:
        raise ValueError('incomplete worker progress observations')
    if any(type(summary.get(key)) is not int or summary[key] != 0
           for key in ('unknown', 'rejected', 'reverted', 'not_sent',
                       'confirmed_incomplete_workflows', 'verification_failures')):
        raise ValueError('worker progress requires successful complete workflows')
    if any(type(summary.get(key)) is not int or summary[key] != count
           for key in ('offered', 'confirmed', 'completed_workflows')):
        raise ValueError('worker progress summary differs from observations')
    groups = [{'workflow': [], 'lag': []} for _ in range(objects)]
    seen = set()
    events = []
    for row in observations:
        index = _integer(row.get('index'), 'index', 0, count - 1)
        if index in seen:
            raise ValueError('duplicate worker progress index')
        seen.add(index)
        worker = index % objects
        if row.get('object_id') != str(worker):
            raise ValueError('worker progress object differs from scheduled worker')
        if (row.get('outcome') != 'confirmed' or row.get('verification_failure') is not False
                or row.get('error') is not None):
            raise ValueError('worker progress requires confirmed verified observations')
        latency = _number(row.get('scheduled_to_workflow_ms'), 'workflow latency', elapsed * 1000)
        lag = _number(row.get('schedule_lag_ms'), 'schedule lag', latency)
        arrival = index / rate
        complete = arrival + latency / 1000
        if complete > elapsed + 1e-6:
            raise ValueError('worker completion exceeds measured interval')
        groups[worker]['workflow'].append(latency)
        groups[worker]['lag'].append(lag)
        events.extend(((arrival, 1, 1), (arrival + lag / 1000, 0, -1), (complete, -1, 0)))
    # Apply simultaneous arrivals, starts and completions together, so a zero-lag
    # start does not create a fictitious queue peak.
    events.sort()
    pending = waiting = peak_pending = peak_waiting = 0
    area_pending = area_waiting = previous = 0.0
    position = 0
    while position < len(events):
        when = events[position][0]
        area_pending += pending * (when - previous)
        area_waiting += waiting * (when - previous)
        while position < len(events) and events[position][0] == when:
            _, delta_pending, delta_waiting = events[position]
            pending += delta_pending
            waiting += delta_waiting
            position += 1
        if not 0 <= waiting <= pending <= count:
            raise ValueError('inconsistent worker progress event ordering')
        peak_pending = max(peak_pending, pending)
        peak_waiting = max(peak_waiting, waiting)
        previous = when
    if pending or waiting:
        raise ValueError('worker progress did not drain')
    workers = [{'worker': index, 'completed': len(group['workflow']),
                'workflow_ms': _percentiles(group['workflow']),
                'schedule_lag_ms': _percentiles(group['lag'])}
               for index, group in enumerate(groups)]
    p95 = [worker['workflow_ms']['p95'] for worker in workers]
    return {'status': 'measured', 'workers': workers,
            'minimum_worker_workflow_p95_ms': min(p95), 'maximum_worker_workflow_p95_ms': max(p95),
            'peak_scheduled_incomplete': peak_pending, 'peak_not_started': peak_waiting,
            'time_weighted_scheduled_incomplete': area_pending / elapsed,
            'time_weighted_not_started': area_waiting / elapsed,
            'scope': 'One signer and sequential task per fixed object, using scheduled arrivals and observed completion times. '
                     'Backlog includes runner scheduling and per-object waits; it is not a validator queue or consensus fairness measurement. '
                     'A finite successful drain does not establish sustainable capacity.'}
