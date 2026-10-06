#!/usr/bin/env python3
"""Create a self-contained, offline replay of recorded workload measurements."""
import argparse
import hashlib
import json
import math
from pathlib import Path

from report import load_run

ASSETS = Path(__file__).with_name('replay')
ARRIVAL_MODELS = {'scheduled_drop_when_full', 'scheduled_wait_for_previous_per_object'}


def number(value, label):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid ' + label)
    return value


def build_replay(directory):
    data = dict(status='unavailable', issue=None, manifest={}, configuration={}, summary={},
                verification={}, recovery={}, members=[], sample_times=[], events=[], duration=0,
                timeline_available=False, untimed_observations=0, missing_member_samples=None,
                input_sha256={})
    try:
        raw_manifest = json.loads((directory / 'manifest.json').read_text())
        records = [json.loads(line) for line in (directory / 'workload.jsonl').read_text().splitlines() if line.strip()]
        if not isinstance(raw_manifest, dict) or any(not isinstance(row, dict) for row in records):
            raise ValueError('manifest and workload records must be JSON objects')
        for row in records:
            if row.get('kind') == 'resources':
                sample = row.get('sample')
                if not isinstance(sample, dict):
                    raise ValueError('resource samples must be JSON objects')
                if 'rows' in sample and not isinstance(sample['rows'], str):
                    raise ValueError('resource sample rows must be text')
        # Keep the existing correctness, replica and restart gates authoritative.
        manifest, config, summary, passed, _, series, missing, verification, recovery = load_run(directory)
        data.update(status='passed' if passed else 'failed', manifest=manifest,
                    configuration={k: v for k, v in config.items() if k != 'node_data_dirs'},
                    summary=summary, verification=verification, recovery=recovery,
                    missing_member_samples=missing)
        samples = [r for r in records if r.get('kind') == 'resources']
        times = [number(r.get('elapsed_seconds'), 'resource timestamp') for r in samples]
        if any(t is None for t in times) or any(a >= b for a, b in zip(times, times[1:])):
            raise ValueError('resource timestamps must increase')
        data['sample_times'] = times
        for index, (pid, values) in enumerate(series.items()):
            by_time = dict(values)
            data['members'].append(dict(index=index, pid=pid, rss_mib=[by_time.get(t) for t in times]))
        rate = number(config.get('arrivals_per_second'), 'offered rate')
        data['timeline_available'] = config.get('arrival_model') in ARRIVAL_MODELS and bool(rate)
        for row in records:
            if row.get('kind') != 'observation':
                continue
            index = row.get('index')
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise ValueError('invalid observation index')
            receipt = number(row.get('scheduled_to_certified_receipt_ms'), 'receipt latency')
            workflow = number(row.get('scheduled_to_workflow_ms'), 'workflow latency')
            if not data['timeline_available'] or receipt is None:
                data['untimed_observations'] += 1
                continue
            scheduled = index / rate
            observed = scheduled + receipt / 1000
            completed = scheduled + workflow / 1000 if workflow is not None else None
            if completed is not None and completed < observed:
                raise ValueError('workflow completion precedes receipt observation')
            data['events'].append(dict(index=index, at=observed, latency_ms=receipt,
                                       completed_at=completed, outcome=row.get('outcome'),
                                       verification_failure=row.get('verification_failure'),
                                       error=row.get('error'), height=row.get('height')))
        data['events'].sort(key=lambda row: (row['at'], row['index']))
        elapsed = number(summary.get('elapsed_seconds'), 'workload duration')
        if elapsed is not None and any(max(e['at'], e['completed_at'] or 0) > elapsed + 0.001 for e in data['events']):
            raise ValueError('observation exceeds recorded workload duration')
        data['duration'] = max([elapsed or 0] + times + [e['at'] for e in data['events']])
        # Reject nonfinite provenance/summary values rather than emit invalid browser JSON.
        json.dumps(data, allow_nan=False)
    except (ValueError, KeyError, TypeError, OSError) as error:
        data.update(status='unavailable', issue=str(error), events=[], members=[], sample_times=[],
                    duration=0, timeline_available=False)
        # Preserve identity when the measurement stream itself is incomplete.
        try:
            manifest = json.loads((directory / 'manifest.json').read_text())
            json.dumps(manifest, allow_nan=False)
            if not isinstance(manifest, dict):
                raise ValueError('manifest must be a JSON object')
            data['manifest'] = manifest
        except (ValueError, TypeError, OSError):
            data['manifest'] = {}
        # Do not leak partially validated measurement values into charts or metrics.
        for field in ('configuration', 'summary', 'verification', 'recovery'):
            data[field] = {}
    for name in ('manifest.json', 'workload.jsonl'):
        path = directory / name
        if path.is_file():
            data['input_sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return data


def render(data):
    # JSON script elements still recognize </script>; escape HTML delimiters first.
    payload = json.dumps(data, allow_nan=False, separators=(',', ':'))
    for char, escaped in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                          ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
        payload = payload.replace(char, escaped)
    return (ASSETS.joinpath('template.html').read_text()
            .replace('__STYLE__', ASSETS.joinpath('style.css').read_text())
            .replace('__SCRIPT__', ASSETS.joinpath('script.js').read_text())
            .replace('__DATA__', payload))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Recorded manifest.json and workload.jsonl directory')
    parser.add_argument('--output', required=True, type=Path, help='New standalone HTML file; never overwritten')
    args = parser.parse_args()
    data = build_replay(args.directory)
    with args.output.open('x') as output:
        output.write(render(data))
    print(args.output)
    if data['status'] != 'passed':
        raise SystemExit('Report written: workload failed, incomplete, or unavailable; no capacity claim.')


if __name__ == '__main__':
    main()
