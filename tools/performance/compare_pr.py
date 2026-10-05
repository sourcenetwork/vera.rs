#!/usr/bin/env python3
"""Compare interleaved passes without treating hosted-runner noise as a speedup."""
import argparse
import json
import math
from pathlib import Path
from statistics import median

from report import load_run

TAGS = ('head1', 'base1', 'base2', 'head2')
COMPONENTS = ('native_bls_verify', 'acp_owner_read_capture', 'consensus_certificate_verify')
LIFECYCLE_COMPONENTS = tuple(
    f'acp_policy_{operation}_{size}'
    for size in ('32', '256', '2048', '32_unrelated_2048')
    for operation in ('edit', 'delete')
)
COMPONENT_FIXTURES = {1: COMPONENTS, 2: COMPONENTS + LIFECYCLE_COMPONENTS}


def change(base, head, lower=True, threshold=5):
    if len(base) != 2 or len(head) != 2 or any(not math.isfinite(x) or x <= 0 for x in base + head):
        raise ValueError('expected two positive finite pass measurements per revision')
    delta = (median(head) / median(base) - 1) * 100
    separated = max(base) < min(head) or max(head) < min(base)
    spread = max((max(values) - min(values)) / median(values) * 100 for values in (base, head))
    if abs(delta) < threshold:
        verdict = 'within threshold'
    elif not separated:
        verdict = 'inconclusive (pass ranges overlap)'
    elif spread > threshold:
        verdict = 'inconclusive (pass variability)'
    else:
        verdict = 'regression signal' if (delta > 0) == lower else 'improvement signal'
    return delta, verdict


def components(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    version = rows[0].get('fixture_version') if rows else None
    if version not in COMPONENT_FIXTURES or rows[0] != {
            'format_version': 1, 'fixture_version': version, 'kind': 'configuration',
            'samples': 9, 'sample_ms': 100, 'warmup_ms': 200}:
        raise ValueError('unsupported component fixture or sampling configuration')
    expected = COMPONENT_FIXTURES[version]
    result = {}
    for row in rows[1:]:
        name = row['name']
        if name in result or name not in expected or row['unit'] != 'ns/op':
            raise ValueError('duplicate or unknown component measurement')
        samples, counts = row['samples'], row['iterations']
        if len(samples) != 9 or len(counts) != 9 or any(not math.isfinite(x) or x <= 0 for x in samples):
            raise ValueError('invalid component samples')
        if any(not isinstance(x, int) or x <= 0 for x in counts):
            raise ValueError('invalid component iterations')
        result[name] = median(samples)
    if set(result) != set(expected):
        raise ValueError('missing component measurement')
    return result


def compare(directory):
    identity = json.loads((directory / 'comparison.json').read_text())
    rows, errors, differences = [], [], []

    def row(name, values, lower=True, comparable=True):
        base = [values[t] for t in ('base1', 'base2')]
        head = [values[t] for t in ('head1', 'head2')]
        delta, verdict = change(base, head, lower)
        if identity['base']['source'] == identity['head']['source']:
            verdict = 'same-revision control; no code-change claim'
        if not comparable:
            delta, verdict = None, 'configuration changed; no delta'
        rows.append({'metric': name, 'base': base, 'head': head, 'change_percent': delta, 'verdict': verdict})

    for objects in (0, 32):
        runs = {}
        try:
            for tag in TAGS:
                run = load_run(directory / tag / f'objects-{objects}')
                manifest, config, _, passed, *_ = run
                side = tag.rstrip('12')
                if manifest['source'] != identity[side]['source'] or manifest['dirty']:
                    raise ValueError(f'{tag}: source provenance mismatch')
                if manifest['node_sha256'] != identity[side]['node_sha256'] or manifest['runner_sha256'] != identity[side]['runner_sha256']:
                    raise ValueError(f'{tag}: binary provenance mismatch')
                if not passed:
                    raise ValueError(f'{tag}: correctness/completeness/recovery gate failed')
                runs[tag] = run
            # Queue and protocol limits can change intentionally; show those changes
            # instead of attributing the resulting delta solely to execution speed.
            ignored = {'node_data_dirs', 'signing_seconds', 'update_preparation_seconds', 'signed_bytes'}
            configs = {tag: {k: v for k, v in run[1].items() if k not in ignored} for tag, run in runs.items()}
            comparable = all(configs[tag] == configs['head1'] for tag in TAGS)
            if not comparable:
                keys = set().union(*(c.keys() for c in configs.values()))
                differences.append({'workload': objects, 'fields': {k: {t: c.get(k) for t, c in configs.items()}
                    for k in sorted(keys) if any(c.get(k) != configs['head1'].get(k) for c in configs.values())}})
            prefix = 'registrations' if objects == 0 else 'fixed updates'
            row(f'{prefix}: completed workflows/s', {t: r[2]['completed_workflows_per_second'] for t, r in runs.items()}, False, comparable)
            for metric in ('scheduled_to_certified_receipt_ms', 'permission_read_ms', 'scheduled_to_workflow_ms'):
                row(f'{prefix}: {metric} p95', {t: r[2][metric]['p95'] for t, r in runs.items()}, comparable=comparable)
            row(f'{prefix}: peak member RSS MiB', {t: max(v for series in r[5].values() for _, v in series) for t, r in runs.items()}, comparable=comparable)
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f'objects-{objects}: {error}')
    try:
        current = {t: components(directory / t / 'components.jsonl') for t in ('head1', 'head2')}
        if set(current['head1']) != set(current['head2']):
            raise ValueError('component fixture changed between head passes')
        baseline = {}
        if identity['base']['components']:
            baseline = {t: components(directory / t / 'components.jsonl') for t in ('base1', 'base2')}
            if set(baseline['base1']) != set(baseline['base2']):
                raise ValueError('component fixture changed between base passes')
            if not set(baseline['base1']).issubset(current['head1']):
                raise ValueError('head removed a component measurement')
        for name in current['head1']:
            if baseline and name in baseline['base1']:
                row(f'{name}: ns/op', {t: values[name] for t, values in (current | baseline).items()})
            else:
                rows.append({'metric': f'{name}: ns/op', 'base': [], 'head': [current[t][name] for t in ('head1', 'head2')],
                             'change_percent': None, 'verdict': 'new benchmark; no baseline'})
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(f'components: {error}')
    result = {'identity': identity, 'metrics': rows, 'errors': errors, 'configuration_differences': differences}
    (directory / 'comparison-report.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    lines = ['# Vera PR performance', '', f"Base `{identity['base']['source']}` → head `{identity['head']['source']}`", '',
             'Release builds, same runner, head/base/base/head passes. 5% advisory threshold. Overlapping ranges or more than 5% within-revision spread are inconclusive; remaining signals are not statistical confidence.', '',
             '| Metric | Base pass range | Head pass range | Change | Result |', '|---|---:|---:|---:|---|']
    for item in rows:
        def span(values):
            return f'{min(values):.2f}–{max(values):.2f}' if values else '—'
        delta = '—' if item['change_percent'] is None else f"{item['change_percent']:+.2f}%"
        lines.append(f"| {item['metric']} | {span(item['base'])} | {span(item['head'])} | {delta} | {item['verdict']} |")
    lines += ['', 'Full-stack throughput is offered-load limited. Certificate verification is a local component cost, not consensus finality. ACP capture excludes authenticated storage proof construction. Policy lifecycle timings exclude fixture construction, fork setup, result disposal and restoration checks; they exclude consensus and durable storage. No maximum-capacity or WAN claim.', '']
    if differences:
        lines += ['Configuration changes (no full-stack deltas):', '', '```json', json.dumps(differences, indent=2), '```', '']
    if errors:
        lines += ['Comparison unavailable or failed:', ''] + [f'- {error}' for error in errors]
    (directory / 'comparison.md').write_text('\n'.join(lines) + '\n')
    return bool(errors)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    raise SystemExit(compare(parser.parse_args().directory))
