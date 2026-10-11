#!/usr/bin/env python3
"""Validate matched Go/Rust registration passes before presenting measurements."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
from statistics import median
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'performance'))
from report import load_run

TAGS = ('go1', 'rust1', 'rust2', 'go2')
PROOF_CASES = {
    'valid_signed_execution', 'forged_receipt_success', 'forged_committed_result',
    'wrong_result_height', 'changed_result_data', 'changed_proof_root',
    'uncommitted_log_is_not_trusted', 'wrong_transaction_index', 'wrong_transaction_bytes',
    'missing_result', 'wrong_signer_set', 'invalid_signatures', 'broken_header_link', 'wrong_network',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    require(path.stat().st_size <= 128 * 1024, 'metadata exceeds bounds')
    return json.loads(path.read_text())


def rows(path):
    require(path.stat().st_size <= 128 * 1024 * 1024, 'observations exceed bounds')
    with path.open() as stream:
        result = []
        for line in stream:
            require(len(line) <= 1024 * 1024 and len(result) < 100000, 'record exceeds bounds')
            if line.strip():
                result.append(json.loads(line))
    return result


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def percentiles(values):
    require(bool(values) and all(positive(value) for value in values), 'invalid receipt latencies')
    ordered = sorted(values)
    return {name: ordered[math.ceil(len(ordered) * fraction) - 1]
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99))}


def metadata_matches(manifest, identity, implementation):
    require(manifest.get('comparison_id') == identity['comparison_id'], 'different host measurement identity')
    for key in ('github_run_id', 'github_job', 'platform', 'architecture', 'logical_cpus', 'runner_image'):
        require(manifest.get(key) == identity[key], 'different host provenance')
    require(manifest['source'] == identity[implementation]['source'], 'different source revision')
    for key in ('node_sha256', 'driver_sha256' if implementation == 'go' else 'runner_sha256'):
        require(manifest[key] == identity[implementation][key]
                and re.fullmatch(r'[0-9a-f]{64}', manifest[key]), 'different measured binary')


def go_pass(directory, identity):
    manifest = read_json(directory / 'manifest.json')
    metadata_matches(manifest, identity, 'go')
    count = identity['count']
    require(manifest.get('status') == 'passed' and manifest['completed'] == count, 'Go fixture failed')
    for key, expected in (('count', count), ('worker_accounts', count), ('nodes', 4),
                          ('arrivals_per_second', identity['rate']), ('max_outstanding', 128),
                          ('permission_reads_per_write', 0), ('history', 'goleveldb'), ('commit_timeout_ms', 200)):
        require(manifest[key] == expected, 'Go logical workload differs')
    observations = rows(directory / 'observations.jsonl')
    require(len(observations) == count and all(type(row['index']) is int for row in observations)
            and {row['index'] for row in observations} == set(range(count)), 'Go observations are incomplete')
    require(len({row['owner'] for row in observations}) == count
            and all(row['status'] == 'completed' and row['object'] == str(row['index'])
                    and not row.get('error') and re.fullmatch(r'[0-9a-fA-F]{64}', row['hash'])
                    and type(row['height']) is int and row['height'] > 0 for row in observations),
            'Go registration outcomes differ')
    proof = read_json(directory / 'verification.json')
    require(proof['passed'] == len(PROOF_CASES) and len(proof['cases']) == len(PROOF_CASES)
            and set(proof['cases']) == PROOF_CASES, 'Go proof rejection coverage is incomplete')
    require(manifest['reconciliation'] == 'all four replicas before and after all-node SIGKILL restart',
            'Go reconciliation incomplete')
    values = [row['certified_execution_ms'] for row in observations]
    distribution = percentiles(values)
    require(math.isclose(manifest['certified_execution_p95_ms'], distribution['p95'], rel_tol=1e-9),
            'Go latency summary differs from observations')
    duration, rate = manifest['duration_seconds'], manifest['completed_per_second']
    require(positive(duration) and positive(rate) and math.isclose(rate, count / duration, rel_tol=1e-4),
            'Go rate differs from completed work')
    samples = rows(directory / 'resources.jsonl')
    pids = None
    for sample in samples:
        members = sample['processes']
        current = {member['pid'] for member in members}
        require(len(members) == len(current) == 4 and all(type(pid) is int and pid > 0 for pid in current),
                'incomplete Go member resource sample')
        require(pids is None or current == pids, 'Go resource participants changed')
        require(all(positive(member['rss_bytes']) for member in members), 'invalid Go member RSS')
        pids = current
    require(bool(samples), 'missing Go resource measurements')
    return {'duration_seconds': duration, 'completed_per_second': rate,
            'receipt_ms': distribution, 'latencies': values}


def rust_pass(directory, identity):
    read_json(directory / 'manifest.json')
    require((directory / 'workload.jsonl').stat().st_size <= 128 * 1024 * 1024, 'Rust workload exceeds bounds')
    manifest, config, summary, passed, values, series, missing, _, _ = load_run(directory)
    metadata_matches(manifest, identity, 'rust')
    require(passed and manifest['dirty'] is False and manifest['runner_dirty'] is False
            and manifest['runner_source'] == identity['rust']['source'], 'Rust fixture failed')
    for key, expected in (('count', identity['count']), ('signer_count', identity['count']),
                          ('nodes', 4), ('arrivals_per_second', identity['rate']), ('max_outstanding', 128),
                          ('permission_reads_per_write', 0), ('fixed_update_objects', 0),
                          ('preset', 'Normal'), ('runner_debug_assertions', False),
                          ('revisions_per_epoch', 192), ('receipt_poll_ms', 50),
                          ('workload', 'certified_native_registrations')):
        require(config.get(key) == expected, 'Rust logical workload differs')
    require(config.get('simplex') is not None and manifest['history'] == 'regolith', 'Rust deployment differs')
    require(config['simplex'] == {'optimistic_views': 4, 'stall_timeout_ms': 5000, 'term_length': 16}
            and config['proposal_batch_wait_ms'] == 100 and config['pruning'] == {
                'maintenance_interval': 64, 'retained_consensus_revisions': 256, 'retained_state_revisions': 0},
            'Rust consensus settings differ')
    require(missing == 0 and len(series) == 4 and all(series.values()), 'missing Rust member resources')
    observations = [row for row in rows(directory / 'workload.jsonl') if row.get('kind') == 'observation']
    require(all(row['object_id'] == str(row['index']) for row in observations), 'Rust object IDs differ')
    distribution = percentiles(values)
    require(len(values) == identity['count'] and math.isclose(
            summary['scheduled_to_certified_receipt_ms']['p95'], distribution['p95'], rel_tol=1e-9),
            'Rust latency summary differs from observations')
    rate, duration = summary['completed_workflows_per_second'], summary['elapsed_seconds']
    require(positive(rate) and positive(duration) and math.isclose(rate, identity['count'] / duration, rel_tol=1e-9),
            'Rust rate differs from completed work')
    return {'duration_seconds': duration, 'completed_per_second': rate,
            'receipt_ms': distribution, 'latencies': values}


def compare(directory):
    identity = read_json(directory / 'comparison.json')
    require(identity['format_version'] == 1 and re.fullmatch(r'[0-9a-f]{32}', identity['comparison_id'])
            and type(identity['count']) is int and 1 <= identity['count'] <= 1024
            and type(identity['rate']) is int and 1 <= identity['rate'] <= 10000
            and identity['order'] == list(TAGS), 'unsupported paired comparison')
    require(identity['architecture'] == 'x86_64' and type(identity['logical_cpus']) is int
            and identity['logical_cpus'] > 0 and re.fullmatch(r'[0-9]+', identity['github_run_id'] or '')
            and identity['github_job'], 'missing hosted runner provenance')
    require(all(re.fullmatch(r'[0-9a-f]{40}', identity[side]['source']) for side in ('go', 'rust')),
            'missing immutable source revisions')
    passes = {tag: (go_pass if tag.startswith('go') else rust_pass)(directory / tag, identity) for tag in TAGS}
    medians = {side: {metric: median(passes[tag][metric] for tag in TAGS if tag.startswith(side))
                      for metric in ('completed_per_second', 'duration_seconds')}
               for side in ('go', 'rust')}
    for side in medians:
        medians[side]['receipt_p95_ms'] = median(passes[tag]['receipt_ms']['p95']
                                               for tag in TAGS if tag.startswith(side))
    hashes = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
              for tag in TAGS for path in (directory / tag).iterdir()
              if path.name in ('manifest.json', 'observations.jsonl', 'resources.jsonl', 'workload.jsonl',
                               'verification.json', 'genesis.public.json', 'evidence.json')}
    return {'status': 'passed', 'identity': identity, 'passes': passes, 'medians': medians,
            'observed_go_over_rust_p95_ratio': medians['go']['receipt_p95_ms'] / medians['rust']['receipt_p95_ms'],
            'evidence_sha256': hashes,
            'scope': 'Two fresh passes per implementation on one host. Receipt latency includes protocol-specific '
                     'result verification; Go needs the next signed header. Different signature schemes, storage '
                     'and timing settings. Go checks all-node restart; Rust checks one recovered replica. '
                     'Go resource sampling includes driver preparation; RSS is not compared. '
                     'Short offered-load measurements, not maximum capacity, steady-state memory or WAN.'}


def render(directory, result):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, 2, figsize=(12, 4), layout='constrained')
    for tag in TAGS:
        values = sorted(result['passes'][tag]['latencies'])
        axes[0].plot(values, [(index + 1) * 100 / len(values) for index in range(len(values))], label=tag)
    axes[0].set(xlabel='Scheduled arrival to certified execution (ms)', ylabel='Measured operations (%)')
    axes[0].legend()
    axes[1].bar(TAGS, [result['passes'][tag]['completed_per_second'] for tag in TAGS])
    axes[1].set(ylabel='Completed registrations/s', title=f"Offered rate: {result['identity']['rate']}/s")
    for axis in axes:
        axis.grid(axis='y', alpha=.2)
    figure.suptitle('Go and Rust Vera · matched registration workload · one host')
    figure.savefig(directory / 'comparison.svg')
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = compare(args.directory)
    render(args.directory, result)
    (args.directory / 'report.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    table = ['| Pass | Completed/s | Receipt p50/p95/p99 (ms) |', '|---|---:|---:|']
    for tag in TAGS:
        run = result['passes'][tag]
        times = '/'.join(f"{run['receipt_ms'][key]:.2f}" for key in ('p50', 'p95', 'p99'))
        table.append(f"| {tag} | {run['completed_per_second']:.3f} | {times} |")
    (args.directory / 'report.md').write_text('# Matched Go/Rust Vera registrations\n\n'
        + '\n'.join(table) + '\n\n![Measured latency and completed work](comparison.svg)\n\n'
        + result['scope'] + '\n')


if __name__ == '__main__':
    main()
