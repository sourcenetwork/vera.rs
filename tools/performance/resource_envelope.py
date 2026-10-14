#!/usr/bin/env python3
"""Check sampled RSS and retained files for the two qualified sustained profiles."""
import argparse
import json
import math
from pathlib import Path

from storage_summary import rows

PROFILES = {
    'growing-90k': (90000, 0, 'certified_native_registrations'),
    'fixed-360k': (360000, 128, 'certified_native_object_updates'),
}
RSS_MIB = 1024
FILES_BYTES = 512 * 1024 * 1024


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('missing or invalid resource measurement')
    return value


def qualify(report, storage, profile):
    count, objects, workload = PROFILES[profile]
    manifest, config, summary = (report[key] for key in ('manifest', 'configuration', 'summary'))
    expected = dict(count=count, fixed_update_objects=objects, workload=workload,
                    nodes=4, arrivals_per_second=50, max_outstanding=128,
                    permission_reads_per_write=1, preset='Normal', proposal_batch_wait_ms=100,
                    revisions_per_epoch=192, runner_debug_assertions=False)
    if (report['status'] != 'passed' or manifest['exit_code'] != 0
            or manifest['history'] != 'regolith' or manifest['dirty'] is not False
            or manifest['runner_dirty'] is not False or manifest['trace_span_close'] is not False
            or any(type(config.get(key)) is not type(value) or config[key] != value
                   for key, value in expected.items())
            or config['pruning']['retained_consensus_revisions'] != 256
            or config['pruning']['retained_state_revisions'] != 0
            or summary['confirmed'] != count or summary['completed_workflows'] != count
            or report['verification']['verified'] != count or report['verification']['unresolved'] != 0
            or report['verification']['replicas'] != 4
            or report['recovery']['inspected_operations'] != count
            or report['recovery']['receipt_mismatches'] != 0 or report['recovery']['state_mismatches'] != 0):
        raise ValueError('workload does not match the qualified resource profile')
    usage = report['resource_usage']
    members = usage['members']
    if (usage['source'] != 'ps_rss_and_cpu_time' or len(members) != 4
            or [member['member'] for member in members] != list(range(4))):
        raise ValueError('incomplete member resource coverage')
    files = {}
    for record in storage:
        if record.get('kind') != 'storage' or record.get('phase') != 'after':
            continue
        node, allocated = record['node'], record['allocated_file_bytes']
        if (type(node) is not int or not 0 <= node < 4 or node in files
                or record['error'] is not None or type(allocated) is not int or allocated <= 0):
            raise ValueError('missing or ambiguous retained-file measurement')
        files[node] = allocated
    if set(files) != set(range(4)):
        raise ValueError('incomplete retained-file coverage')
    results = []
    for member in members:
        window = member['observed_window']
        peak = number(member['rss_mib']['peak'])
        duration = number(window['duration_seconds'])
        if (type(member['samples']) is not int or member['samples'] < count // 50
                or member['missing_samples'] != 0 or peak == 0
                or duration < count / 50 - 2):
            raise ValueError('incomplete sustained resource sampling')
        node = member['member']
        if peak > RSS_MIB:
            raise ValueError(f'member {node} sampled RSS {peak:g} MiB exceeds {RSS_MIB} MiB')
        if files[node] > FILES_BYTES:
            raise ValueError(f'member {node} retained files {files[node]} bytes exceed {FILES_BYTES} bytes')
        results.append(dict(member=node, samples=member['samples'], observed_seconds=duration,
                            peak_rss_mib=peak, rss_budget_unused_fraction=1 - peak / RSS_MIB,
                            retained_allocated_file_bytes=files[node],
                            file_budget_unused_fraction=1 - files[node] / FILES_BYTES))
    return dict(format_version=1, status='passed', profile=profile, source=manifest['source'],
                node_sha256=manifest['node_sha256'], runner_sha256=manifest['runner_sha256'],
                budgets=dict(sampled_rss_mib_per_member=RSS_MIB,
                             retained_allocated_file_bytes_per_member=FILES_BYTES),
                members=results,
                scope='Finite local qualification profiles. Budgets are regression thresholds, not enforced process limits or deployment sizing guarantees. RSS excludes startup and restart and can miss between-sample peaks; files are measured after the workload. Live state and durable history may grow beyond this dataset and duration.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--profile', required=True, choices=PROFILES)
    args = parser.parse_args()
    output = args.directory / 'resource-envelope.json'
    output.unlink(missing_ok=True)
    try:
        result = qualify(json.loads((args.directory / 'report.json').read_text()),
                         rows(args.directory / 'workload.jsonl'), args.profile)
    except ValueError as error:
        raise SystemExit(f'sustained resource qualification failed: {error}') from None
    except (OSError, KeyError, TypeError):
        raise SystemExit('sustained resource qualification failed') from None
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(f"{args.profile}: four validators remained within the sampled resource budgets.")


if __name__ == '__main__':
    main()
