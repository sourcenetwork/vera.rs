#!/usr/bin/env python3
"""Summarize private storage traces without copying log text or filesystem paths."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import re


PARTITIONS = ('accounts', 'storage', 'code', 'acp', 'bulletin', 'identity', 'native_sequences', 'commitment')
UNITS = {'ns': 1e-6, 'µs': .001, 'us': .001, 'ms': 1, 's': 1000}
TIMES = re.compile(r'time\.(busy|idle)=(\d+(?:\.\d+)?)(ns|µs|us|ms|s)(?=\s|$)')
APPLIED = re.compile(r'vera_publication_diagnostics: finalized state apply height=(\d+)\b')
STARTED = re.compile(r'vera_publication_diagnostics: finalized state synchronization started height=Some\((\d+)\)')
STRACE_LINE = re.compile(r'^\s*(?:\[pid\s+)?(\d+)\]?\s+\d+(?:\.\d+)?\s+(.*)$')
CALL = re.compile(r'^(fsync|fdatasync)\(\d+(?:<([^>]+)>)?\)\s+=\s+(-?\d+|\?)(?=\s).* <(\d+(?:\.\d+)?)>$')
RESUMED = re.compile(r'^<\.\.\. (fsync|fdatasync) resumed>(.*)$')

# These fixed labels mirror the existing events, not span-close lifetimes.
PUBLICATION_EVENTS = {
    'finalized state apply': ('apply', ('database_apply_us', 'publication_us')),
    'finalized state synchronization started': ('synchronization_started', ('sync_start_us',)),
    'finalized state durability completed': ('durability_completed', ('wait_us', 'since_finalize_us')),
    'finalized revision publication': ('revision_published', ('lookup_us', 'history_us', 'index_us')),
    'finalized sink completed': ('sink_completed', ('total_us',)),
}


def publication_event(line):
    """Read one target only: vera_diagnostics emits duplicate events when enabled."""
    marker = 'vera_publication_diagnostics: '
    if marker not in line:
        return None
    body = line.split(marker, 1)[1].strip()
    for message, (event, names) in PUBLICATION_EVENTS.items():
        if body != message and not body.startswith(message + ' '):
            continue
        fields = body[len(message):]

        def field(name):
            matches = re.findall(r'(?:^|\s)' + name + r'=(\S*)', fields)
            if len(matches) != 1:
                raise ValueError('publication event has missing or duplicate fields')
            return matches[0]

        height = field('height')
        optional = event in ('synchronization_started', 'durability_completed')
        unknown_height = optional and height == 'None'
        if optional and not unknown_height:
            if not height.startswith('Some(') or not height.endswith(')'):
                raise ValueError('publication event has invalid height')
            height = height[5:-1]
        if not unknown_height and (not re.fullmatch(r'[0-9]{1,20}', height)
                                   or int(height) > (1 << 64) - 1):
            raise ValueError('publication event has invalid height')
        outcome = 'observed'
        if event == 'durability_completed':
            durable = field('durable')
            if durable not in ('true', 'false'):
                raise ValueError('publication event has invalid durability outcome')
            outcome = 'durable' if durable == 'true' else 'not_durable'
        values = {}
        for name in names:
            value = field(name)
            # Rust emits elapsed microseconds as u128; reject units, floats,
            # nonfinite values and oversized tokens without echoing private logs.
            if not re.fullmatch(r'[0-9]{1,39}', value) or int(value) > (1 << 128) - 1:
                raise ValueError('publication event has invalid duration')
            values[name] = int(value) / 1000
        return event, outcome, unknown_height, values
    return None


def inside(path, root):
    """Resolve symlinks and reject both lexical and resolved escapes."""
    path = Path(path)
    if '..' in path.parts or not path.is_absolute():
        raise ValueError('trace path is not within the expected run root')
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        raise ValueError('trace path is not within the expected run root') from None
    return resolved


def distribution(values):
    values = sorted(values)
    if not values:
        return {'count': 0}
    return {'count': len(values), 'p50_ms': values[math.ceil(len(values) * .50) - 1],
            'p95_ms': values[math.ceil(len(values) * .95) - 1],
            'p99_ms': values[math.ceil(len(values) * .99) - 1], 'max_ms': values[-1]}


def closed_span(line):
    """Match the emitting span, not a parent printed in a nested close event."""
    match = None
    if ': commonware_utils::sync: close ' in line:
        prefix = line.split(': commonware_utils::sync: close ', 1)[0]
        match = re.search(r'utils\.rwlock\.(read|write)\{lock="stateful\.db\.([0-7])"\}$', prefix)
        operation = match.group(1) if match else None
        index = int(match.group(2)) if match else None
    elif ': commonware_glue::stateful::db: close ' in line:
        prefix = line.split(': commonware_glue::stateful::db: close ', 1)[0]
        match = re.search(r'stateful\.db\.finalize\{index=([0-7])\}$', prefix)
        operation, index = 'finalize', int(match.group(1)) if match else None
    elif ': commonware_storage::qmdb::any::db: close ' in line:
        prefix = line.split(': commonware_storage::qmdb::any::db: close ', 1)[0]
        match = re.search(r'stateful\.db\.finalize\{index=([0-7])\}:.*qmdb\.any\.db\.start_sync\{[^{}]*\}$', prefix)
        operation, index = 'start_sync', int(match.group(1)) if match else None
    if not match:
        return None
    return operation, index, *span_duration(line)


def span_duration(line):
    times = TIMES.findall(line)
    if len(times) != 2 or {kind for kind, _, _ in times} != {'busy', 'idle'}:
        raise ValueError('recognized span has invalid duration fields')
    milliseconds = {kind: float(value) * UNITS[unit] for kind, value, unit in times}
    if not all(math.isfinite(value) for value in milliseconds.values()):
        raise ValueError('recognized span has nonfinite duration')
    return milliseconds['busy'], milliseconds['idle']


def closed_blob_span(line):
    marker = ': commonware_runtime::storage::metered: close '
    if marker not in line:
        return None
    prefix = line.split(marker, 1)[0]
    match = re.search(r'runtime\.storage\.blob\.(write_at|start_sync|sync)(?:\{[^{}]*\})?$', prefix)
    if not match:
        return None
    return match.group(1), *span_duration(line)


def durations(values):
    return {'elapsed': distribution([busy + idle for busy, idle in values]),
            'busy': distribution([busy for busy, _ in values]),
            'idle': distribution([idle for _, idle in values])}


def span_summary(lines):
    groups, blobs = defaultdict(list), defaultdict(list)
    publication_groups = defaultdict(list)
    event_counts = {event: 0 for event, _ in PUBLICATION_EVENTS.values()}
    durability_outcomes = {'durable': 0, 'not_durable': 0}
    unknown_height_events = 0
    height, pending = None, []
    complete, discarded, outside, incomplete_finalize = 0, 0, 0, 0
    for line in lines:
        publication = publication_event(line)
        if publication:
            event, outcome, unknown_height, values = publication
            event_counts[event] += 1
            unknown_height_events += int(unknown_height)
            if event == 'durability_completed':
                durability_outcomes[outcome] += 1
            for field, value in values.items():
                publication_groups[event, field, outcome].append(value)
        blob = closed_blob_span(line)
        if blob:
            operation, busy, idle = blob
            blobs[operation].append((busy, idle))
        applied = APPLIED.search(line)
        if applied:
            discarded += int(height is not None)
            height, pending = int(applied.group(1)), []
        started = STARTED.search(line)
        if started:
            if height == int(started.group(1)):
                complete += 1
                finalized = {index for operation, index, _, _ in pending
                             if operation == 'finalize' and index < 7}
                incomplete_finalize += int(len(finalized) != 7)
                for operation, index, busy, idle in pending:
                    groups[operation, index].append((busy, idle))
            else:
                discarded += int(height is not None)
            height, pending = None, []
        span = closed_span(line)
        if span:
            if height is not None:
                pending.append(span)
            else:
                outside += 1
    discarded += int(height is not None)
    rows = []
    for (operation, index), values in sorted(groups.items()):
        rows.append({'operation': operation, 'partition': PARTITIONS[index], 'index': index,
                     **durations(values)})
    return {'completed_finalization_windows': complete, 'discarded_windows': discarded,
            'spans_outside_windows': outside,
            'persistent_finalize_window_samples': sum(len(values) for (operation, index), values
                                                      in groups.items() if operation == 'finalize' and index < 7),
            'incomplete_persistent_finalize_windows': incomplete_finalize,
            'persistent_finalize_window_coverage_complete': complete > 0 and incomplete_finalize == 0,
            'groups': rows,
            'publication_event_counts': event_counts,
            'publication_unknown_height_events': unknown_height_events,
            'durability_outcomes': durability_outcomes,
            'publication_groups': [
                {'event': event, 'field': field, 'outcome': outcome, **distribution(values)}
                for (event, field, outcome), values in sorted(publication_groups.items())],
            'blob_groups': [{'operation': operation, **durations(values)}
                            for operation, values in sorted(blobs.items())]}


def syscall_location(annotation, run_root):
    if annotation is None:
        return None
    # strace marks unlinked, still-open descriptors this way. Never echo its annotation.
    name = annotation.removesuffix(' (deleted)')
    path = inside(Path(name), run_root)
    relative = path.relative_to(run_root.resolve()).parts
    if len(relative) >= 3 and relative[0] == 'clusters' and re.fullmatch(r'node[0-3]', relative[2]):
        return int(relative[2][-1])
    # Durable fixture creation can sync the private root or cluster directories.
    return None


def syscall_summary(lines, run_root):
    pending, groups = {}, defaultdict(list)
    failed, interrupted, unattributed = 0, 0, 0
    for line in lines:
        envelope = STRACE_LINE.match(line.rstrip())
        if not envelope:
            if re.search(r'\b(?:fsync|fdatasync)\(', line) or RESUMED.search(line):
                raise ValueError('unrecognized syscall trace format')
            continue
        pid, body = envelope.groups()
        resumed = RESUMED.match(body)
        if resumed:
            previous = pending.pop(pid, None)
            if previous is None or not previous.startswith(resumed.group(1) + '('):
                raise ValueError('resumed syscall has no matching unfinished call')
            suffix = resumed.group(2).lstrip()
            # Depending on when strace decoded the descriptor, its path can
            # appear on the resumed side; do not drop that annotation.
            before = re.search(r'<([^>]+)>$', previous)
            after = re.match(r'<([^>]+)>', suffix)
            if before and after:
                if before.group(1) != after.group(1):
                    raise ValueError('resumed syscall descriptor changed')
                suffix = suffix[after.end():]
            body = previous + suffix
        elif not re.match(r'^(fsync|fdatasync)\(', body):
            continue
        if body.endswith('<unfinished ...>'):
            if pid in pending:
                raise ValueError('multiple unfinished calls for one trace thread')
            pending[pid] = body.removesuffix('<unfinished ...>').rstrip()
            continue
        call = CALL.fullmatch(body)
        if not call:
            raise ValueError('sync syscall has no complete result and duration')
        syscall, annotation, result, seconds = call.groups()
        node = syscall_location(annotation, run_root)
        elapsed = float(seconds) * 1000
        if not math.isfinite(elapsed):
            raise ValueError('sync syscall has nonfinite duration')
        outcome = 'interrupted' if result == '?' else ('success' if result == '0' else 'error')
        failed += int(outcome == 'error')
        interrupted += int(outcome == 'interrupted')
        unattributed += int(node is None)
        groups[node, syscall, outcome].append(elapsed)
    # Interrupted calls are not successful observations. Validate their paths too.
    for body in pending.values():
        annotation = re.search(r'^\w+\(\d+<([^>]+)>', body)
        if annotation:
            syscall_location(annotation.group(1), run_root)
    rows = [{'node': node, 'syscall': syscall, 'outcome': outcome, **distribution(values)}
            for (node, syscall, outcome), values in sorted(groups.items(), key=lambda item: str(item[0]))]
    return {'groups': rows, 'failed_calls': failed, 'interrupted_calls': interrupted, 'unfinished_calls': len(pending),
            'unattributed_calls': unattributed}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def summarize_run(run_root, publication_only=False):
    root = run_root.resolve(strict=True)
    logs = sorted((root / 'clusters').glob('*/node[0-3]/logs/stdout.log'))
    nodes, hashes = [], {}
    for path in logs:
        node = int(path.parent.parent.name[-1])
        if any(row['node'] == node for row in nodes):
            raise ValueError('expected exactly one cluster in the run root')
        path = inside(path, root)
        with path.open() as source:
            lines = (line for line in source if 'vera_publication_diagnostics: ' in line) if publication_only else source
            summary = span_summary(lines)
        if publication_only:
            if not all(summary['publication_event_counts'].values()):
                raise ValueError('expected all publication lifecycle events on every node')
            for field in ('groups', 'blob_groups', 'spans_outside_windows',
                          'persistent_finalize_window_samples', 'incomplete_persistent_finalize_windows',
                          'persistent_finalize_window_coverage_complete'):
                summary[field] = None
        nodes.append({'node': node, **summary})
        hashes[f'node{node}_stdout'] = digest(path)
    if len(nodes) != 4 or any(not node['completed_finalization_windows'] for node in nodes):
        raise ValueError('expected completed finalization windows on all four nodes')
    syscalls = None
    if not publication_only:
        calls = inside(root / 'syscalls.log', root)
        with calls.open() as source:
            syscalls = syscall_summary(source, root)
        if not syscalls['groups']:
            raise ValueError('no completed durability syscalls were captured')
        hashes['syscalls'] = digest(calls)
    result = {
        'format_version': 2,
        'scope': 'Normal is an uninstrumented comparator only. Traced timings include scheduling, tracing and ptrace overhead; neither run establishes capacity or a baseline improvement.',
        'span_scope': 'Close events are grouped only inside complete apply-to-synchronization-start windows at a matching revision; bootstrap and incomplete windows excluded. Concurrent users and retained child spans prevent exact revision attribution. Coverage reports windows missing any of seven persistent-partition finalize closes; missing samples are not zero-duration work. Finalize and start_sync overlap; do not add them or subtract their percentiles.',
        'duration_scope': 'Read/write spans end at acquisition. Finalize starts after acquisition, but enabled completion spans retain finalize/start_sync ancestors beyond function return and potentially beyond the originating window. Their close lifetimes do not measure guard holding or initiation alone. The actor completes the previous finalization barrier before starting another. Syscalls cover the whole run, including startup and restart, without revision or partition attribution.',
        'blob_scope': 'Blob groups cover the whole run, including bootstrap and restart, without partition or revision attribution. Write_at includes the awaited write and scheduling. Start_sync close lifetime includes retention by its sync child and does not isolate initiation. Sync measures synchronous sync calls or observation of a returned completion handle, potentially including time before first polling. These overlapping populations do not isolate prior-sync waits or physical I/O; do not add their durations or subtract their percentiles.',
        'publication_scope': 'Only vera_publication_diagnostics events are counted. Scalar timings cover the whole run, including restart, independently of span windows. Preparation ends when finalize returns its barrier; wait starts at barrier polling; since-finalize includes intervening work before polling. Sink history includes blocking-pool scheduling and persistence. Durability false means not durable, not successful storage completion. Missing event groups are unavailable, not zero work. Fields overlap and are not additive or physical disk latency.',
        'nodes': nodes, 'syscalls': syscalls, 'private_input_sha256': hashes,
    }
    if publication_only:
        result['summary_scope'] = 'publication_only'
        result['scope'] = 'Publication event summary only. This scope does not establish collection settings or overhead; consult the recording manifest. It establishes neither capacity nor a baseline improvement.'
        result['span_scope'] = 'Unavailable in this summary scope; span events are excluded, not measured as zero. Their absence does not establish that tracing was disabled.'
        result['duration_scope'] = 'Syscall evidence is unavailable in this summary scope. Publication scalar durations include scheduling and overlapping work, not isolated physical I/O.'
        result['blob_scope'] = 'Unavailable in this summary scope; blob span events are excluded.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publication-only', action='store_true',
                        help='Summarize lifecycle events on all four nodes; syscall and span evidence stays unavailable.')
    args = parser.parse_args()
    try:
        summary = summarize_run(args.run_root, publication_only=args.publication_only)
        with args.output.open('x') as output:
            json.dump(summary, output, indent=2, allow_nan=False)
            output.write('\n')
    except (OSError, ValueError):
        # Input paths and log content are private, including in errors.
        parser.exit(1, 'Storage attribution failed: invalid, incomplete or inaccessible trace input/output.\n')


if __name__ == '__main__':
    main()
