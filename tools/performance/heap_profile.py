#!/usr/bin/env python3
"""Attribute allocations in one validator; retain only numeric and source-location evidence."""
import argparse
import collections
from decimal import Decimal
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from record import digest

COUNT = 6000
RATE = 20


def source_location(frame):
    match = re.search(r"(?:^|/)(crates/vera-[\w-]+/src/[\w/.-]+\.rs|"
                      r"commonware-[\w-]+-[0-9.]+/src/[\w/.-]+\.rs|"
                      r"(?:storage|runtime|consensus|p2p|utils|broadcast|marshal|glue)/src/[\w/.-]+\.rs):(\d+)\)", frame)
    if match and '..' not in match.group(1).split('/'):
        return '%s:%s' % match.groups()
    symbol = frame.split(' (', 1)[0]
    match = re.search(r'(?:vera_[a-z_]+|commonware_[a-z_]+|alloc|std|core|tokio|hashbrown|rocksdb)'
                      r'(?:::[a-zA-Z_][a-zA-Z_0-9]*)+', symbol)
    if not match:
        return 'unresolved'
    filename = re.search(r' \(([a-zA-Z_0-9-]+\.(?:rs|cpp|h))\)$', frame)
    return match.group() + (' (%s)' % filename.group(1) if filename else '')


def retained_sites(path):
    sites = collections.Counter()
    with path.open() as stream:
        for line in stream:
            stack, weight = line.rstrip().rsplit(' ', 1)
            amount = int(weight)
            if amount < 0:
                raise ValueError('negative allocation weight')
            locations = [source_location(frame) for frame in stack.split(';') if frame]
            owned = [location for location in locations if location.startswith(('crates/vera-', 'commonware-', 'vera_', 'commonware_'))
                     or re.match(r'^(storage|runtime|consensus|p2p|utils|broadcast|marshal|glue)/src/', location)]
            # Each allocation contributes once, at its innermost known source location.
            sites[(owned or locations or ['unresolved'])[-1]] += amount
    return sites


def heap_timeline(path):
    samples, current = [], {}
    content = path.read_text()
    units = re.findall(r'^time_unit: (\w+)$', content, re.M)
    if len(units) != 1 or units[0] not in ('s', 'ms'):
        raise ValueError('unsupported allocation timeline units')
    multiplier = 1000 if units[0] == 's' else 1
    for line in content.splitlines():
        key, separator, value = line.partition('=')
        if key == 'snapshot' and separator:
            if current:
                samples.append(current)
            current = {}
        elif key == 'time' and separator:
            milliseconds = Decimal(value) * multiplier
            if not milliseconds.is_finite() or milliseconds < 0 or milliseconds != milliseconds.to_integral_value():
                raise ValueError('invalid allocation timeline timestamp')
            current[key] = int(milliseconds)
        elif key == 'mem_heap_B' and separator:
            current[key] = int(value)
    if current:
        samples.append(current)
    if not samples or any(set(sample) != {'time', 'mem_heap_B'} or sample['mem_heap_B'] < 0 for sample in samples):
        raise ValueError('missing or invalid allocation timeline')
    if any(right['time'] < left['time'] for left, right in zip(samples, samples[1:])):
        raise ValueError('allocation timeline regressed')
    return [{'milliseconds': sample['time'], 'interval_peak_heap_bytes': sample['mem_heap_B']} for sample in samples]


def installed_tool(name):
    result = subprocess.run(['dpkg-query', '-L', 'heaptrack', 'libheaptrack'],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    paths = {Path(line) for line in result.stdout.splitlines()
             if Path(line).name == name and Path(line).is_file()}
    if len(paths) != 1:
        raise ValueError('missing or ambiguous heaptrack component')
    return paths.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', required=True, choices=('rocksdb', 'regolith'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    node = Path('target/release/verad').resolve(strict=True)
    launcher = Path('.github/scripts/profiled-verad.sh').resolve(strict=True)
    library = installed_tool('libheaptrack_preload.so')
    interpreter = installed_tool('heaptrack_interpret')
    with tempfile.TemporaryDirectory(prefix='vera-heap-', dir=os.environ['RUNNER_TEMP']) as directory:
        private = Path(directory)
        environment = dict(os.environ, VERA_PROFILE_BINARY=str(node), VERA_PROFILE_ROOT=str(private),
                           VERA_PROFILE_LIBRARY=str(library), VERA_E2E_DIR=str(private / 'nodes'), VERA_E2E_KEEP='0')
        environment.pop('LD_PRELOAD', None)
        environment.pop('DUMP_HEAPTRACK_OUTPUT', None)
        record = private / 'workload'
        with (private / 'runner.log').open('w') as log:
            result = subprocess.run(['python3', 'tools/performance/record.py', '--node', str(launcher),
                                     '--runner', 'target/release/examples/operation_baseline', '--history', args.history,
                                     '--output', str(record), '--timeout-seconds', '1200',
                                     str(COUNT), str(RATE), '128', '1', 'normal', '100', '192', '0', '128', '256', '1'],
                                    env=environment, stdout=subprocess.DEVNULL, stderr=log)
        records = {}
        with (record / 'workload.jsonl').open() as stream:
            for line in stream:
                row = json.loads(line)
                if row.get('kind') in ('summary', 'verification', 'recovery'):
                    records[row['kind']] = row
                if row.get('kind') == 'resources' and 'first_resources' not in records:
                    records['first_resources'] = row['sample']['rss_breakdown']
        manifest = json.loads((record / 'manifest.json').read_text())
        manifest['node_launcher_sha256'] = manifest.pop('node_sha256')
        manifest['node_sha256'] = digest(node)
        manifest['heap_profile'] = {'member': 3, 'tool': subprocess.check_output(['heaptrack', '--version'], text=True).strip(),
                                    'library_sha256': digest(library), 'release_debug': 'line-tables-only', 'release_strip': 'none',
                                    'instrumented': True, 'capacity_measurement': False, 'profiled_first_boot_only': True}
        manifest['source_binding'] += ' The launcher execs the hashed node; allocation instrumentation is restricted to member3 first boot.'
        workload_evidence = {'manifest': manifest, 'workload_exit_code': result.returncode,
                             'outcomes': {key: value for key, value in records.items() if key != 'first_resources'}}
        (args.output / 'workload.json').write_text(json.dumps(workload_evidence, indent=2) + '\n')
        pid = int((private / 'pid').read_text())
        if records['first_resources'][3]['pid'] != pid:
            raise ValueError('profile did not preserve the selected validator PID')
        interpreted = private / 'heap.gz'
        with (private / 'heap.raw').open('rb') as source, gzip.open(interpreted, 'wb') as destination, \
                (private / 'interpret.log').open('w') as log:
            with subprocess.Popen([str(interpreter)], stdin=source, stdout=subprocess.PIPE, stderr=log) as process:
                shutil.copyfileobj(process.stdout, destination, length=1024 * 1024)
                if process.wait():
                    raise ValueError('allocation trace interpretation failed')
        massif, stacks = private / 'heap.massif', private / 'retained.stacks'
        with (private / 'analysis.log').open('w') as log:
            subprocess.run(['heaptrack_print', str(interpreted), '--print-massif', str(massif),
                            '--print-flamegraph', str(stacks), '--flamegraph-cost-type', 'leaked',
                            '--disable-builtin-suppressions', '--disable-embedded-suppressions',
                            '--merge-backtraces', 'false', '--print-peaks', 'false', '--print-allocators', 'false',
                            '--print-temporary', 'false'], stdout=log, stderr=log, check=True)
        timeline = heap_timeline(massif)
        if timeline[-1]['milliseconds'] < COUNT / RATE * 1000:
            raise ValueError('profile ended before the required workload duration')
        sites = retained_sites(stacks)
        evidence = {'manifest': manifest, 'outcomes': {key: value for key, value in records.items() if key != 'first_resources'},
                    'timeline': timeline, 'total_retained_bytes': sum(sites.values()),
                    'retained_sites': dict(sites.most_common(50)),
                    'retained_interpretation': 'Bytes still allocated when the first process ended; these are not necessarily leaks.'}
        (args.output / 'allocations.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if result.returncode:
            raise SystemExit(result.returncode)
        summary, verification, recovery = (records[name] for name in ('summary', 'verification', 'recovery'))
        if (summary['offered'] != COUNT or summary['completed_workflows'] != COUNT or
                verification['verified'] != COUNT or verification['replicas'] != 4 or verification['unresolved'] != 0 or
                recovery['inspected_operations'] != COUNT or recovery['receipt_mismatches'] or recovery['state_mismatches']):
            raise ValueError('incomplete certified workload qualification')


if __name__ == '__main__':
    main()
