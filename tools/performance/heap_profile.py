#!/usr/bin/env python3
"""Attribute allocations in one validator; retain only numeric and source-location evidence."""
import argparse
import collections
from decimal import Decimal
from functools import lru_cache
import gzip
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from record import allocator_environment, digest

def profile_workload(selection):
    if selection == 'startup':
        return 6000, 20, 1200, None
    if selection == 'sustained':
        return 90000, 50, 7200, '2'
    raise ValueError('unsupported allocation profile selection')


def qualify_outcomes(records, count):
    summary, verification, recovery = (records[name] for name in ('summary', 'verification', 'recovery'))
    if (summary['offered'] != count or summary['completed_workflows'] != count or
            verification['verified'] != count or verification['replicas'] != 4 or verification['unresolved'] != 0 or
            recovery['inspected_operations'] != count or recovery['receipt_mismatches'] or recovery['state_mismatches']):
        raise ValueError('incomplete certified workload qualification')


def profile_settings(environment):
    expected = {'CARGO_PROFILE_RELEASE_DEBUG': 'full',
                'CARGO_PROFILE_RELEASE_STRIP': 'none',
                'RUSTFLAGS': '-C force-frame-pointers=yes'}
    if ('CARGO_ENCODED_RUSTFLAGS' in environment or
            any(environment.get(key) != value for key, value in expected.items())):
        raise ValueError('unsupported allocation build settings')
    return {'release_debug': 'full', 'release_strip': 'none',
            'rustflags': expected['RUSTFLAGS']}


def component_site(location):
    return (location.startswith(('crates/vera-', 'commonware-', 'vera_', 'commonware_')) or
            re.match(r'^(storage|runtime|consensus|p2p|utils|broadcast|marshal|glue)/src/', location))


def attribution_class(location):
    if component_site(location):
        return 'vera_commonware_caller'
    if location == 'unresolved':
        return 'unresolved'
    if location.startswith(('std::alloc::', 'std::sys::alloc::', 'alloc::')):
        return 'allocator_only'
    return 'library_caller'


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


def unresolved_format(frames):
    symbols = [frame.split(' (', 1)[0] for frame in frames]
    if not symbols:
        return 'missing_stack'
    if any(symbol.startswith(('_R', '_ZN')) for symbol in symbols):
        return 'mangled_symbols'
    if all(symbol == '??' or re.fullmatch(r'0x[0-9a-fA-F]+', symbol) for symbol in symbols):
        return 'missing_symbols'
    return 'unrecognized_symbols'


def retained_sites(path, unresolved=None, attribution=None):
    sites = collections.Counter()
    with path.open() as stream:
        for line in stream:
            stack, weight = line.rstrip().rsplit(' ', 1)
            amount = int(weight)
            if amount < 0:
                raise ValueError('negative allocation weight')
            frames = [frame for frame in stack.split(';') if frame]
            locations = [source_location(frame) for frame in frames]
            owned = [location for location in locations if component_site(location)]
            # Each allocation contributes once, at its innermost known source location.
            known = [location for location in locations if location != 'unresolved']
            site = (owned or known or ['unresolved'])[-1]
            sites[site] += amount
            if attribution is not None:
                attribution[attribution_class(site)] += amount
            if site == 'unresolved' and unresolved is not None:
                unresolved[unresolved_format(frames)] += amount
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


def rust_demangler():
    command = ['c++filt', '--format=rust', '--no-strip-underscore', '--no-verbose']
    probe = subprocess.run(command, input='_RNvC6_123foo3bar\n', text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=10)
    if probe.stdout != '123foo::bar\n':
        raise ValueError('allocation decoder cannot resolve Rust v0 symbols')
    version = subprocess.check_output(['c++filt', '--version'], text=True, timeout=10).splitlines()[0]
    return command, version


def demangle_stacks(source, destination, command):
    deadline = time.monotonic() + 120
    symbols = {}
    symbol_bytes = 0
    mangled = re.compile(r'(?:_R|_ZN)[a-zA-Z_0-9]+(?:\.[a-zA-Z_0-9]+)*')

    @lru_cache(maxsize=4096)
    def frame_symbol(frame):
        symbol = frame.partition(' (')[0]
        return symbol if mangled.fullmatch(symbol) else None
    with source.open() as raw:
        for line in raw:
            if time.monotonic() >= deadline:
                raise ValueError('allocation symbol decoding exceeded its deadline')
            stack, _ = line.rstrip().rsplit(' ', 1)
            for frame in stack.split(';'):
                symbol = frame_symbol(frame)
                if symbol is not None and symbol not in symbols:
                    symbol_bytes += len(symbol)
                    if len(symbol) > 65536 or len(symbols) >= 65536 or symbol_bytes > 16 * 1024 * 1024:
                        raise ValueError('allocation symbol inventory exceeds decoding budget')
                    symbols[symbol] = None

    # Give each bounded phase its own budget; scans must not consume decoder time.
    deadline = time.monotonic() + 120
    # Shared frames recur across many allocation stacks; decode each symbol once.
    pending = iter(symbols)
    while batch := list(itertools.islice(pending, 256)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('allocation symbol decoding exceeded its deadline')
        result = subprocess.run(command, input='\n'.join(batch) + '\n', text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=True, timeout=remaining)
        decoded = result.stdout.splitlines()
        if len(decoded) != len(batch) or any(not symbol for symbol in decoded):
            raise ValueError('allocation decoder changed the symbol count')
        # Rust array types can contain semicolons, which delimit flamegraph frames.
        symbols.update((symbol, value.replace(';', r'\x3b')) for symbol, value in zip(batch, decoded))

    frame_symbol.cache_clear()

    @lru_cache(maxsize=4096)
    def decode_frame(frame):
        symbol = frame.partition(' (')[0]
        value = symbols.get(symbol)
        return value + frame[len(symbol):] if value is not None else frame

    deadline = time.monotonic() + 120
    with source.open() as raw, destination.open('w') as decoded:
        for line in raw:
            if time.monotonic() >= deadline:
                raise ValueError('allocation symbol decoding exceeded its deadline')
            stack, separator, weight = line.rpartition(' ')
            decoded.write(';'.join(map(decode_frame, stack.split(';'))) + separator + weight)


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
    parser.add_argument('--profile', choices=('startup', 'sustained'), default='startup')
    args = parser.parse_args()
    build = profile_settings(os.environ)
    count, rate, timeout, arena = profile_workload(args.profile)
    environment, allocator = allocator_environment(os.environ, arena)
    arena_arguments = [] if arena is None else ['--glibc-arena-max', arena]
    args.output.mkdir(parents=True, exist_ok=False)
    node = Path('target/release/verad').resolve(strict=True)
    launcher = Path('.github/scripts/profiled-verad.sh').resolve(strict=True)
    library = installed_tool('libheaptrack_preload.so')
    interpreter = installed_tool('heaptrack_interpret')
    demangler, demangler_version = rust_demangler()
    with tempfile.TemporaryDirectory(prefix='vera-heap-', dir=os.environ['RUNNER_TEMP']) as directory:
        private = Path(directory)
        environment.update(VERA_PROFILE_BINARY=str(node), VERA_PROFILE_ROOT=str(private),
                           VERA_PROFILE_LIBRARY=str(library), VERA_E2E_DIR=str(private / 'nodes'), VERA_E2E_KEEP='0')
        environment.pop('LD_PRELOAD', None)
        environment.pop('DUMP_HEAPTRACK_OUTPUT', None)
        record = private / 'workload'
        with (private / 'runner.log').open('w') as log:
            result = subprocess.run(['python3', 'tools/performance/record.py', '--node', str(launcher),
                                     '--runner', 'target/release/examples/operation_baseline', '--history', args.history,
                                     '--output', str(record), '--timeout-seconds', str(timeout), *arena_arguments,
                                     str(count), str(rate), '128', '1', 'normal', '100', '192', '0', '128', '256', '1'],
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
                                    'library_sha256': digest(library), **build,
                                    'instrumented': True, 'capacity_measurement': False, 'profiled_first_boot_only': True, 'rust_demangler': demangler_version,
                                    'selection': args.profile, 'operations': count, 'offered_per_second': rate,
                                    'controlled_allocator_environment': allocator}
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
        if timeline[-1]['milliseconds'] < count / rate * 1000:
            raise ValueError('profile ended before the required workload duration')
        original_sites = retained_sites(stacks)
        decoded = private / 'retained.rust.stacks'
        demangle_stacks(stacks, decoded, demangler)
        unresolved = collections.Counter()
        attribution = collections.Counter()
        sites = retained_sites(decoded, unresolved, attribution)
        if sum(original_sites.values()) != sum(sites.values()):
            raise ValueError('symbol decoding changed allocation accounting')
        if sum(attribution.values()) != sum(sites.values()):
            raise ValueError('allocation attribution changed accounting')
        evidence = {'manifest': manifest, 'outcomes': {key: value for key, value in records.items() if key != 'first_resources'},
                    'timeline': timeline, 'total_retained_bytes': sum(sites.values()),
                    'retained_sites': dict(sites.most_common(50)),
                    'attribution_bytes': {kind: attribution[kind] for kind in
                                          ('vera_commonware_caller', 'library_caller', 'allocator_only', 'unresolved')},
                    'symbolization': {'unresolved_before_bytes': original_sites['unresolved'],
                                      'unresolved_after_bytes': sites['unresolved'],
                                      'unresolved_stack_formats': dict(unresolved)},
                    'retained_interpretation': 'Bytes still allocated when the first process ended; these are not necessarily leaks.'}
        (args.output / 'allocations.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if result.returncode:
            raise SystemExit(result.returncode)
        qualify_outcomes(records, count)


if __name__ == '__main__':
    main()
