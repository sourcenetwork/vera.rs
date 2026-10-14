#!/usr/bin/env python3
"""Export bounded counts, source locations and static test names, never log contents."""
import argparse
import itertools
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_FILES = 128
TAIL_BYTES = 256 * 1024
MAX_LOCATIONS = 16
MAX_RESULTS = 32
MAX_CASES = 128
MAX_ADMISSION_SAMPLES = 16
MAX_NETEM_SAMPLES = 16
NETEM_COVERAGE = re.compile(r'netem_coverage active=(\d{1,4}) installed=(\d{1,4}) uncovered=(\d{1,4})')
ADMISSION_PROGRESS = re.compile(
    r'native_admission_progress replica=([0-3]) '
    r'nonce=(\d{1,20}|unavailable) elapsed_ms=(\d{1,7})(?: worker=([0-3]))?')
ADMISSION_STATE = re.compile(
    r'native_admission_state replica=([0-3]) worker=([0-3]) '
    r'height=(\d{1,20}|unavailable) epoch=(\d{1,20}|unavailable) '
    r'view=(\d{1,20}|unavailable) peers=(\d{1,20}|unavailable) '
    r'backfilling=(true|false|unavailable) elapsed_ms=(\d{1,7})')
MAX_RPC_FAILURES = 16
RPC_PHASES = {"initial", "survivors", "restored", "renewed-quorum",
              "admission-pages", "admission-receipts", "admission-backlog"}
RPC_KINDS = {"client-capacity", "server-capacity", "finality-unavailable",
             "rpc-internal", "rpc-rejected", "transport-timeout", "transport",
             "json", "response", "response-limit", "proof-limit", "proof-invalid",
             "finality-invalid", "client-deadline", "receipt-deadline", "other"}
RPC_FAILURE = re.compile(r"recovery_rpc_failure phase=([a-z-]{1,32}) "
                         r"kind=([a-z-]{1,32}) replica=([0-3])(?=\s|$)")
LOCATION = re.compile(r'((?:crates|bin)/[A-Za-z0-9_./-]+\.rs):(\d{1,7}):(\d{1,4})')
RESULT = re.compile(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
CASE = re.compile(r'^test (?:[A-Za-z_][A-Za-z0-9_]*::)*'
                  r'([A-Za-z_][A-Za-z0-9_]*) \.\.\. (ok|FAILED|ignored)(?=\s|,|$)')
FUNCTION = re.compile(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<|\()')


def source_inventory(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', '*.rs'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=10)
    inventory = {}
    for raw in result.stdout.split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if name.startswith(('crates/', 'bin/')):
            inventory[name] = len((root / name).read_bytes().splitlines())
    return inventory


def source_function_names(root, inventory):
    return frozenset(name for path in inventory
                     for name in FUNCTION.findall((root / path).read_text()))


def read_tail(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('test evidence input must be a regular file')
        truncated = metadata.st_size > TAIL_BYTES
        stream.seek(max(0, metadata.st_size - TAIL_BYTES))
        content = stream.read(TAIL_BYTES).decode('utf-8', errors='replace')
        if truncated:
            content = content.partition('\n')[2]
        return content, truncated


def summarize(root, inventory, function_names=frozenset()):
    evidence = {'format_version': 1, 'files_read': 0, 'files_unreadable': 0,
                'tails_truncated': 0, 'file_limit_reached': False,
                'location_limit_reached': False, 'result_limit_reached': False,
                'runner_exit_code': None, 'source_locations': [], 'test_results': [],
                'recovery_rpc_failures': [], 'recovery_rpc_failure_limit_reached': False,
                'test_cases': [], 'case_limit_reached': False,
                'admission_progress': [], 'admission_progress_limit_reached': False,
                'admission_state': [], 'admission_state_limit_reached': False,
                'netem_coverage': [], 'netem_coverage_limit_reached': False}
    exit_path = root / 'test-exit-code'
    if exit_path.exists() or exit_path.is_symlink():
        try:
            content, truncated = read_tail(exit_path)
            if truncated or not re.fullmatch(r'\d{1,3}\n?', content) or int(content) > 255:
                raise ValueError('invalid test exit code')
            evidence['runner_exit_code'] = int(content)
        except (OSError, ValueError):
            evidence['files_unreadable'] += 1

    candidates = iter([root / 'test-output.log'])
    cluster_logs = root.glob('**/logs/*.log')
    candidates = itertools.chain(candidates, cluster_logs)
    for index, path in enumerate(candidates):
        if index >= MAX_FILES:
            evidence['file_limit_reached'] = True
            break
        try:
            content, truncated = read_tail(path)
        except (OSError, ValueError):
            evidence['files_unreadable'] += 1
            continue
        evidence['files_read'] += 1
        evidence['tails_truncated'] += int(truncated)
        for raw in content.splitlines():
            if len(raw) > 16384:
                continue
            line = ANSI.sub('', raw)
            coverage = NETEM_COVERAGE.fullmatch(line) if path == root / 'test-output.log' else None
            if coverage is not None:
                active, installed, uncovered = map(int, coverage.groups())
                if 0 <= uncovered <= active <= 4096 and 1 <= installed <= 4096:
                    sample = {'active': active, 'installed': installed, 'uncovered': uncovered}
                    if sample not in evidence['netem_coverage']:
                        if len(evidence['netem_coverage']) == MAX_NETEM_SAMPLES:
                            evidence['netem_coverage_limit_reached'] = True
                        else:
                            evidence['netem_coverage'].append(sample)
            progress = ADMISSION_PROGRESS.fullmatch(line) if path == root / 'test-output.log' else None
            if progress is not None:
                replica, nonce, elapsed, worker = progress.groups()
                nonce = None if nonce == 'unavailable' else int(nonce)
                elapsed = int(elapsed)
                if (nonce is None or nonce <= (1 << 64) - 1) and elapsed <= 900000:
                    sample = {'replica': int(replica), 'native_nonce': nonce, 'elapsed_ms': elapsed}
                    if worker is not None:
                        sample['worker'] = int(worker)
                    if sample not in evidence['admission_progress']:
                        if len(evidence['admission_progress']) == MAX_ADMISSION_SAMPLES:
                            evidence['admission_progress_limit_reached'] = True
                        else:
                            evidence['admission_progress'].append(sample)
            state = ADMISSION_STATE.fullmatch(line) if path == root / 'test-output.log' else None
            if state is not None:
                replica, worker, height, epoch, view, peers, backfilling, elapsed = state.groups()
                values = [None if value == 'unavailable' else int(value)
                          for value in (height, epoch, view, peers)]
                if all(value is None or value <= (1 << 64) - 1 for value in values) and int(elapsed) <= 900000:
                    sample = dict(zip(('finalized_height', 'finalized_epoch', 'current_view', 'peer_count'), values))
                    sample.update(replica=int(replica), worker=int(worker), elapsed_ms=int(elapsed),
                                  backfilling=None if backfilling == 'unavailable' else backfilling == 'true')
                    if sample not in evidence['admission_state']:
                        if len(evidence['admission_state']) == MAX_ADMISSION_SAMPLES:
                            evidence['admission_state_limit_reached'] = True
                        else:
                            evidence['admission_state'].append(sample)
            # Export only source-whitelisted leaf names from the runner output.
            # Module prefixes and ignored-test reasons may contain private data.
            case = CASE.match(line) if path == root / 'test-output.log' else None
            if case is not None and case[1] in function_names:
                if len(evidence['test_cases']) == MAX_CASES:
                    evidence['case_limit_reached'] = True
                else:
                    evidence['test_cases'].append({'name': case[1], 'status': case[2]})
            for match in LOCATION.finditer(line):
                name, row, column = match.groups()
                row, column = int(row), int(column)
                if name not in inventory or not 1 <= row <= inventory[name] or column < 1:
                    continue
                location = {'file': name, 'line': row, 'column': column}
                if location in evidence['source_locations']:
                    continue
                if len(evidence['source_locations']) == MAX_LOCATIONS:
                    evidence['location_limit_reached'] = True
                else:
                    evidence['source_locations'].append(location)
            for match in RPC_FAILURE.finditer(line):
                phase, kind, replica = match.groups()
                if phase not in RPC_PHASES or kind not in RPC_KINDS:
                    continue
                failure = {'phase': phase, 'kind': kind, 'replica': int(replica)}
                if failure in evidence['recovery_rpc_failures']:
                    continue
                if len(evidence['recovery_rpc_failures']) == MAX_RPC_FAILURES:
                    evidence['recovery_rpc_failure_limit_reached'] = True
                else:
                    evidence['recovery_rpc_failures'].append(failure)
            for match in RESULT.finditer(line):
                outcome, passed, failed, ignored = match.groups()
                counts = [int(passed), int(failed), int(ignored)]
                if any(count > 100000 for count in counts):
                    continue
                if len(evidence['test_results']) == MAX_RESULTS:
                    evidence['result_limit_reached'] = True
                else:
                    evidence['test_results'].append({'passed': counts[0], 'failed': counts[1],
                                                     'ignored': counts[2], 'success': outcome == 'ok'})
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        inventory = source_inventory(Path.cwd())
        evidence = summarize(args.logs, inventory, source_function_names(Path.cwd(), inventory))
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True,
                                           stderr=subprocess.DEVNULL, timeout=10).strip()
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('invalid source revision')
        evidence['source_revision'] = revision
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + '\n')
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Unable to collect bounded test evidence') from None


if __name__ == '__main__':
    main()
