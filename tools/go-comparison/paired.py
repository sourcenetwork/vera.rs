#!/usr/bin/env python3
"""Run fresh interleaved Go/Rust fixtures sequentially on one hosted runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import uuid

from compare import PROOF_CASES, TAGS


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def proof_cases(log):
    names = re.findall(r'--- PASS: TestCertifiedExecution/([A-Za-z0-9_]+) \([0-9.]+s\)', log)
    if len(names) != len(PROOF_CASES) or set(names) != PROOF_CASES:
        raise ValueError('Go proof rejection coverage is incomplete')
    return names


def command(arguments, root, environment, log, timeout):
    with log.open('xb') as output:
        process = subprocess.Popen(arguments, cwd=root, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        if code:
            raise subprocess.CalledProcessError(code, arguments)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go-node', 'go-driver', 'go-root', 'rust-node', 'rust-runner', 'output', 'public-output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--go-source', required=True)
    parser.add_argument('--count', type=int, default=600)
    parser.add_argument('--rate', type=int, default=20)
    args = parser.parse_args()
    if (not re.fullmatch(r'[0-9a-f]{40}', args.go_source) or not 1 <= args.count <= 1024
            or not 1 <= args.rate <= 10000):
        parser.error('invalid reference source or bounded workload')
    root = Path(__file__).resolve().parents[2]
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    environment = dict(os.environ, VERA_COMPARISON_ID=uuid.uuid4().hex, VERA_E2E_KEEP='0')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    identity = {'format_version': 1, 'comparison_id': environment['VERA_COMPARISON_ID'],
                'count': args.count, 'rate': args.rate, 'order': list(TAGS),
                'platform': platform.platform(), 'architecture': platform.machine(),
                'logical_cpus': os.cpu_count(), 'runner_image': os.environ.get('ImageVersion'),
                'github_run_id': os.environ.get('GITHUB_RUN_ID'), 'github_job': os.environ.get('GITHUB_JOB'),
                'go': {'source': args.go_source, 'node_sha256': digest(args.go_node),
                       'driver_sha256': digest(args.go_driver)},
                'rust': {'source': source, 'node_sha256': digest(args.rust_node),
                         'runner_sha256': digest(args.rust_runner)}}
    (args.output / 'comparison.json').write_text(json.dumps(identity, indent=2) + '\n')
    for tag in TAGS:
        destination = args.output / tag
        log = args.output / (tag + '.private.log')
        if tag.startswith('go'):
            command([sys.executable, str(root / 'tools/go-comparison/run.py'),
                     '--source-root', str(args.go_root.resolve()), '--source', args.go_source,
                     '--node', str(args.go_node.resolve()), '--driver', str(args.go_driver.resolve()),
                     '--output', str(destination), '--count', str(args.count),
                     '--workers', str(args.count), '--rate', str(args.rate)],
                    root, environment, log, 1800)
            verify_environment = dict(environment, VERA_GO_EVIDENCE=str(destination),
                                      VERA_GO_GENESIS=str(destination / 'genesis.public.json'))
            verify_log = args.output / (tag + '-verification.private.log')
            command(['go', 'test', '-mod=readonly', '-p', '2', './comparison-driver',
                     '-run', '^TestCertifiedExecution$', '-count=1', '-v'],
                    args.go_root, verify_environment, verify_log, 300)
            names = proof_cases(verify_log.read_text())
            (destination / 'verification.json').write_text(json.dumps({
                'passed': len(names), 'cases': names, 'log_sha256': digest(verify_log)}, indent=2) + '\n')
        else:
            command([sys.executable, str(root / 'tools/performance/record.py'),
                     '--node', str(args.rust_node.resolve()), '--runner', str(args.rust_runner.resolve()),
                     '--history', 'regolith', '--output', str(destination),
                     str(args.count), str(args.rate), '128', '0', 'normal', '100', '192', '0', '0', '256', '1'],
                    root, environment, log, 960)
    command([sys.executable, str(root / 'tools/go-comparison/compare.py'), str(args.output)],
            root, environment, args.output / 'comparison.private.log', 120)
    args.public_output.mkdir(parents=True, exist_ok=False)
    for name in ('comparison.json', 'report.json', 'report.md', 'comparison.svg'):
        shutil.copyfile(args.output / name, args.public_output / name)
    for tag in TAGS:
        public = args.public_output / tag
        public.mkdir()
        names = ('manifest.json', 'observations.jsonl', 'resources.jsonl', 'genesis.public.json',
                 'evidence.json', 'verification.json') if tag.startswith('go') else ('manifest.json', 'workload.jsonl')
        for name in names:
            shutil.copyfile(args.output / tag / name, public / name)


if __name__ == '__main__':
    main()
