#!/usr/bin/env python3
"""Run a private four-validator Go registration fixture using prebuilt binaries."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import threading
import time
import urllib.request


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def configure(text, index, commit_ms, application=False):
    if application:
        return text.replace('localhost:1317', f'127.0.0.1:{28317 + index * 10}').replace(
            'localhost:9090', f'127.0.0.1:{28090 + index * 10}')
    for before, after in (
            ('tcp://0.0.0.0:26657', f'tcp://127.0.0.1:{28657 + index * 10}'),
            ('tcp://0.0.0.0:26656', f'tcp://127.0.0.1:{28656 + index * 10}')):
        if text.count(before) != 1:
            raise ValueError('unexpected fixture listener template')
        text = text.replace(before, after)
    text = text.replace('localhost:6060', f'127.0.0.1:{28659 + index * 10}')
    text = text.replace('addr_book_strict = true', 'addr_book_strict = false')
    text = text.replace('allow_duplicate_ip = false', 'allow_duplicate_ip = true')
    text = re.sub(r'@0.0.0.0:(266\d\d)', lambda match:
                  '@127.0.0.1:' + str(int(match[1]) + 2000), text)
    text, count = re.subn(r'^timeout_commit = "[^"\n]+"$',
                         f'timeout_commit = "{commit_ms}ms"', text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError('unexpected fixture commit-timeout template')
    return text


def cli_failure(arguments, stderr, code):
    stage = {('testnet', 'init-files'): 'initialize', ('keys', 'add'): 'worker-key',
             ('genesis', 'add-genesis-account'): 'fund-worker', ('tx', 'acp'): 'create-policy'}.get(
                 tuple(arguments[:2]), 'other')
    kind = 'unknown'
    lowered = stderr.lower()
    for label, fragments in (
            ('invalid-owner-expression', ('permission cannot reference `owner` relation',)),
            ('rpc-unavailable', ('connection refused', 'code = unavailable')),
            ('insufficient-funds', ('insufficient funds',)),
            ('cli-usage', ('unknown flag', 'unknown command')),
            ('deadline', ('deadline exceeded',))):
        if any(fragment in lowered for fragment in fragments):
            kind = label
            break
    return {'format_version': 1, 'stage': stage, 'kind': kind, 'exit_code': code,
            'stderr_bytes': len(stderr.encode())}


class Fixture:
    def __init__(self, binary, output):
        self.binary, self.output = binary, output
        self.network = output / 'network'
        self.processes, self.logs = [], []

    def cli(self, *arguments):
        result = subprocess.run([str(self.binary), *map(str, arguments)],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            (self.output / 'command-error.private.log').write_text(result.stderr)
            (self.output / 'command-error.json').write_text(json.dumps(
                cli_failure(arguments, result.stderr, result.returncode), indent=2) + '\n')
            raise RuntimeError('fixture command failed; inspect private log')
        return result.stdout

    def start(self):
        if self.processes:
            raise RuntimeError('fixture is already running')
        for index in range(4):
            log = (self.output / f'node{index}.private.log').open('ab')
            self.logs.append(log)
            self.processes.append(subprocess.Popen(
                [str(self.binary), 'start', '--home', str(self.network / f'node{index}/verad'),
                 '--log_level', 'warn', '--log_no_color'], stdout=log,
                stderr=subprocess.STDOUT))

    def stop(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in self.logs:
            log.close()
        self.processes.clear()
        self.logs.clear()

    def wait_for(self, check, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in self.processes):
                raise RuntimeError('validator exited; inspect private logs')
            try:
                result = check()
                if result:
                    return result
            except (OSError, RuntimeError):
                pass
            time.sleep(.2)
        raise TimeoutError('fixture check deadline')

    @staticmethod
    def get(url):
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError('fixture response exceeds bounds')
        return json.loads(body)

    def rpc(self, index, query):
        body = self.get(f'http://127.0.0.1:{28657 + index * 10}/{query}')
        if 'error' in body:
            raise RuntimeError('fixture RPC error')
        return body['result']

    def advance(self):
        def heights():
            return [int(self.rpc(index, 'status')['sync_info']['latest_block_height'])
                    for index in range(4)]
        initial = max(self.wait_for(heights))
        def advanced():
            current = heights()
            return current if min(current) > initial else None
        return self.wait_for(advanced)


def reconcile(fixture, rows, policy):
    for index in range(4):
        for row in rows:
            transaction = fixture.rpc(index, f"tx?hash=0x{row['hash']}&prove=true")
            if int(transaction['tx_result']['code']) != 0 or int(transaction['height']) != row['height']:
                raise ValueError('replica execution differs')
            owner = fixture.get(f'http://127.0.0.1:{28317 + index * 10}/sourcenetwork/vera/acp/'
                                f"object_owner/{policy}/file/{row['object']}")
            record = owner['record']
            if (not owner['is_registered'] or record['archived'] or record['policy_id'] != policy
                    or record['metadata']['owner_did'] != row['owner']
                    or record['relationship']['subject']['actor']['id'] != row['owner']):
                raise ValueError('replica owner differs')


def run(args):
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.source_root, text=True).strip()
    if source != args.source or subprocess.check_output(
            ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=args.source_root):
        raise ValueError('Go checkout differs from selected clean source')
    fixture = Fixture(args.node.resolve(strict=True), args.output.resolve())
    manifest = {'format_version': 1, 'source': source, 'status': 'incomplete',
                'node_sha256': digest(args.node), 'driver_sha256': digest(args.driver),
                'orchestrator_sha256': digest(Path(__file__)),
                'history': 'goleveldb', 'nodes': 4, 'count': args.count,
                'arrivals_per_second': args.rate, 'max_outstanding': args.outstanding,
                'worker_accounts': args.workers, 'permission_reads_per_write': 0,
                'commit_timeout_ms': args.commit_ms,
                'platform': platform.platform(), 'architecture': platform.machine(),
                'logical_cpus': os.cpu_count(), 'runner_image': os.environ.get('ImageVersion'),
                'comparison_id': os.environ.get('VERA_COMPARISON_ID'),
                'github_run_id': os.environ.get('GITHUB_RUN_ID'),
                'github_job': os.environ.get('GITHUB_JOB'),
                'go_version': subprocess.check_output(['go', 'version'], text=True).strip(),
                'driver_source_hashes': {path.name: digest(path) for path in Path(__file__).parent.glob('*.go')},
                'load_before': os.getloadavg(),
                'proof_contract': 'genesis-anchored inclusion and next-header committed execution results',
                'state_query_trust': 'replica RPC consistency; no authenticated owner-state claim'}
    stop = threading.Event()
    sampler = None
    sampling_errors = []
    try:
        fixture.cli('testnet', 'init-files', '--v', 4, '--output-dir', fixture.network,
                    '--chain-id', 'vera-comparison', '--keyring-backend', 'test', '--home', args.output / 'cli')
        for index in range(args.workers):
            key = json.loads(fixture.cli('keys', 'add', f'worker{index}', '--home', fixture.network / 'workers',
                                         '--keyring-backend', 'test', '--output', 'json'))
            fixture.cli('genesis', 'add-genesis-account', key['address'], '1000000000ucredit',
                        '--home', fixture.network / 'node0/verad')
        genesis = (fixture.network / 'node0/verad/config/genesis.json').read_bytes()
        for index in range(4):
            directory = fixture.network / f'node{index}/verad/config'
            (directory / 'genesis.json').write_bytes(genesis)
            for name in ('config.toml', 'app.toml'):
                path = directory / name
                path.write_text(configure(path.read_text(), index, args.commit_ms, name == 'app.toml'))
        manifest['config_hashes'] = {str(path.relative_to(fixture.network)): digest(path)
                                     for path in fixture.network.glob('node*/verad/config/*')
                                     if path.name in ('genesis.json', 'config.toml', 'app.toml')}
        fixture.start()
        fixture.advance()
        policy_path = args.output / 'policy.yaml'
        policy_path.write_text('name: baseline\nresources:\n  - name: file\n    permissions:\n'
                               '      - name: read\n        expr: ""\n')
        created = json.loads(fixture.cli('tx', 'acp', 'create-policy', 'YAML', policy_path,
                             '--home', fixture.network / 'node0/verad', '--from', 'node0',
                             '--keyring-backend', 'test', '--chain-id', 'vera-comparison',
                             '--node', 'tcp://127.0.0.1:28657', '--gas', 'auto', '--gas-adjustment', '1.5',
                             '--gas-prices', '0.01ucredit', '--yes', '--output', 'json'))
        if int(created['code']):
            raise ValueError('fixture policy rejected')
        receipt = fixture.wait_for(lambda: fixture.rpc(0, f"tx?hash=0x{created['txhash']}&prove=true"))
        if int(receipt['tx_result']['code']):
            raise ValueError('fixture policy reverted')
        policy = next(json.loads(attribute['value']) for event in receipt['tx_result']['events']
                      if event['type'].endswith('EventPolicyCreated') for attribute in event['attributes']
                      if attribute['key'] == 'policy_id')
        command = [str(args.driver.resolve()), '-network', str(fixture.network), '-policy', policy,
                   '-count', str(args.count), '-rate', str(args.rate), '-outstanding', str(args.outstanding),
                   '-workers', str(args.workers), '-deadline', '30s',
                   '-verification-evidence', str(args.output.resolve() / 'evidence.json')]
        def sample():
            try:
                with (args.output / 'resources.jsonl').open('w') as output:
                    while not stop.is_set():
                        result = subprocess.run(['ps', '-o', 'pid=,rss=,%cpu=', '-p',
                                                 ','.join(str(process.pid) for process in fixture.processes)],
                                                capture_output=True, text=True, timeout=10)
                        rows = []
                        for line in result.stdout.splitlines():
                            pid, rss, cpu = line.split()
                            rows.append({'pid': int(pid), 'rss_bytes': int(rss) * 1024,
                                         'cpu_percent_ps': float(cpu)})
                        if result.returncode or {row['pid'] for row in rows} != {
                                process.pid for process in fixture.processes}:
                            raise ValueError('incomplete member resource sample')
                        output.write(json.dumps({'at': time.time(), 'processes': rows}) + '\n')
                        output.flush()
                        stop.wait(1)
            except Exception as error:
                sampling_errors.append(type(error).__name__)
        sampler = threading.Thread(target=sample)
        sampler.start()
        with (args.output / 'observations.jsonl').open('w') as output, \
                (args.output / 'stderr.private.log').open('w') as error:
            process = subprocess.Popen(command, stdout=output, stderr=error)
            try:
                code = process.wait(timeout=args.count / args.rate + 180)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
        stop.set()
        sampler.join()
        if sampling_errors:
            raise ValueError('member resource collection failed')
        rows = [json.loads(line) for line in (args.output / 'observations.jsonl').read_text().splitlines()]
        if (code or len(rows) != args.count or {row['index'] for row in rows} != set(range(args.count))
                or len({row['owner'] for row in rows}) != args.workers
                or any(row['status'] != 'completed' or row['object'] != str(row['index'])
                       or not math.isfinite(row['certified_execution_ms'])
                       or row['certified_execution_ms'] < 0 for row in rows)):
            raise ValueError('registration workload failed')
        summary = re.findall(r'^offered=(\d+) completed=(\d+) failed=(\d+) duration_seconds=([0-9.]+) '
                             r'completed_per_second=([0-9.]+)$',
                             (args.output / 'stderr.private.log').read_text(), flags=re.MULTILINE)
        if len(summary) != 1 or tuple(map(int, summary[0][:3])) != (args.count, args.count, 0):
            raise ValueError('driver summary differs from raw observations')
        manifest['duration_seconds'], manifest['completed_per_second'] = map(float, summary[0][3:])
        reconcile(fixture, rows, policy)
        for process in fixture.processes:
            process.kill()
        fixture.stop()
        fixture.start()
        fixture.advance()
        reconcile(fixture, rows, policy)
        (args.output / 'genesis.public.json').write_bytes(genesis)
        latencies = sorted(row['certified_execution_ms'] for row in rows)
        manifest.update(status='passed', completed=len(rows), certified_execution_p95_ms=
                        latencies[math.ceil(len(rows) * .95) - 1],
                        reconciliation='all four replicas before and after all-node SIGKILL restart',
                        load_after=os.getloadavg())
    except BaseException as error:
        manifest.update(status='failed', error_class=type(error).__name__)
        raise
    finally:
        stop.set()
        if sampler is not None:
            sampler.join()
        fixture.stop()
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('node', 'driver', 'source-root', 'output'):
        parser.add_argument('--' + argument, required=True, type=Path)
    parser.add_argument('--source', required=True)
    for name, default in (('count', 600), ('rate', 20), ('outstanding', 128), ('workers', 600), ('commit-ms', 200)):
        parser.add_argument('--' + name, type=int, default=default)
    args = parser.parse_args()
    if (not re.fullmatch(r'[0-9a-f]{40}', args.source) or not 1 <= args.count <= 100000
            or not 1 <= args.rate <= 10000 or not 1 <= args.outstanding <= 1024
            or not 1 <= args.workers <= min(args.count, 1024) or not 1 <= args.commit_ms <= 60000):
        parser.error('invalid source or bounded workload parameters')
    run(args)


if __name__ == '__main__':
    main()
