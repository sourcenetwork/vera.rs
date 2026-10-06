#!/usr/bin/env python3
"""Run a prebuilt workload and retain source, binary, and host provenance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def cpu_model():
    if Path('/proc/cpuinfo').exists():
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                return line.split(':', 1)[1].strip()
    if platform.system() == 'Darwin':
        result = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None
    return platform.processor() or None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True, type=Path)
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--runner-source', type=Path, default=Path.cwd(),
                        help='Checkout used to build the workload runner; defaults to the node checkout.')
    parser.add_argument('--history', required=True, choices=['rocksdb', 'regolith'])
    parser.add_argument('--rust-log', default='warn,vera_storage=info')
    parser.add_argument('--sync-trace', type=Path,
                        help='Private output for Linux fsync/fdatasync tracing of the runner and its children only.')
    parser.add_argument('workload_args', nargs='+')
    args = parser.parse_args()
    node, runner = args.node.resolve(strict=True), args.runner.resolve(strict=True)
    runner_source = args.runner_source.resolve(strict=True)
    command = [str(runner), *args.workload_args]
    if args.sync_trace is not None:
        if not args.sync_trace.is_absolute():
            parser.error('--sync-trace must be an absolute private output path')
        # Reserve a new file; never replace an unrelated trace or follow an existing symlink.
        with args.sync_trace.open('x'):
            pass
        command = ['strace', '-f', '-ttt', '-T', '-yy', '-e', 'trace=fsync,fdatasync',
                   '-o', str(args.sync_trace), *command]
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {
        'format_version': 2,
        'source_binding': 'Node source is the current checkout; runner source is its declared checkout. Caller builds the recorded binaries.',
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'])),
        'runner_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=runner_source, text=True).strip(),
        'runner_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=runner_source)),
        'node_sha256': digest(node), 'runner_sha256': digest(runner),
        'history': args.history, 'arguments': args.workload_args,
        'rust_log': args.rust_log,
        'trace_span_close': os.environ.get('VERA_TRACE_SPANS') == '1',
        'platform': platform.platform(), 'architecture': platform.machine(),
        'logical_cpus': os.cpu_count(), 'cpu_model': cpu_model(), 'load_before': os.getloadavg(),
        'runner_image': os.environ.get('ImageVersion'),
        'run_url': (f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}"
                    f"/actions/runs/{os.environ.get('GITHUB_RUN_ID')}") if os.environ.get('GITHUB_RUN_ID') else None,
    }
    try:
        manifest['physical_memory_bytes'] = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    except (ValueError, OSError):
        manifest['physical_memory_bytes'] = None
    if args.sync_trace is not None:
        manifest['sync_trace'] = {'tool': 'strace', 'syscalls': ['fsync', 'fdatasync'],
                                  'scope': 'workload executable and descendants only'}
    path = args.output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    environment = dict(os.environ, VERAD_BINARY=str(node), RUST_LOG=args.rust_log)
    with (args.output / 'workload.jsonl').open('w') as output, (args.output / 'stderr.log').open('w') as error:
        process = subprocess.Popen(command, env=environment,
                                   stdout=output, stderr=error, start_new_session=True)
        try:
            exit_code = process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            exit_code = 124
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    manifest.update(exit_code=exit_code, load_after=os.getloadavg())
    if args.sync_trace is not None:
        manifest['sync_trace']['sha256'] = digest(args.sync_trace)
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    raise SystemExit(exit_code)


if __name__ == '__main__':
    main()
