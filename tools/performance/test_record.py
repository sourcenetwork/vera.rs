"""Recorder failures retain evidence and cannot overwrite an existing run."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class RecorderTests(unittest.TestCase):
    def checkout(self, path):
        path.mkdir()
        subprocess.run(['git', 'init', '-q', str(path)], check=True)
        (path / 'source.txt').write_text(path.name)
        subprocess.run(['git', '-C', str(path), 'add', 'source.txt'], check=True)
        subprocess.run(['git', '-C', str(path), '-c', 'user.name=fixture',
                        '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Create fixture'], check=True)
        return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()

    def test_node_and_runner_checkouts_are_attributed_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node_source, runner_source = root / 'node-source', root / 'runner-source'
            node_revision, runner_revision = self.checkout(node_source), self.checkout(runner_source)
            self.assertNotEqual(node_revision, runner_revision)
            runner = root / 'workload'
            runner.write_text('#!/bin/sh\nexit 0\n')
            runner.chmod(0o700)
            node = root / 'node'
            node.write_text('node binary fixture')
            for dirty in (False, True):
                if dirty:
                    (runner_source / 'source.txt').write_text('modified')
                output = root / ('dirty' if dirty else 'clean')
                command = [sys.executable, str(Path(__file__).resolve().with_name('record.py')),
                           '--node', str(node), '--runner', str(runner), '--runner-source', str(runner_source),
                           '--history', 'rocksdb', '--output', str(output), '1']
                result = subprocess.run(command, cwd=node_source, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads((output / 'manifest.json').read_text())
                self.assertEqual(metadata['format_version'], 2)
                self.assertEqual(metadata['source'], node_revision)
                self.assertFalse(metadata['dirty'])
                self.assertEqual(metadata['runner_source'], runner_revision)
                self.assertEqual(metadata['runner_dirty'], dirty)
                self.assertNotEqual(metadata['node_sha256'], metadata['runner_sha256'])

    def test_sync_trace_wraps_only_runner_and_preserves_its_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'source'
            revision = self.checkout(checkout)
            runner = root / 'runner'
            runner.write_text('#!/bin/sh\nprintf "workload evidence\\n"\nexit 7\n')
            runner.chmod(0o700)
            tracer = root / 'strace'
            tracer.write_text(
                '#!/usr/bin/env python3\n'
                'import pathlib, subprocess, sys\n'
                'args = sys.argv[1:]\n'
                'assert args[:6] == ["-f", "-ttt", "-T", "-yy", "-e", "trace=fsync,fdatasync"]\n'
                'assert args[6] == "-o"\n'
                'pathlib.Path(args[7]).write_text("private syscall trace")\n'
                'assert pathlib.Path(args[8]).name == "runner"\n'
                'assert args[9:] == ["fixture-argument"]\n'
                'raise SystemExit(subprocess.run(args[8:]).returncode)\n')
            tracer.chmod(0o700)
            trace = root / 'sync.log'
            output = root / 'result'
            command = [sys.executable, str(Path(__file__).resolve().with_name('record.py')),
                       '--node', str(runner), '--runner', str(runner), '--history', 'rocksdb',
                       '--output', str(output), '--sync-trace', str(trace), 'fixture-argument']
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
            result = subprocess.run(command, cwd=checkout, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            manifest = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(manifest['source'], revision)
            self.assertEqual(manifest['exit_code'], 7)
            self.assertEqual(manifest['sync_trace']['sha256'],
                             hashlib.sha256(b'private syscall trace').hexdigest())
            self.assertEqual(manifest['sync_trace']['syscalls'], ['fsync', 'fdatasync'])
            self.assertNotIn(str(trace), json.dumps(manifest))
            self.assertEqual((output / 'workload.jsonl').read_text(), 'workload evidence\n')
            self.assertFalse((output / 'sync.log').exists())

    def test_failure_retains_exit_status_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'runner'
            runner.write_text('#!/bin/sh\nprintf "partial measurement\\n"\nprintf "%s" "$RUST_LOG" >&2\nexit 7\n')
            runner.chmod(0o700)
            output = root / 'result'
            checkout = Path(__file__).resolve().parents[2]
            command = [sys.executable, str(Path(__file__).resolve().with_name('record.py')),
                       '--node', str(runner), '--runner', str(runner),
                       '--history', 'rocksdb', '--output', str(output),
                       '--rust-log', 'warn,vera_diagnostics=debug', '1']
            result = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            metadata = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(metadata['exit_code'], 7)
            self.assertEqual(metadata['runner_source'], metadata['source'])
            self.assertEqual(metadata['runner_dirty'], metadata['dirty'])
            self.assertEqual(metadata['rust_log'], 'warn,vera_diagnostics=debug')
            self.assertEqual((output / 'stderr.log').read_text(), metadata['rust_log'])
            self.assertEqual((output / 'workload.jsonl').read_text(), 'partial measurement\n')
            repeated = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(json.loads((output / 'manifest.json').read_text()), metadata)


if __name__ == '__main__':
    unittest.main()
