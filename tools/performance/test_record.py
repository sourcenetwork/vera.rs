"""Recorder failures retain evidence and cannot overwrite an existing run."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import record


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


    def record_with_mocked_process(self, timeout, waits, arena=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'runner'
            runner.write_bytes(b'binary fixture')
            output = root / 'result'
            command = ['record.py', '--node', str(runner), '--runner', str(runner),
                       '--history', 'rocksdb', '--output', str(output)]
            if timeout is not None:
                command += ['--timeout-seconds', str(timeout)]
            if arena is not None:
                command += ['--glibc-arena-max', arena]
            command += ['fixture-argument']
            process = Mock(pid=12345)
            process.wait.side_effect = waits
            with patch.object(sys, 'argv', command), \
                    patch('record.subprocess.check_output', side_effect=['revision', b'', 'revision', b'']), \
                    patch('record.cpu_model', return_value='fixture'), \
                    patch('record.platform.platform', return_value='fixture'), \
                    patch('record.platform.system', return_value='Linux'), \
                    patch('record.platform.libc_ver', return_value=('glibc', '2.39')), \
                    patch('record.subprocess.Popen', return_value=process) as spawn, \
                    patch('record.os.killpg') as killpg:
                with self.assertRaises(SystemExit) as result:
                    record.main()
            manifest = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(manifest['exit_code'], result.exception.code)
            child = spawn.call_args.kwargs['env']
            effective = child.get('MALLOC_ARENA_MAX')
            self.assertEqual(manifest['allocator_environment']['glibc_arena_max'],
                             None if effective is None else int(effective))
            self.assertTrue(spawn.call_args.kwargs['start_new_session'])
            self.assertEqual(spawn.call_args.args[0], [str(runner.resolve()), 'fixture-argument'])
            return manifest, process.wait.call_args_list, killpg.call_args_list

    def test_controlled_arena_selection_reaches_only_the_child(self):
        with patch.dict(os.environ, {'MALLOC_ARENA_MAX': '32'}, clear=True):
            for selected, effective in (('default', None), ('2', 2)):
                with self.subTest(selected=selected):
                    manifest, _, _ = self.record_with_mocked_process(None, [0, 0], selected)
                    self.assertEqual(manifest['allocator_environment'], {
                        'controlled': True, 'glibc_arena_max': effective,
                        'libc_name': 'glibc', 'libc_version': '2.39'})
                    self.assertEqual(os.environ['MALLOC_ARENA_MAX'], '32')

    def test_unselected_arena_environment_is_preserved_without_private_values(self):
        environment = {'MALLOC_ARENA_MAX': '8', 'PRIVATE_SETTING': 'private-secret'}
        with patch('record.platform.libc_ver', return_value=('glibc', '2.39')):
            child, metadata = record.allocator_environment(environment)
        self.assertEqual(child, environment)
        self.assertEqual(metadata['glibc_arena_max'], 8)
        self.assertFalse(metadata['controlled'])
        self.assertNotIn('private-secret', json.dumps(metadata))

    def test_controlled_selection_rejects_allocator_overrides(self):
        with patch('record.platform.system', return_value='Linux'), \
                patch('record.platform.libc_ver', return_value=('glibc', '2.39')):
            for key in ('GLIBC_TUNABLES', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'MALLOC_TRIM_THRESHOLD_'):
                for selected in ('default', '2'):
                    with self.subTest(key=key, selected=selected), self.assertRaises(ValueError) as error:
                        record.allocator_environment({key: 'private-secret'}, selected)
                    self.assertNotIn('private-secret', str(error.exception))

    def test_controlled_selection_rejects_other_libc_and_platforms(self):
        for system, libc in (('Darwin', ('', '')), ('Linux', ('musl', '1.2'))):
            with patch('record.platform.system', return_value=system), \
                    patch('record.platform.libc_ver', return_value=libc):
                with self.assertRaises(ValueError):
                    record.allocator_environment({}, '2')
                _, metadata = record.allocator_environment({})
                self.assertIsNone(metadata['glibc_arena_max'])
                self.assertFalse(metadata['controlled'])

    def test_unsupported_arena_values_are_not_exported(self):
        for raw in ('', '-1', '2.0', '01', '4294967296', 'private-secret'):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as error:
                record.allocator_environment({'MALLOC_ARENA_MAX': raw})
            self.assertEqual(str(error.exception), 'unsupported arena limit')

    def test_invalid_controlled_environment_creates_no_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            command = ['record.py', '--node', 'missing-node', '--runner', 'missing-runner',
                       '--history', 'rocksdb', '--output', str(output),
                       '--glibc-arena-max', '2', 'fixture-argument']
            with patch.object(sys, 'argv', command), \
                    patch.dict(os.environ, {'GLIBC_TUNABLES': 'private-secret'}, clear=True), \
                    patch('record.platform.system', return_value='Linux'), \
                    patch('record.platform.libc_ver', return_value=('glibc', '2.39')), \
                    patch('record.subprocess.Popen') as spawn, \
                    contextlib.redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as result:
                    record.main()
            self.assertEqual(result.exception.code, 2)
            spawn.assert_not_called()
            self.assertFalse(output.exists())
            self.assertNotIn('private-secret', error.getvalue())

    def test_default_and_configured_timeout_reach_child_wait(self):
        for configured, expected in ((None, 900), (1, 1), (1800, 1800), (86400, 86400)):
            with self.subTest(timeout=configured):
                manifest, waits, signals = self.record_with_mocked_process(configured, [0, 0])
                self.assertEqual(manifest['timeout_seconds'], expected)
                self.assertEqual(manifest['exit_code'], 0)
                self.assertEqual(waits, [call(timeout=expected), call()])
                self.assertEqual(signals, [call(12345, signal.SIGKILL)])

    def test_timeout_records_failure_and_cleans_up_process_group(self):
        for grace in (0, subprocess.TimeoutExpired('fixture', 10)):
            with self.subTest(grace_timed_out=isinstance(grace, subprocess.TimeoutExpired)):
                manifest, waits, signals = self.record_with_mocked_process(
                    1800, [subprocess.TimeoutExpired('fixture', 1800), grace, 0])
                self.assertEqual(manifest['timeout_seconds'], 1800)
                self.assertEqual(manifest['exit_code'], 124)
                self.assertEqual(waits, [call(timeout=1800), call(timeout=10), call()])
                self.assertEqual(signals, [call(12345, signal.SIGTERM), call(12345, signal.SIGKILL)])

    def test_invalid_timeout_creates_no_artifacts_or_processes(self):
        for value in ('0', '-1', '86401', '1.5', 'nan', 'inf', '9999999999999999999999999999'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output, trace = root / 'result', root / 'sync.log'
                command = ['record.py', '--node', str(root / 'missing-node'),
                           '--runner', str(root / 'missing-runner'), '--history', 'rocksdb',
                           '--output', str(output), '--sync-trace', str(trace),
                           '--timeout-seconds', value, 'fixture-argument']
                with patch.object(sys, 'argv', command), \
                        patch('record.subprocess.check_output') as git, \
                        patch('record.subprocess.Popen') as spawn, \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as result:
                        record.main()
                self.assertEqual(result.exception.code, 2)
                git.assert_not_called()
                spawn.assert_not_called()
                self.assertFalse(output.exists())
                self.assertFalse(trace.exists())


if __name__ == '__main__':
    unittest.main()
