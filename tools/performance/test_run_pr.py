"""Interleaved passes share the head driver while retaining each node's identity."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run_pr
from record import digest


class RunPrTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.binaries = self.root / 'binaries'
        self.output = self.root / 'results'
        self.revisions = {}
        for side in ('head', 'base'):
            source = self.root / side
            source.mkdir()
            (source / 'revision').write_text(side)
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            subprocess.run(['git', 'add', 'revision'], cwd=source, check=True)
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                            'commit', '-qm', side], cwd=source, check=True)
            self.revisions[side] = subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            self.executable(side, 'verad', f'#!/bin/sh\nprintf "{side}\\n"\n')
            self.executable(side, 'component_baseline', f'#!/bin/sh\nprintf \'{{"component":"{side}"}}\\n\'\n')
        self.executable('head', 'operation_baseline', f'''#!{sys.executable}
import json
import os
from pathlib import Path
import subprocess
import sys
print(json.dumps(dict(driver='head',
                      node=subprocess.check_output([os.environ['VERAD_BINARY']], text=True).strip(),
                      checkout=Path.cwd().name, arguments=sys.argv[1:])))
''')

    def executable(self, side, name, content):
        path = self.binaries / side / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o700)
        return path

    def measure(self):
        command = ['run_pr.py', '--head', str(self.root / 'head'), '--base', str(self.root / 'base'),
                   '--binaries', str(self.binaries), '--output', str(self.output), '--count', '3', '--rate', '7']
        invoke = subprocess.run
        events = []

        def run(arguments, *args, **kwargs):
            if len(arguments) > 1 and Path(arguments[1]).name in ('record.py', 'report.py'):
                events.append(Path(arguments[1]).name)
                if events[-1] == 'report.py':
                    return subprocess.CompletedProcess(arguments, 0)
            return invoke(arguments, *args, **kwargs)

        with patch.object(sys, 'argv', command), patch('run_pr.subprocess.run', side_effect=run), \
                patch('run_pr.compare', return_value=False) as compare, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                run_pr.main()
        self.assertEqual(result.exception.code, 0)
        compare.assert_called_once_with(self.output)
        self.assertEqual(events, ['record.py'] * 8 + ['report.py'] * 8)

    def test_one_head_driver_records_each_node_and_component_revision(self):
        self.assertFalse((self.binaries / 'base' / 'operation_baseline').exists())
        self.measure()
        identity = json.loads((self.output / 'comparison.json').read_text())
        self.assertEqual(identity['format_version'], 2)
        runner_hash = digest(self.binaries / 'head' / 'operation_baseline')
        for tag in ('head1', 'base1', 'base2', 'head2'):
            side = tag.rstrip('12')
            self.assertEqual(identity[side]['source'], self.revisions[side])
            self.assertEqual(identity[side]['runner_source'], self.revisions['head'])
            self.assertEqual(identity[side]['runner_sha256'], runner_hash)
            self.assertEqual(identity[side]['node_sha256'], digest(self.binaries / side / 'verad'))
            self.assertEqual(identity[side]['component_sha256'], digest(self.binaries / side / 'component_baseline'))
            component = json.loads((self.output / tag / 'components.jsonl').read_text())
            self.assertEqual(component, {'component': side})
            for objects in (0, 32):
                destination = self.output / tag / f'objects-{objects}'
                manifest = json.loads((destination / 'manifest.json').read_text())
                row = json.loads((destination / 'workload.jsonl').read_text())
                self.assertEqual(row, dict(driver='head', node=side, checkout=side,
                                           arguments=['3', '7', '128', '1', 'normal', '100',
                                                      '192', '0', str(objects), '256', '1']))
                self.assertEqual(manifest['format_version'], 2)
                for field in ('source', 'runner_source', 'node_sha256', 'runner_sha256'):
                    self.assertEqual(manifest[field], identity[side][field])
                self.assertFalse(manifest['dirty'])
                self.assertFalse(manifest['runner_dirty'])
                self.assertEqual(manifest['exit_code'], 0)

    def test_base_without_component_benchmark_keeps_workload_passes(self):
        (self.binaries / 'base' / 'component_baseline').unlink()
        self.measure()
        identity = json.loads((self.output / 'comparison.json').read_text())
        self.assertFalse(identity['base']['components'])
        self.assertNotIn('component_sha256', identity['base'])
        for tag in ('base1', 'base2'):
            self.assertFalse((self.output / tag / 'components.jsonl').exists())
            for objects in (0, 32):
                row = json.loads((self.output / tag / f'objects-{objects}' / 'workload.jsonl').read_text())
                self.assertEqual((row['driver'], row['node']), ('head', 'base'))

    def test_missing_head_driver_cannot_fall_back_to_base_driver(self):
        head_runner = self.binaries / 'head' / 'operation_baseline'
        head_runner.rename(self.binaries / 'base' / 'operation_baseline')
        with self.assertRaises(FileNotFoundError):
            self.measure()
        self.assertFalse((self.output / 'comparison.json').exists())
        self.assertFalse((self.output / 'head1').exists())


if __name__ == '__main__':
    unittest.main()
