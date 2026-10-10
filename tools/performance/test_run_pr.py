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
from protocol import KEYS, TYPES, source_schema, unavailable


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
            self.write_schema(side, 'relationship/v5/')
            subprocess.run(['git', 'add', '.'], cwd=source, check=True)
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                            'commit', '-qm', side], cwd=source, check=True)
            self.revisions[side] = subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            self.node(side, supports_listener=True)
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

    def node(self, side, supports_listener):
        help_text = 'Usage: verad validator [OPTIONS]'
        if supports_listener:
            help_text += '\n      --rpc-listener-fd <RPC_LISTENER_FD>'
        return self.executable(side, 'verad', f'''#!{sys.executable}
import sys
print({help_text!r} if sys.argv[1:] == ['validator', '--help'] else {side!r})
''')

    def write_schema(self, side, namespace):
        source = self.root / side
        (source / KEYS).parent.mkdir(parents=True, exist_ok=True)
        (source / KEYS).write_text(f'pub const RELATIONSHIP_PREFIX: &[u8] = b"{namespace}";\n')
        fields = '    pub relations: RelationGenerations,\n' if namespace != 'relationship/v3/' else ''
        record = 'pub struct PolicyRecord {\n' + fields + '}\n'
        if namespace == 'relationship/v5/':
            record += 'pub struct RelationshipRecord {\n    pub incarnation: u64,\n}\n'
        (source / TYPES).write_text(record)

    def commit_schema(self, side, namespace):
        self.write_schema(side, namespace)
        source = self.root / side
        subprocess.run(['git', 'add', '.'], cwd=source, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                        'commit', '-qm', 'schema'], cwd=source, check=True)
        self.revisions[side] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()

    def executable(self, side, name, content):
        path = self.binaries / side / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o700)
        return path

    def measure(self, workloads=8, exit_code=0):
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
        self.assertEqual(result.exception.code, exit_code)
        compare.assert_called_once_with(self.output)
        self.assertEqual(events, ['record.py'] * workloads + ['report.py'] * workloads)

    def test_one_head_driver_records_each_node_and_component_revision(self):
        self.assertFalse((self.binaries / 'base' / 'operation_baseline').exists())
        self.measure()
        identity = json.loads((self.output / 'comparison.json').read_text())
        self.assertEqual(identity['format_version'], 2)
        self.assertTrue(identity['inherit_rpc_listener'])
        runner_hash = digest(self.binaries / 'head' / 'operation_baseline')
        for tag in ('head1', 'base1', 'base2', 'head2'):
            side = tag.rstrip('12')
            self.assertTrue(identity[side]['supports_rpc_listener_fd'])
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
                                                      '192', '0', str(objects), '256', '1', '1']))
                self.assertEqual(manifest['format_version'], 2)
                for field in ('source', 'runner_source', 'node_sha256', 'runner_sha256'):
                    self.assertEqual(manifest[field], identity[side][field])
                self.assertFalse(manifest['dirty'])
                self.assertFalse(manifest['runner_dirty'])
                self.assertEqual(manifest['exit_code'], 0)
                self.assertEqual(manifest['history'], 'regolith')

    def test_older_node_disables_inheritance_for_both_sides(self):
        self.node('base', supports_listener=False)
        self.measure()
        identity = json.loads((self.output / 'comparison.json').read_text())
        self.assertTrue(identity['head']['supports_rpc_listener_fd'])
        self.assertFalse(identity['base']['supports_rpc_listener_fd'])
        self.assertFalse(identity['inherit_rpc_listener'])
        for tag in ('head1', 'base1', 'base2', 'head2'):
            for objects in (0, 32):
                destination = self.output / tag / f'objects-{objects}'
                row = json.loads((destination / 'workload.jsonl').read_text())
                manifest = json.loads((destination / 'manifest.json').read_text())
                self.assertEqual(row['arguments'][-1], '0')
                self.assertEqual(manifest['arguments'], row['arguments'])

    def test_failed_help_probe_does_not_silently_downgrade(self):
        self.executable('base', 'verad', '#!/bin/sh\nexit 7\n')
        with self.assertRaises(subprocess.CalledProcessError):
            self.measure()
        self.assertFalse((self.output / 'head1').exists())

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

    def test_incompatible_baseline_is_recorded_without_starting_its_workloads(self):
        self.commit_schema('base', 'relationship/v4/')
        self.measure(workloads=4)
        identity = json.loads((self.output / 'comparison.json').read_text())
        for tag in ('base1', 'base2'):
            self.assertTrue((self.output / tag / 'components.jsonl').exists())
            for objects in (0, 32):
                directory = self.output / tag / f'objects-{objects}'
                self.assertEqual(json.loads((directory / 'unavailable.json').read_text()), unavailable(identity, objects))
                self.assertFalse((directory / 'manifest.json').exists())
                self.assertFalse((directory / 'workload.jsonl').exists())
        for tag in ('head1', 'head2'):
            for objects in (0, 32):
                self.assertTrue((self.output / tag / f'objects-{objects}' / 'manifest.json').exists())

    def test_incompatible_base_does_not_suppress_head_process_failure(self):
        self.commit_schema('base', 'relationship/v4/')
        self.executable('head', 'operation_baseline', '#!/bin/sh\nexit 1\n')
        self.measure(workloads=4, exit_code=1)

    def test_unknown_schema_fails_before_any_pass(self):
        self.commit_schema('base', 'relationship/v6/')
        with self.assertRaisesRegex(ValueError, 'unrecognized ACP relationship'):
            self.measure()
        self.assertFalse((self.output / 'head1').exists())

    def test_namespace_and_policy_record_must_agree_at_committed_revision(self):
        self.write_schema('base', 'relationship/v3/')
        # Uncommitted bytes do not replace the schema of the recorded binary source.
        self.assertEqual(source_schema(self.root / 'base', self.revisions['base'])['policy_generations'], 'required')
        source = self.root / 'base'
        (source / TYPES).write_text('pub struct PolicyRecord {\n    pub relations: RelationGenerations,\n}\n')
        subprocess.run(['git', 'add', '.'], cwd=source, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                        'commit', '-qm', 'incoherent'], cwd=source, check=True)
        with self.assertRaisesRegex(ValueError, 'differs from its versioned'):
            source_schema(source, 'HEAD')

    def test_missing_head_driver_cannot_fall_back_to_base_driver(self):
        head_runner = self.binaries / 'head' / 'operation_baseline'
        head_runner.rename(self.binaries / 'base' / 'operation_baseline')
        with self.assertRaises(FileNotFoundError):
            self.measure()
        self.assertFalse((self.output / 'comparison.json').exists())
        self.assertFalse((self.output / 'head1').exists())


if __name__ == '__main__':
    unittest.main()
