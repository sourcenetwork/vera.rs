import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('go_fixture', Path(__file__).with_name('run.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class PortableGoFixture(unittest.TestCase):
    def test_four_node_configuration_uses_distinct_local_listeners(self):
        template = ('laddr = "tcp://0.0.0.0:26657"\n'
                    'laddr = "tcp://0.0.0.0:26656"\n'
                    'persistent_peers = "first@0.0.0.0:26656,second@0.0.0.0:26666"\n'
                    'timeout_commit = "5s"\naddr_book_strict = true\nallow_duplicate_ip = false\n')
        for index in range(4):
            with self.subTest(index=index):
                actual = fixture.configure(template, index, 200)
                self.assertIn(f'127.0.0.1:{28657 + index * 10}', actual)
                self.assertIn(f'127.0.0.1:{28656 + index * 10}', actual)
                self.assertIn('first@127.0.0.1:28656,second@127.0.0.1:28666', actual)
                self.assertIn('timeout_commit = "200ms"', actual)
                self.assertNotIn('0.0.0.0', actual)
                self.assertIn('allow_duplicate_ip = true', actual)
        self.assertEqual(fixture.configure('localhost:1317 localhost:9090', 3, 200, True),
                         '127.0.0.1:28347 127.0.0.1:28120')

    def test_changed_listener_or_commit_template_is_rejected(self):
        valid = 'tcp://0.0.0.0:26657 tcp://0.0.0.0:26656\ntimeout_commit = "5s"\n'
        for invalid in (valid.replace('26657', '30000'), valid.replace('timeout_commit', 'other'),
                        valid + 'timeout_commit = "5s"\n'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                fixture.configure(invalid, 0, 200)

    def test_advance_requires_every_replica_to_pass_the_previous_maximum(self):
        with tempfile.TemporaryDirectory() as directory:
            cluster = fixture.Fixture(Path('/unused/node'), Path(directory))
            cluster.rpc = Mock(side_effect=[{'sync_info': {'latest_block_height': str(height)}}
                                           for height in (5, 5, 6, 5, 6, 7, 7, 7, 7, 7, 7, 7)])
            with patch.object(fixture.time, 'sleep'):
                self.assertEqual(cluster.advance(), [7, 7, 7, 7])

    def test_stop_reaps_only_owned_processes_and_closes_logs(self):
        cluster = fixture.Fixture(Path('/unused/node'), Path('/unused/output'))
        running, exited, slow, log = Mock(), Mock(), Mock(), Mock()
        running.poll.return_value = None
        exited.poll.return_value = 0
        slow.poll.return_value = None
        slow.wait.side_effect = [subprocess.TimeoutExpired('node', 15), 0]
        cluster.processes = [running, exited, slow]
        cluster.logs = [log]
        cluster.stop()
        running.terminate.assert_called_once()
        exited.terminate.assert_not_called()
        slow.kill.assert_called_once()
        self.assertEqual(slow.wait.call_count, 2)
        log.close.assert_called_once()
        self.assertEqual(cluster.processes, [])

    def test_cli_failure_keeps_remote_messages_in_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cluster = fixture.Fixture(Path('/unused/node'), root)
            result = subprocess.CompletedProcess([], 1, '', 'private key material')
            with patch.object(fixture.subprocess, 'run', return_value=result), \
                    self.assertRaisesRegex(RuntimeError, '^fixture command failed; inspect private log$'):
                cluster.cli('start')
            self.assertEqual((root / 'command-error.private.log').read_text(), 'private key material')
            public = json.loads((root / 'command-error.json').read_text())
            self.assertEqual(public['stage'], 'other')
            self.assertEqual(public['kind'], 'unknown')
            self.assertNotIn('private key material', json.dumps(public))

    def test_owner_expression_failure_is_classified_without_remote_text_or_arguments(self):
        private = 'private-token=secret localhost:1234; permission cannot reference `owner` relation'
        public = fixture.cli_failure(('tx', 'acp', 'create-policy', '/private/key'), private, 1)
        self.assertEqual(public['stage'], 'create-policy')
        self.assertEqual(public['kind'], 'invalid-owner-expression')
        for value in ('secret', 'localhost', '/private', 'forbidden'):
            self.assertNotIn(value, json.dumps(public))

    def test_oversized_rpc_body_is_rejected_before_json_decoding(self):
        response = Mock()
        response.read.return_value = bytes(2 * 1024 * 1024 + 1)
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(fixture.urllib.request, 'urlopen', return_value=context), \
                patch.object(fixture.json, 'loads') as decode:
            with self.assertRaisesRegex(ValueError, 'exceeds bounds'):
                fixture.Fixture.get('http://127.0.0.1:1/status')
            decode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
