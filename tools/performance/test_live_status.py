"""Failure boundaries for local observations; never contact external endpoints."""
import json
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import unittest
from unittest.mock import patch

import live_status as live


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.status = dict(chainId=7, uptimeSecs=20, finalizedHeight=1, peerCount=None)
        self.failure = False
        self.light = dict(height=1, block_hash='0x' + 'a'*64, timestamp=1000)
        self.config = dict(environment='same-host', members=[dict(id='node1', chain_id=7,
                           rpc='http://private.invalid/secret')])
        self.collector = live.Collector(self.config, 'config-hash', call=self.call,
                                        clock=lambda: self.now, wall=lambda: 1000+self.now)

    def call(self, url, method, params, timeout):
        if self.failure:
            raise ValueError('private endpoint secret')
        if method == 'eth_chainId':
            return hex(self.status['chainId'])
        return dict(self.status) if method == 'vera_nodeStatus' else dict(self.light)

    def poll(self):
        self.collector.poll_all()
        return self.collector.snapshot()['members'][0]

    def test_missing_connected_stale_disconnected_reconnect(self):
        self.assertEqual(self.collector.snapshot()['members'][0]['state'], 'missing')
        row = self.poll()
        self.assertEqual(row['state'], 'connected')
        self.assertEqual(row['last']['authentication'], 'unverified')
        self.assertIsNone(row['last']['peer_count'])
        self.now += 16
        self.assertEqual(self.collector.snapshot()['members'][0]['state'], 'stale')
        self.failure = True
        row = self.poll()
        self.assertEqual(row['state'], 'disconnected')
        self.assertEqual(row['last']['revision'], 1)
        self.assertNotIn('secret', json.dumps(self.collector.snapshot()))
        self.failure = False
        self.assertEqual(self.poll()['state'], 'connected')

    def test_gap_restart_regression_and_stalled_progress(self):
        self.poll()
        self.now += 2
        self.status['finalizedHeight'] = 2
        self.assertEqual(self.poll()['revisions'][-1]['interval_seconds'], 2)
        self.now += 2
        self.status['finalizedHeight'] = 5
        self.assertIsNone(self.poll()['revisions'][-1]['interval_seconds'])
        self.now += 70
        row = self.poll()
        self.assertEqual(row['revisions'], [])
        self.assertEqual(row['progress_age_seconds'], 70)
        self.status['finalizedHeight'] = 3
        self.assertEqual(self.poll()['state'], 'disconnected')
        self.status['uptimeSecs'] = 1
        row = self.poll()
        self.assertEqual(row['state'], 'connected')
        self.assertEqual(row['restarts'], 1)
        self.assertEqual(len(row['revisions']), 1)

    def test_delayed_response_and_clock_skew(self):
        original = self.call
        def delayed(*args):
            self.now += 20
            return original(*args)
        self.collector.call = delayed
        self.assertEqual(self.poll()['state'], 'disconnected')
        self.assertIsNone(self.collector.snapshot()['members'][0]['last'])
        self.collector.call = original
        self.collector.wall = lambda: -100000
        self.assertEqual(self.poll()['state'], 'connected')
        self.now += 3
        self.status['finalizedHeight'] = 2
        self.assertEqual(self.poll()['revisions'][-1]['interval_seconds'], 3)

    def test_invalid_status_never_published(self):
        for key, value in [('chainId', 8), ('finalizedHeight', -1), ('uptimeSecs', True),
                           ('peerCount', float('nan'))]:
            old = self.status[key]
            self.status[key] = value
            self.assertEqual(self.poll()['state'], 'disconnected')
            self.status[key] = old
        self.assertIsNone(self.collector.snapshot()['members'][0]['last'])

    def test_verified_evidence_and_bad_evidence_no_fallback(self):
        with tempfile.NamedTemporaryFile() as verifier:
            self.config['trusted_key'] = 'a'*192
            self.collector = live.Collector(self.config, 'hash', verifier.name, call=self.call,
                verify=lambda *args: dict(self.light), clock=lambda: self.now, wall=lambda: 1100)
            row = self.poll()
            self.assertIn('verified finality', row['last']['authentication'])
            self.assertEqual(row['last']['block_clock_offset_seconds'], 100)
            self.light['height'] = 2
            row = self.poll()
            self.assertEqual(row['state'], 'disconnected')
            self.assertEqual(row['last']['verified']['height'], 1)
            self.light['height'] = 1
            self.collector.verify = lambda *args: (_ for _ in ()).throw(ValueError('bad signature'))
            self.assertEqual(self.poll()['state'], 'disconnected')

    def test_replay_exports_only_allowlisted_fields(self):
        data = dict(status='failed', input_sha256={'workload.jsonl': 'hash'}, duration=10,
                    summary=dict(elapsed_seconds=10, completed_workflows=5,
                                 scheduled_to_certified_receipt_ms=dict(p95=12),
                                 permission_read_ms=dict(p95=4), scheduled_to_workflow_ms=dict(p95=20),
                                 secret='private endpoint'))
        with patch.object(live, 'build_replay', return_value=data):
            result = live.benchmark(Path('.'))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['metrics']['completed_workflows_per_second'], .5)
        self.assertEqual(result['metrics']['permission_read_ms']['p95'], 4)
        self.assertNotIn('secret', json.dumps(result))

    def test_configuration_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'private.json'
            path.write_text(json.dumps(self.config))
            config, identity = live.load_config(path)
            self.assertEqual(config, self.config)
            self.assertEqual(len(identity), 64)
            self.config['members'][0]['rpc'] = 'http://user:password@localhost/'
            path.write_text(json.dumps(self.config))
            with self.assertRaises(ValueError):
                live.load_config(path)

    def test_local_rpc_and_browser_api(self):
        status = dict(self.status)
        status.pop('chainId')  # Real nodeStatus does not include chain ID.
        class RPC(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                result = '0x7' if request['method'] == 'eth_chainId' else status
                body = json.dumps(dict(jsonrpc='2.0', id=request['id'], result=result)).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        def serve(server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), RPC)
        serve(upstream)
        self.config['members'][0]['rpc'] = f'http://127.0.0.1:{upstream.server_port}/private'
        self.collector.call = live.rpc
        self.assertEqual(self.poll()['state'], 'connected')
        view = ThreadingHTTPServer(('127.0.0.1', 0), live.handler(self.collector))
        serve(view)
        base = f'http://127.0.0.1:{view.server_port}'
        for path in ('/', '/app.js', '/style.css', '/api/status'):
            with urlopen(base+path) as response:
                self.assertEqual(response.status, 200)
                self.assertIn("default-src 'self'", response.headers['Content-Security-Policy'])
                self.assertNotIn(b'/private', response.read())
        for path in ('/../live_status.py', '/api/status?endpoint=private'):
            with self.assertRaises(HTTPError) as error:
                urlopen(base+path)
            self.assertEqual(error.exception.code, 404)
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(base+'/', headers={'Host': 'outside.invalid'}))
        self.assertEqual(error.exception.code, 403)

    def test_ui_has_no_html_interpolation_or_fake_activity(self):
        script = live.ASSETS.joinpath('app.js').read_text()
        self.assertNotIn('innerHTML', script)
        self.assertNotIn('Math.random', script)
        self.assertIn('collector disconnected', script)


if __name__ == '__main__':
    unittest.main()
