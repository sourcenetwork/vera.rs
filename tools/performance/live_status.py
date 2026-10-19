#!/usr/bin/env python3
"""Local-only, read-only Vera observations. No deployment, signing or endpoint discovery."""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import re
import subprocess
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from replay import build_replay

LIMIT = 72 * 1024 * 1024  # Covers the current ~70 MiB light-block response budget.
ASSETS = Path(__file__).with_name('live')


def finite(value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < minimum:
        raise ValueError('invalid number')
    return value


def uint(value):
    finite(value)
    if not isinstance(value, int) or value > 2**64 - 1:
        raise ValueError('invalid integer')
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_config(path):
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('configuration too large')
    cfg = json.loads(raw)
    if cfg.get('environment') not in ('same-host', 'wan', 'unknown'):
        raise ValueError('environment must be same-host, wan or unknown (operator declaration)')
    if not isinstance(cfg.get('members'), list) or not 1 <= len(cfg['members']) <= 64:
        raise ValueError('configure 1 to 64 members')
    ids = set()
    for member in cfg['members']:
        name = member['id']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', name) or name in ids:
            raise ValueError('member IDs must be unique public-safe labels')
        ids.add(name)
        url = urlsplit(member['rpc'])
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError('RPC requires HTTP(S), without embedded credentials or fragment')
        uint(member['chain_id'])
    key = cfg.get('trusted_key')
    if key is not None and (not isinstance(key, str) or not re.fullmatch(r'(0x)?[0-9a-fA-F]{192}', key)):
        raise ValueError('trusted_key must be an operator-provisioned 96-byte consensus public key')
    return cfg, digest(raw)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('RPC redirects refused')


def rpc(url, method, params, timeout):
    body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()
    # Ignore ambient proxy settings; never send operator endpoints through an implicit proxy.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(url, body, {'Content-Type': 'application/json'}), timeout=timeout) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('RPC response too large')
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get('jsonrpc') != '2.0' or data.get('id') != 1 or 'error' in data:
        raise ValueError('invalid RPC response')
    return data['result']


def verify_light(executable, trusted_key, light, timeout):
    result = subprocess.run([str(executable)], input=json.dumps(dict(trusted_key=trusted_key, light=light)),
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=True)
    if len(result.stdout) > 4096:
        raise ValueError('invalid verifier response')
    verified = json.loads(result.stdout)
    if verified != {key: light[key] for key in ('height', 'block_hash', 'timestamp')}:
        raise ValueError('verifier output does not bind the requested header')
    return verified


class Collector:
    def __init__(self, config, config_hash, verifier=None, stale=15, window=60, timeout=3,
                 call=rpc, verify=verify_light, clock=time.monotonic, wall=time.time):
        self.config, self.config_hash, self.verifier = config, config_hash, verifier
        self.stale, self.window, self.timeout = stale, window, timeout
        self.call, self.verify, self.clock, self.wall = call, verify, clock, wall
        self.started = clock()
        self.source_hash = digest(Path(__file__).read_bytes() + b''.join(p.read_bytes() for p in sorted(ASSETS.iterdir())))
        self.verifier_hash = digest(Path(verifier).read_bytes()) if verifier else None
        self.lock = threading.Lock()
        self.members = {m['id']: dict(state='missing', last=None, success=None, attempt=None,
                                    error=None, history=deque(maxlen=4096), restarts=0,
                                    revision=None, uptime=None, progress=None) for m in config['members']}

    def poll(self, member):
        name = member['id']
        with self.lock:
            self.members[name]['attempt'] = self.wall()
        began = self.clock()
        try:
            chain = self.call(member['rpc'], 'eth_chainId', [], self.timeout)
            if not isinstance(chain, str) or not re.fullmatch(r'0x[0-9a-fA-F]+', chain) or uint(int(chain, 16)) != member['chain_id']:
                raise ValueError('wrong deployment')
            status = self.call(member['rpc'], 'vera_nodeStatus', [], self.timeout)
            if not isinstance(status, dict):
                raise ValueError('wrong deployment')
            height = status.get('finalizedHeight')
            if height is not None:
                uint(height)
            uptime = uint(status['uptimeSecs'])
            peer = status.get('peerCount')
            if peer is not None:
                uint(peer)
            authenticated = None
            auth = 'unverified'
            if height is not None and self.config.get('trusted_key') and self.verifier:
                light = self.call(member['rpc'], 'vera_getLightBlock', [hex(height)], self.timeout)
                if uint(light['height']) != height:
                    raise ValueError('wrong revision')
                authenticated = self.verify(self.verifier, self.config['trusted_key'], light, self.timeout)
                uint(authenticated['timestamp'])
                if not re.fullmatch(r'0x[0-9a-fA-F]{64}', authenticated['block_hash']):
                    raise ValueError('invalid hash')
                auth = 'verified finality (not freshness or member identity)'
            now = self.clock()
            if now - began > self.stale:
                raise ValueError('delayed response')
            observed = self.wall()
            with self.lock:
                row = self.members[name]
                restart = row['uptime'] is not None and uptime < row['uptime']
                if restart:
                    row['restarts'] += 1
                    row['history'].clear()
                    row['revision'] = None
                    row['progress'] = None
                if height is not None and row['revision'] is not None and height < row['revision']:
                    raise ValueError('regressed revision without restart')
                if height is not None and height != row['revision']:
                    previous = row['history'][-1] if row['history'] else None
                    interval = now - previous['at'] if previous and height == previous['height'] + 1 else None
                    # Polling can skip revisions: never call a gap one revision interval.
                    row['progress'] = now
                    row['history'].append(dict(at=now, height=height, interval_seconds=interval))
                while row['history'] and row['history'][0]['at'] < now - self.window:
                    row['history'].popleft()
                row.update(state='connected', success=now, error=None, revision=height, uptime=uptime,
                           last=dict(observed_at=observed, revision=height, authentication=auth,
                                     verified=authenticated, peer_count=peer, uptime_seconds=uptime,
                                     clock_policy='collector monotonic intervals; no cross-clock latency',
                                     block_clock_offset_seconds=(observed - authenticated['timestamp'])
                                     if authenticated else None))
        except Exception:
            # Exceptions and RPC payloads can contain credentials/private addresses. Never publish them.
            with self.lock:
                self.members[name].update(state='disconnected', error='observation failed')

    def poll_all(self):
        with ThreadPoolExecutor(max_workers=min(8, len(self.config['members']))) as pool:
            list(pool.map(self.poll, self.config['members']))

    def snapshot(self):
        now = self.clock()
        with self.lock:
            members = []
            for name, row in self.members.items():
                age = now - row['success'] if row['success'] is not None else None
                state = row['state']
                if state == 'connected' and age > self.stale:
                    state = 'stale'
                history = [dict(height=h['height'], seconds_ago=now-h['at'],
                                interval_seconds=h['interval_seconds']) for h in row['history']
                           if now - h['at'] <= self.window]
                members.append(dict(id=name, state=state, last=row['last'], age_seconds=age,
                                    attempted_at=row['attempt'], error=row['error'], restarts=row['restarts'],
                                    progress_age_seconds=now-row['progress'] if row['progress'] is not None else None,
                                    revisions=history))
        return dict(mode='live observations', environment=self.config['environment'],
                    environment_authority='operator declaration, not WAN qualification',
                    configuration_sha256=self.config_hash, source_sha256=self.source_hash,
                    verifier_sha256=self.verifier_hash,
                    trust_sha256=digest(self.config['trusted_key'].encode()) if self.config.get('trusted_key') else None,
                    generated_at=self.wall(), session_seconds=now-self.started,
                    window_seconds=self.window, members=members,
                    quorum='unknown: RPC reachability does not establish voting quorum',
                    client_measurements=None)


def benchmark(directory):
    """Reuse authoritative replay gates; export only allowlisted numbers/hashes, never raw provenance."""
    data = build_replay(directory)
    result = dict(mode='benchmark replay', status=data['status'], input_sha256=data['input_sha256'],
                  environment='unknown; benchmark does not establish WAN placement',
                  window_seconds=data['duration'], metrics=None)
    if data['status'] == 'unavailable':
        return result
    summary = data['summary']
    metrics = {}
    for name in ('scheduled_to_certified_receipt_ms', 'permission_read_ms', 'scheduled_to_workflow_ms'):
        dist = summary.get(name)
        if dist is None:
            metrics[name] = None
        elif isinstance(dist, dict):
            metrics[name] = {k: finite(v) for k, v in dist.items() if k in ('count', 'p50', 'p95', 'p99', 'max') and v is not None}
        else:
            raise ValueError('invalid distribution')
    elapsed = finite(summary.get('elapsed_seconds'))
    completed = uint(summary['completed_workflows'])
    metrics['completed_workflows_per_second'] = completed / elapsed if elapsed > 0 else None
    metrics['completed_workflows'] = completed
    result['metrics'] = metrics
    return result


def handler(collector, replay_data=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # No credentials, endpoint paths, query parameters, CORS or arbitrary filesystem access.
            if self.headers.get('Host') not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
                self.send_error(403)
                return
            if self.path == '/api/status':
                data = collector.snapshot() if collector else dict(mode='benchmark replay', members=[])
                data['benchmark'] = replay_data
                body, kind = json.dumps(data, allow_nan=False).encode(), 'application/json'
            elif self.path in ('/', '/app.js', '/style.css'):
                filename, kind = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                                  '/style.css': ('style.css', 'text/css')}[self.path]
                body = ASSETS.joinpath(filename).read_bytes()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', kind + '; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='Private operator configuration; never served')
    parser.add_argument('--verifier', type=Path, help='Built vera-domain verify_status example')
    parser.add_argument('--replay', type=Path, help='Optional recorded manifest/workload directory')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--stale', type=float, default=15)
    parser.add_argument('--window', type=float, default=60)
    args = parser.parse_args()
    for value in (args.interval, args.stale, args.window):
        finite(value, 0.1)
    if not args.config and not args.replay:
        parser.error('provide --config and/or --replay')
    collector = None
    if args.config:
        cfg, config_hash = load_config(args.config)
        if cfg.get('trusted_key') and not args.verifier:
            parser.error('trusted_key requires --verifier; refusing an unverified fallback')
        collector = Collector(cfg, config_hash, args.verifier.resolve() if args.verifier else None,
                              stale=args.stale, window=args.window)
    replay_data = benchmark(args.replay) if args.replay else None
    stop = threading.Event()
    def loop():
        while not stop.is_set():
            collector.poll_all()
            stop.wait(args.interval)
    if collector:
        threading.Thread(target=loop, daemon=True).start()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler(collector, replay_data))
    print(f'Local view: http://127.0.0.1:{server.server_port} (no deployment performed)', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
