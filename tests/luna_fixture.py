"""Isolated Luna artifacts and synthetic contract fixtures, never production state."""
import contextlib
import ipaddress
import json
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import luna_bridge as bridge
from mcp_fixtures import LoopbackServer

PRODUCT_SHA = 'f2c81429db651c0bfe9da7a22b3853dfb6d9c9ac'
RUN = {'id': 'fixture-run-1', 'state': 'needs_operator', 'owner_thread': 'fixture-owner-thread',
       'worker_threads': ['fixture-worker-thread'], 'delta': 'Synthetic result; no inference.'}


def contract():
    return json.loads((ROOT / 'tests/fixtures/luna-contract.json').read_text())


@contextlib.contextmanager
def real_runtime(binary, ui, seed=None):
    import tempfile
    with tempfile.TemporaryDirectory(prefix='luna-integration-runtime-') as temporary:
        root = Path(temporary)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = {'listen': f'127.0.0.1:{port}', 'database': str(root / 'state/runs.sqlite'),
                  'codex_binary': str(root / 'native-deliberately-absent'), 'skill_path': str(root / 'SKILL.md'),
                  'repositories': {}, 'profiles': {},
                  'limits': {'capacity': 1, 'repair_attempts': 1, 'wall_seconds': 30}}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([str(Path(binary).resolve()), 'serve', '--config', str(path),
                                    '--ui', str(Path(ui).resolve())], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            upstream = bridge.Luna(f'http://127.0.0.1:{port}/mcp')
            deadline = time.monotonic() + 10
            while True:
                try:
                    upstream.rpc('server/discover', {})
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError('Isolated real Luna runtime did not become ready')
                    time.sleep(0.1)
            if seed is not None:
                seed(Path(config['database']))
            yield upstream
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def seed_large_history(database):
    """Only the real_runtime-owned temporary database; no claim or native work."""
    with sqlite3.connect(database) as db:
        for index in range(100):
            identity = 'fixture-history-' + str(index)
            request = {'repository': 'old-repo', 'objective': 'x' * 1000,
                'acceptance': ['a' * 700] * 32, 'non_goals': [], 'finish': 'local_candidate',
                'profile': 'old-profile', 'capacity': 1, 'repair_attempts': 0, 'wall_seconds': 30,
                'idempotency_key': identity}
            run = {'id': identity, 'request': request, 'canonical_root': '/isolated',
                'repository_identity': '/isolated/.git', 'state': 'FAILED', 'base_head': 'abc',
                'current_subject': 'abc', 'thread_id': None, 'turn_id': None, 'owned_threads': [],
                'generation': 1, 'repairs_used': 0, 'created_at': 1, 'updated_at': 1,
                'deadline_at': 31, 'delta': 'Synthetic terminal history', 'blocker': None,
                'observed_model': None, 'observed_effort': None, 'configured_model': None,
                'configured_effort': None, 'claim_held': False}
            db.execute('INSERT INTO runs(id,idem,fingerprint,root,state,payload) VALUES(?,?,?,?,?,?)',
                       (identity, identity, identity, '/isolated', 'FAILED', json.dumps(run)))


@contextlib.contextmanager
def adapter(upstream, host='127.0.0.1', subnet='127.0.0.0/8'):
    server = bridge.Server((host, 0), upstream, ipaddress.ip_network(subnet))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://{host}:{server.server_port}/executor/mcp'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextlib.contextmanager
def synthetic_runtime():
    snapshot, calls, requests = contract(), [], []
    def dispatch(method, path, headers, body):
        requests.append({'method': method, 'path': path, 'headers': dict(headers), 'body': body})
        name = body.get('params', {}).get('name')
        if body['method'] == 'server/discover':
            result = snapshot['discovery']
        elif body['method'] == 'tools/list':
            result = {'tools': snapshot['tools']}
        elif body['method'] == 'resources/read':
            result = {'contents': [{'uri': bridge.APP_URI, 'mimeType': 'text/html;profile=mcp-app',
                                   'text': '<!doctype html><title>Synthetic Luna workbench</title>'}]}
        elif body['method'] == 'tools/call':
            args = body['params'].get('arguments', {})
            calls.append({'name': name, 'arguments': args})
            payload = ({'status_inference_calls': 0} if name == 'get_factory_capabilities' else
                       {'runs': [RUN]} if name == 'list_factory_runs' else RUN)
            result = {'content': [{'type': 'text', 'text': 'Synthetic Luna result'}],
                      'structuredContent': payload, 'isError': False,
                      '_meta': {'fixture': 'same-runtime'}}
        else:
            return 400, {}, False
        return 200, {'jsonrpc': '2.0', 'id': body['id'], 'result': result}, False
    server = LoopbackServer(dispatch)
    try:
        yield bridge.Luna(server.url + '/mcp'), calls, requests
    finally:
        server.close()
