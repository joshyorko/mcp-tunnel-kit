"""Isolated Luna artifacts and synthetic contract fixtures, never production state."""
import contextlib
import ipaddress
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import luna_bridge as bridge
from mcp_fixtures import LoopbackServer

PRODUCT_SHA = '9609821752804f11799d04880cd2c7fb7e129333'
RUN = {'id': 'fixture-run-1', 'state': 'needs_operator', 'owner_thread': 'fixture-owner-thread',
       'worker_threads': ['fixture-worker-thread'], 'delta': 'Synthetic result; no inference.'}


def contract():
    return json.loads((ROOT / 'tests/fixtures/luna-contract.json').read_text())


@contextlib.contextmanager
def real_runtime(binary, ui):
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
            yield upstream
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@contextlib.contextmanager
def adapter(upstream):
    server = bridge.Server(('127.0.0.1', 0), upstream, ipaddress.ip_network('127.0.0.0/8'))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/executor/mcp'
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
