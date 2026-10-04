#!/usr/bin/env python3
"""Opt-in foreground Executor tool view of the existing loopback Luna runtime.

This is not a native MCP Apps endpoint. The original runtime owns every run,
thread, authorization check and resource. No process or database is created here.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import signal
import sys
import threading
import urllib.parse

import compose_control as control
from devsy_bridge import validate_bind

READS = frozenset({'list_factory_runs', 'get_factory_run', 'get_factory_capabilities'})
MUTATIONS = frozenset({'start_factory', 'steer_factory_run', 'cancel_factory_run', 'resume_factory_run'})
MODEL_TOOLS = READS | MUTATIONS
APP_TOOLS = frozenset({'open_factory', 'open_factory_panel', 'refresh_factory',
                       'read_factory_settings', 'update_factory_settings'})
APP_URI = 'ui://luna-factory/workbench.html'
PROTOCOL = '2026-07-28'
MAX_REQUEST = 65536


def upstream_origin(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
                or not parsed.port or parsed.path != '/mcp' or parsed.query
                or parsed.fragment or parsed.username or parsed.password):
            raise ValueError()
        return f'http://127.0.0.1:{parsed.port}'
    except ValueError:
        raise control.ControlError('Luna upstream must be one numeric loopback HTTP /mcp endpoint.') from None


def model_catalog(tools):
    names = [tool['name'] for tool in tools]
    if len(names) != len(set(names)) or not MODEL_TOOLS | APP_TOOLS <= set(names):
        raise control.ControlError('Luna catalog is incomplete or duplicated; the product contract changed.')
    result = []
    for tool in tools:
        if tool['name'] not in MODEL_TOOLS:
            continue
        visibility = tool.get('_meta', {}).get('ui', {}).get('visibility', ['model', 'app'])
        if 'model' not in visibility:
            raise control.ControlError('A required model tool became app-only; review the product contract.')
        # UI metadata has meaning only at the canonical endpoint with resources.
        meta = {key: value for key, value in tool.get('_meta', {}).items()
                if key not in {'ui', 'openai/ui'}}
        item = {key: value for key, value in tool.items() if key != '_meta'}
        if meta:
            item['_meta'] = meta
        read = tool['name'] in READS
        item['annotations'] = {'readOnlyHint': read, 'destructiveHint': not read,
                               'idempotentHint': read, 'openWorldHint': not read}
        result.append(item)
    return result


class Luna:
    def __init__(self, url):
        self.origin = upstream_origin(url)

    def rpc(self, method, params):
        # Each call has its own bounded HTTP client. Never retry a dispatch.
        params = {**params, '_meta': {
            'io.modelcontextprotocol/protocolVersion': PROTOCOL,
            'io.modelcontextprotocol/clientInfo': {'name': 'tunnel-kit-luna-tools', 'version': '1'},
            'io.modelcontextprotocol/clientCapabilities': {},
        }}
        headers = {'MCP-Protocol-Version': PROTOCOL, 'Mcp-Method': method}
        if 'name' in params or 'uri' in params:
            headers['Mcp-Name'] = params.get('name', params.get('uri'))
        response, _ = control.Http(self.origin).request('POST', '/mcp', {
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params,
        }, headers)
        if response.get('id') != 1 or 'error' in response or 'result' not in response:
            raise control.ControlError('Luna request failed; do not replay an uncertain mutation.')
        return response['result']

    def catalog(self):
        return model_catalog(self.rpc('tools/list', {}).get('tools', []))

    def call(self, name, arguments):
        if name not in MODEL_TOOLS or not isinstance(arguments, dict):
            raise control.ControlError('Only the explicit Luna model-tool contract may be called here.')
        return self.rpc('tools/call', {'name': name, 'arguments': arguments})


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, upstream, subnet):
        self.upstream, self.subnet = upstream, subnet
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(8)
        self.connections = set()
        self.lock = threading.Lock()
        super().__init__(address, Handler)
        self.authority = f'{self.server_address[0]}:{self.server_port}'

    def process_request(self, request, client_address):
        if not self.slots.acquire(timeout=0.25):
            try:
                request.settimeout(0.25)
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:
                pass
            request.close()
            return
        with self.lock:
            if self.stopping.is_set():
                request.close()
                self.slots.release()
                return
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.lock:
                self.connections.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.lock:
                self.connections.discard(request)
            self.slots.release()

    def shutdown(self):
        with self.lock:
            self.stopping.set()
            for connection in self.connections:
                try:
                    connection.shutdown(2)
                except OSError:
                    pass
                connection.close()
        super().shutdown()

    def handle_error(self, *_args):
        pass


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass

    def reply(self, status, body=None):
        encoded = b'' if body is None else json.dumps(body, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(encoded)

    def allowed(self):
        peer = ipaddress.ip_address(self.client_address[0])
        if (peer not in self.server.subnet and not peer.is_loopback
                or self.headers.get_all('Host') != [self.server.authority]
                or len(self.headers.get_all('Origin', [])) > 1
                or self.headers.get('Origin') not in (None, 'http://' + self.server.authority)):
            self.reply(403)
            return False
        return True

    def do_GET(self):
        if self.allowed():
            self.reply(405)

    do_DELETE = do_GET

    def do_POST(self):
        if not self.allowed():
            return
        if self.path != '/executor/mcp':
            self.reply(404)
            return
        identifier = None
        try:
            lengths = self.headers.get_all('Content-Length', [])
            length = int(lengths[0]) if len(lengths) == 1 else 0
            if (not 0 < length <= MAX_REQUEST or self.headers.get('Transfer-Encoding')
                    or self.headers.get_content_type() != 'application/json'):
                self.reply(400)
                return
            raw = self.rfile.read(length)
            if len(raw) != length or self.server.stopping.is_set():
                return
            request = json.loads(raw)
            if not isinstance(request, dict) or request.get('jsonrpc') != '2.0':
                raise control.ControlError('Invalid MCP request.')
            identifier, method, params = request.get('id'), request.get('method'), request.get('params', {})
            if not isinstance(params, dict):
                raise control.ControlError('Invalid MCP parameters.')
            if 'id' not in request:
                if method != 'notifications/initialized':
                    raise control.ControlError('Unsupported notification.')
                self.reply(202)
                return
            if method == 'initialize':
                self.server.upstream.catalog()
                version = params.get('protocolVersion')
                result = {'protocolVersion': version if version in control.PROTOCOL_VERSIONS else '2025-11-25',
                          'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'luna-factory-executor-tools', 'version': '1'},
                          'instructions': 'Luna Factory model tools only. Native workbench resources and entrypoints require the canonical app endpoint. Never replay an uncertain mutation.'}
            elif self.headers.get('MCP-Protocol-Version', '2025-03-26') not in control.PROTOCOL_VERSIONS:
                raise control.ControlError('Unsupported adapter protocol.')
            elif method == 'ping':
                result = {}
            elif method == 'tools/list' and not params.get('cursor'):
                result = {'tools': self.server.upstream.catalog()}
            elif method == 'tools/call':
                result = self.server.upstream.call(params.get('name'), params.get('arguments', {}))
            else:
                self.reply(200, {'jsonrpc': '2.0', 'id': identifier,
                                'error': {'code': -32601, 'message': 'Unsupported method on the Executor tool view.'}})
                return
            self.reply(200, {'jsonrpc': '2.0', 'id': identifier, 'result': result})
        except Exception:
            self.reply(200, {'jsonrpc': '2.0', 'id': identifier, 'error': {
                'code': -32603, 'message': 'Luna request failed or was refused. Reconcile the original run before retrying; no automatic retry was made.'}})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', default='http://127.0.0.1:8787/mcp')
    args = parser.parse_args()
    try:
        upstream = Luna(args.upstream)
        configuration = control.config()
        control.network_preflight(configuration)
        ipam = configuration['networks']['control-plane']['ipam']['config'][0]
        subnet = validate_bind(ipam['subnet'], ipam['gateway'])
        upstream.catalog()
        server = Server((ipam['gateway'], 8090), upstream, subnet)
        def stop(_signum, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        print('Luna Executor tool view ready on the verified managed gateway. Trusted host/network peers only. Native UI is not served here.', flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    except Exception:
        print('Luna adapter failed. Check the canonical loopback runtime and managed Compose network; details omitted.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
