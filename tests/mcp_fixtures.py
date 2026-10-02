"""Loopback-only MCP/control-plane fixtures; never use production state."""

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TEST_KEY = 'NONPRODUCTION_CONTROL_PLANE_FIXTURE'
TEST_TUNNEL = 'tunnel_00000000000000000000000000000000'
CATALOG = {
    'tools': [{
        'name': 'read_thread',
        'description': 'Fixture exact-workstream metadata query.',
        'inputSchema': {
            'type': 'object', 'required': ['payload'], 'properties': {
                'payload': {
                    'type': 'object', 'additionalProperties': False,
                    'required': ['target', 'cwd', 'thread_id'],
                    'properties': {
                        'target': {'type': 'string', 'enum': ['local']},
                        'cwd': {'type': 'string'},
                        'thread_id': {'type': 'string'},
                        'include_turns': {'type': 'boolean', 'default': False},
                    },
                },
            },
        },
        'outputSchema': {'type': 'object'},
        'annotations': {
            'readOnlyHint': False, 'destructiveHint': True,
            'idempotentHint': False, 'openWorldHint': True,
        },
        '_meta': {'fixture': 'annotation-must-survive'},
    }, {
        'name': 'discover_threads',
        'inputSchema': {'type': 'object', 'required': ['payload']},
    }, {
        'name': 'future_codex_tool',
        'inputSchema': {'type': 'object'},
    }],
    '_meta': {'actions.catalogRevision': 'fixture-revision'},
}
SUCCESS = {
    'content': [
        {'type': 'text', 'text': 'Fixture metadata, no prompt content.'},
        {'type': 'image', 'data': 'AA==', 'mimeType': 'image/png'},
    ],
    'structuredContent': {'result': {'operation': 'thread/read',
                                    'connection': {'target': 'local'},
                                    'result': {'thread': {'id': 'fixture-thread',
                                                          'cwd': '/fixture/worktree'}}},
                          'error': None},
    'isError': False,
    '_meta': {'fixture': 'result-must-survive'},
}
GUARD_ERROR = {'content': [{'type': 'text', 'text':
                          'Stored thread id/cwd does not match the requested workstream'}],
               'isError': True, '_meta': {'fixture': 'guard-denied'}}
RPC_ERROR = {'code': -32602, 'message': 'Exact turn guard rejected',
             'data': {'thread_id': 'fixture-thread', 'turn_id': 'fixture-turn'}}


class LoopbackServer:
    def __init__(self, dispatch):
        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                raw = b''
                if self.headers.get('Transfer-Encoding') == 'chunked':
                    while True:
                        size = int(self.rfile.readline().split(b';')[0], 16)
                        if not size:
                            self.rfile.readline()
                            break
                        raw += self.rfile.read(size)
                        self.rfile.read(2)
                else:
                    raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                body = json.loads(raw) if raw else None
                code, data, sse = dispatch(self.command, self.path, self.headers, body)
                payload = json.dumps(data).encode() if data is not None else b''
                if sse:
                    payload = b'event: message\ndata: ' + payload + b'\n\n'
                self.send_response(code)
                self.send_header('Content-Type', 'text/event-stream' if sse else 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The fixture client can cancel an idle poll during shutdown.

            do_GET = do_POST = do_DELETE = handle_request

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Upstream(LoopbackServer):
    def __init__(self):
        self.requests = []
        self.sse = False
        self.fail_query = False
        self.deny_auth = False
        super().__init__(self.dispatch)

    def dispatch(self, method, path, headers, body):
        if method != 'POST' or path != '/mcp':
            return 405, None, False
        if body is None:
            return 400, None, False
        self.requests.append((body, dict(headers)))
        if 'id' not in body:
            return 202, None, False
        reply = {'jsonrpc': '2.0', 'id': body['id']}
        name = body['method']
        if name == 'initialize':
            reply['result'] = {'protocolVersion': '2025-11-25',
                               'capabilities': {'tools': {}},
                               'serverInfo': {'name': 'fixture-action-server', 'version': '1'}}
        elif name == 'tools/list':
            reply['result'] = CATALOG
        elif name == 'tools/call':
            if self.deny_auth:
                reply['error'] = {'code': -32001, 'message': 'Permission denied',
                                  'data': {'reason': 'fixture-policy'}}
                return 403, reply, False
            tool = body['params']['name']
            if tool == 'discover_threads':
                reply['result'] = GUARD_ERROR if self.fail_query else {
                    'content': [], 'isError': False,
                    'structuredContent': {'result': {'operation': 'thread/list',
                        'connection': {'target': 'local'},
                        'result': {'data': [{'id': 'fixture-thread', 'cwd': '/fixture/worktree',
                                             'preview': 'MUST_NOT_APPEAR_IN_CHECK_OUTPUT'}]}},
                        'error': None}}
            elif tool == 'read_thread':
                payload = body['params']['arguments']['payload']
                reply['result'] = SUCCESS if payload['cwd'] == '/fixture/worktree' else GUARD_ERROR
            else:
                reply['error'] = RPC_ERROR
        else:
            reply['error'] = {'code': -32601, 'message': 'Method not found'}
        return 200, reply, self.sse


class ControlPlane(LoopbackServer):
    def __init__(self):
        self.commands = queue.Queue()
        self.responses = queue.Queue()
        self.unexpected = []
        super().__init__(self.dispatch)

    def dispatch(self, method, path, headers, body):
        prefix = f'/v1/tunnels/{TEST_TUNNEL}'
        if headers.get('Authorization') != f'Bearer {TEST_KEY}':
            self.unexpected.append('incorrect fixture authorization')
            return 401, {}, False
        if path.split('?')[0] == prefix + '/poll' and method == 'GET':
            try:
                command = self.commands.get(timeout=0.2)
            except queue.Empty:
                return 204, None, False
            return 200, {'commands': [command]}, False
        if path == prefix + '/response' and method == 'POST':
            self.responses.put(body)
            return 200, {}, False
        # Runtime metadata lookup, if performed by this client version.
        if path == prefix and method == 'GET':
            return 200, {'id': TEST_TUNNEL}, False
        self.unexpected.append((method, path))
        return 404, {}, False

    def exchange(self, rpc):
        self.commands.put({'command_type': 'jsonrpc', 'channel': 'main',
                           'request_id': 'fixture-' + str(rpc.get('id', 'notification')),
                           'shard_token': 'fixture-shard',
                           'headers': {'Mcp-Protocol-Version': ['2025-11-25']},
                           'jsonrpc': rpc})
        return self.responses.get(timeout=8)
