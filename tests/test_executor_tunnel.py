"""Executor launcher isolation and native forwarding through loopback fixtures."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_fixtures import RPC_ERROR, TEST_KEY, TEST_TUNNEL, ControlPlane, Upstream


ROOT = Path(__file__).resolve().parents[1]
CLIENT = os.environ.get('TUNNEL_CLIENT_BIN', str(Path.home() / '.local/bin/tunnel-client'))
ZSH = os.environ.get('ZSH_BIN') or shutil.which('zsh') or 'zsh'
EXECUTOR_KEY = 'NONPRODUCTION_EXECUTOR_API_KEY_32_CHARS_MINIMUM'
ENCRYPTION_KEY = '9a' * 32
OUTPUT_MARKER = 'NONPRODUCTION_EXECUTOR_OUTPUT_SECRET'
EXECUTOR_CATALOG = {'tools': [
    {'name': 'execute', 'inputSchema': {'type': 'object', 'required': ['code'],
                                      'properties': {'code': {'type': 'string'}}}},
    {'name': 'resume', 'inputSchema': {'type': 'object', 'required': ['requestId', 'response'],
                                     'properties': {'requestId': {'type': 'string'},
                                                    'response': {'type': 'object'}}}},
    {'name': 'skills', 'inputSchema': {'type': 'object'},
     'annotations': {'readOnlyHint': True}},
], '_meta': {'fixture': 'executor-catalog'}}
EXECUTOR_RESULT = {
    'content': [{'type': 'text', 'text': OUTPUT_MARKER}],
    'structuredContent': {'status': 'completed',
                          'execution': {'ok': True, 'value': 42, 'toolCalls': []},
                          'unavailableApps': []},
    'isError': False,
    '_meta': {'fixture': 'executor-result'},
}


class ExecutorUpstream(Upstream):
    def __init__(self):
        self.http_requests = []
        super().__init__()

    def dispatch(self, method, path, headers, body):
        self.http_requests.append((method, path))
        code, reply, sse = super().dispatch(method, path, headers, body)
        if code == 200 and body and body.get('method') == 'tools/list':
            reply['result'] = EXECUTOR_CATALOG
        elif code == 200 and body and body.get('method') == 'tools/call':
            if body['params']['name'] == 'execute':
                reply.pop('error', None)
                reply['result'] = EXECUTOR_RESULT
        return code, reply, sse


class RecordingControlPlane(ControlPlane):
    def __init__(self):
        self.requests = []
        super().__init__()

    def dispatch(self, method, path, headers, body):
        self.requests.append((method, path))
        return super().dispatch(method, path, headers, body)


class ExecutorFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.data = self.base / 'executor-data'
        self.data.mkdir(mode=0o700)
        self.keys = self.data / 'keys.json'
        self.keys.write_text(json.dumps({'apiKey': EXECUTOR_KEY, 'encryptionKey': ENCRYPTION_KEY}))
        self.keys.chmod(0o600)
        self.upstream = ExecutorUpstream()
        self.addCleanup(self.upstream.close)
        self.control = RecordingControlPlane()
        self.addCleanup(self.control.close)
        # No production keys, tunnel IDs, proxy settings or shell profile are inherited.
        self.env = {'PATH': os.defpath, 'HOME': str(self.base), 'TMPDIR': str(self.base),
                    'CONTROL_PLANE_API_KEY': TEST_KEY, 'CONTROL_PLANE_TUNNEL_ID': TEST_TUNNEL,
                    'CONTROL_PLANE_BASE_URL': self.control.url,
                    'TUNNEL_CLIENT_BIN': CLIENT, 'CODEX_CHECK_PYTHON': sys.executable,
                    'EXECUTOR_DATA_DIR': str(self.data),
                    'EXECUTOR_MCP_URL': self.upstream.url + '/mcp'}

    def run_launcher(self, *arguments):
        return subprocess.run([ZSH, str(ROOT / 'launch-executor-tunnel.zsh'), *arguments],
                              cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=8)

    def assert_no_secrets(self, output):
        for value in (EXECUTOR_KEY, ENCRYPTION_KEY, TEST_KEY, OUTPUT_MARKER):
            self.assertNotIn(value, output)

    def assert_no_network(self):
        self.assertEqual(self.upstream.http_requests, [])
        self.assertEqual(self.control.requests, [])

    def assert_private_auth_file(self):
        header = self.data / 'tunnel-auth-header'
        self.assertFalse(header.is_symlink())
        self.assertEqual(stat.S_IMODE(header.stat().st_mode), 0o600)
        self.assertEqual(header.read_text().rstrip('\n'), 'Bearer ' + EXECUTOR_KEY)


@unittest.skipUnless(Path(CLIENT).is_file(), 'Install tunnel-client or set TUNNEL_CLIENT_BIN')
class ExecutorOfflineTests(ExecutorFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.run_marker = self.base / 'unexpected-tunnel-run'
        client = self.base / 'offline-tunnel-client'
        client.write_text(
            '#!' + sys.executable + '\n'
            'import os, sys\n'
            'from pathlib import Path\n'
            'if sys.argv[1:] == ["run", "--help"]:\n'
            '    os.execv(' + repr(CLIENT) + ', [' + repr(CLIENT) + ', *sys.argv[1:]])\n'
            'Path(' + repr(str(self.run_marker)) + ').write_text("unexpected tunnel run")\n'
            'sys.exit(91)\n'
        )
        client.chmod(0o700)
        self.env['TUNNEL_CLIENT_BIN'] = str(client)

    def assert_no_network(self):
        super().assert_no_network()
        self.assertFalse(self.run_marker.exists(), 'The launcher started tunnel-client run')

    def test_check_has_no_network_or_tunnel_start(self):
        result = self.run_launcher('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_network()
        self.assert_no_secrets(result.stdout + result.stderr)

    def test_missing_or_world_readable_keys_fail_before_network(self):
        for case in ('missing', 'world-readable'):
            with self.subTest(case=case):
                if case == 'missing':
                    self.keys.unlink()
                else:
                    self.keys.write_text(json.dumps({'apiKey': EXECUTOR_KEY,
                                                     'encryptionKey': ENCRYPTION_KEY}))
                    self.keys.chmod(0o644)
                result = self.run_launcher()
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_network()
                self.assert_no_secrets(result.stdout + result.stderr)
                self.assertFalse((self.data / 'tunnel-auth-header').exists())

    def test_malformed_keys_fail_without_echoing_contents(self):
        self.keys.write_text('{"apiKey": "' + EXECUTOR_KEY + '", INVALID_JSON')
        result = self.run_launcher('--check')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_network()
        self.assert_no_secrets(result.stdout + result.stderr)

    def test_auth_header_symlink_is_refused_without_overwriting_target(self):
        target = self.base / 'unrelated-private-file'
        target.write_text('preserve this file')
        header = self.data / 'tunnel-auth-header'
        header.symlink_to(target)
        result = self.run_launcher('--check')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'preserve this file')
        self.assertTrue(header.is_symlink())
        self.assert_no_network()
        self.assert_no_secrets(result.stdout + result.stderr)

    def test_unsafe_url_overrides_fail_without_network_or_secret_echo(self):
        urls = ('http://user:fixture-url-secret@127.0.0.1:4312/mcp',
                'http://example.com:4312/mcp', 'http://localhost:4312/mcp',
                'http://127.0.0.1:4312/p/executor',
                'http://127.0.0.1:4312/mcp?key=fixture-url-secret',
                'http://127.0.0.1:4312/mcp#fixture-url-secret',
                'http://127.0.0.1:4312/mcp,channel=other')
        for url in urls:
            with self.subTest(url=url):
                self.env['EXECUTOR_MCP_URL'] = url
                result = self.run_launcher()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('fixture-url-secret', result.stdout + result.stderr)
                self.assert_no_network()
                self.assert_no_secrets(result.stdout + result.stderr)


@unittest.skipUnless(Path(CLIENT).is_file(), 'Install tunnel-client or set TUNNEL_CLIENT_BIN')
class ExecutorNativeForwardingTests(ExecutorFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.log = tempfile.TemporaryFile()
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen([ZSH, str(ROOT / 'launch-executor-tunnel.zsh')],
                                        cwd=ROOT, env=self.env, stdout=self.log, stderr=self.log)
        self.addCleanup(self.stop_fixture_client)
        self.rpc_id = 0
        reply = self.exchange('initialize', {'protocolVersion': '2025-11-25',
                                             'capabilities': {},
                                             'clientInfo': {'name': 'executor-fixture', 'version': '1'}})
        self.assertEqual(reply['resp_json']['result']['serverInfo']['name'],
                         'fixture-action-server')
        self.control.exchange({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def stop_fixture_client(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def launcher_output(self):
        self.log.seek(0)
        return self.log.read().decode()

    def exchange(self, method, params):
        self.rpc_id += 1
        try:
            reply = self.control.exchange({'jsonrpc': '2.0', 'id': self.rpc_id,
                                           'method': method, 'params': params})
        except Exception:
            output = self.launcher_output()
            self.assert_no_secrets(output)
            self.fail('Fixture executor tunnel failed: ' + output)
        self.assertEqual(reply['request_id'], f'fixture-{self.rpc_id}')
        self.assertEqual(reply['resp_json']['id'], self.rpc_id)
        self.assertFalse(self.control.unexpected)
        self.assertTrue(self.upstream.requests)
        for _, headers in self.upstream.requests:
            authorization = next((value for name, value in headers.items()
                                  if name.lower() == 'authorization'), None)
            self.assertEqual(authorization, 'Bearer ' + EXECUTOR_KEY)
        self.assert_no_secrets(self.launcher_output())
        return reply

    def test_main_channel_catalog_and_private_bearer_forwarding(self):
        reply = self.exchange('tools/list', {})
        self.assertEqual(reply['resp_json']['result'], EXECUTOR_CATALOG)
        self.assert_private_auth_file()
        argv = Path(f'/proc/{self.process.pid}/cmdline').read_bytes().split(b'\0')
        self.assertEqual(Path(os.fsdecode(argv[0])).name, 'tunnel-client')
        for value in (EXECUTOR_KEY, ENCRYPTION_KEY, TEST_KEY, TEST_TUNNEL):
            self.assertNotIn(value.encode(), b'\0'.join(argv))
        self.assertNotIn(b'--control-plane.tunnel-id', argv)

    def test_json_and_sse_results_preserve_payload_without_logging_contents(self):
        arguments = {'code': 'return 42'}
        for sse in (False, True):
            with self.subTest(sse=sse):
                self.upstream.sse = sse
                reply = self.exchange('tools/call', {'name': 'execute', 'arguments': arguments})
                self.assertEqual(reply['resp_json']['result'], EXECUTOR_RESULT)
        calls = [rpc for rpc, _ in self.upstream.requests if rpc['method'] == 'tools/call']
        self.assertEqual([rpc['params']['arguments'] for rpc in calls], [arguments, arguments])

    def test_jsonrpc_and_http_permission_errors_survive_without_retries(self):
        arguments = {'requestId': 'fixture-request',
                     'response': {'action': 'accept', 'content': {}}}
        reply = self.exchange('tools/call', {'name': 'resume', 'arguments': arguments})
        self.assertEqual(reply['resp_json']['error'], RPC_ERROR)
        self.upstream.deny_auth = True
        reply = self.exchange('tools/call', {'name': 'execute', 'arguments': {'code': 'return 42'}})
        self.assertEqual(reply['resp_code'], 403)
        self.assertEqual(reply['resp_json']['error'], {
            'code': -32001, 'message': 'Permission denied', 'data': {'reason': 'fixture-policy'}})
        calls = [rpc for rpc, _ in self.upstream.requests if rpc['method'] == 'tools/call']
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]['params']['arguments'], arguments)

    def test_second_launcher_refuses_competing_tunnel_without_stopping_owner(self):
        for launcher in ('launch-executor-tunnel.zsh', 'launch-codex.zsh'):
            with self.subTest(launcher=launcher):
                result = subprocess.run([ZSH, str(ROOT / launcher)], cwd=ROOT,
                                        env=self.env, capture_output=True, text=True, timeout=8)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('already running', result.stderr)
                self.assert_no_secrets(result.stdout + result.stderr)
        self.assertIsNone(self.process.poll())
        reply = self.exchange('tools/list', {})
        self.assertEqual(reply['resp_json']['result'], EXECUTOR_CATALOG)


if __name__ == '__main__':
    unittest.main()
