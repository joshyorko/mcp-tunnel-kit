"""Local readiness and real native HTTP forwarding against isolated fixtures."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_fixtures import CATALOG, GUARD_ERROR, RPC_ERROR, SUCCESS, TEST_KEY, TEST_TUNNEL
from mcp_fixtures import ControlPlane, Upstream

ROOT = Path(__file__).resolve().parents[1]
CLIENT = os.environ.get('TUNNEL_CLIENT_BIN', str(Path.home() / '.local/bin/tunnel-client'))


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.upstream = Upstream()
        self.addCleanup(self.upstream.close)

    def run_probe(self):
        env = {'PATH': os.defpath, 'CODEX_MCP_URL': self.upstream.url + '/mcp'}
        return subprocess.run([sys.executable, str(ROOT / 'codex_mcp_check.py'),
                               '--probe', '--cwd', '/fixture/worktree'],
                              env=env, capture_output=True, text=True, timeout=8)

    def test_probe_initializes_discovers_and_reads_only_metadata(self):
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('read_thread OK', result.stdout)
        self.assertNotIn('MUST_NOT_APPEAR', result.stdout + result.stderr)
        calls = [{'name': r['params']['name'], 'arguments': r['params']['arguments']}
                 for r, _ in self.upstream.requests if r['method'] == 'tools/call']
        self.assertEqual(calls, [
            {'name': 'discover_threads', 'arguments': {'payload': {
                'target': 'local', 'cwd': '/fixture/worktree', 'limit': 1}}},
            {'name': 'read_thread', 'arguments': {'payload': {
                'target': 'local', 'cwd': '/fixture/worktree',
                'thread_id': 'fixture-thread', 'include_turns': False}}},
        ])

    def test_upstream_query_error_fails_without_dumping_response(self):
        self.upstream.fail_query = True
        result = self.run_probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Stored thread', result.stdout + result.stderr)
        self.assertEqual(sum(r['method'] == 'tools/call' for r, _ in self.upstream.requests), 1)


@unittest.skipUnless(Path(CLIENT).is_file(), 'Install tunnel-client or set TUNNEL_CLIENT_BIN')
class NativeForwardingTests(unittest.TestCase):
    def setUp(self):
        self.upstream = Upstream()
        self.addCleanup(self.upstream.close)
        self.control = ControlPlane()
        self.addCleanup(self.control.close)
        self.log = tempfile.TemporaryFile()
        self.addCleanup(self.log.close)
        # No inherited production configuration, credentials, IDs, proxies or profiles.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = {'PATH': os.defpath, 'HOME': self.temp.name,
               'CONTROL_PLANE_API_KEY': TEST_KEY, 'CONTROL_PLANE_TUNNEL_ID': TEST_TUNNEL,
               'CONTROL_PLANE_BASE_URL': self.control.url,
               'TUNNEL_CLIENT_BIN': CLIENT, 'CODEX_CHECK_PYTHON': sys.executable,
               'CODEX_MCP_URL': self.upstream.url + '/mcp'}
        self.process = subprocess.Popen([shutil.which('zsh'), str(ROOT / 'launch-codex.zsh')],
                                        env=env, stdout=self.log, stderr=self.log)
        self.addCleanup(self.stop_fixture_client)
        self.rpc_id = 0
        init = self.exchange('initialize', {'protocolVersion': '2025-11-25',
                                            'capabilities': {},
                                            'clientInfo': {'name': 'fixture', 'version': '1'}})
        self.assertEqual(init['resp_json']['result']['serverInfo']['name'], 'fixture-action-server')
        self.control.exchange({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def stop_fixture_client(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def exchange(self, method, params):
        self.rpc_id += 1
        try:
            result = self.control.exchange({'jsonrpc': '2.0', 'id': self.rpc_id,
                                            'method': method, 'params': params})
        except Exception:
            self.log.seek(0)
            self.fail('Fixture client failed: ' + self.log.read().decode())
        self.assertEqual(result['request_id'], f'fixture-{self.rpc_id}')
        self.assertEqual(result['resp_json']['id'], self.rpc_id)
        return result

    def test_catalog_schemas_annotations_and_future_tools_are_unchanged(self):
        response = self.exchange('tools/list', {})
        self.assertEqual(response['resp_json']['result'], CATALOG)
        self.assertFalse(self.control.unexpected)
        self.assertTrue(all('Authorization' not in headers
                            for _, headers in self.upstream.requests))

    def test_structured_results_content_and_metadata_survive_json_and_sse(self):
        for sse in (False, True):
            with self.subTest(sse=sse):
                self.upstream.sse = sse
                response = self.exchange('tools/call', {'name': 'read_thread', 'arguments': {
                    'payload': {'target': 'local', 'cwd': '/fixture/worktree',
                                'thread_id': 'fixture-thread', 'include_turns': False}}})
                self.assertEqual(response['resp_json']['result'], SUCCESS)

    def test_cwd_guard_error_is_not_rewritten_or_retried(self):
        arguments = {'payload': {'target': 'local', 'cwd': '/fixture/wrong',
                                 'thread_id': 'fixture-thread', 'include_turns': False}}
        response = self.exchange('tools/call', {'name': 'read_thread', 'arguments': arguments})
        self.assertEqual(response['resp_json']['result'], GUARD_ERROR)
        calls = [r for r, _ in self.upstream.requests if r['method'] == 'tools/call']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['params']['arguments'], arguments)

    def test_jsonrpc_errors_and_exact_thread_cwd_turn_arguments_survive(self):
        arguments = {'payload': {'target': 'local', 'cwd': '/fixture/worktree',
                                 'thread_id': 'fixture-thread', 'turn_id': 'fixture-turn'}}
        response = self.exchange('tools/call', {'name': 'list_thread_items', 'arguments': arguments})
        self.assertEqual(response['resp_json']['error'], RPC_ERROR)
        calls = [r for r, _ in self.upstream.requests if r['method'] == 'tools/call']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['params']['arguments'], arguments)

    def test_upstream_permission_denial_keeps_http_status_and_mcp_error(self):
        self.upstream.deny_auth = True
        response = self.exchange('tools/call', {'name': 'read_thread', 'arguments': {
            'payload': {'target': 'local', 'cwd': '/fixture/worktree',
                        'thread_id': 'fixture-thread'}}})
        self.assertEqual(response['resp_code'], 403)
        self.assertEqual(response['resp_json']['error'], {
            'code': -32001, 'message': 'Permission denied',
            'data': {'reason': 'fixture-policy'}})
        self.assertEqual(sum(r['method'] == 'tools/call' for r, _ in self.upstream.requests), 1)


if __name__ == '__main__':
    unittest.main()
