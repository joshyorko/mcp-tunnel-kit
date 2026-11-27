import importlib.util
import asyncio
from pathlib import Path
import unittest
import tempfile
import os
import json
import io
from contextlib import redirect_stderr
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, unused_port
from yarl import URL

spec = importlib.util.spec_from_file_location('private_app_bridge',
    Path(__file__).resolve().parents[1] / 'scripts/private_app_bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
INBOUND, UPSTREAM = 'inbound-fixture-' + 'a' * 32, 'upstream-fixture-' + 'b' * 32


class PolicyTests(unittest.TestCase):
    def test_foreground_launcher_binds_only_configured_socket_without_access_log(self):
        import ipaddress
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [('inbound', INBOUND), ('upstream', UPSTREAM)]:
                (root / name).write_text(value)
                (root / name).chmod(0o600)
            port = unused_port()
            config = root / 'config.json'
            config.write_text(json.dumps({'subnet': '192.168.50.0/24', 'gateway': '192.168.50.1',
                'port': port, 'endpoint': 'http://10.0.0.1/mcp', 'read_tools': ['read'],
                'inbound_token_file': str(root / 'inbound'), 'upstream_token_file': str(root / 'upstream')}))
            config.chmod(0o600)
            observed = []
            def run_app(app, **kwargs):
                observed.append(kwargs['sock'].getsockname())
                self.assertIsNone(kwargs['access_log'])
                self.assertIsNone(kwargs['print'])
                self.assertNotIn('host', kwargs)
            with patch('sys.argv', ['bridge', '--config', str(config)]), \
                    patch.object(bridge, 'listener_policy', return_value=(
                        ipaddress.ip_network('127.0.0.0/24'), '127.0.0.1', port)), \
                    patch.object(bridge.web, 'run_app', side_effect=run_app):
                self.assertEqual(bridge.main(), 0)
            self.assertEqual(observed, [('127.0.0.1', port)])
            config.chmod(0o644)
            diagnostic = io.StringIO()
            with patch('sys.argv', ['bridge', '--config', str(config)]), \
                    patch.object(bridge.web, 'run_app') as runner, redirect_stderr(diagnostic):
                self.assertEqual(bridge.main(), 1)
                runner.assert_not_called()
            self.assertNotIn(INBOUND, diagnostic.getvalue())
            self.assertNotIn(str(config), diagnostic.getvalue())

    def test_credentials_require_private_regular_owned_files(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'credential'
            secret.write_text(INBOUND)
            secret.chmod(0o600)
            self.assertEqual(bridge.private_file(secret), INBOUND)
            secret.chmod(0o644)
            with self.assertRaises(ValueError):
                bridge.private_file(secret)
            secret.chmod(0o600)
            link = Path(directory) / 'link'
            link.symlink_to(secret)
            with self.assertRaises(OSError):
                bridge.private_file(link)
            os.link(secret, Path(directory) / 'hardlink')
            with self.assertRaises(ValueError):
                bridge.private_file(secret)

    def test_only_fixed_private_mcp_endpoints(self):
        for value in ('http://127.0.0.1/mcp', 'http://169.254.169.254/mcp',
                      'https://example.com/mcp', 'http://8.8.8.8/mcp',
                      'http://10.0.0.1/mcp?url=x', 'http://user:pass@10.0.0.1/mcp',
                      'http://10.0.0.1/other', 'ftp://10.0.0.1/mcp'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.private_endpoint(value)
        self.assertEqual(str(bridge.private_endpoint('http://100.64.0.1:3000/mcp')),
                         'http://100.64.0.1:3000/mcp')

    def test_credentials_cannot_be_reused(self):
        with self.assertRaises(ValueError):
            bridge.create_app('http://10.0.0.1/mcp', INBOUND, INBOUND, ['read'],
                              subnet='192.168.50.0/24', gateway='192.168.50.1', port=8091)

    def test_listener_rejects_public_wildcard_non_gateway_and_broad_subnet(self):
        for subnet, gateway, port in [('0.0.0.0/0', '0.0.0.0', 8091),
                ('192.168.50.0/24', '0.0.0.0', 8091), ('192.168.50.0/24', '192.168.50.2', 8091),
                ('192.168.0.0/16', '192.168.0.1', 8091), ('8.8.8.0/24', '8.8.8.1', 8091),
                ('192.168.50.0/24', '192.168.50.1', 80)]:
            with self.subTest(subnet=subnet, gateway=gateway), self.assertRaises(ValueError):
                bridge.listener_policy(subnet, gateway, port)
        self.assertEqual(bridge.listener_policy('192.168.50.0/24', '192.168.50.1', 8091)[1:],
                         ('192.168.50.1', 8091))


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.seen = []
        self.mode = 'json'

        async def upstream(request):
            message = await request.json()
            self.seen.append((dict(request.headers), message))
            if self.mode == 'redirect':
                return web.Response(status=302, headers={'Location': 'http://127.0.0.1/private'})
            if self.mode == 'error':
                return web.Response(status=401, text=UPSTREAM)
            if self.mode == 'sse':
                return web.Response(text='data: secret', content_type='text/event-stream')
            if self.mode == 'oversized':
                return web.Response(body=b' ' * (bridge.LIMIT + 1), content_type='application/json')
            if self.mode == 'timeout':
                await asyncio.sleep(0.05)
            if message['method'] == 'notifications/initialized':
                return web.Response(status=202)
            result = {'tools': [{'name': 'read'}, {'name': 'write'}]}
            if message['method'] == 'initialize':
                result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'fixture', 'version': '1'}}
            if message['method'] == 'tools/call':
                result = {'content': [{'type': 'text', 'text': 'synthetic read'}]}
            return web.json_response({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result})

        remote = web.Application()
        remote.router.add_post('/mcp', upstream)
        self.remote = TestServer(remote)
        await self.remote.start_server()
        # Only the synthetic test substitutes loopback; production validates literal private IPs.
        import ipaddress
        self.port = unused_port()
        # Substitute only address policy: real TCP peer, local socket and Host checks still execute.
        self.policy = (ipaddress.ip_network('127.0.0.0/24'), '127.0.0.1', self.port)
        with patch.object(bridge, 'private_endpoint', return_value=URL(self.remote.make_url('/mcp'))), \
                patch.object(bridge, 'listener_policy', return_value=self.policy):
            app = bridge.create_app('http://10.0.0.1/mcp', INBOUND, UPSTREAM, ['read'],
                                    subnet='192.168.50.0/24', gateway='192.168.50.1', port=8091)
        self.client = TestClient(TestServer(app, port=self.port))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.remote.close()

    async def call(self, method='tools/list', params=None, **kwargs):
        return await self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1,
            'method': method, 'params': params or {}}, **kwargs)

    async def test_unauthorized_and_write_calls_never_reach_upstream(self):
        response = await self.call()
        self.assertEqual(response.status, 401)
        response = await self.call('tools/call', {'name': 'write'},
                                   headers={'Authorization': 'Bearer ' + INBOUND})
        self.assertEqual(response.status, 403)
        response = await self.call(headers=[('Authorization', 'Bearer ' + INBOUND),
                                           ('Authorization', 'Bearer ' + INBOUND)])
        self.assertEqual(response.status, 401)
        self.assertEqual(self.seen, [])

    async def test_separate_auth_fixed_destination_and_filtered_discovery(self):
        response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND,
                                           'Cookie': 'private-cookie', 'X-Upstream': 'evil'})
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())['result']['tools'], [{'name': 'read'}])
        headers, _ = self.seen[0]
        self.assertEqual(headers['Authorization'], 'Bearer ' + UPSTREAM)
        self.assertNotIn('Cookie', headers)
        self.assertNotIn('X-Upstream', headers)

    async def test_redirect_errors_and_unsupported_transport_are_redacted(self):
        for mode in ('redirect', 'error', 'sse'):
            self.mode = mode
            response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND})
            self.assertEqual(response.status, 502)
            self.assertNotIn(UPSTREAM, await response.text())
        self.assertEqual(len(self.seen), 3)

    async def test_sessions_origins_and_unknown_methods_are_refused(self):
        for extra in ({'Mcp-Session-Id': 'session'},):
            response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND, **extra})
            self.assertEqual(response.status, 400)
        response = await self.call('resources/read', headers={'Authorization': 'Bearer ' + INBOUND})
        self.assertEqual(response.status, 502)
        self.assertEqual(self.seen, [])

    async def test_host_origin_and_forwarding_spoofs_never_reach_upstream(self):
        for extra in ({'Host': 'evil.example'}, {'Host': '127.0.0.1'},
                      {'Origin': 'http://evil'}, {'X-Forwarded-For': '192.168.50.2'},
                      {'Forwarded': 'for=192.168.50.2'}, {'X-Forwarded-Host': 'evil'},
                      {'X-Forwarded-Proto': 'https'}):
            with self.subTest(headers=list(extra)):
                response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND, **extra})
                self.assertEqual(response.status, 403)
        # aiohttp's client normalizes Host; send actual duplicate wire headers.
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write((f'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n'
                      f'Host: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {INBOUND}\r\n'
                      'Content-Length: 0\r\nConnection: close\r\n\r\n').encode())
        await writer.drain()
        status = await reader.readline()
        self.assertIn(status.split()[1], (b'400', b'403'))
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.seen, [])

    async def test_disallowed_real_peer_and_wrong_local_bind_fail_closed(self):
        import ipaddress
        for network, gateway in [('10.0.0.0/24', '127.0.0.1'),
                                 ('127.0.0.0/24', '192.168.50.1')]:
            port = unused_port()
            with patch.object(bridge, 'private_endpoint', return_value=URL(self.remote.make_url('/mcp'))), \
                    patch.object(bridge, 'listener_policy', return_value=(
                        ipaddress.ip_network(network), gateway, port)):
                app = bridge.create_app('http://10.0.0.1/mcp', INBOUND, UPSTREAM, ['read'],
                                        subnet='192.168.50.0/24', gateway='192.168.50.1', port=8091)
            async with TestClient(TestServer(app, port=port)) as client:
                response = await client.post('/mcp', headers={
                    'Authorization': 'Bearer ' + INBOUND, 'Host': f'{gateway}:{port}'},
                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
                self.assertEqual(response.status, 403)
        self.assertEqual(self.seen, [])

    async def test_initialize_notification_and_allowed_read(self):
        headers = {'Authorization': 'Bearer ' + INBOUND}
        response = await self.call('initialize', headers=headers)
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())['result']['protocolVersion'], '2025-03-26')
        response = await self.client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        self.assertEqual(response.status, 202)
        response = await self.call('tools/call', {'name': 'read', 'arguments': {}}, headers=headers)
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())['result']['content'][0]['text'], 'synthetic read')

    async def test_size_and_timeout_fail_closed(self):
        self.mode = 'oversized'
        response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND})
        self.assertEqual(response.status, 502)
        self.mode = 'timeout'
        client_key = next(key for key in self.client.app if getattr(key, '_name', '').endswith('private_app_client'))
        client = self.client.app[client_key]
        from aiohttp import ClientTimeout
        with patch.object(client, '_timeout', ClientTimeout(total=0.01)):
            response = await self.call(headers={'Authorization': 'Bearer ' + INBOUND})
        self.assertEqual(response.status, 502)
