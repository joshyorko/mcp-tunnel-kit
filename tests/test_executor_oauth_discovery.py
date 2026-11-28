"""Fixed public discovery routes cannot become an authenticated generic proxy."""
import copy
import asyncio
import importlib.util
import json
from pathlib import Path
import unittest

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

spec = importlib.util.spec_from_file_location('discovery_proxy',
    Path(__file__).resolve().parents[1] / 'scripts/executor_schema_proxy.py')
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.policy = proxy.OAuthDiscovery('https://issuer.example.test',
            'https://resource.example.test/mcp?elicitation_mode=browser&connection=fixture', 'proxy.example.test')
        self.documents = {
            proxy.RESOURCE_METADATA: {'resource': self.policy.resource,
                'authorization_servers': [self.policy.issuer], 'bearer_methods_supported': ['header']},
            proxy.SERVER_METADATA: {'issuer': self.policy.issuer, **{
                name: self.policy.issuer + path for name, path in proxy.OAUTH_ENDPOINTS.items()}},
        }
        self.seen = []
        self.status = 200
        self.raw = None

        async def upstream(request):
            self.seen.append((request.raw_path, dict(request.headers)))
            if request.path == '/mcp':
                message = await request.json()
                return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                    'tools': [{'name': n, 'inputSchema': {}} for n in sorted(proxy.BETA79_TOOLS)]}})
            return web.Response(status=self.status,
                body=self.raw if self.raw is not None else json.dumps(self.documents[request.path]).encode(),
                headers={'Content-Type': 'application/json', 'Set-Cookie': 'must-not-pass=1',
                         'Location': 'https://untrusted.example.test/'})

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', upstream)
        self.upstream = TestServer(app)
        await self.upstream.start_server()
        self.client = TestClient(TestServer(proxy.create_app(
            str(self.upstream.make_url('')).rstrip('/'), legacy_surface=True,
            oauth_discovery=self.policy)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream.close()

    async def get(self, path, **kwargs):
        headers = {'Host': self.policy.host, **kwargs.pop('headers', {})}
        return await self.client.get(path, headers=headers, **kwargs)

    async def test_client_discovers_exact_public_resource_and_issuer(self):
        r = await self.get(self.policy.target(proxy.RESOURCE_METADATA))
        self.assertEqual(r.status, 200)
        resource = await r.json()
        self.assertEqual(resource['resource'], self.policy.resource)
        r = await self.get(proxy.SERVER_METADATA, headers={'Origin': self.policy.issuer})
        self.assertEqual(r.status, 200)
        server = await r.json()
        self.assertEqual(server['issuer'], resource['authorization_servers'][0])
        self.assertEqual(server['token_endpoint'], self.policy.issuer + '/api/auth/oauth2/token')
        self.assertNotIn('Set-Cookie', r.headers)
        self.assertNotIn('Location', r.headers)
        self.assertEqual(r.headers['Cache-Control'], 'no-store')
        self.assertTrue(all('Authorization' not in h and 'Cookie' not in h and 'Origin' not in h
                            for _, h in self.seen))

    async def test_unexpected_paths_queries_hosts_origins_and_methods_never_reach_upstream(self):
        for path in ('/api/auth/oauth2/token', '/.well-known/oauth-protected-resource',
                     proxy.RESOURCE_METADATA, proxy.RESOURCE_METADATA + '?connection=other',
                     proxy.SERVER_METADATA + '?url=https://untrusted.example.test',
                     '/.well-known/%6fauth-authorization-server'):
            self.assertIn((await self.get(URL(path, encoded=True), allow_redirects=False)).status, (400, 404))
        target = self.policy.target(proxy.RESOURCE_METADATA)
        for headers in ({'Host': 'wrong.example.test'}, {'Origin': 'https://wrong.example.test'},
                        {'Authorization': 'Bearer synthetic'}, {'Cookie': 'synthetic=1'},
                        {'Forwarded': 'host=wrong'}, {'X-Forwarded-Host': self.policy.host}):
            self.assertIn((await self.get(target, headers=headers)).status, (400, 403))
        for method in ('POST', 'HEAD', 'OPTIONS'):
            self.assertEqual((await self.client.request(method, target,
                headers={'Host': self.policy.host})).status, 405)
        reader, writer = await asyncio.open_connection(self.client.server.host, self.client.server.port)
        writer.write(('GET ' + target + ' HTTP/1.1\r\nHost: ' + self.policy.host +
                      '\r\nHost: ' + self.policy.host + '\r\nConnection: close\r\n\r\n').encode())
        await writer.drain()
        self.assertIn(b' 400 ', await reader.readline())
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.seen, [])

    async def test_upstream_identity_endpoint_redirect_and_duplicate_field_controls(self):
        original = copy.deepcopy(self.documents)
        changes = [(proxy.RESOURCE_METADATA, 'resource', 'https://wrong.example.test/mcp'),
                   (proxy.RESOURCE_METADATA, 'authorization_servers', ['https://wrong.example.test']),
                   (proxy.SERVER_METADATA, 'issuer', 'https://wrong.example.test'),
                   (proxy.SERVER_METADATA, 'token_endpoint', 'https://issuer.example.test/arbitrary'),
                   (proxy.SERVER_METADATA, 'jwks_uri', 'https://wrong.example.test/jwks'),
                   (proxy.SERVER_METADATA, 'unknown_endpoint', self.policy.issuer + '/api/auth/unknown'),
                   (proxy.SERVER_METADATA, 'signed_metadata', 'unverified'),
                   (proxy.SERVER_METADATA, 'mtls_endpoint_aliases', {}),
                   (proxy.RESOURCE_METADATA, 'jwks_uri', 'https://wrong.example.test/keys')]
        for path, key, value in changes:
            self.documents = copy.deepcopy(original)
            self.documents[path][key] = value
            self.assertEqual((await self.get(self.policy.target(path))).status, 502)
        self.documents = original
        self.status = 302
        self.assertEqual((await self.get(proxy.SERVER_METADATA)).status, 502)
        self.status = 200
        for raw in (b'{"issuer":"one","issuer":"two"}', b'not json', b' ' * 65537):
            self.raw = raw
            self.assertEqual((await self.get(proxy.SERVER_METADATA)).status, 502)

    async def test_mcp_filter_remains_exactly_three_tools(self):
        r = await self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        self.assertEqual({t['name'] for t in (await r.json())['result']['tools']}, proxy.PERMITTED_TOOLS)
        seen = len(self.seen)
        r = await self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 2,
            'method': 'tools/call', 'params': {'name': 'search'}})
        self.assertEqual((await r.json())['error']['code'], -32601)
        self.assertEqual(len(self.seen), seen)


class ConfigurationTests(unittest.TestCase):
    def test_metadata_cannot_enable_without_the_three_tool_filter(self):
        policy = proxy.OAuthDiscovery('https://issuer.example.test/api/auth',
            'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy.example.test')
        with self.assertRaises(ValueError):
            proxy.create_app(oauth_discovery=policy)

    def test_configuration_rejects_remote_plain_http_credentials_fragments_and_invalid_resource(self):
        for issuer, resource, host in (
            ('http://remote.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy'),
            ('https://user:password@issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy'),
            ('https://issuer.example.test#', 'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy'),
            ('https://issuer.example.test', 'https://resource.example.test/arbitrary', 'proxy'),
            ('https://issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=model', 'proxy'),
            ('https://issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser&connection=a&connection=b', 'proxy'),
            ('https://issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser&url=other', 'proxy'),
            ('https://issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy:invalid'),
            ('https://issuer.example.test', 'https://resource.example.test/mcp?elicitation_mode=browser', 'proxy/path')):
            with self.assertRaises(ValueError):
                proxy.OAuthDiscovery(issuer, resource, host)
