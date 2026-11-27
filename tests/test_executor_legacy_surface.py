"""The optional beta.79 boundary preserves the existing three-tool contract."""
import gzip
import importlib.util
import json
from pathlib import Path
import unittest

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

spec = importlib.util.spec_from_file_location('schema_boundary',
    Path(__file__).resolve().parents[1] / 'scripts/executor_schema_proxy.py')
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)
BETA79_NAMES = ('call', 'describe', 'execute', 'resume', 'search', 'skills')


def catalog(names=None):
    return {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [
        {'name': name, 'inputSchema': {'type': 'object'}}
        for name in (BETA79_NAMES if names is None else names)]}}


class BoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.seen = []
        self.names = list(BETA79_NAMES)
        self.content_type = 'application/json'

        async def upstream(request):
            raw = await request.read()
            if request.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            message = json.loads(raw)
            self.seen.append((dict(request.headers), message))
            if message['method'] == 'tools/list':
                return web.Response(text=json.dumps(catalog(self.names)), content_type=self.content_type)
            return web.json_response({'jsonrpc': '2.0', 'id': message['id'],
                                      'result': {'status': 'approval-required', 'requestId': 'apr_fixture'}})

        app = web.Application(handler_args={'auto_decompress': False})
        app.router.add_post('/mcp', upstream)
        self.upstream = TestServer(app)
        await self.upstream.start_server()
        self.client = TestClient(TestServer(proxy.create_app(
            str(self.upstream.make_url('')).rstrip('/'), legacy_surface=True)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream.close()

    async def test_exact_permitted_catalog_and_upstream_negative_controls(self):
        async def listing():
            return await self.client.post('/mcp', json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        response = await listing()
        self.assertEqual({t['name'] for t in (await response.json())['result']['tools']},
                         {'execute', 'resume', 'skills'})
        for names in (['execute', 'resume', 'skills'],
                      list(BETA79_NAMES) + ['unexpected'],
                      list(BETA79_NAMES) + ['execute']):
            self.names = names
            self.assertEqual((await listing()).status, 502)
        self.names = list(BETA79_NAMES)
        self.content_type = 'text/plain'
        self.assertEqual((await listing()).status, 502)

    async def test_hidden_tools_and_batches_cannot_bypass_boundary(self):
        for name in ('search', 'describe', 'call', 'unexpected', {}):
            response = await self.client.post('/mcp', json={
                'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': name}})
            self.assertEqual((await response.json())['error']['code'], -32601)
        message = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'call'}}
        response = await self.client.post('/mcp', data=gzip.compress(json.dumps(message).encode()),
                                          headers={'Content-Encoding': 'gzip'})
        self.assertEqual((await response.json())['error']['code'], -32601)
        self.assertEqual((await self.client.post('/mcp', json=[message])).status, 400)
        self.assertEqual((await self.client.post('/mcp', json={
            'jsonrpc': '2.0', 'method': 'tools/list'})).status, 400)
        self.assertEqual(self.seen, [])

    async def test_allowed_resume_preserves_auth_session_arguments_and_approval(self):
        message = {'jsonrpc': '2.0', 'id': 9, 'method': 'tools/call',
                   'params': {'name': 'resume', 'arguments': {'requestId': 'apr_fixture'}}}
        response = await self.client.post('/mcp?elicitation_mode=browser', json=message,
            headers={'Authorization': 'Bearer fixture', 'Mcp-Session-Id': 'fixture-session'})
        result = await response.json()
        self.assertEqual(result['result']['status'], 'approval-required')
        self.assertEqual(self.seen[0][1], message)
        self.assertEqual(self.seen[0][0]['Authorization'], 'Bearer fixture')
        self.assertEqual(self.seen[0][0]['Mcp-Session-Id'], 'fixture-session')

    async def test_sse_catalog_has_same_strict_filter_and_keeps_event_metadata(self):
        event = b'id: fixture\nevent: message\ndata: ' + json.dumps(catalog()).encode() + b'\n\n'
        changed = proxy.rewrite_event(event, 1, True)
        self.assertTrue(changed.startswith(b'id: fixture\nevent: message\n'))
        data = json.loads(next(line[6:] for line in changed.splitlines() if line.startswith(b'data: ')))
        self.assertEqual({t['name'] for t in data['result']['tools']}, proxy.PERMITTED_TOOLS)
        invalid = catalog()
        invalid['id'] = 99
        with self.assertRaises(ValueError):
            proxy.rewrite_message(json.dumps(invalid).encode(), 1, True)
