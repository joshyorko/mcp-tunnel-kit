"""Consumer validation and real HTTP/session forwarding regressions."""
import asyncio
import gzip
import importlib.util
import json
from pathlib import Path
import re
import unittest

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("schema_proxy", ROOT / "scripts/executor_schema_proxy.py")
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


def catalog():
    return {"jsonrpc": "2.0", "id": 2, "result": {"tools": [
        {"name": "resume", "inputSchema": {"type": "object", "properties": {
            "requestId": {"anyOf": [
                {"type": "string", "pattern": "^apr_", "minLength": 5},
                {"type": "string", "pattern": "^elc_", "minLength": 5}]}},
            "required": ["requestId"], "additionalProperties": True}},
        {"name": "execute", "inputSchema": {"pattern": "^apr_"}}]}}


class SchemaTests(unittest.TestCase):
    def test_full_match_connector_accepts_exactly_the_original_prefix_language(self):
        original = catalog()
        updated = json.loads(proxy.rewrite_message(json.dumps(original).encode(), 2))
        old_variants = original["result"]["tools"][0]["inputSchema"]["properties"]["requestId"]["anyOf"]
        new_variants = updated["result"]["tools"][0]["inputSchema"]["properties"]["requestId"]["anyOf"]
        for value in ["apr_11111111-2222-4333-8444-555555555555", "elc_example", "apr_a\nb",
                      "apr_", "elc_", "wrong", " apr_example", "xapr_example"]:
            for before, after in zip(old_variants, new_variants):
                with self.subTest(value=value, pattern=before["pattern"]):
                    expected = len(value) >= before["minLength"] and bool(re.search(before["pattern"], value))
                    actual = len(value) >= after["minLength"] and bool(re.fullmatch(after["pattern"], value))
                    self.assertEqual(actual, expected)
        for before, after in zip(old_variants, new_variants):
            after["pattern"] = before["pattern"]
        self.assertEqual(updated, original)

    def test_unrelated_or_unrecognized_messages_remain_byte_identical(self):
        cases = [b'{"id":1,"result":{"status":"approval-required","requestId":"apr_pending"}}',
                 b'{"method":"notifications/message","params":{"pattern":"^apr_"}}',
                 json.dumps(catalog()).encode(), b'not json']
        for raw in cases:
            self.assertEqual(proxy.rewrite_message(raw, 99), raw)


class ProductionServer(TestServer):
    async def _make_runner(self, **kwargs):
        # TestServer forces cancellation on. Exercise the application's own setting.
        kwargs.pop('handler_cancellation', None)
        return web.AppRunner(self.app, **kwargs)


class ForwardingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.mode = "json"
        self.release = asyncio.Event()
        self.upstream_closed = asyncio.Event()

        async def upstream(request):
            raw = await request.read()
            self.requests.append((request.method, request.raw_path, dict(request.headers), raw))
            if request.headers.get("Authorization") != "Bearer fixture":
                return web.Response(status=401, body=b"unauthorized")
            if self.mode == "redirect":
                return web.Response(status=307, headers={"Location": "http://example.invalid/private"})
            if self.mode == "sse":
                response = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "original-session"})
                await response.prepare(request)
                data = b': keepalive\r\nid: cursor\r\nevent: message\r\ndata: ' + json.dumps(catalog()).encode() + b'\r\n\r\n'
                await response.write(data[:37])
                await response.write(data[37:])
                try:
                    await self.release.wait()
                finally:
                    self.upstream_closed.set()
                return response
            decoded = gzip.decompress(raw) if request.headers.get('Content-Encoding') == 'gzip' else raw
            payload = json.loads(decoded) if decoded else {}
            result = catalog() if payload.get("method") == "tools/list" else {
                "jsonrpc": "2.0", "id": payload.get("id"), "result": {
                    "status": "approval-required", "requestId": "apr_pending",
                    "approvalUrl": "http://executor/approval/fixture"}}
            return web.json_response(result, headers={"Mcp-Session-Id": "original-session", "Set-Cookie": "private=fixture"})

        app = web.Application(handler_args={'auto_decompress': False})
        app.router.add_route("*", "/mcp", upstream)
        self.upstream = TestServer(app)
        await self.upstream.start_server()
        self.front = ProductionServer(proxy.create_app(str(self.upstream.make_url("")).rstrip("/")))
        await self.front.start_server()
        self.client = ClientSession()

    async def asyncTearDown(self):
        self.release.set()
        await self.client.close()
        await self.front.close()
        await self.upstream.close()

    async def post(self, payload, **kwargs):
        headers = {"Authorization": "Bearer fixture", "Mcp-Session-Id": "original-session", "MCP-Protocol-Version": "2025-11-25"}
        return await self.client.post(self.front.make_url("/mcp?elicitation_mode=browser"),
                                      data=payload, headers=headers, **kwargs)

    async def test_discovery_rewrites_schema_and_resume_keeps_original_request_and_session(self):
        response = await self.post(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
        result = await response.json()
        pattern = result["result"]["tools"][0]["inputSchema"]["properties"]["requestId"]["anyOf"][0]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "apr_valid"))
        self.assertEqual(response.headers["Mcp-Session-Id"], "original-session")
        raw = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resume","arguments":{"requestId":"apr_pending"}}}'
        response = await self.post(raw)
        self.assertEqual((await response.json())["result"]["status"], "approval-required")
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path, body), ("POST", "/mcp?elicitation_mode=browser", raw))
        self.assertEqual(headers["Mcp-Session-Id"], "original-session")
        self.assertEqual(headers["MCP-Protocol-Version"], "2025-11-25")
        self.assertEqual(headers["Authorization"], "Bearer fixture")
        self.assertNotIn("Cookie", headers)

    async def test_sse_discovery_does_not_wait_for_stream_close_and_preserves_event_metadata(self):
        self.mode = "sse"
        response = await self.post(b'{"id":2,"method":"tools/list"}')
        async def event():
            lines = []
            while True:
                line = await response.content.readline()
                lines.append(line)
                if line in (b'\n', b'\r\n'):
                    return b''.join(lines)
        data = await asyncio.wait_for(event(), 2)
        self.assertIn(b'id: cursor', data)
        self.assertIn(b': keepalive', data)
        payload = json.loads(next(line[5:].strip() for line in data.splitlines() if line.startswith(b'data:')))
        self.assertIn('[\\s\\S]*$', payload['result']['tools'][0]['inputSchema']['properties']['requestId']['anyOf'][0]['pattern'])
        response.close()

    async def test_auth_rejection_and_redirects_are_not_bypassed(self):
        response = await self.client.post(self.front.make_url('/mcp'), data=b'{}')
        self.assertEqual(response.status, 401)
        self.assertEqual(await response.read(), b'unauthorized')
        self.mode = 'redirect'
        response = await self.post(b'{}', allow_redirects=False)
        self.assertEqual(response.status, 307)
        self.assertEqual(len(self.requests), 2)

    async def test_other_paths_are_not_proxied(self):
        response = await self.client.get(self.front.make_url('/api/private'))
        self.assertEqual(response.status, 404)
        self.assertEqual(self.requests, [])

    async def test_get_delete_and_reconnect_headers_keep_session_identity(self):
        for method in ('GET', 'DELETE'):
            async with self.client.request(method, self.front.make_url('/mcp?elicitation_mode=browser'),
                    headers={'Authorization': 'Bearer fixture', 'Mcp-Session-Id': 'original-session',
                             'Last-Event-ID': 'event-cursor'}) as response:
                await response.read()
                self.assertEqual(response.status, 200)
            verb, path, headers, body = self.requests[-1]
            self.assertEqual((verb, path, body), (method, '/mcp?elicitation_mode=browser', b''))
            self.assertEqual(headers['Mcp-Session-Id'], 'original-session')
            self.assertEqual(headers['Last-Event-ID'], 'event-cursor')

    async def test_compressed_body_is_forwarded_without_decompression(self):
        body = gzip.compress(b'{"id":2,"method":"tools/list"}')
        async with self.client.post(self.front.make_url('/mcp'), data=body,
                headers={'Authorization': 'Bearer fixture', 'Content-Encoding': 'gzip'},
                allow_redirects=False) as response:
            self.assertEqual(response.status, 200)
            result = await response.json()
            pattern = result['result']['tools'][0]['inputSchema']['properties']['requestId']['anyOf'][0]['pattern']
            self.assertIsNotNone(re.fullmatch(pattern, 'apr_compressed'))
        self.assertEqual(self.requests[-1][3], body)
        self.assertEqual(self.requests[-1][2]['Content-Encoding'], 'gzip')

    async def test_disconnect_releases_idle_upstream_stream(self):
        self.mode = 'sse'
        response = await self.post(b'{"id":3,"method":"tools/call"}')
        await response.content.readline()
        response.close()
        await asyncio.wait_for(self.upstream_closed.wait(), 2)
