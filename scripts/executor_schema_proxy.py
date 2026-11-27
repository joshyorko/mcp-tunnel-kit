#!/usr/bin/env python3
"""Normalize Executor resume discovery for connectors using regex full matches.

No request IDs, tool calls, approval decisions, or MCP sessions are changed.
Executor remains the sole authentication and approval authority.
"""
import asyncio
import json
import os
import re
import zlib
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, web

MAX_CATALOG = 2 * 1024 * 1024
MAX_REQUEST = 16 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}
CLIENT = web.AppKey("client", ClientSession)
UPSTREAM = web.AppKey("upstream", str)
LEGACY_SURFACE = web.AppKey("legacy_surface", bool)
PERMITTED_TOOLS = frozenset({'execute', 'resume', 'skills'})
BETA79_TOOLS = PERMITTED_TOOLS | {'call', 'describe', 'search'}
OAUTH_DISCOVERY = web.AppKey('oauth_discovery', object)
RESOURCE_METADATA = '/.well-known/oauth-protected-resource/mcp'
SERVER_METADATA = '/.well-known/oauth-authorization-server'
OAUTH_ENDPOINTS = {
    'authorization_endpoint': '/api/auth/oauth2/authorize',
    'token_endpoint': '/api/auth/oauth2/token',
    'registration_endpoint': '/api/auth/oauth2/register',
    'revocation_endpoint': '/api/auth/oauth2/revoke',
    'introspection_endpoint': '/api/auth/oauth2/introspect',
    'device_authorization_endpoint': '/api/auth/oauth2/device-authorization',
    'jwks_uri': '/api/auth/jwks',
}


def oauth_origin(value):
    parsed = urlsplit(value)
    if (any(c.isspace() or c in '#\\' for c in value)
            or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.scheme not in {'https', 'http'}
            or (parsed.scheme == 'http' and parsed.hostname not in {'127.0.0.1', '::1', 'localhost'})):
        raise ValueError('Invalid OAuth identity URL')
    _ = parsed.port
    return parsed.scheme + '://' + parsed.netloc


@dataclass(frozen=True)
class OAuthDiscovery:
    issuer: str
    resource: str
    host: str

    def __post_init__(self):
        oauth_origin(self.issuer)
        oauth_origin(self.resource)
        if (urlsplit(self.issuer).query or urlsplit(self.resource).path != '/mcp'
                or not self.host or any(c in self.host for c in '/?#@\\ \t\r\n')
                or urlsplit('http://' + self.host).netloc != self.host):
            raise ValueError('Invalid OAuth discovery configuration')
        host = urlsplit('http://' + self.host)
        if not host.hostname:
            raise ValueError('Invalid OAuth discovery host')
        _ = host.port
        query = parse_qsl(urlsplit(self.resource).query, keep_blank_values=True, strict_parsing=True)
        if (len(dict(query)) != len(query) or set(dict(query)) - {'connection', 'elicitation_mode'}
                or dict(query).get('elicitation_mode') != 'browser'
                or ('connection' in dict(query) and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', dict(query)['connection']))):
            raise ValueError('Invalid OAuth resource address')

    def target(self, path):
        query = urlsplit(self.resource).query if path == RESOURCE_METADATA else ''
        return path + ('?' + query if query else '')

    def validate(self, path, document):
        if (not isinstance(document, dict) or 'signed_metadata' in document
                or 'mtls_endpoint_aliases' in document):
            raise ValueError('Invalid OAuth metadata')
        if path == RESOURCE_METADATA:
            if (set(document) - {'resource', 'authorization_servers', 'scopes_supported',
                                 'bearer_methods_supported', 'resource_name'}
                    or document.get('resource') != self.resource
                    or document.get('authorization_servers') != [self.issuer]
                    or document.get('bearer_methods_supported') != ['header']):
                raise ValueError('Unexpected OAuth resource identity')
        else:
            if document.get('issuer') != self.issuer:
                raise ValueError('Unexpected OAuth issuer')
            origin = oauth_origin(self.issuer)
            for key in ('authorization_endpoint', 'token_endpoint', 'registration_endpoint'):
                if key not in document:
                    raise ValueError('Incomplete OAuth server metadata')
            for key, value in document.items():
                if key.endswith('_endpoint') or key == 'jwks_uri':
                    if key not in OAUTH_ENDPOINTS or value != origin + OAUTH_ENDPOINTS[key]:
                        raise ValueError('Unexpected OAuth endpoint')


def metadata_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate OAuth metadata field')
        result[key] = value
    return result


async def oauth_metadata(request):
    policy = request.app[OAUTH_DISCOVERY]
    if (request.raw_path != policy.target(request.path)
            or request.headers.getall('Host', []) != [policy.host]
            or request.can_read_body):
        return web.Response(status=400)
    if (any(key.lower() in {'authorization', 'cookie', 'forwarded'}
            or key.lower().startswith('x-forwarded-') for key in request.headers)
            or ('Origin' in request.headers and request.headers.getall('Origin') not in
                [[oauth_origin(policy.issuer)], [oauth_origin(policy.resource)]])):
        return web.Response(status=403)
    try:
        async with request.app[CLIENT].get(
                request.app[UPSTREAM] + policy.target(request.path),
                headers={'Accept': 'application/json', 'Accept-Encoding': 'identity'},
                allow_redirects=False, timeout=ClientTimeout(total=10)) as response:
            if (response.status != 200 or response.content_type != 'application/json'
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                raise ValueError('Invalid OAuth metadata response')
            body = bytearray()
            async for chunk in response.content.iter_any():
                body.extend(chunk)
                if len(body) > 65536:
                    raise ValueError('OAuth metadata limit')
            document = json.loads(bytes(body), object_pairs_hook=metadata_object)
            policy.validate(request.path, document)
        return web.json_response(document, headers={'Cache-Control': 'no-store'})
    except (ClientError, asyncio.TimeoutError, ValueError, UnicodeError):
        return web.Response(status=502, text='OAuth metadata unavailable')


def rewrite_message(raw, identifier, legacy_surface=False):
    try:
        message = json.loads(raw)
    except (ValueError, UnicodeError):
        if legacy_surface:
            raise ValueError('Invalid upstream catalog') from None
        return raw
    if legacy_surface and (not isinstance(message, dict) or message.get('jsonrpc') != '2.0'):
        raise ValueError('Invalid upstream catalog')
    if not isinstance(message, dict) or message.get("id") != identifier:
        if legacy_surface and 'method' not in message:
            raise ValueError('Mismatched upstream catalog')
        return raw
    result = message.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        if legacy_surface:
            raise ValueError('Invalid upstream catalog')
        return raw
    changed = False
    if legacy_surface:
        catalog = result['tools']
        names = [tool.get('name') for tool in catalog if isinstance(tool, dict)]
        if (not all(isinstance(name, str) for name in names)
                or len(names) != len(catalog) or len(names) != len(BETA79_TOOLS)
                or set(names) != BETA79_TOOLS):
            raise ValueError('Unexpected upstream tool surface')
        result['tools'] = [tool for tool in catalog if tool['name'] in PERMITTED_TOOLS]
        changed = True
    for tool in result["tools"]:
        if not isinstance(tool, dict) or tool.get("name") != "resume":
            continue
        schema = tool.get("inputSchema", {}).get("properties", {}).get("requestId", {})
        for variant in schema.get("anyOf", [schema]):
            if variant.get("type") == "string" and variant.get("pattern") in {"^apr_", "^elc_"}:
                # [\s\S] includes newlines: preserve the original prefix language.
                variant["pattern"] += r"[\s\S]*$"
                changed = True
    return json.dumps(message, separators=(",", ":")).encode() if changed else raw


def rewrite_event(event, identifier, legacy_surface=False):
    lines = event.splitlines(keepends=True)
    if not any(line.startswith(b'data:') for line in lines):
        return event
    data = b"\n".join(line[5:].lstrip(b" ").rstrip(b"\r\n")
                      for line in lines if line.startswith(b"data:"))
    updated = rewrite_message(data, identifier, legacy_surface)
    if updated == data:
        return event
    result, inserted = [], False
    for line in lines:
        if line.startswith(b"data:"):
            if not inserted:
                result.append(b"data: " + updated + b"\n")
                inserted = True
        else:
            result.append(line)
    return b"".join(result)


def end_to_end_headers(headers, *extra):
    excluded = HOP_HEADERS | {name.strip().lower() for name in headers.get("Connection", "").split(",")} | set(extra)
    return [(name, value) for name, value in headers.items() if name.lower() not in excluded]


async def forward(request):
    raw = await request.read()
    try:
        inspected = raw
        encoding = request.headers.get('Content-Encoding', 'identity').lower()
        if encoding in {'gzip', 'deflate'}:
            decoder = zlib.decompressobj(31 if encoding == 'gzip' else 15)
            inspected = decoder.decompress(raw, MAX_REQUEST + 1)
            if not decoder.eof or len(inspected) > MAX_REQUEST:
                inspected = b''
        message = json.loads(inspected) if inspected else None
    except (ValueError, UnicodeError, zlib.error):
        message = None
    legacy_surface = request.app[LEGACY_SURFACE]
    if legacy_surface and request.method == 'POST':
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            return web.Response(status=400, text='Invalid MCP request')
        if message.get('method') == 'tools/list' and 'id' not in message:
            return web.Response(status=400, text='Invalid MCP discovery request')
        if message.get('method') == 'tools/call':
            params = message.get('params')
            if (not isinstance(params, dict) or not isinstance(params.get('name'), str)
                    or params['name'] not in PERMITTED_TOOLS):
                return web.json_response({'jsonrpc': '2.0', 'id': message.get('id'),
                    'error': {'code': -32601, 'message': 'Tool outside permitted surface'}})
    discovery = (request.method == "POST" and isinstance(message, dict)
                 and message.get("method") == "tools/list" and "id" in message)
    headers = end_to_end_headers(request.headers, "host", "content-length", "accept-encoding")
    headers.append(("Accept-Encoding", "identity"))
    downstream = None
    try:
        async with request.app[CLIENT].request(
            request.method, request.app[UPSTREAM] + request.raw_path,
            data=raw, headers=headers, allow_redirects=False,
        ) as upstream:
            transform = discovery and upstream.status == 200
            if (transform and legacy_surface and upstream.content_type not in
                    {'application/json', 'text/event-stream'}):
                raise ValueError('Unsupported upstream catalog encoding')
            response_headers = end_to_end_headers(upstream.headers, *(
                ("content-length", "etag", "content-md5") if transform else ()))
            if transform and upstream.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("Unexpected catalog encoding")
            if transform and upstream.content_type == "application/json":
                body = bytearray()
                async for chunk in upstream.content.iter_any():
                    body.extend(chunk)
                    if len(body) > MAX_CATALOG:
                        raise ValueError("Catalog limit")
                return web.Response(status=upstream.status, headers=response_headers,
                                    body=rewrite_message(bytes(body), message["id"], legacy_surface))
            downstream = web.StreamResponse(status=upstream.status, headers=response_headers)
            await downstream.prepare(request)
            pending = b""
            async for chunk in upstream.content.iter_any():
                if transform and upstream.content_type == "text/event-stream":
                    pending += chunk
                    while boundary := re.search(br"\r?\n\r?\n", pending):
                        end = boundary.end()
                        if end > MAX_CATALOG:
                            raise ValueError("Catalog event limit")
                        await downstream.write(rewrite_event(pending[:end], message["id"], legacy_surface))
                        pending = pending[end:]
                    if len(pending) > MAX_CATALOG:
                        raise ValueError("Catalog event limit")
                else:
                    await downstream.write(chunk)
            if pending:
                # An incomplete SSE event cannot contain a complete MCP response.
                if transform and legacy_surface:
                    raise ValueError('Incomplete upstream catalog event')
                await downstream.write(pending)
            await downstream.write_eof()
            return downstream
    except (ClientError, asyncio.TimeoutError, ValueError, ConnectionError):
        if downstream is not None and downstream.prepared:
            if request.transport is not None:
                request.transport.close()
            return downstream
        return web.Response(status=502, text="Executor transport unavailable")


async def client_context(app):
    async with ClientSession(cookie_jar=DummyCookieJar(), auto_decompress=False,
                             timeout=ClientTimeout(total=None, sock_connect=10)) as client:
        app[CLIENT] = client
        yield


async def health(_request):
    return web.Response(text="ok")


def create_app(upstream="http://executor:4312", *, legacy_surface=False, oauth_discovery=None):
    if oauth_discovery is not None and not legacy_surface:
        raise ValueError('OAuth discovery requires the three-tool boundary')
    app = web.Application(client_max_size=MAX_REQUEST,
                          handler_args={'auto_decompress': False, 'handler_cancellation': True})
    app[UPSTREAM] = upstream
    app[LEGACY_SURFACE] = legacy_surface
    app.cleanup_ctx.append(client_context)
    app.router.add_get("/healthz", health)
    app.router.add_route("*", "/mcp", forward)
    if oauth_discovery is not None:
        if not isinstance(oauth_discovery, OAuthDiscovery):
            raise ValueError('Invalid OAuth discovery policy')
        app[OAUTH_DISCOVERY] = oauth_discovery
        for path in (RESOURCE_METADATA, SERVER_METADATA):
            app.router.add_get(path, oauth_metadata, allow_head=False)
    return app


if __name__ == "__main__":
    setting = os.environ.get('EXECUTOR_SCHEMA_BETA79_LEGACY_SURFACE', '0')
    if setting not in {'0', '1'}:
        raise ValueError('Invalid Executor surface setting')
    values = [os.environ.get('EXECUTOR_SCHEMA_OAUTH_' + key) for key in ('ISSUER', 'RESOURCE', 'HOST')]
    policy = OAuthDiscovery(*values) if all(values) else None
    if any(value is not None for value in values) and not all(values):
        raise ValueError('Incomplete OAuth discovery policy')
    web.run_app(create_app(legacy_surface=setting == '1', oauth_discovery=policy), host="0.0.0.0", port=4313,
                access_log=None, print=None)
