#!/usr/bin/env python3
"""Normalize Executor resume discovery for connectors using regex full matches.

No request IDs, tool calls, approval decisions, or MCP sessions are changed.
Executor remains the sole authentication and approval authority.
"""
import asyncio
import json
import re
import zlib

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, web

MAX_CATALOG = 2 * 1024 * 1024
MAX_REQUEST = 16 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}
CLIENT = web.AppKey("client", ClientSession)
UPSTREAM = web.AppKey("upstream", str)


def rewrite_message(raw, identifier):
    try:
        message = json.loads(raw)
    except (ValueError, UnicodeError):
        return raw
    if not isinstance(message, dict) or message.get("id") != identifier:
        return raw
    result = message.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return raw
    changed = False
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


def rewrite_event(event, identifier):
    lines = event.splitlines(keepends=True)
    data = b"\n".join(line[5:].lstrip(b" ").rstrip(b"\r\n")
                      for line in lines if line.startswith(b"data:"))
    updated = rewrite_message(data, identifier)
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
                                    body=rewrite_message(bytes(body), message["id"]))
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
                        await downstream.write(rewrite_event(pending[:end], message["id"]))
                        pending = pending[end:]
                    if len(pending) > MAX_CATALOG:
                        raise ValueError("Catalog event limit")
                else:
                    await downstream.write(chunk)
            if pending:
                # An incomplete SSE event cannot contain a complete MCP response.
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


def create_app(upstream="http://executor:4312"):
    app = web.Application(client_max_size=MAX_REQUEST,
                          handler_args={'auto_decompress': False, 'handler_cancellation': True})
    app[UPSTREAM] = upstream
    app.cleanup_ctx.append(client_context)
    app.router.add_get("/healthz", health)
    app.router.add_route("*", "/mcp", forward)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=4313, access_log=None, print=None)
