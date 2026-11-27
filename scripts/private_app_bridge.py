"""Disabled-by-default, fixed-destination JSON MCP bridge for private apps.

The explicit foreground launcher installs no service, registration or deployment.
"""
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import stat
import sys

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, web
from yarl import URL

LIMIT = 2 * 1024 * 1024


def listener_policy(subnet, gateway, port):
    network = ipaddress.IPv4Network(subnet, strict=True)
    address = ipaddress.IPv4Address(gateway)
    if (network.prefixlen != 24 or address != network.network_address + 1
            or not any(network.subnet_of(ipaddress.ip_network(net)) for net in
                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
            or type(port) is not int or not 1024 <= port <= 65535):
        raise ValueError('Listener requires a managed private /24 gateway and unprivileged port')
    return network, str(address), port


def private_file(path):
    """Read only a bounded, operator-owned regular file with mode 0600."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Private input requires an absolute path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('Private input must be operator-owned mode 0600')
        data = source.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('Private input exceeds limit')
        return data.decode()


def private_endpoint(endpoint):
    url = URL(endpoint)
    try:
        address = ipaddress.ip_address(url.host)
    except (ValueError, TypeError):
        raise ValueError('A fixed private IP endpoint is required') from None
    networks = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')
    if (url.scheme not in {'http', 'https'} or url.user is not None
            or url.query_string or url.fragment or url.path != '/mcp'
            or not any(address in ipaddress.ip_network(net) for net in networks)):
        raise ValueError('A fixed private /mcp endpoint is required')
    return url


def create_app(endpoint, inbound_token, upstream_token, read_tools, *, subnet, gateway, port,
               upstream_token_file=None):
    """Create one app; tokens are operator supplied, never read from requests.

    Use a distinct instance and credential pair for each upstream app. The owner
    must verify read scope and live trust before supplying either credential.
    """
    destination = private_endpoint(endpoint)
    network, gateway, port = listener_policy(subnet, gateway, port)
    if not isinstance(read_tools, (list, tuple)):
        raise ValueError('An explicit read tool allowlist is required')
    tools = frozenset(read_tools)
    if (not tools or any(not isinstance(name, str) or not name for name in tools)
            or any(not isinstance(token, str) or len(token) < 32
                   or not token.isascii() or any(c.isspace() for c in token)
                   for token in (inbound_token, upstream_token))
            or hmac.compare_digest(inbound_token, upstream_token)):
        raise ValueError('Separate credentials and an explicit read tool allowlist are required')
    @web.middleware
    async def boundary(request, handler):
        peer = request.transport.get_extra_info('peername') if request.transport else None
        local = request.transport.get_extra_info('sockname') if request.transport else None
        try:
            permitted = (peer and ipaddress.ip_address(peer[0]) in network
                         and local and local[:2] == (gateway, port)
                         and request.headers.getall('Host', []) == [f'{gateway}:{port}']
                         and not any(name in request.headers for name in
                                     ('Forwarded', 'X-Forwarded-For', 'X-Forwarded-Host',
                                      'X-Forwarded-Proto', 'Origin')))
        except ValueError:
            permitted = False
        if not permitted:
            return web.json_response({'error': 'Private bridge request refused'}, status=403)
        return await handler(request)

    # Parser errors can include malformed header values before middleware runs.
    # Use a dedicated silent logger, without changing process-wide logging policy.
    parser_logger = logging.Logger('private-app-http')
    parser_logger.disabled = True
    app = web.Application(client_max_size=LIMIT, middlewares=[boundary],
                          handler_args={'logger': parser_logger})
    client_key = web.AppKey('private_app_client', ClientSession)

    async def lifecycle(application):
        async with ClientSession(timeout=ClientTimeout(total=15),
                                 cookie_jar=DummyCookieJar(), trust_env=False) as client:
            application[client_key] = client
            yield

    async def forward(request):
        if (len(request.headers.getall('Authorization', [])) != 1
                or not hmac.compare_digest(request.headers.get('Authorization', '').encode(),
                                   ('Bearer ' + inbound_token).encode())):
            return web.json_response({'error': 'Unauthorized'}, status=401)
        # No browser origins, session forwarding, query destinations, or extra paths.
        if (request.query_string or request.headers.get('Origin') is not None
                or request.headers.get('Mcp-Session-Id') is not None):
            return web.json_response({'error': 'Unsupported request'}, status=400)
        try:
            message = await request.json()
            if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
                raise ValueError()
            method, params = message.get('method'), message.get('params', {})
            if not isinstance(params, dict):
                raise ValueError()
            if method not in {'initialize', 'notifications/initialized', 'tools/list', 'tools/call', 'ping'}:
                raise ValueError()
            if method == 'tools/call' and params.get('name') not in tools:
                return web.json_response({'error': 'Tool outside read scope'}, status=403)
            # Atomic issuer replacement is consumed without retaining a stale token.
            token = (private_file(upstream_token_file).strip()
                     if upstream_token_file is not None else upstream_token)
            if (len(token) < 32 or not token.isascii() or any(c.isspace() for c in token)
                    or hmac.compare_digest(token, inbound_token)):
                raise ValueError()
            headers = {'Authorization': 'Bearer ' + token,
                       'Accept': 'application/json, text/event-stream'}
            protocol = request.headers.get('MCP-Protocol-Version')
            if protocol:
                headers['MCP-Protocol-Version'] = protocol
            async with request.app[client_key].post(destination, json=message, headers=headers,
                                                     allow_redirects=False) as response:
                if response.status == 202 and 'id' not in message:
                    return web.Response(status=202)
                if response.status != 200 or response.content_type != 'application/json':
                    raise ValueError()
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw) > LIMIT:
                        raise ValueError()
                result = json.loads(raw)
                if (not isinstance(result, dict) or result.get('jsonrpc') != '2.0'
                        or result.get('id') != message.get('id') or 'error' in result
                        or not isinstance(result.get('result'), dict)
                        or response.headers.get('Mcp-Session-Id')):
                    raise ValueError()
                if method == 'tools/list':
                    catalog = result['result'].get('tools')
                    if not isinstance(catalog, list) or any(not isinstance(t, dict) for t in catalog):
                        raise ValueError()
                    result['result']['tools'] = [t for t in catalog if t.get('name') in tools]
                return web.json_response(result, headers={'Cache-Control': 'no-store'})
        except (ValueError, TypeError, OSError, ClientError, TimeoutError):
            return web.json_response({'error': 'Private MCP request failed; details omitted'}, status=502)

    app.cleanup_ctx.append(lifecycle)
    app.router.add_post('/mcp', forward)
    return app


def main():
    """Opt-in foreground listener; never installs services or registers apps."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Existing owner-private JSON configuration path')
    args = parser.parse_args()
    listener = None
    try:
        config = json.loads(private_file(args.config))
        network, gateway, port = listener_policy(config['subnet'], config['gateway'], config['port'])
        app = create_app(config['endpoint'], private_file(config['inbound_token_file']).strip(),
                         private_file(config['upstream_token_file']).strip(), config['read_tools'],
                         subnet=str(network), gateway=gateway, port=port,
                         upstream_token_file=config['upstream_token_file'])
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((gateway, port))
        listener.listen(128)
        listener.setblocking(False)
        web.run_app(app, sock=listener, access_log=None, print=None)
        return 0
    except Exception:
        # Never include config, credentials, paths or upstream errors in diagnostics.
        print('Private app bridge failed; details omitted', file=sys.stderr)
        return 1
    finally:
        if listener is not None:
            listener.close()


if __name__ == '__main__':
    raise SystemExit(main())
