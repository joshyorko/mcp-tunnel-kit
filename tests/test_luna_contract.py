"""Luna's model view must not expose app-only controls or alter safety hints."""
import importlib.util
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

ROOT = Path(__file__).resolve().parents[1]
READS = {'list_factory_runs', 'get_factory_run', 'get_factory_capabilities'}
MUTATIONS = {'start_factory', 'steer_factory_run', 'cancel_factory_run', 'resume_factory_run'}
APP_ONLY = {'open_factory', 'open_factory_panel', 'refresh_factory', 'read_factory_settings', 'update_factory_settings'}


def helper():
    path = ROOT / 'scripts/luna_bridge.py'
    assert path.is_file(), 'The Luna transport and model view are missing'
    spec = importlib.util.spec_from_file_location('luna_bridge', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog():
    return [{'name': name, 'inputSchema': {'type': 'object'},
             'annotations': {'readOnlyHint': True, 'destructiveHint': False},
             '_meta': {'ui': {'visibility': ['app']}} if name in APP_ONLY else {}}
            for name in READS | MUTATIONS | APP_ONLY]


def test_model_view_hides_app_only_and_unknown_names_and_normalizes_hints():
    module = helper()
    original = catalog() + [{'name': 'future_tool'}]
    result = module.model_catalog(original)
    assert {t['name'] for t in result} == READS | MUTATIONS
    for tool in result:
        assert tool['annotations']['readOnlyHint'] is (tool['name'] in READS)
        assert tool['annotations']['destructiveHint'] is (tool['name'] in MUTATIONS)
    assert original == catalog() + [{'name': 'future_tool'}]


def test_model_view_rejects_incomplete_duplicate_or_reclassified_catalog():
    module = helper()
    for tools in ([t for t in catalog() if t["name"] != "start_factory"], catalog() + [catalog()[0]]):
        with pytest.raises(module.control.ControlError):
            module.model_catalog(tools)
    tools = catalog()
    next(t for t in tools if t['name'] == 'start_factory')['_meta'] = {'ui': {'visibility': ['app']}}
    with pytest.raises(module.control.ControlError):
        module.model_catalog(tools)


def test_upstream_must_be_numeric_loopback_without_credentials_or_redirects():
    module = helper()
    assert module.upstream_origin('http://127.0.0.1:8787/mcp') == 'http://127.0.0.1:8787'
    for url in ('http://0.0.0.0:8787/mcp', 'http://172.30.86.1:8787/mcp',
                'http://localhost:8787/mcp', 'http://user:pass@127.0.0.1:8787/mcp',
                'http://127.0.0.1:8787/mcp?q=x', 'http://127.0.0.1:8787/other'):
        with pytest.raises(module.control.ControlError):
            module.upstream_origin(url)


def test_luna_import_uses_existing_app_identity_without_touching_other_apps():
    import compose_control as control
    from mcp_fixtures import LoopbackServer
    from test_compose_control import INDEX
    apps = [{'name': n, 'slug': n.lower(), 'id': n.lower(), 'activeDeployment': 'retained'}
            for n in ('Codex', 'Devsy')]
    posts = []
    url = 'http://172.30.86.1:8090/executor/mcp'
    def dispatch(method, path, headers, body):
        if path == '/api/context':
            return 200, {'organization': 'fixture_org'}, False
        if path.endswith('/inventory'):
            return 200, {'apps': apps}, False
        if method == 'POST' and path.endswith('/apps/import'):
            posts.append(body)
            app = {'name': 'LunaFactory', 'slug': 'lunafactory', 'id': 'fixture_luna', 'activeDeployment': 'fixture_deploy'}
            apps.append(app)
            return 200, app, False
        if path == '/api/organizations/fixture_org/apps/fixture_luna/source':
            return 200, {'files': [{'path': 'index.ts', 'content': INDEX.replace('http://172.30.86.1:8088/mcp', url)}]}, False
        return 404, {}, False
    server = LoopbackServer(dispatch)
    try:
        original = [dict(app) for app in apps]
        receipt = control.ensure_mcp_app(control.Http(server.url), url, 'LunaFactory')
        for _ in range(2):
            assert control.ensure_mcp_app(control.Http(server.url), url, 'LunaFactory', receipt) == receipt
        assert apps[:2] == original
        assert len(posts) == 1
    finally:
        server.close()


def test_http_model_route_keeps_run_ids_and_forwards_exactly_once():
    import compose_control as control
    from luna_fixture import adapter, synthetic_runtime, RUN
    with synthetic_runtime() as (upstream, calls, requests), adapter(upstream) as url:
        session = control.Mcp(control.Http(url.removesuffix('/executor/mcp')), '/executor/mcp')
        tools = session.tools()
        assert {tool['name'] for tool in tools} == READS | MUTATIONS
        result = session.call('tools/call', {'name': 'get_factory_run', 'arguments': {'run_id': RUN['id']}})
        assert result['structuredContent'] == RUN
        assert result['_meta'] == {'fixture': 'same-runtime'}
        args = {'run_id': RUN['id'], 'expected_turn_id': 'fixture-turn', 'message': 'Synthetic only'}
        session.call('tools/call', {'name': 'steer_factory_run', 'arguments': args})
        assert calls == [{'name': 'get_factory_run', 'arguments': {'run_id': RUN['id']}},
                         {'name': 'steer_factory_run', 'arguments': args}]
        for request in requests:
            headers = {key.lower(): value for key, value in request['headers'].items()}
            assert headers['host'] == upstream.origin.removeprefix('http://')
            assert headers['mcp-protocol-version'] == '2026-07-28'
            assert headers['mcp-method'] == request['body']['method']
            assert 'authorization' not in headers and 'cookie' not in headers and 'origin' not in headers


def test_http_app_only_unknown_and_resource_calls_never_reach_runtime():
    import compose_control as control
    from luna_fixture import adapter, synthetic_runtime
    with synthetic_runtime() as (upstream, calls, requests), adapter(upstream) as url:
        session = control.Mcp(control.Http(url.removesuffix('/executor/mcp')), '/executor/mcp')
        count = len(requests)
        for name in APP_ONLY | {'future_tool', '__proto__'}:
            with pytest.raises(control.ControlError):
                session.call('tools/call', {'name': name, 'arguments': {}})
        for method, params in [('resources/list', {}), ('resources/read', {'uri': helper().APP_URI})]:
            with pytest.raises(control.ControlError):
                session.call(method, params)
        assert len(requests) == count
        assert calls == []


def test_http_origin_host_path_and_framing_guards_run_before_forwarding():
    import urllib.request
    import urllib.error
    import json
    from luna_fixture import adapter, synthetic_runtime
    with synthetic_runtime() as (upstream, calls, requests), adapter(upstream) as url:
        for target, headers in [(url, {'Origin': 'https://evil.example'}),
                                (url, {'Host': 'evil.example'}),
                                (url.replace('/executor/mcp', '/mcp'), {}),
                                (url + '?url=http://evil.example', {}),
                                (url, {'Transfer-Encoding': 'chunked'})]:
            request = urllib.request.Request(target, json.dumps({'jsonrpc': '2.0', 'id': 1,
                'method': 'tools/list'}).encode(), {'Content-Type': 'application/json', **headers})
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(request, timeout=2)
        assert requests == []


def test_uncertain_mutation_is_not_replayed():
    import compose_control as control
    from luna_fixture import adapter
    calls = []
    class FailingRuntime:
        def call(self, name, arguments):
            calls.append((name, arguments))
            raise TimeoutError('Synthetic uncertain dispatch')
    with adapter(FailingRuntime()) as url:
        response, _ = control.Http(url.removesuffix('/executor/mcp')).request('POST', '/executor/mcp', {
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'cancel_factory_run', 'arguments': {'run_id': 'fixture-run'}},
        })
        assert 'error' in response
        assert len(calls) == 1
        assert 'Reconcile' in response['error']['message']
