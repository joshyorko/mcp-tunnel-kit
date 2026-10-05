"""Operator setup must preserve other apps, receipts, and pending approvals."""
import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import compose_control as control
import luna_bridge as bridge
from luna_fixture import contract
from mcp_fixtures import LoopbackServer


def test_luna_url_requires_exact_private_gateway_and_adapter_route():
    assert control.luna_url('172.30.86.1') == 'http://172.30.86.1:8090/executor/mcp'
    for gateway in ('127.0.0.1', '0.0.0.0', '8.8.8.1', '172.30.86.2', 'localhost', '172.30.86.1/x'):
        with pytest.raises(control.ControlError):
            control.luna_url(gateway)


def test_luna_catalog_requires_exact_model_tools_and_truthful_hints():
    tools = bridge.model_catalog(contract()['tools'])
    control.verify_luna_catalog(tools)
    for bad in (tools[:-1], tools + [{'name': 'open_factory'}], tools + [tools[0]]):
        with pytest.raises(control.ControlError):
            control.verify_luna_catalog(bad)
    tools[0]['annotations']['readOnlyHint'] = not tools[0]['annotations']['readOnlyHint']
    with pytest.raises(control.ControlError):
        control.verify_luna_catalog(tools)


def test_verify_only_never_imports_a_missing_app():
    requests = []
    def dispatch(method, path, headers, body):
        requests.append((method, path))
        return 200, ({'organization': 'fixture'} if path == '/api/context' else {'apps': []}), False
    server = LoopbackServer(dispatch)
    try:
        with pytest.raises(control.ControlError, match='missing'):
            control.ensure_mcp_app(control.Http(server.url), 'http://172.30.86.1:8090/executor/mcp',
                                   'LunaFactory', allow_import=False)
        assert all(method == 'GET' for method, _ in requests)
    finally:
        server.close()


def test_read_only_verification_never_migrates_legacy_codex_source():
    from test_compose_control import INDEX, CODEX_INDEX
    requests, migrated = [], False
    app = {'id': 'codex', 'name': 'Codex', 'slug': 'codex', 'activeDeployment': 'old'}
    def dispatch(method, path, headers, body):
        nonlocal migrated
        requests.append((method, path))
        if path == '/api/context':
            return 200, {'organization': 'fixture'}, False
        if path.endswith('/inventory'):
            return 200, {'apps': [app]}, False
        if path.endswith('/source'):
            return 200, {'files': [{'path': 'index.ts', 'content': CODEX_INDEX if migrated else INDEX}]}, False
        if method == 'POST' and path.endswith('/deploy'):
            migrated = True
            return 200, {'app': {**app, 'activeDeployment': 'new'}}, False
        return 200, {**app, 'activeDeployment': 'new' if migrated else 'old'}, False
    server = LoopbackServer(dispatch)
    try:
        with pytest.raises(control.ControlError, match='read-only'):
            control.ensure_mcp_app(control.Http(server.url), 'http://172.30.86.1:8088/mcp',
                                   'Codex', allow_import=False)
        assert all(method == 'GET' for method, _ in requests)
    finally:
        server.close()


@pytest.mark.parametrize('name', ['Devsy', 'LunaFactory'])
def test_only_codex_accepts_the_ungated_source(name):
    from test_compose_control import CODEX_INDEX
    writes = []
    app = {'id': name.lower(), 'name': name, 'slug': name.lower(), 'activeDeployment': 'retained'}
    def dispatch(method, path, headers, body):
        if method != 'GET':
            writes.append(body)
        if path == '/api/context':
            return 200, {'organization': 'fixture'}, False
        if path.endswith('/inventory'):
            return 200, {'apps': [app]}, False
        return 200, {'files': [{'path': 'index.ts', 'content': CODEX_INDEX}]}, False
    server = LoopbackServer(dispatch)
    try:
        with pytest.raises(control.ControlError):
            control.ensure_mcp_app(control.Http(server.url), 'http://172.30.86.1:8088/mcp', name)
        assert writes == []
    finally:
        server.close()


@pytest.mark.parametrize('import_allowed', [False, True])
def test_operator_preserves_pending_and_other_receipts(tmp_path, monkeypatch, import_allowed):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    receipt = {'organization': 'fixture', 'id': 'luna', 'url': 'http://172.30.86.1:8090/executor/mcp'}
    for name, value in [('luna-integration.json', receipt), ('codex-integration.json', {'id': 'codex'}),
                        ('devsy-integration.json', {'id': 'devsy'}), ('browser-approval.json', {'requestId': 'pending'})]:
        control.write_private(state / name, json.dumps(value))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state.iterdir()}
    monkeypatch.setenv('CONTROL_PLANE_BOOTSTRAP_DIR', str(state))
    monkeypatch.setenv('CONTROL_PLANE_GATEWAY', '172.30.86.1')
    sentinel = object()
    monkeypatch.setattr(control, 'executor_session', lambda: (sentinel, sentinel))
    monkeypatch.setattr(control, 'verify_compact', lambda session: None)
    class Adapter:
        def __init__(self, *_): pass
        def tools(self): return bridge.model_catalog(contract()['tools'])
    monkeypatch.setattr(control, 'Mcp', Adapter)
    def ensure(http, url, name, saved, *, allow_import=True):
        assert http is sentinel and url == receipt['url'] and name == 'LunaFactory' and saved == receipt
        assert allow_import is import_allowed
        return receipt
    monkeypatch.setattr(control, 'ensure_mcp_app', ensure)
    monkeypatch.setattr(control, 'search_luna', lambda session: None)
    monkeypatch.setattr(control, 'read_luna', lambda session, run_id=None: None)
    control.luna_setup(import_allowed)
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state.iterdir()} == before


def test_scoped_discovery_and_reads_never_call_mutations():
    calls = []
    class Session:
        def call(self, method, params):
            calls.append(params)
            code = params['arguments']['code']
            value = {'items': [{'path': 'tools.lunafactory.' + name} for name in bridge.MODEL_TOOLS]} if 'tools.search' in code else {'isError': False, 'valid': True}
            return {'structuredContent': {'status': 'completed', 'execution': {'ok': True, 'value': value}}}
    control.search_luna(Session())
    control.read_luna(Session(), 'fixture-run')
    assert len(calls) == 4
    assert '"namespace": "lunafactory"' in calls[0]['arguments']['code']
    assert all(not any(name in call['arguments']['code'] for name in bridge.MUTATIONS) for call in calls)
    assert 'get_factory_run' in calls[-1]['arguments']['code']


def test_operator_reads_return_only_bounded_validation_fields():
    class Session:
        def call(self, method, params):
            code = params['arguments']['code']
            assert 'return {isError:' in code, 'Operator probe returned an arbitrarily large full run'
            return {'structuredContent': {'status': 'completed', 'execution': {
                'ok': True, 'value': {'isError': False, 'valid': True}}}}
    control.read_luna(Session(), 'fixture-run')


def test_http_ignores_empty_sse_priming_event():
    import io
    class Response(io.BytesIO):
        headers = {'Content-Type': 'text/event-stream'}
    class Opener:
        def open(self, *args, **kwargs):
            return Response(b'event: message\ndata:\n\nevent: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')
    http = control.Http('http://127.0.0.1:1')
    http.opener = Opener()
    assert http.request('POST', '/mcp', {})[0]['result'] == {}


def test_http_preserves_valid_utf8_size_before_canonical_body_limit():
    import io
    payload = {'acceptance': ['é' * 400] * 32}
    class Response(io.BytesIO):
        headers = {'Content-Type': 'application/json'}
    class Opener:
        def open(self, request, **kwargs):
            assert len(request.data) < 65536, 'Valid UTF-8 arguments were expanded beyond the product limit'
            assert json.loads(request.data) == payload
            return Response(b'{}')
    http = control.Http('http://127.0.0.1:1')
    http.opener = Opener()
    assert http.request('POST', '/mcp', payload)[0] == {}
