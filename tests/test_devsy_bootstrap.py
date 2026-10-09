"""Codex imports without Executor approvals while Devsy keeps its mutation gate."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def helper():
    spec = importlib.util.spec_from_file_location('compose_control', ROOT / 'scripts/compose_control.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_imports_and_retains_both_apps_without_overwriting_sources():
    from mcp_fixtures import LoopbackServer
    from test_compose_control import CODEX_INDEX, INDEX
    module = helper()
    apps, posts = [], []
    urls = {'Codex': 'http://172.30.86.1:8088/mcp', 'Devsy': 'http://172.30.86.1:8089/mcp'}
    def dispatch(method, path, headers, body):
        if path == '/api/context':
            return 200, {'organization': 'fixture_org'}, False
        if path.endswith('/inventory'):
            return 200, {'apps': apps}, False
        if method == 'POST' and path.endswith('/apps/import'):
            name = body['source']['name']
            posts.append(body)
            app = {'name': name, 'slug': name.lower(), 'id': 'fixture_' + name.lower(), 'activeDeployment': 'fixture_deployment'}
            apps.append(app)
            return 200, app, False
        if path.endswith('/source'):
            name = next(app['name'] for app in apps if '/' + app['id'] + '/' in path)
            content = CODEX_INDEX if name == 'Codex' else INDEX.replace(urls['Codex'], urls[name])
            return 200, {'files': [{'path': 'index.ts', 'content': content}]}, False
        return 400, {}, False
    server = LoopbackServer(dispatch)
    try:
        receipts = {name: module.ensure_mcp_app(module.Http(server.url), url, name) for name, url in urls.items()}
        for _ in range(2):
            for name, url in urls.items():
                assert module.ensure_mcp_app(module.Http(server.url), url, name, receipts[name]) == receipts[name]
        assert [app['slug'] for app in apps] == ['codex', 'devsy']
        assert len(posts) == 2
    finally:
        server.close()


def test_devsy_bootstrap_rejects_missing_and_misleading_safety_hints():
    import pytest
    module = helper()
    tools = [{'name': name, 'annotations': {'readOnlyHint': name in module.DEVSY_READS,
             'destructiveHint': name not in module.DEVSY_READS}} for name in module.DEVSY_TOOLS | {'future_tool'}]
    module.verify_devsy_catalog(tools)
    for changed in ({}, {'readOnlyHint': True, 'destructiveHint': False}):
        invalid = json.loads(json.dumps(tools))
        next(tool for tool in invalid if tool['name'] == 'workspace_exec')['annotations'] = changed
        with pytest.raises(module.ControlError):
            module.verify_devsy_catalog(invalid)


def test_devsy_search_and_reads_use_namespace_and_never_mutate():
    module = helper()
    calls = []
    class Session:
        def call(self, method, params):
            code = params['arguments']['code']
            calls.append(code)
            value = {'items': [{'path': 'tools.devsy.' + name} for name in module.DEVSY_TOOLS]} if 'tools.search(' in code else {'content': [], 'isError': False}
            return {'structuredContent': {'status': 'completed', 'execution': {'ok': True, 'value': value}}}
    module.search_devsy(Session())
    module.read_devsy(Session())
    assert all('"namespace": "devsy"' in code for code in calls if 'tools.search(' in code)
    assert [code for code in calls if 'tools.search(' not in code] == [
        'return await tools.devsy.provider_list({});', 'return await tools.devsy.workspace_list({});']


def test_normal_up_revalidates_both_apps_before_single_tunnel(monkeypatch):
    module = helper()
    order = []
    class Bridge:
        def settings(self, configuration):
            return {'fixture': True}
        def start(self, value):
            order.append('host-bridge-ready')
    monkeypatch.setattr(module, 'host_bridge', lambda: Bridge())
    monkeypatch.setattr(module, 'network_preflight', lambda configuration: order.append('network-verified'))
    monkeypatch.setattr(module, 'compose', lambda *args, **kwargs: order.append(args))
    module.start_control_plane({})
    assert order[0] == ('pull',)
    order = order[1:]
    assert order[0] == ('stop', '--timeout', '30', 'tunnel-client')
    assert order[2:4] == ['network-verified', 'host-bridge-ready']
    assert order[4] == ('up', '-d', '--no-deps', '--wait', '--wait-timeout', '60', 'executor-schema-proxy')
    assert order[5] == ('up', '--force-recreate', '--no-deps', '--exit-code-from', 'app-ready', 'app-ready')
    assert order[6] == ('up', '-d', '--no-deps', '--wait', '--wait-timeout', '120', 'tunnel-client')
    assert len(order) == 7


def test_bootstrap_failure_leaves_tunnel_stopped(monkeypatch):
    import pytest
    module = helper()
    calls = []
    class Bridge:
        def settings(self, configuration):
            return {'fixture': True}
        def start(self, value):
            pass
    def compose(*args, **kwargs):
        calls.append(args)
        if 'app-ready' in args:
            raise module.ControlError('Fixture bootstrap failure')
    monkeypatch.setattr(module, 'host_bridge', lambda: Bridge())
    monkeypatch.setattr(module, 'network_preflight', lambda configuration: None)
    monkeypatch.setattr(module, 'compose', compose)
    with pytest.raises(module.ControlError):
        module.start_control_plane({})
    assert not any(args[0] == 'up' and 'tunnel-client' in args for args in calls)
