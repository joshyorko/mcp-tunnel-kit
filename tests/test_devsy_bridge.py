"""Host bridge contracts use a synthetic stdio server, never a real workspace."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def bridge():
    path = ROOT / "scripts/devsy_bridge.py"
    assert path.is_file(), "Host bridge is missing"
    spec = importlib.util.spec_from_file_location("devsy_bridge", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_explicit_reads_are_safe_even_with_missing_or_lying_annotations():
    module = bridge()
    for name in module.KNOWN_TOOLS | {"future_tool"}:
        for annotations in ({}, {"destructiveHint": False, "readOnlyHint": True}):
            tool = {"name": name, "inputSchema": {"type": "object"}, "annotations": annotations}
            actual = module.normalize_tool(tool)
            assert actual["annotations"]["destructiveHint"] is (name not in module.READ_ONLY)
            assert actual["annotations"]["readOnlyHint"] is (name in module.READ_ONLY)
            assert tool["annotations"] == annotations


def test_bind_refuses_wildcard_loopback_lan_and_wrong_gateway():
    module = bridge()
    module.validate_bind("172.30.86.0/24", "172.30.86.1")
    for subnet, gateway in (("172.30.86.0/24", "0.0.0.0"),
                            ("127.0.0.0/24", "127.0.0.1"),
                            ("172.30.86.0/24", "192.168.1.1"),
                            ("172.30.86.0/24", "172.30.86.2")):
        try:
            module.validate_bind(subnet, gateway)
        except module.BridgeError:
            pass
        else:
            raise AssertionError("Unsafe bind accepted")


def fixture(module, tmp_path, **environment):
    import os
    import sys
    binary = tmp_path / 'devsy'
    binary.write_text('#!' + sys.executable + '\n' + (ROOT / 'tests/devsy_stdio_fixture.py').read_text())
    binary.chmod(0o700)
    return module.Devsy(str(binary), str(tmp_path), {**os.environ, **environment}, timeout=0.4)


def test_real_stdio_catalog_and_read_call(tmp_path):
    module = bridge()
    devsy = fixture(module, tmp_path)
    catalog = devsy.catalog()
    assert {tool['name'] for tool in catalog} == module.KNOWN_TOOLS | {'future_tool'}
    assert devsy.call('provider_list', {})['content'][0]['type'] == 'text'
    assert devsy.call('workspace_list', {})['content'][0]['type'] == 'text'
    assert all(tool['annotations']['destructiveHint'] for tool in catalog if tool['name'] not in module.READ_ONLY)


def test_running_bridge_follows_executable_symlink_after_upgrade(tmp_path):
    module = bridge()
    old_directory = tmp_path / '1.22.0'
    new_directory = tmp_path / '1.23.0'
    old_directory.mkdir()
    new_directory.mkdir()
    old = fixture(module, old_directory)
    new = fixture(module, new_directory)
    executable = tmp_path / 'devsy'
    executable.symlink_to(old.binary)
    devsy = module.Devsy(str(executable), str(tmp_path), old.env, timeout=0.4)
    assert devsy.catalog()

    executable.unlink()
    executable.symlink_to(new.binary)
    Path(old.binary).unlink()
    assert devsy.catalog()
    assert devsy.call('workspace_list', {})['content'][0]['type'] == 'text'


def test_unknown_calls_never_reach_child(tmp_path):
    import pytest
    module = bridge()
    marker = tmp_path / 'calls'
    devsy = fixture(module, tmp_path, FIXTURE_CALLS=str(marker))
    with pytest.raises(module.BridgeError):
        devsy.call('future_tool', {})
    assert not marker.exists()


def test_operator_scoped_diagnostics_are_readonly_and_not_upstream_tools(tmp_path):
    import json
    module = bridge()
    devsy = fixture(module, tmp_path)
    source = tmp_path / 'operator-targets.json'
    source.write_text(json.dumps({'targets': {'devsy': {'context': 'default',
        'provider': 'kubernetes', 'workspace': 'codex-action-server',
        'workspace_uid': 'default-co-f715f'}}}))
    source.chmod(0o600)
    devsy.targets_source = str(source)
    tools = {tool['name']: tool for tool in devsy.catalog()}
    assert tools['workspace_diagnostics']['annotations']['readOnlyHint'] is True
    assert tools['workspace_diagnostics']['annotations']['destructiveHint'] is False
    assert tools['workspace_exec']['annotations']['destructiveHint'] is True


def test_wrong_diagnostic_uid_is_a_classified_refusal_without_upstream_execution(tmp_path):
    import json
    module = bridge()
    marker = tmp_path / 'calls'
    devsy = fixture(module, tmp_path, FIXTURE_CALLS=str(marker))
    source = tmp_path / 'operator-targets.json'
    source.write_text(json.dumps({'targets': {'devsy': {'context': 'default',
        'provider': 'kubernetes', 'workspace': 'codex-action-server',
        'workspace_uid': 'default-co-f715f'}}}))
    source.chmod(0o600)
    devsy.targets_source = str(source)
    result = devsy.call('workspace_diagnostics', {'name': 'codex-action-server',
                                                 'workspace_uid': 'default-co-93408'})
    assert result['isError'] is True
    assert result['structuredContent']['error']['code'] == 'worker_diagnostics_refused'
    assert not marker.exists()


def test_incomplete_catalog_and_hung_child_fail_closed(tmp_path):
    import pytest
    import time
    module = bridge()
    for mode in ('incomplete', 'hang'):
        started = time.monotonic()
        with pytest.raises(module.BridgeError):
            fixture(module, tmp_path, FIXTURE_MODE=mode).catalog()
        assert time.monotonic() - started < 3


def test_http_actual_mcp_traversal_origin_guard_and_health(tmp_path):
    import ipaddress
    import json
    import threading
    import urllib.request
    import urllib.error
    import pytest
    module = bridge()
    server = module.BridgeServer(('127.0.0.1', 0), fixture(module, tmp_path),
                                 ipaddress.ip_network('127.0.0.0/8'), 'fixture-instance')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    def request(body, headers=None):
        req = urllib.request.Request(origin + '/mcp', json.dumps(body).encode(),
            {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', **(headers or {})})
        with urllib.request.urlopen(req, timeout=2) as response:
            return json.load(response)
    try:
        health = json.load(urllib.request.urlopen(origin + '/health', timeout=2))
        assert health['instance'] == 'fixture-instance' and health['ready'] is True
        initialized = request({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'}})
        assert initialized['result']['capabilities'] == {'tools': {}}
        tools = request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})['result']['tools']
        assert len(tools) == 12
        result = request({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'workspace_list', 'arguments': {}}})
        assert 'result' in result
        with pytest.raises(urllib.error.HTTPError) as error:
            request({'jsonrpc': '2.0', 'id': 4, 'method': 'tools/list'}, {'Origin': 'https://evil.example'})
        assert error.value.code == 403
        denied = request({'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': {'name': 'future_tool', 'arguments': {}}})
        assert 'error' in denied
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_process_identity_rejects_stale_pid_receipt(tmp_path):
    import os
    import json
    import pytest
    module = bridge()
    # Production config is strict; test the PID reuse boundary without a host listener.
    assert module.process_identity(os.getpid())
    record = {'pid': os.getpid(), 'started': 'definitely-stale'}
    assert not module.owned_process(record)
    with pytest.raises(module.BridgeError):
        module.validate_settings({'subnet': '172.30.86.0/24', 'gateway': '0.0.0.0',
                                  'binary': '/bin/true', 'cwd': str(tmp_path)})


def test_host_settings_are_explicit_optional_and_not_credential_mounts(tmp_path):
    import pytest
    module = bridge()
    configuration = {'x-operator': {'devsy_enabled': 'false'}, 'networks': {'control-plane': {'ipam': {
        'config': [{'subnet': '172.30.86.0/24', 'gateway': '172.30.86.1'}]}}}}
    assert module.settings(configuration) is None
    configuration['x-operator'].update(devsy_enabled='true', devsy_binary='/bin/true',
                                      devsy_cwd=str(tmp_path), devsy_state=str(tmp_path / 'state'))
    actual = module.settings(configuration)
    assert actual['gateway'] == '172.30.86.1'
    assert actual['binary'] == '/bin/true'
    configuration['x-operator']['devsy_binary'] = 'devsy'
    with pytest.raises(module.BridgeError):
        module.settings(configuration)


def test_child_is_reaped_if_bridge_owner_is_killed(tmp_path):
    import os
    import signal
    import subprocess
    import sys
    import time
    import pytest
    binary = tmp_path / 'hanging-devsy'
    marker = tmp_path / 'child-pid'
    binary.write_text('#!' + sys.executable + '\nimport os,time\nfrom pathlib import Path\n' +
                      f'Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(120)\n')
    binary.chmod(0o700)
    owner = subprocess.Popen([sys.executable, '-c',
        "import sys;sys.path.insert(0, 'scripts');from devsy_bridge import Devsy;"
        f"Devsy({str(binary)!r}, {str(tmp_path)!r}).catalog()"], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child = None
    try:
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), 'Fixture child did not start'
        child = int(marker.read_text())
        owner.kill()
        owner.wait(timeout=2)
        deadline = time.monotonic() + 3
        while bridge().process_identity(child) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert bridge().process_identity(child) is None, 'Devsy child escaped its dead bridge owner'
    finally:
        if owner.poll() is None:
            owner.kill()
        owner.wait(timeout=2)
        if child and bridge().process_identity(child):
            os.kill(child, signal.SIGKILL)


def test_shutdown_closes_withheld_http_body_without_dispatch(tmp_path):
    import ipaddress
    import json
    import socket
    import threading
    import time
    module = bridge()
    marker = tmp_path / 'calls'
    server = module.BridgeServer(('127.0.0.1', 0), fixture(module, tmp_path, FIXTURE_CALLS=str(marker)),
                                 ipaddress.ip_network('127.0.0.0/8'), 'fixture')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sock = socket.create_connection(server.server_address)
    body = json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call',
                       'params':{'name':'workspace_exec','arguments':{}}}).encode()
    sock.sendall((f'POST /mcp HTTP/1.1\r\nHost: {server.authority}\r\nContent-Type: application/json\r\n'
                  f'Content-Length: {len(body)}\r\n\r\n').encode())
    time.sleep(0.1)
    started = time.monotonic()
    server.shutdown()
    server.server_close()
    sock.close()
    thread.join(timeout=1)
    assert time.monotonic() - started < 2
    assert not marker.exists()


def test_stop_treats_exit_during_pidfd_open_as_already_stopped(tmp_path, monkeypatch):
    import json
    import sys
    from unittest.mock import Mock
    import pytest
    module = bridge()
    monkeypatch.syspath_prepend(str(ROOT / 'scripts'))
    import compose_control as control
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    marker = state / 'process.json'
    control.write_private(marker, json.dumps({'pid': 987654, 'started': 'fixture'}))
    monkeypatch.setattr(module, 'owned_process', Mock(side_effect=[True, False]))
    monkeypatch.setattr(module.os, 'pidfd_open', Mock(side_effect=ProcessLookupError()))
    module.stop(state)
    assert not marker.exists()


def test_host_health_uses_explicit_loopback_source_with_private_subnet_policy(tmp_path):
    import ipaddress
    import json
    import threading
    module = bridge()
    server = module.BridgeServer(('127.0.0.1', 0), fixture(module, tmp_path),
                                 ipaddress.ip_network('172.30.86.0/24'), 'fixture')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with module.host_opener().open(f'http://127.0.0.1:{server.server_port}/health') as response:
            assert json.load(response)['ready'] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_http_admission_waits_for_previous_handler_cleanup(tmp_path):
    import ipaddress
    import json
    import threading
    import urllib.request
    module = bridge()
    server = module.BridgeServer(('127.0.0.1', 0), fixture(module, tmp_path),
                                 ipaddress.ip_network('127.0.0.0/8'), 'fixture')
    for _ in range(8):
        assert server.slots.acquire(blocking=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    release = threading.Timer(0.05, server.slots.release)
    release.start()
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/health', timeout=2) as response:
            assert json.load(response)['ready'] is True
    finally:
        release.join()
        server.shutdown()
        server.server_close()
        thread.join()
        for _ in range(7):
            server.slots.release()


def test_saturated_http_returns_503_without_dispatch(tmp_path):
    import ipaddress
    import json
    import threading
    import urllib.request
    import urllib.error
    import pytest
    module = bridge()
    marker = tmp_path / 'calls'
    server = module.BridgeServer(('127.0.0.1', 0), fixture(module, tmp_path, FIXTURE_CALLS=str(marker)),
                                 ipaddress.ip_network('127.0.0.0/8'), 'fixture')
    for _ in range(8):
        assert server.slots.acquire(blocking=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call',
                           'params':{'name':'workspace_delete','arguments':{}}}).encode()
        request = urllib.request.Request(f'http://127.0.0.1:{server.server_port}/mcp', body,
                                         {'Content-Type':'application/json'})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 503
        assert not marker.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        for _ in range(8):
            server.slots.release()


def scoped_fixture(tmp_path, body):
    import hashlib
    import json
    import os
    import sys
    module = bridge()
    binary = tmp_path / 'fake-devsy'
    prefix = '''import sys, json, os
from pathlib import Path
if sys.argv[1:4] == ['--context', 'default', 'context']:
    copy = Path(os.environ['DEVSY_CONFIG'])
    if sys.argv[4] == 'set':
        copy.write_text(json.dumps({'SSH_TUNNEL_MODE': {'value': 'false'}}))
    elif sys.argv[4] == 'get':
        print(copy.read_text())
    else:
        raise SystemExit(7)
    raise SystemExit(0)
'''
    binary.write_text('#!' + sys.executable + '\n' + prefix + body)
    binary.chmod(0o700)
    native_config = tmp_path / 'config.yaml'
    native_config.write_text(json.dumps({'SSH_TUNNEL_MODE': {'value': 'true'}}))
    native_config.chmod(0o600)
    scope = json.loads((ROOT / 'docs/devsy-worker-scope.proposed.json').read_text())
    scope.update(enabled=True, expires_at=None,
                 bindings={str(native_config.resolve()): hashlib.sha256(native_config.read_bytes()).hexdigest()}, binary=str(binary),
                 capability_sha256=hashlib.sha256(b'fixture-owner-secret').hexdigest())
    config = tmp_path / 'scope.json'
    config.write_text(json.dumps(scope))
    config.chmod(0o600)
    devsy = module.Devsy(str(binary), str(tmp_path), dict(os.environ, DEVSY_HOME=str(tmp_path)),
                        creation_state=tmp_path / 'receipts', scope_source=config)
    return devsy, scope


def scoped_job(devsy, scope, request_id='fixture-create'):
    import hashlib
    import uuid
    recipe = b'{}'
    execution = {key: scope[key] for key in (
        'context', 'provider', 'kubernetes_context', 'namespace', 'repository', 'source_ref', 'recipe', 'binary')}
    execution.update(revision='b' * 40, recipe_sha256=hashlib.sha256(recipe).hexdigest())
    operation_id = str(uuid.uuid4())
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {
        'name': 'cas-worker-01', 'operation_id': operation_id, 'operation': 'create',
        'request_id': request_id, 'status': 'running', 'execution_context': execution,
    })
    return {**scope, 'execution_context': execution, 'recipe_snapshot': recipe,
            'operation_id': operation_id}


def test_scoped_supervisor_passes_commit_source_and_execution_context(tmp_path):
    import hashlib
    import json
    import uuid
    devsy, scope = scoped_fixture(tmp_path, '''import json, os, sys
from pathlib import Path
Path('invocation.json').write_text(json.dumps({'args': sys.argv[1:], 'home': os.environ['DEVSY_HOME']}))
''')
    recipe = b'{"name":"remote worker"}\n'
    execution = {key: scope[key] for key in ('context', 'provider', 'kubernetes_context', 'namespace', 'repository', 'recipe', 'binary')}
    execution.update(source_ref='refs/heads/main', revision='b' * 40,
                     recipe_sha256=hashlib.sha256(recipe).hexdigest())
    operation_id = str(uuid.uuid4())
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {'name': 'cas-worker-01', 'operation_id': operation_id,
        'operation': 'create', 'request_id': 'pinned-main', 'status': 'running',
        'execution_context': execution})
    result = devsy.scoped_execute('create', 'cas-worker-01', {**scope, 'execution_context': execution,
        'recipe_snapshot': recipe, 'operation_id': operation_id})
    invocation = json.loads((tmp_path / 'invocation.json').read_text())
    assert 'git:https://github.com/joshyorko/codex-action-server.git@sha256:' + 'b' * 40 in invocation['args']
    assert invocation['home'] == str(tmp_path)
    assert result['exit_code'] == 0
    assert result['devsy_invoked'] is True


def test_scoped_child_uses_the_persisted_source_snapshot(tmp_path):
    import hashlib
    import json
    import uuid

    capture = tmp_path / 'child-arguments.json'
    devsy, approved = scoped_fixture(tmp_path, f'''import hashlib, json, os, stat, sys
from pathlib import Path
scratch = Path(os.environ['TMPDIR'])
snapshot = scratch / 'recipe-snapshot.json'
Path({str(capture)!r}).write_text(json.dumps({{
    'args': sys.argv[1:], 'scratch_mode': stat.S_IMODE(scratch.stat().st_mode),
    'snapshot_mode': stat.S_IMODE(snapshot.stat().st_mode),
    'snapshot_hash': hashlib.sha256(snapshot.read_bytes()).hexdigest(),
}}))
''')
    recipe = b'{"name":"worker from main"}\n'
    execution = {
        'context': approved['context'], 'provider': approved['provider'],
        'kubernetes_context': approved['kubernetes_context'], 'namespace': approved['namespace'],
        'repository': 'https://github.com/joshyorko/codex-action-server.git',
        'source_ref': 'refs/heads/main', 'revision': 'a' * 40,
        'recipe': '.devcontainer/remote-worker/devcontainer.json',
        'recipe_sha256': hashlib.sha256(recipe).hexdigest(), 'binary': approved['binary'],
    }
    operation_id = str(uuid.uuid4())
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {
        'name': 'cas-worker-01', 'operation_id': operation_id, 'operation': 'create',
        'request_id': 'source-snapshot', 'status': 'running', 'execution_context': execution,
    })
    job_scope = {**approved, 'execution_context': execution,
                 'recipe_snapshot': recipe, 'operation_id': operation_id}

    result = devsy.scoped_execute('create', 'cas-worker-01', job_scope)

    observed = json.loads(capture.read_text())
    arguments = observed['args']
    assert 'git:https://github.com/joshyorko/codex-action-server.git@sha256:' + 'a' * 40 in arguments
    assert arguments[arguments.index('--devcontainer') + 1] == '.devcontainer/remote-worker/devcontainer.json'
    assert observed['scratch_mode'] == 0o700
    assert observed['snapshot_mode'] == 0o600
    assert observed['snapshot_hash'] == hashlib.sha256(recipe).hexdigest()
    assert result['exit_code'] == 0
    assert result['devsy_invoked'] is True


def test_scoped_start_uses_existing_workspace_without_main_or_recipe_flags(tmp_path):
    import json
    import uuid
    capture = tmp_path / 'start-arguments.json'
    devsy, approved = scoped_fixture(tmp_path, f'''import json, sys
from pathlib import Path
Path({str(capture)!r}).write_text(json.dumps(sys.argv[1:]))
''')
    execution = {key: approved[key] for key in (
        'context', 'provider', 'kubernetes_context', 'namespace', 'repository', 'source_ref', 'recipe', 'binary')}
    execution.update(revision='a' * 40, recipe_sha256='b' * 64)
    operation_id = str(uuid.uuid4())
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {
        'name': 'cas-worker-01', 'operation_id': operation_id, 'operation': 'start',
        'request_id': 'start-pinned-main', 'status': 'running', 'workspace_uid': 'fixture-uid',
        'execution_context': execution,
    })

    result = devsy.scoped_execute('start', 'cas-worker-01', {
        **approved, 'execution_context': execution, 'operation_id': operation_id,
    })

    arguments = json.loads(capture.read_text())
    assert arguments[arguments.index('up') + 1] == 'cas-worker-01'
    assert '--devcontainer' not in arguments
    assert result['exit_code'] == 0
    assert result['devsy_invoked'] is True


def test_scoped_supervisor_retains_exit_without_leaking_stderr(tmp_path):
    import json
    devsy, scope = scoped_fixture(tmp_path, '''import sys
sys.stderr.write('fatal: Remote branch missing not found in upstream origin\\nPRIVATE_TOKEN=do-not-retain\\n')
sys.exit(17)
''')
    result = devsy.scoped_execute('create', 'cas-worker-01', scoped_job(devsy, scope))
    assert result['exit_code'] == 17
    assert result['devsy_invoked'] is True
    assert result['stderr_code'] == 'git_ref_not_found'
    assert 'do-not-retain' not in json.dumps(result)


def test_scoped_receipt_exposes_same_operation_and_nested_error(tmp_path):
    devsy, _ = scoped_fixture(tmp_path, 'raise SystemExit(0)\n')
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {'name': 'cas-worker-01', 'operation_id': 'incident',
        'request_id': 'request-1', 'operation': 'create', 'status': 'outcome_unknown', 'retry_safe': False})
    credential = 'Bearer fixture-owner-secret'
    status = devsy.call('workspace_status_scoped', {'name': 'cas-worker-01'}, credential)
    receipt = devsy.call('workspace_create_receipt', {'name': 'cas-worker-01'}, credential)
    assert receipt['structuredContent']['operation_id'] == status['structuredContent']['operation_id']
    assert receipt['structuredContent']['status'] == 'outcome_unknown'
    assert receipt['isError'] is True
    assert receipt['structuredContent']['retry_safe'] is False


def test_raw_create_cannot_bypass_scoped_duplicate_protection(tmp_path):
    import pytest
    devsy, _ = scoped_fixture(tmp_path, 'raise SystemExit(0)\n')
    with pytest.raises(Exception, match='scoped'):
        devsy.call('workspace_create', {'name': 'cas-worker-01', 'source': 'git:https://example.invalid/repo'},
                   'Bearer fixture-owner-secret')


def test_scoped_outer_exception_never_claims_no_invocation(monkeypatch, capsys):
    import json
    import sys
    module = bridge()
    def unexpected(*_args):
        raise OSError('post-launch cleanup failure with private details')
    monkeypatch.setattr(module, 'scoped_child', unexpected)
    monkeypatch.setattr(sys, 'argv', ['bridge', '--scoped-child', '/unused', '1', 'create',
                                      'cas-worker-01', '/state', 'operation', ''])
    assert module.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result.get('devsy_invoked') is not False
    assert result['exit_code'] != 0
    assert 'private details' not in json.dumps(result)


def test_scoped_large_output_is_drained_and_not_retained(tmp_path):
    import json
    devsy, scope = scoped_fixture(tmp_path, "import sys\nsys.stderr.write('sensitive' * 100000)\nsys.exit(9)\n")
    result = devsy.scoped_execute('create', 'cas-worker-01', scoped_job(devsy, scope))
    assert result['exit_code'] == 9
    assert result['devsy_invoked'] is True
    assert len(json.dumps(result)) < 500
    assert 'sensitive' not in json.dumps(result)


def test_scoped_supervisor_timeout_stays_unknown_and_reaps_child(tmp_path):
    import json
    import time
    devsy, scope = scoped_fixture(tmp_path, '''import os, time
from pathlib import Path
Path('devsy-pid').write_text(str(os.getpid()))
time.sleep(60)
''')
    # Shorten only the parent's test deadline; child still loads the approved scope.
    result = devsy.scoped_execute('create', 'cas-worker-01',
                                  {**scoped_job(devsy, scope), 'job_timeout_seconds': 0.01})
    assert result['phase'] == 'supervisor_timeout'
    assert result.get('devsy_invoked') is not False
    pid = int((tmp_path / 'devsy-pid').read_text())
    module = bridge()
    deadline = time.monotonic() + 2
    while module.process_identity(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert module.process_identity(pid) is None


def test_scoped_status_and_receipt_report_guarded_fresh_admission(tmp_path):
    import time
    devsy, _ = scoped_fixture(tmp_path, 'raise SystemExit(0)\n')
    devsy.scope.root()
    devsy.scope.write('cas-worker-01', {'name': 'cas-worker-01', 'operation_id': 'incident',
        'request_id': 'request-1', 'operation': 'create', 'status': 'outcome_unknown', 'retry_safe': False})
    assert devsy.scope.absence is not None, 'Live bridge must wire provider reconciliation'
    devsy.scope.absence = lambda name, scope: {
        'kind': 'absent', 'observed_at': time.time(), 'namespace_uid': 'fixture-namespace',
        'namespace': 'devsy', 'kubernetes_context': 'ror', 'workspace_absent': True,
        'provider_resources_absent': True, 'lifecycle_processes_absent': True}
    for tool in ('workspace_status_scoped', 'workspace_create_receipt'):
        result = devsy.call(tool, {'name': 'cas-worker-01'}, 'Bearer fixture-owner-secret')
        value = result['structuredContent']
        assert value['status'] == 'failed'
        assert value['new_request_allowed'] is True
        assert value['retry_safe'] is False
        assert value['may_have_succeeded'] is False
        assert value['operation_id'] == 'incident'


def test_scoped_job_uses_private_scratch_and_removes_only_its_own_directory(tmp_path):
    import json
    devsy, scope = scoped_fixture(tmp_path, '''import json, os, stat, tempfile
from pathlib import Path
root = Path(tempfile.gettempdir())
Path('scratch.json').write_text(json.dumps({'path': str(root), 'mode': stat.S_IMODE(root.stat().st_mode)}))
with tempfile.TemporaryFile() as f:
    f.write(b'fixture')
''')
    result = devsy.scoped_execute('create', 'cas-worker-01', scoped_job(devsy, scope))
    observed = json.loads((tmp_path / 'scratch.json').read_text())
    assert Path(observed['path']).parent == devsy.scope.state
    assert observed['mode'] == 0o700
    assert not Path(observed['path']).exists()
    assert result['exit_code'] == 0


def test_revoked_worker_scope_does_not_disable_static_worker_diagnostics(tmp_path):
    import json
    from types import SimpleNamespace
    devsy, scope = scoped_fixture(tmp_path, 'raise SystemExit(0)\n')
    source = tmp_path / 'static-targets.json'
    source.write_text(json.dumps({'targets': {'devsy': {'workspace': 'existing-worker'}}}))
    source.chmod(0o600)
    devsy.targets_source = str(source)
    scope['enabled'] = False
    devsy.scope.config.write_text(json.dumps(scope))
    real = devsy.diagnostic_module()
    def diagnose(source, arguments, call, environment, *, selection=None):
        assert selection is None
        return {'static_worker': True}
    devsy.diagnostic_module = lambda: SimpleNamespace(_private_json=real._private_json,
        DiagnosticError=real.DiagnosticError, diagnose=diagnose)
    result = devsy.call('workspace_diagnostics', {'name': 'existing-worker', 'workspace_uid': 'existing-uid'})
    assert result['structuredContent']['static_worker'] is True
    assert result['isError'] is False


def test_expanded_scope_cannot_hide_generic_unknown_receipt(tmp_path):
    import pytest
    devsy, _ = scoped_fixture(tmp_path, 'raise SystemExit(0)\n')
    _, receipts = devsy.receipts()
    receipts.private_root()
    key, fingerprint = receipts.key({'name': 'rcc-worker-01'})
    receipts.write(receipts.state / (key + '.json'), {'name': 'rcc-worker-01', 'operation_id': 'legacy',
                   'fingerprint': fingerprint, 'status': 'outcome_unknown'})
    for tool in ('workspace_status_scoped', 'workspace_create_receipt', 'workspace_create_scoped'):
        args = {'name': 'rcc-worker-01'}
        if tool == 'workspace_create_scoped':
            args['request_id'] = 'fresh'
        with pytest.raises(Exception, match='requires operator migration'):
            devsy.call(tool, args, 'Bearer fixture-owner-secret')
    assert devsy.scope.read('rcc-worker-01') is None
