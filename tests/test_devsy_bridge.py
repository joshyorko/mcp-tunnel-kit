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


def test_unknown_calls_never_reach_child(tmp_path):
    import pytest
    module = bridge()
    marker = tmp_path / 'calls'
    devsy = fixture(module, tmp_path, FIXTURE_CALLS=str(marker))
    with pytest.raises(module.BridgeError):
        devsy.call('future_tool', {})
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
