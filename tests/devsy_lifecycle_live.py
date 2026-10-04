#!/usr/bin/env python3
"""Exercise the real host daemon on an isolated Linux Docker runner, no provider."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import compose_control as control
import devsy_bridge as bridge


def docker(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True, timeout=30).stdout


STAGE = "network isolation"


def main():
    global STAGE
    # Never adopt/remove a pre-existing network, state directory, process or service.
    names = docker('network', 'ls', '--format', '{{.Name}}').splitlines()
    assert control.NETWORK not in names, 'Lifecycle fixture requires an empty dedicated runner'
    created = False
    with tempfile.TemporaryDirectory(prefix='devsy-lifecycle-') as temporary:
        directory = Path(temporary)
        binary = directory / 'devsy'
        binary.write_text('#!' + sys.executable + '\n' + (ROOT / 'tests/devsy_stdio_fixture.py').read_text())
        binary.chmod(0o700)
        os.environ.update(DEVSY_MCP_ENABLED='true', DEVSY_MCP_BIN=str(binary),
                          DEVSY_MCP_CWD=str(directory), CONTROL_PLANE_STATE_DIR=str(directory / 'state'))
        state = directory / 'state' / 'devsy-bridge'
        try:
            docker('network', 'create', '--driver', 'bridge', '--subnet', '172.30.86.0/24',
                   '--gateway', '172.30.86.1', '--label', 'com.docker.compose.project=' + control.PROJECT,
                   '--label', 'com.docker.compose.network=control-plane', control.NETWORK)
            created = True
            STAGE = 'configuration and network preflight'
            configuration = control.config()
            control.network_preflight(configuration)
            value = bridge.settings(configuration)
            STAGE = 'initial host bridge startup'
            bridge.start(value)
            first = json.loads(control.read_private(state / 'process.json'))
            bridge.start(value)
            assert json.loads(control.read_private(state / 'process.json')) == first, 'Repeated up replaced live daemon'
            http = control.Http('http://172.30.86.1:8089')
            http.opener = bridge.host_opener()
            session = control.Mcp(http, '/mcp')
            control.verify_devsy_catalog(session.tools())
            for name in ('provider_list', 'workspace_list'):
                assert 'content' in session.call('tools/call', {'name': name, 'arguments': {}})
            # A killed daemon leaves a stale receipt; up must recover rather than duplicate it.
            os.kill(first['pid'], signal.SIGKILL)
            deadline = time.monotonic() + 3
            while bridge.owned_process(first) and time.monotonic() < deadline:
                time.sleep(0.05)
            STAGE = 'stale daemon recovery'
            bridge.start(value)
            second = json.loads(control.read_private(state / 'process.json'))
            assert second['instance'] != first['instance'], 'Stale daemon receipt was retained'
            STAGE = 'repeated down'
            bridge.stop(state)
            bridge.stop(state)
            assert not bridge.owned_process(second), 'Down left the daemon alive'
            # A fresh up after down retains the same private config and directory.
            saved = control.read_private(state / 'config.json')
            STAGE = 'up after down'
            bridge.start(value)
            third = json.loads(control.read_private(state / 'process.json'))
            assert control.read_private(state / 'config.json') == saved
            assert third['instance'] != second['instance']
            bridge.stop(state)
            assert not bridge.owned_process(third)
            # TERM during initialization, before a receipt/listener exists, must reap Devsy.
            STAGE = 'TERM during startup'
            marker = directory / 'startup-child'
            child = subprocess.Popen([sys.executable, str(ROOT / 'scripts/devsy_bridge.py'),
                                      '--serve', str(state / 'config.json')],
                                     env={**os.environ, 'FIXTURE_MODE': 'hang', 'FIXTURE_PID': str(marker)},
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert marker.exists(), 'Startup fixture did not reach Devsy'
                native_pid = int(marker.read_text())
                child.terminate()
                child.wait(timeout=3)
                deadline = time.monotonic() + 3
                while bridge.process_identity(native_pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert bridge.process_identity(native_pid) is None, 'Startup TERM orphaned Devsy'
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
        finally:
            bridge.stop(state)
            if created:
                docker('network', 'rm', control.NETWORK)
    print('Host daemon: real managed-gateway bind, start/start retention, stale recovery, stop/stop and down/up passed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, (bridge.BridgeError, control.ControlError, AssertionError)) else type(error).__name__
        print('Isolated host lifecycle fixture failed at ' + STAGE + ': ' + detail, file=sys.stderr)
        raise SystemExit(1)
