"""Real dotenv/private-file behavior across Devsy-enabled startup boundaries.

Only process/network/service boundaries are replaced. No credentials, bridge or
provider outside the temporary fixture is touched.
"""
import importlib.util
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALUES = {
    'CONTROL_PLANE_API_KEY': 'COMBINED_FIXTURE_KEY',
    'CONTROL_PLANE_TUNNEL_ID': 'tunnel_' + 'b' * 32,
    'EXECUTOR_PAT': 'COMBINED_FIXTURE_PAT',
}


@pytest.fixture
def combined(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('combined_control', ROOT / 'scripts/compose_control.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    for name in module.SECRET_VARIABLES.values():
        monkeypatch.delenv(name, raising=False)
    configuration = {
        'services': {'codex-action-server': {'image': 'ghcr.io/joshyorko/codex-action-server:sha-' + 'a' * 40}},
        'x-operator': {'devsy_enabled': 'true', 'devsy_binary': sys.executable,
                       'devsy_cwd': str(tmp_path), 'devsy_state': str(tmp_path / 'bridge')},
        'networks': {'control-plane': {'ipam': {'config': [
            {'subnet': '172.30.86.0/24', 'gateway': '172.30.86.1'}]}}},
        'secrets': {name: {'file': str(tmp_path / 'private' / name)} for name in
                    (*module.SECRET_VARIABLES, 'executor-auth-header')},
    }
    events, rows = [], []
    real_bridge = module.host_bridge()

    def private_snapshot():
        return {name: (Path(entry['file']).read_bytes(), Path(entry['file']).stat().st_ino)
                for name, entry in configuration['secrets'].items()}

    def assert_ready():
        pat = module.read_private(Path(configuration['secrets']['executor-pat']['file']))
        header = module.read_private(Path(configuration['secrets']['executor-auth-header']['file']))
        assert header == 'Bearer ' + pat
        assert set(private_snapshot()) == set(configuration['secrets'])

    class Bridge:
        def settings(self, config):
            events.append('bridge-settings')
            return real_bridge.settings(config)
        def start(self, value):
            assert_ready()
            events.append('bridge-start')
        def stop(self, state):
            events.append('bridge-stop')

    def prepare(config):
        assert_ready()
        events.append('prepare')

    def compose(*args, **kwargs):
        events.append(args)
        if 'app-ready' in args or ('tunnel-client' in args and args[0] == 'up'):
            assert_ready()
        return ''

    monkeypatch.setattr(module, 'config', lambda: configuration)
    monkeypatch.setattr(module, 'compose_rows', lambda: rows)
    monkeypatch.setattr(module, 'host_bridge', lambda: Bridge())
    monkeypatch.setattr(module, 'network_preflight', lambda config: events.append('network-preflight'))
    monkeypatch.setattr(module, 'prepare', prepare)
    monkeypatch.setattr(module, 'compose', compose)
    monkeypatch.setattr(module, 'refuse_external_tunnel', lambda: events.append('single-tunnel-check'))
    monkeypatch.setattr(module, 'status', lambda: events.append('status'))
    monkeypatch.setattr(module.getpass, 'getpass', lambda *_: pytest.fail('Combined startup prompted'))

    def dotenv(values=None):
        values = VALUES if values is None else values
        path = tmp_path / '.env'
        path.write_text('DEVSY_MCP_ENABLED=true\nDEVSY_MCP_CWD=${HOME}/existing\n' +
                        ''.join(f'{key}={value}\n' for key, value in values.items()))
        return path

    def run(mode):
        monkeypatch.setattr(sys, 'argv', ['compose_control.py', mode])
        return module.main()

    return module, configuration, events, rows, dotenv, run, private_snapshot


@pytest.mark.parametrize('enabled', ['true', 'false'])
def test_normal_up_retains_credentials_and_routes_both_optional_modes(combined, monkeypatch, capsys, enabled):
    module, config, events, rows, dotenv, run, snapshot = combined
    config['x-operator']['devsy_enabled'] = enabled
    path = dotenv()
    original = path.read_bytes()
    monkeypatch.setenv('EXECUTOR_PAT', 'ENV_COMBINED_FIXTURE_PAT')
    assert run('up') == 0
    assert module.read_private(Path(config['secrets']['executor-pat']['file'])) == 'ENV_COMBINED_FIXTURE_PAT'
    assert path.read_bytes() == original and path.stat().st_mode & 0o777 == 0o600
    startup = 'bridge-start' if enabled == 'true' else 'bridge-stop'
    bootstrap = ('up', '--force-recreate', '--no-deps', '--exit-code-from', 'app-ready', 'app-ready')
    tunnel = ('up', '-d', '--no-deps', '--wait', '--wait-timeout', '120', 'tunnel-client')
    assert events.index('prepare') < events.index(startup) < events.index(bootstrap) < events.index(tunnel)
    assert events.count(tunnel) == 1
    before = snapshot()
    rows.append({'Service': 'tunnel-client', 'State': 'running'})
    events.clear()
    assert run('up') == 0
    assert snapshot() == before, 'Repeated up replaced unchanged credentials'
    assert events.count(bootstrap) == 1 and events.count(tunnel) == 1
    output = capsys.readouterr()
    assert all(value not in output.out + output.err for value in (*VALUES.values(), 'ENV_COMBINED_FIXTURE_PAT'))


@pytest.mark.parametrize('mode', ['up', 'check'])
def test_invalid_dotenv_blocks_devsy_and_all_secret_writes(combined, capsys, mode):
    module, config, events, rows, dotenv, run, snapshot = combined
    dotenv({**VALUES, 'EXECUTOR_PAT': '"PRIVATE_SENTINEL\nINJECTED"'})
    assert run(mode) == 2
    assert events == []
    assert not Path(config['secrets']['executor-pat']['file']).parent.exists()
    assert 'PRIVATE_SENTINEL' not in capsys.readouterr().err


def test_active_rotation_cannot_stop_tunnel_or_replace_private_files(combined):
    module, config, events, rows, dotenv, run, snapshot = combined
    dotenv()
    module.materialize_secrets(config)
    before = snapshot()
    dotenv({**VALUES, 'EXECUTOR_PAT': 'ROTATED_COMBINED_FIXTURE_PAT'})
    rows.append({'Service': 'app-ready', 'State': 'running'})
    assert run('up') == 2
    assert snapshot() == before
    assert 'prepare' not in events and 'bridge-start' not in events and 'bridge-stop' not in events
    assert not any(isinstance(event, tuple) for event in events)


def test_check_materializes_without_starting_devsy_or_services(combined):
    module, config, events, rows, dotenv, run, snapshot = combined
    dotenv()
    assert run('check') == 0
    assert len(snapshot()) == 4
    assert events.count('bridge-settings') == 1 and 'prepare' in events
    assert 'bridge-start' not in events and 'bridge-stop' not in events
    assert not any(isinstance(event, tuple) for event in events)


def test_first_run_ignores_credentials_and_incomplete_enabled_devsy(combined):
    module, config, events, rows, dotenv, run, snapshot = combined
    dotenv({key: '' for key in VALUES})
    config['x-operator']['devsy_binary'] = ''
    assert run('first-run') == 0
    assert events == ['network-preflight', ('up', '-d', '--wait', '--wait-timeout', '120', 'executor')]
    assert not Path(config['secrets']['executor-pat']['file']).parent.exists()


def test_down_up_retains_private_files_and_both_integration_receipts(combined, tmp_path):
    module, config, events, rows, dotenv, run, snapshot = combined
    path = dotenv()
    assert run('up') == 0
    before = snapshot()
    receipts = [tmp_path / 'bootstrap' / (name + '-integration.json') for name in ('codex', 'devsy')]
    for receipt in receipts:
        module.write_private(receipt, '{"fixture":"retained-identity"}\n')
    receipt_before = {path: (path.read_bytes(), path.stat().st_ino) for path in receipts}
    path.unlink()  # A restored setup must fall back to its existing private files.
    events.clear()
    assert run('down') == 0
    assert events == [('stop', '--timeout', '30', 'tunnel-client'), 'bridge-stop', ('down', '--timeout', '30')]
    assert run('up') == 0
    assert snapshot() == before
    assert {path: (path.read_bytes(), path.stat().st_ino) for path in receipts} == receipt_before
