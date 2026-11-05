"""Kamal key rotation uses private files and survives interrupted receipt updates."""
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import compose_control as c
import deploy_control_plane as d
import local_kamal as cli
import vm_deploy_host as h


@pytest.fixture
def rotation(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    store = state / 'deployment'
    store.mkdir(mode=0o700)
    secrets = state / 'secrets'
    secrets.mkdir(mode=0o700)
    key = secrets / 'control-plane-api-key'
    c.write_private(key, 'old-fixture-key\n')
    c.write_private(secrets / 'control-plane-tunnel-id', 'tunnel_' + 'a' * 32 + '\n')
    monkeypatch.setattr(h, 'STATE', state)
    monkeypatch.setattr(h, 'STORE', store)
    core = {'changed': False}
    def identity(_executor, *, tunnel_api_key=None, **_kwargs):
        value = tunnel_api_key if tunnel_api_key is not None else key.read_bytes()
        return ('drift-' if core['changed'] else '') + {
            b'old-fixture-key\n': 'old-identity',
            b'new-fixture-key\n': 'new-identity',
            b'other-fixture-key\n': 'other-identity',
        }[value]
    monkeypatch.setattr(h, 'identity', identity)
    originals = {
        name: {'authority': 'kamal', 'identity': 'old-identity', 'source_sha': name,
               'manifest': {'pin': name}, 'publication_proof': {'verified': True}}
        for name in ('current', 'previous')
    }
    for name, document in originals.items():
        h.write(store / (name + '.json'), document)
    rows = {
        name: {'Id': 'id-' + name, 'Name': '/' + container,
               'Config': {'Labels': {'service': container}},
               'Image': 'image-' + name,
               'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}},
               'State': {'Running': True, 'Paused': False, 'Status': 'running',
                         'Health': {'Status': 'unhealthy' if name == 'tunnel' else 'healthy'}}}
        for name, container in h.NAMES['kamal'].items()
    }
    tunnels = [rows['tunnel']['Name']]
    monkeypatch.setattr(h, 'inspect', lambda: ('kamal', {
        'kamal': rows, 'compose': dict.fromkeys(h.NAMES['compose'])},
        tunnels if rows['tunnel']['State']['Running'] else []))
    monkeypatch.setattr(h, 'run', lambda *a, **kw: b'mcp-control-plane-executor\n')
    return SimpleNamespace(state=state, store=store, key=key, rows=rows,
                           tunnels=tunnels, core=core, originals=originals)


def stopped(r):
    r.rows['tunnel']['State'].update(Running=False, Status='exited')


def healthy(r):
    r.rows['tunnel']['State'].update(Running=True, Status='running')
    r.rows['tunnel']['State']['Health']['Status'] = 'healthy'


def documents(r):
    return {name: json.loads((r.store / (name + '.json')).read_text())
            for name in r.originals}


def test_changed_key_can_prepare_while_only_tunnel_is_unhealthy(rotation):
    result = h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    assert result == {'changed': True, 'was_running': True, 'was_healthy': False}
    assert rotation.key.read_text() == 'old-fixture-key\n'
    assert documents(rotation) == rotation.originals
    assert 'new-fixture-key' not in json.dumps(result)


def test_unchanged_key_is_noop_without_journal(rotation):
    assert h.tunnel_key_prepare({'api_key': 'old-fixture-key'}) == {'changed': False}
    assert not (rotation.store / 'tunnel-key-rotation').exists()


def test_rotation_requires_stop_and_polling_health_before_acceptance(rotation):
    h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    with pytest.raises(ValueError, match='stopped'):
        h.tunnel_key_apply()
    stopped(rotation)
    h.tunnel_key_apply()
    assert rotation.key.read_text() == 'new-fixture-key\n'
    assert rotation.key.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match='healthy'):
        h.tunnel_key_accept()
    healthy(rotation)
    result = h.tunnel_key_accept()
    assert result == {'updated': True}
    assert documents(rotation) == {
        name: {**value, 'identity': 'new-identity'}
        for name, value in rotation.originals.items()}
    assert not (rotation.store / 'tunnel-key-rotation').exists()
    assert 'fixture-key' not in json.dumps(result)


def test_retry_reconciles_applied_key_and_partial_receipts(rotation):
    h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    stopped(rotation)
    h.tunnel_key_apply()
    h.write(rotation.store / 'current.json',
            {**rotation.originals['current'], 'identity': 'new-identity'})
    assert h.tunnel_key_prepare({'api_key': 'new-fixture-key'})['changed'] is True
    h.tunnel_key_apply()
    healthy(rotation)
    h.tunnel_key_accept()
    assert documents(rotation)['previous']['identity'] == 'new-identity'


def test_failed_rotation_restores_expired_key_without_requiring_old_poll_health(rotation):
    h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    stopped(rotation)
    h.tunnel_key_apply()
    result = h.tunnel_key_restore()
    assert result == {'restored': True, 'was_running': True, 'was_healthy': False}
    assert rotation.key.read_text() == 'old-fixture-key\n'
    assert documents(rotation) == rotation.originals
    assert h.tunnel_key_prepare({'api_key': 'other-fixture-key'})['changed'] is True


@pytest.mark.parametrize('service', ['executor', 'schema-proxy', 'cas'])
def test_unrelated_unhealthy_service_blocks_key_rotation(rotation, service):
    rotation.rows[service]['State']['Health']['Status'] = 'unhealthy'
    with pytest.raises(ValueError, match='healthy'):
        h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    assert rotation.key.read_text() == 'old-fixture-key\n'


@pytest.mark.parametrize('tamper', ['executor', 'receipt', 'container', 'duplicate', 'symlink'])
def test_rotation_rejects_unrelated_drift(rotation, tamper, tmp_path):
    h.tunnel_key_prepare({'api_key': 'new-fixture-key'})
    if tamper == 'executor':
        rotation.core['changed'] = True
    elif tamper == 'receipt':
        h.write(rotation.store / 'previous.json',
                {**rotation.originals['previous'], 'source_sha': 'unexpected'})
    elif tamper == 'container':
        rotation.rows['cas']['Id'] = 'replacement-container'
    elif tamper == 'duplicate':
        rotation.tunnels.append('/another-tunnel')
    else:
        target = tmp_path / 'other-key'
        target.write_text('old-fixture-key\n')
        target.chmod(0o600)
        rotation.key.unlink()
        rotation.key.symlink_to(target)
    with pytest.raises((ValueError, c.ControlError)):
        h.tunnel_key_prepare({'api_key': 'new-fixture-key'})


@pytest.mark.parametrize('key', ['', ' ', 'key\nvalue', None, 'new\\key'])
def test_invalid_transferred_keys_are_rejected_without_mutation(rotation, key):
    with pytest.raises((ValueError, c.ControlError)):
        h.tunnel_key_prepare({'api_key': key})
    assert rotation.key.read_text() == 'old-fixture-key\n'
    assert documents(rotation) == rotation.originals


def test_local_deploy_reads_key_but_never_prints_it(tmp_path, monkeypatch, capsys):
    (tmp_path / '.env').write_text('CONTROL_PLANE_API_KEY=new-fixture-key\n')
    monkeypatch.setattr(c, 'ROOT', tmp_path)
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    monkeypatch.setattr(d, 'configure_local', lambda _: None)
    monkeypatch.setattr(d, 'trusted_context', lambda *_a, **_kw: None)
    supplied = []
    monkeypatch.setattr(d, 'execute', lambda args: supplied.append(args.tunnel_api_key) or {'ok': True})
    assert cli.main(['deploy']) == 0
    assert supplied == ['new-fixture-key']
    assert 'new-fixture-key' not in capsys.readouterr().out


def test_local_invalid_key_fails_before_vm_access(tmp_path, monkeypatch, capsys):
    (tmp_path / '.env').write_text('CONTROL_PLANE_API_KEY=\n')
    monkeypatch.setattr(c, 'ROOT', tmp_path)
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    calls = []
    monkeypatch.setattr(d, 'configure_local', lambda _: calls.append('vm'))
    monkeypatch.setattr(d, 'execute', lambda _: calls.append('deploy'))
    assert cli.main(['deploy']) == 1
    assert calls == []


def test_controller_recovers_tunnel_before_full_deployment_snapshot(rotation, monkeypatch):
    events = []
    def remote(action, data=None):
        events.append(action)
        if action == 'tunnel-key-prepare':
            return h.tunnel_key_prepare(data)
        if action == 'tunnel-key-apply':
            return h.tunnel_key_apply()
        if action == 'tunnel-key-accept':
            return h.tunnel_key_accept()
        if action == 'devsy-check':
            return {'status': 'current'}
        if action == 'wait':
            assert rotation.key.read_text() == 'new-fixture-key\n'
            healthy(rotation)
            return {}
        raise AssertionError(action)
    def kamal(_config, operation, name):
        assert name == 'tunnel'
        events.append(operation)
        if operation == 'stop':
            stopped(rotation)
        else:
            rotation.rows['tunnel']['State'].update(Running=True, Status='running')
    monkeypatch.setattr(d, 'remote', remote)
    monkeypatch.setattr(d, 'kamal', kamal)
    monkeypatch.setattr(d, 'configuration', lambda *_: Path('/fixture/config'))
    monkeypatch.setattr(d, 'devsy_payload', lambda: {})
    monkeypatch.setattr(d, 'smoke', lambda *_a, **_kw: events.append('native-smoke'))
    assert d.rotate_tunnel_key('new-fixture-key', {}, '/fixture', None) is True
    assert events.index('devsy-check') < events.index('stop')
    assert events.index('native-smoke') < events.index('stop')
    assert documents(rotation)['current']['identity'] == 'new-identity'
