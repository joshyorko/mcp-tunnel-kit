import base64
import json
import struct
from pathlib import Path

import pytest

from native_registration import Registration, validate_descriptor


def public_key(byte=b'a'):
    kind = b'ssh-ed25519'
    return 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', len(kind)) + kind + struct.pack('>I', 32) + byte * 32).decode()


@pytest.fixture
def setup(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    native = tmp_path / 'ssh'
    state.mkdir(mode=0o700)
    native.mkdir(mode=0o700)
    def write(path, text):
        path.write_text(text)
        path.chmod(0o600)
    write(state / 'cas-targets.json', json.dumps({'targets': {'local': {'transport': 'ssh', 'destination': 'gpu'}}}))
    write(native / 'ssh_config.native', 'Host gpu\n  HostName 100.81.124.110\n  User operator\n')
    write(native / 'known_hosts.native', '[100.81.124.110]:22222 ' + public_key(b'b') + ' gpu\n')
    write(native / 'identity', 'private fixture')
    profile = {'deploy_host': {'host_key_fingerprint': 'SHA256:' + 'a' * 43}, 'vm': {'state_dir': str(state), 'native_ssh_dir': str(native)}}
    descriptor = {'schema_version': 1, 'name': 'dakota-cpu', 'address': '100.118.115.62', 'port': 22222, 'user': 'kdlocpanda', 'codex_bin': '/home/kdlocpanda/.codex/packages/app-server-daemon/current/bin/codex', 'socket': '/home/kdlocpanda/.codex/app-server-control/app-server-control.sock', 'host_public_key': public_key(), 'controller_fingerprint': profile['deploy_host']['host_key_fingerprint']}
    registration = Registration(profile)
    monkeypatch.setattr(registration, 'probe', lambda descriptor: {'status': 'PASS'})
    return registration, descriptor, state, native


@pytest.mark.parametrize('field,value', [('name', 'local'), ('name', '../evil'), ('address', '192.168.1.1'), ('port', True), ('user', 'a\nPermitRootLogin yes'), ('socket', '/tmp/a;id'), ('codex_bin', '/tmp/../bin/codex'), ('host_public_key', 'ssh-ed25519 YQ==')])
def test_descriptor_rejects_unsafe_values(setup, field, value):
    _, descriptor, _, _ = setup
    descriptor[field] = value
    with pytest.raises(ValueError):
        validate_descriptor(descriptor)


def test_apply_preserves_existing_target_and_rolls_back(setup):
    reg, descriptor, state, native = setup
    originals = {p: p.read_bytes() for p in reg.paths.values()}
    assert reg.plan(descriptor)['changed']
    result = reg.apply(descriptor)
    targets = json.loads((state / 'cas-targets.json').read_text())['targets']
    assert targets['local'] == {'transport': 'ssh', 'destination': 'gpu'}
    assert targets['dakota-cpu']['destination'] == 'dakota-cpu-native'
    assert 'UserKnownHostsFile /run/codex-ssh/known_hosts\n' in (native / 'ssh_config.native').read_text()
    assert not reg.plan(descriptor)['changed']
    reg.rollback(result['transaction_id'])
    assert all(path.read_bytes() == content for path, content in originals.items())


def test_completed_registration_adopts_identical_state(setup):
    reg, descriptor, _, native = setup
    result = reg.apply(descriptor)
    reg.complete(result['transaction_id'])
    path = native / 'known_hosts.native'
    path.write_text(path.read_text().replace(descriptor['host_public_key'] + '\n', descriptor['host_public_key'] + ' imported comment\n'))
    before = {p: (p.stat().st_ino, p.read_bytes()) for p in reg.paths.values()}
    descriptor['host_public_key'] += ' device comment'
    assert reg.apply(descriptor) == {'changed': False, 'transaction_id': None, 'name': 'dakota-cpu'}
    assert all((p.stat().st_ino, p.read_bytes()) == value for p, value in before.items())


def test_pending_transaction_blocks_apply(setup):
    reg, descriptor, _, _ = setup
    reg.apply(descriptor)
    with pytest.raises(ValueError, match='pending'):
        reg.apply(descriptor)


def test_rollback_refuses_intervening_edit_without_partial_restore(setup):
    reg, descriptor, state, native = setup
    result = reg.apply(descriptor)
    (native / 'known_hosts.native').write_text('operator changed this\n')
    before = {p: p.read_bytes() for p in reg.paths.values()}
    with pytest.raises(ValueError, match='changed'):
        reg.rollback(result['transaction_id'])
    assert all(p.read_bytes() == content for p, content in before.items())


def test_wrong_controller_and_name_collision_are_rejected(setup):
    reg, descriptor, state, _ = setup
    descriptor['controller_fingerprint'] = 'SHA256:' + 'b' * 43
    with pytest.raises(ValueError, match='controller'):
        reg.plan(descriptor)
    descriptor['controller_fingerprint'] = reg.instance['deploy_host']['host_key_fingerprint']
    (state / 'cas-targets.json').write_text(json.dumps({'targets': {'local': {}, 'dakota-cpu': {'transport': 'local'}}}))
    with pytest.raises(ValueError, match='conflict'):
        reg.plan(descriptor)


def test_symlink_and_unsafe_mode_rejected(setup, tmp_path):
    reg, descriptor, state, _ = setup
    path = state / 'cas-targets.json'
    path.chmod(0o644)
    with pytest.raises(ValueError):
        reg.plan(descriptor)
    path.unlink()
    other = tmp_path / 'other'
    other.write_text('{}')
    other.chmod(0o600)
    path.symlink_to(other)
    with pytest.raises(ValueError):
        reg.plan(descriptor)


def test_failed_probe_never_publishes(setup, monkeypatch):
    reg, descriptor, _, _ = setup
    before = {p: p.read_bytes() for p in reg.paths.values()}
    def failed(_):
        raise ValueError('endpoint unavailable')
    monkeypatch.setattr(reg, 'probe', failed)
    with pytest.raises(ValueError, match='endpoint unavailable'):
        reg.apply(descriptor)
    assert all(p.read_bytes() == content for p, content in before.items())


def test_partial_publication_is_recoverable(setup, monkeypatch):
    import native_registration as module
    reg, descriptor, _, native = setup
    originals = {p: p.read_bytes() for p in reg.paths.values()}
    original_write = module._write
    def interrupted(path, content):
        if path == native / 'ssh_config.native':
            raise OSError('simulated interruption')
        original_write(path, content)
    monkeypatch.setattr(module, '_write', interrupted)
    with pytest.raises(OSError, match='simulated interruption'):
        reg.apply(descriptor)
    monkeypatch.setattr(module, '_write', original_write)
    pending = reg.plan(descriptor)['pending_transaction_id']
    assert pending
    reg.rollback(pending)
    assert all(p.read_bytes() == content for p, content in originals.items())


@pytest.mark.parametrize('config', [
    'Host dakota-cpu-native\n HostName 100.100.100.1\n',
    'Host *\n ProxyCommand sh -c evil\n',
    'Match all\n User operator\n',
])
def test_alias_and_wildcard_conflicts_rejected(setup, config):
    reg, descriptor, _, native = setup
    path = native / 'ssh_config.native'
    path.write_text(path.read_text() + '\n' + config)
    with pytest.raises(ValueError):
        reg.plan(descriptor)


def test_conflicting_host_key_rejected(setup):
    reg, descriptor, _, native = setup
    path = native / 'known_hosts.native'
    path.write_text(path.read_text() + '[100.118.115.62]:22222 ' + public_key(b'c') + '\n')
    with pytest.raises(ValueError, match='Host key conflict'):
        reg.plan(descriptor)


def test_adopt_manual_cpu_block_without_optional_options(setup):
    reg, descriptor, _, native = setup
    result = reg.apply(descriptor)
    reg.complete(result['transaction_id'])
    path = native / 'ssh_config.native'
    text = path.read_text().replace('  GlobalKnownHostsFile /dev/null\n', '').replace('  PreferredAuthentications publickey\n', '')
    path.write_text(text)
    assert reg.plan(descriptor)['changed'] is False
    assert reg.apply(descriptor)['changed'] is False
    assert path.read_text() == text


def test_complete_refuses_changed_files(setup):
    reg, descriptor, state, _ = setup
    result = reg.apply(descriptor)
    path = state / 'cas-targets.json'
    path.write_text(path.read_text() + '\n')
    with pytest.raises(ValueError, match='changed before completion'):
        reg.complete(result['transaction_id'])
    assert reg.pending.exists()


def test_probe_uses_verified_key_and_ignores_user_ssh_config(setup, monkeypatch):
    from types import SimpleNamespace
    import native_registration as module
    reg, descriptor, _, native = setup
    observed = []
    def run(args, **kwargs):
        observed.append(args)
        known_path = next(x.split('=', 1)[1] for x in args if x.startswith('UserKnownHostsFile='))
        assert descriptor['host_public_key'] in Path(known_path).read_text()
        assert Path(known_path).stat().st_mode & 0o777 == 0o600
        return SimpleNamespace(returncode=0, stdout=json.dumps({'status': 'running', 'socketPath': descriptor['socket']}))
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert Registration.probe(reg, descriptor)['status'] == 'PASS'
    args = observed[0]
    assert args[1:3] == ['-F', '/dev/null']
    assert 'StrictHostKeyChecking=yes' in args
    assert 'ForwardAgent=no' in args
    assert str(native / 'identity') in args
    assert args[-1].endswith(' app-server daemon version')


def test_finish_operations_are_retryable(setup):
    reg, descriptor, _, _ = setup
    result = reg.apply(descriptor)
    reg.rollback(result['transaction_id'])
    assert reg.rollback(result['transaction_id'])['status'] == 'rolled_back'
    result = reg.apply(descriptor)
    reg.complete(result['transaction_id'])
    assert reg.complete(result['transaction_id'])['status'] == 'complete'


def test_plan_identifies_pending_target(setup):
    reg, descriptor, _, _ = setup
    assert reg.plan(descriptor)['pending_name'] is None
    result = reg.apply(descriptor)
    plan = reg.plan(descriptor)
    assert plan['pending_name'] == descriptor['name']
    assert plan['pending_transaction_id'] == result['transaction_id']


@pytest.mark.parametrize('response', ['not json', '{}', '[]', '{"status":"stopped"}', '{"status":"running","socketPath":"/tmp/other.sock"}'])
def test_probe_rejects_inactive_or_unverified_daemon(setup, monkeypatch, response):
    from types import SimpleNamespace
    import native_registration as module
    reg, descriptor, _, _ = setup
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=response))
    with pytest.raises(ValueError, match='daemon'):
        Registration.probe(reg, descriptor)


def test_probe_accepts_running_daemon_without_optional_socket_field(setup, monkeypatch):
    from types import SimpleNamespace
    import native_registration as module
    reg, descriptor, _, _ = setup
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='{"status":"running"}'))
    assert Registration.probe(reg, descriptor)['status'] == 'PASS'
