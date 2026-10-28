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
    assert reg.pending_path.exists()


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


def lifecycle_request(reg, operation='rename', name='local', new_name='dakota-nvidia'):
    before = {'target': 'local', 'cwd': '/home/kdlocpanda/second_brain',
              'thread_id': '12345678-1234-5678-9abc-def012345678'}
    after = {'target': new_name if operation == 'rename' else 'local',
             'cwd': '/home/kdlocpanda/second_brain',
             'thread_id': '12345678-1234-5678-9abc-def012345678'}
    request = {'operation': operation, 'name': name,
               'controller_fingerprint': reg.instance['deploy_host']['host_key_fingerprint'],
               'native_before': before, 'native_after': after}
    if operation == 'rename':
        request['new_name'] = new_name
    return request


def test_lifecycle_rename_preserves_entry_and_journals_native_tuples(setup):
    reg, _, state, _ = setup
    targets = {'local': {'transport': 'ssh', 'destination': 'dakota-native', 'opaque': {'x': 1}},
               'keep': {'transport': 'ssh', 'destination': 'other'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': targets}))
    request = lifecycle_request(reg)
    plan = reg.lifecycle_plan(request)
    assert plan['targets_before'] == targets
    assert plan['targets_after'] == {'dakota-nvidia': targets['local'], 'keep': targets['keep']}
    assert plan['operation'] == 'rename' and plan['new_name'] == 'dakota-nvidia'
    result = reg.lifecycle_apply(request)
    journal = reg._journal(result['transaction_id'])
    assert journal['native_before'] == request['native_before']
    assert journal['native_after'] == request['native_after']
    assert journal['targets_before'] == targets
    assert json.loads((state / 'cas-targets.json').read_text())['targets'] == plan['targets_after']
    assert set(result['files']) == {'targets'}


def test_lifecycle_rename_rejects_conflicting_destination(setup):
    reg, _, state, _ = setup
    (state / 'cas-targets.json').write_text(json.dumps({'targets': {
        'local': {'transport': 'ssh', 'destination': 'dakota-native'},
        'dakota-nvidia': {'transport': 'local', 'destination': 'other'}}}))
    with pytest.raises(ValueError, match='conflict'):
        reg.lifecycle_plan(lifecycle_request(reg))


def test_lifecycle_rename_rejects_missing_source_without_receipt(setup):
    reg, _, state, _ = setup
    (state / 'cas-targets.json').write_text(json.dumps({'targets': {
        'dakota-nvidia': {'transport': 'ssh', 'destination': 'dakota-native'},
        'keep': {'transport': 'ssh'}}}))
    with pytest.raises(ValueError, match='source missing'):
        reg.lifecycle_plan(lifecycle_request(reg))


def test_lifecycle_remove_refuses_last_and_acceptance_target(setup):
    reg, _, state, _ = setup
    (state / 'cas-targets.json').write_text(json.dumps({'targets': {'local': {'transport': 'ssh'}}}))
    request = lifecycle_request(reg, operation='remove', name='local')
    request['native_after'] = {'target': 'local', 'cwd': request['native_before']['cwd'], 'thread_id': request['native_before']['thread_id']}
    with pytest.raises(ValueError, match='last|acceptance'):
        reg.lifecycle_plan(request)
    (state / 'cas-targets.json').write_text(json.dumps({'targets': {
        'local': {'transport': 'ssh'}, 'keep': {'transport': 'ssh'}}}))
    with pytest.raises(ValueError, match='acceptance'):
        reg.lifecycle_plan(request)


def test_lifecycle_remove_retry_and_rollback_restore_local(setup):
    reg, _, state, _ = setup
    original = {'local': {'transport': 'ssh'}, 'keep': {'transport': 'ssh'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': original}))
    request = lifecycle_request(reg, operation='remove', name='keep')
    request['native_before']['target'] = 'local'
    request['native_after']['target'] = 'local'
    result = reg.lifecycle_apply(request)
    reg.rollback(result['transaction_id'])
    assert json.loads((state / 'cas-targets.json').read_text())['targets'] == original
    reg.lifecycle_apply(request)
    assert reg.lifecycle_plan(request)['changed'] is False


def test_pending_matches_lifecycle_request_after_rename_publication(setup):
    reg, _, state, _ = setup
    targets = {'local': {'transport': 'ssh', 'destination': 'dakota-native'},
               'keep': {'transport': 'ssh'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': targets}))
    request = lifecycle_request(reg)
    result = reg.lifecycle_apply(request)
    pending = reg.pending(request)
    assert pending['transaction_id'] == result['transaction_id']
    assert pending['targets_before'] == targets
    with pytest.raises(ValueError, match='pending'):
        reg.pending(lifecycle_request(reg, new_name='other'))


def test_pending_dispatch_recovers_with_identity_only_after_source_is_gone(setup):
    import native_registration as module
    reg, _, state, _ = setup
    targets = {'local': {'transport': 'ssh', 'destination': 'dakota-native'},
               'keep': {'transport': 'ssh'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': targets}))
    request = lifecycle_request(reg)
    result = reg.lifecycle_apply(request)
    assert 'local' not in json.loads(reg.paths['targets'].read_text())['targets']
    identity = {key: request[key] for key in ('operation', 'name', 'new_name', 'controller_fingerprint')}
    response = module.dispatch('pending', identity, reg.instance)
    assert response['pending']['transaction_id'] == result['transaction_id']
    assert response['pending']['native_before'] == request['native_before']
    assert response['pending']['native_after'] == request['native_after']


def test_lifecycle_rejects_control_characters_in_native_cwd(setup):
    reg, _, _, _ = setup
    request = lifecycle_request(reg)
    request['native_before']['cwd'] = '/repo\nmalicious'
    with pytest.raises(ValueError, match='acceptance tuple'):
        reg.lifecycle_plan(request)


def test_completed_lifecycle_rename_is_idempotent_only_for_receipted_entry(setup):
    reg, _, state, _ = setup
    original = {'local': {'transport': 'ssh', 'destination': 'dakota-native', 'custom': [1, 2]},
                'keep': {'transport': 'ssh'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': original}))
    request = lifecycle_request(reg)
    result = reg.lifecycle_apply(request)
    reg.complete(result['transaction_id'])
    assert reg.lifecycle_plan(request)['changed'] is False
    changed = {'dakota-nvidia': {'transport': 'ssh', 'destination': 'changed'},
               'keep': original['keep']}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': changed}))
    with pytest.raises(ValueError, match='source missing'):
        reg.lifecycle_plan(request)


def test_lifecycle_partial_publication_rolls_back_and_changed_assets_are_refused(setup, monkeypatch):
    import native_registration as module
    reg, _, state, _ = setup
    original = {'local': {'transport': 'ssh'}, 'keep': {'transport': 'ssh'}}
    (state / 'cas-targets.json').write_text(json.dumps({'targets': original}))
    request = lifecycle_request(reg)
    original_write = module._write
    def interrupted(path, content):
        if path == reg.paths['targets']:
            raise OSError('simulated interruption')
        original_write(path, content)
    monkeypatch.setattr(module, '_write', interrupted)
    with pytest.raises(OSError, match='simulated interruption'):
        reg.lifecycle_apply(request)
    monkeypatch.setattr(module, '_write', original_write)
    journal = reg.pending(request)
    assert journal['operation'] == 'rename'
    assert journal['targets_before'] == original
    reg.rollback(journal['transaction_id'])
    assert json.loads(reg.paths['targets'].read_text())['targets'] == original
    result = reg.lifecycle_apply(request)
    reg.paths['ssh_config'].write_text('operator edit\n')
    with pytest.raises(ValueError, match='changed since transaction'):
        reg.rollback(result['transaction_id'])
    assert reg.paths['ssh_config'].read_text() == 'operator edit\n'
