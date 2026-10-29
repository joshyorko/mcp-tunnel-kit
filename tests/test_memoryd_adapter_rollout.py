"""Admission and recovery checks for a fenced adapter-only rollout."""
import hashlib
import base64
import fcntl
import json
import os
import stat
import itertools

import pytest

import vm_deploy_host as host
import deploy_control_plane as deploy


@pytest.fixture
def rollout_state(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    store = state / 'deployment'
    bootstrap = state / 'bootstrap'
    store.mkdir(mode=0o700, parents=True)
    bootstrap.mkdir(mode=0o700)
    state.chmod(0o700)
    current = store / 'current.json'
    host.write(current, {'authority': 'kamal', 'identity': 'fixture-identity'})
    pin = bootstrap / 'memoryd-adapter-image.json'
    image = 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'a' * 64
    old = 'b' * 64
    host.write(pin, {'schema_version': 1, 'image': image, 'adapter_sha256': old})
    payload = b'synthetic fixed adapter\n'
    digest = hashlib.sha256(payload).hexdigest()
    artifact = state / 'memoryd-adapter' / digest
    artifact.mkdir(mode=0o700, parents=True)
    artifact.parent.chmod(0o700)
    source = artifact / 'codex_memoryd_mcp.py'
    source.write_bytes(payload)
    source.chmod(0o600)
    host.write(artifact / 'artifact.json', {'adapter_sha256': digest,
               'size_bytes': len(payload), 'controller_sha': 'c' * 40})
    monkeypatch.setattr(host, 'STATE', state)
    monkeypatch.setattr(host, 'STORE', store)
    monkeypatch.setattr(host, 'memoryd_health', lambda: {'status': 'PASS', 'adapter_image': image,
                        'adapter_sha256': old})
    monkeypatch.setattr(host, '_verify_registered_memoryd_app', lambda: {'id': 'fixture'})
    monkeypatch.setattr(host, 'snapshot', lambda: {'authority': 'kamal', 'identity': 'fixture-identity',
                        'tunnel_count': 1, 'inventory': {'executor': {'state': 'running'}}})
    monkeypatch.setattr(host, '_memoryd_rollout_workers_clear', lambda: True, raising=False)
    monkeypatch.setattr(host, '_memoryd_rollout_exclusion', lambda _rollout_id: None, raising=False)
    monkeypatch.setattr(host, '_memoryd_rollout_container_identities', lambda: {'executor': 'fixture-id'}, raising=False)
    return {'state': state, 'store': store, 'bootstrap': bootstrap, 'pin': pin,
            'current': current, 'digest': digest, 'payload': payload, 'image': image,
            'request': {'rollout_id': 'd' * 32, 'adapter_sha256': digest,
                        'size_bytes': len(payload), 'controller_sha': 'c' * 40}}


def test_fence_blocks_legacy_lock_and_preserves_pin_bytes(rollout_state):
    fixture = rollout_state
    original_current, original_pin = fixture['current'].read_bytes(), fixture['pin'].read_bytes()
    result = host.memoryd_rollout_begin(fixture['request'])
    assert result['status'] == 'fenced'
    assert fixture['current'].read_bytes() == original_current
    assert fixture['pin'].read_bytes() == original_pin
    assert stat.S_IMODE(fixture['store'].stat().st_mode) == 0o500
    assert stat.S_IMODE(fixture['bootstrap'].stat().st_mode) == 0o500
    assert stat.S_IMODE(fixture['current'].stat().st_mode) == 0o400
    assert stat.S_IMODE(fixture['pin'].stat().st_mode) == 0o400
    with pytest.raises(ValueError, match='state directory is unsafe'):
        host._ensure_private_state_store()
    intent = json.loads((fixture['state'] / 'memoryd-adapter-rollouts' / ('d' * 32 + '.json')).read_text())
    assert intent['old_pin_sha256'] == hashlib.sha256(original_pin).hexdigest()
    assert intent['current_sha256'] == hashlib.sha256(original_current).hexdigest()
    assert intent['old_adapter_sha256'] == 'b' * 64
    assert intent['new_adapter_sha256'] == fixture['digest']
    assert intent['adapter_image'] == fixture['image']


def test_fence_refuses_active_worker_without_mutation(rollout_state, monkeypatch):
    monkeypatch.setattr(host, '_memoryd_rollout_workers_clear', lambda: False, raising=False)
    with pytest.raises(ValueError, match='workers'):
        host.memoryd_rollout_begin(rollout_state['request'])
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o700
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode) == 0o600
    assert not (rollout_state['state'] / 'memoryd-adapter-rollouts').exists()


def test_fence_refuses_changed_artifact_before_mutation(rollout_state):
    path = rollout_state['state'] / 'memoryd-adapter' / rollout_state['digest'] / 'codex_memoryd_mcp.py'
    path.write_bytes(b'altered')
    with pytest.raises(ValueError, match='artifact'):
        host.memoryd_rollout_begin(rollout_state['request'])
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o700


def test_select_requires_expected_live_container_and_keeps_admission_fenced(rollout_state, monkeypatch):
    host.memoryd_rollout_begin(rollout_state['request'])
    monkeypatch.setattr(host, '_memoryd_rollout_live_adapter', lambda: {
        'adapter_sha256': rollout_state['digest'], 'image': rollout_state['image'],
        'state': 'running', 'health': 'healthy'}, raising=False)
    result = host.memoryd_rollout_select({'rollout_id': 'd' * 32})
    assert result['status'] == 'selected'
    assert json.loads(rollout_state['pin'].read_text())['adapter_sha256'] == rollout_state['digest']
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500
    assert stat.S_IMODE(rollout_state['bootstrap'].stat().st_mode) == 0o500
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode) == 0o400
    assert stat.S_IMODE(rollout_state['current'].stat().st_mode) == 0o400
    assert host.memoryd_rollout_select({'rollout_id': 'd' * 32})['status'] == 'selected'


def test_select_rejects_unexpected_live_container_without_changing_pin(rollout_state, monkeypatch):
    old = rollout_state['pin'].read_bytes()
    host.memoryd_rollout_begin(rollout_state['request'])
    monkeypatch.setattr(host, '_memoryd_rollout_live_adapter', lambda: {
        'adapter_sha256': 'b' * 64, 'image': rollout_state['image'],
        'state': 'running', 'health': 'healthy'}, raising=False)
    with pytest.raises(ValueError, match='live adapter'):
        host.memoryd_rollout_select({'rollout_id': 'd' * 32})
    assert rollout_state['pin'].read_bytes() == old
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500


def selected(rollout_state, monkeypatch):
    host.memoryd_rollout_begin(rollout_state['request'])
    monkeypatch.setattr(host, '_memoryd_rollout_live_adapter', lambda: {
        'adapter_sha256': rollout_state['digest'], 'image': rollout_state['image'],
        'state': 'running', 'health': 'healthy'}, raising=False)
    host.memoryd_rollout_select({'rollout_id': 'd' * 32})
    monkeypatch.setattr(host, 'memoryd_health', lambda: {'status': 'PASS',
                        'adapter_image': rollout_state['image'],
                        'adapter_sha256': rollout_state['digest']})
    monkeypatch.setattr(host, 'smoke', lambda _data=None: {'catalog': 'PASS',
                        'devsy_reads': 'PASS', 'memoryd_discovery': 'PASS'})
    monkeypatch.setattr(host, '_memoryd_rollout_executor_accept', lambda: {'status': 'PASS'}, raising=False)


def test_accept_remains_fenced_until_explicit_finish(rollout_state, monkeypatch):
    selected(rollout_state, monkeypatch)
    result = host.memoryd_rollout_accept({'rollout_id': 'd' * 32})
    assert result['status'] == 'accepted'
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode) == 0o400
    result = host.memoryd_rollout_finish({'rollout_id': 'd' * 32})
    assert result['status'] == 'complete'
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o700
    assert stat.S_IMODE(rollout_state['bootstrap'].stat().st_mode) == 0o700
    assert stat.S_IMODE(rollout_state['current'].stat().st_mode) == 0o600
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode) == 0o600
    assert not (rollout_state['state'] / 'memoryd-adapter-rollouts' / 'active.json').exists()
    assert host.memoryd_rollout_release_check({'rollout_id': 'd' * 32})['status'] == 'complete'


def test_failed_acceptance_remains_fenced(rollout_state, monkeypatch):
    selected(rollout_state, monkeypatch)
    monkeypatch.setattr(host, '_memoryd_rollout_executor_accept', lambda: {'status': 'FAILED'})
    with pytest.raises(ValueError, match='acceptance'):
        host.memoryd_rollout_accept({'rollout_id': 'd' * 32})
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode) == 0o400


def test_acceptance_rejects_an_unrelated_container_restart(rollout_state, monkeypatch):
    selected(rollout_state, monkeypatch)
    monkeypatch.setattr(host, '_memoryd_rollout_container_identities', lambda: {'executor': 'replacement-id'})
    with pytest.raises(ValueError, match='acceptance'):
        host.memoryd_rollout_accept({'rollout_id': 'd' * 32})
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500


def test_release_check_refuses_when_an_active_rollout_still_exists(rollout_state, monkeypatch):
    selected(rollout_state, monkeypatch)
    with pytest.raises(ValueError, match='active'):
        host.memoryd_rollout_release_check({'rollout_id': 'd' * 32})
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode) == 0o500


def test_release_check_accepts_healthy_never_started_rollout(rollout_state):
    result=host.memoryd_rollout_release_check({'rollout_id': 'd' * 32})
    assert result == {'status': 'not-started', 'rollout_id': 'd' * 32, 'safe_to_release': True}
    assert not (rollout_state['state'] / 'memoryd-adapter-rollouts').exists()


def test_abort_restores_old_healthy_state_without_reboot(rollout_state, monkeypatch):
    old = rollout_state['pin'].read_bytes()
    host.memoryd_rollout_begin(rollout_state['request'])
    monkeypatch.setattr(host, '_memoryd_rollout_live_adapter', lambda: {
        'adapter_sha256': 'b' * 64, 'image': rollout_state['image'],
        'state': 'running', 'health': 'healthy'}, raising=False)
    monkeypatch.setattr(host, 'smoke', lambda _data=None: {'catalog': 'PASS',
                        'devsy_reads': 'PASS', 'memoryd_discovery': 'PASS'})
    result=host.memoryd_rollout_abort({'rollout_id': 'd' * 32})
    assert result['status']=='aborted'
    assert rollout_state['pin'].read_bytes()==old
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode)==0o700
    assert stat.S_IMODE(rollout_state['pin'].stat().st_mode)==0o600
    assert host.memoryd_rollout_release_check({'rollout_id': 'd' * 32})['status']=='aborted'


def test_abort_refuses_new_or_unknown_live_adapter(rollout_state, monkeypatch):
    host.memoryd_rollout_begin(rollout_state['request'])
    monkeypatch.setattr(host, '_memoryd_rollout_live_adapter', lambda: {
        'adapter_sha256': rollout_state['digest'], 'image': rollout_state['image'],
        'state': 'running', 'health': 'healthy'}, raising=False)
    with pytest.raises(ValueError, match='live adapter'):
        host.memoryd_rollout_abort({'rollout_id': 'd' * 32})
    assert stat.S_IMODE(rollout_state['store'].stat().st_mode)==0o500


def test_exclusion_requires_held_flock_and_exact_encoded_kamal_message(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    store = state / 'deployment'
    store.mkdir(mode=0o700, parents=True)
    lock = store / 'deploy.lock'
    lock.touch(mode=0o600)
    kamal = tmp_path / '.kamal' / 'lock-mcp-control-plane'
    kamal.mkdir(parents=True)
    details = kamal / 'details'
    details.write_bytes(base64.encodebytes(('Locked by: fixture\nMessage: memoryd-adapter-rollout:' + 'd' * 32).encode()))
    monkeypatch.setattr(host, 'STORE', store)
    monkeypatch.setattr(host.Path, 'home', staticmethod(lambda: tmp_path))
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        host._memoryd_rollout_exclusion('d' * 32)
        with pytest.raises(ValueError, match='another operation'):
            host._memoryd_rollout_exclusion('e' * 32)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    with pytest.raises(ValueError, match='lock was lost'):
        host._memoryd_rollout_exclusion('d' * 32)


@pytest.mark.parametrize('modes', itertools.product((0o500, 0o700), (0o500, 0o700),
                                                     (0o400, 0o600), (0o400, 0o600)))
def test_reconcile_refences_every_partial_completion_mode(rollout_state, monkeypatch, modes):
    selected(rollout_state, monkeypatch)
    host.memoryd_rollout_accept({'rollout_id': 'd' * 32})
    journal = rollout_state['state'] / 'memoryd-adapter-rollouts' / ('d' * 32 + '.json')
    intent = json.loads(journal.read_text())
    intent['status'] = 'complete'
    host.write(journal, intent)
    for path, mode in zip((rollout_state['store'], rollout_state['bootstrap'],
                           rollout_state['current'], rollout_state['pin']), modes):
        path.chmod(mode)
    result = host.memoryd_rollout_reconcile({'rollout_id': 'd' * 32})
    assert result['status'] == 'fenced'
    assert result['requires_acceptance'] is True
    assert [stat.S_IMODE(path.stat().st_mode) for path in
            (rollout_state['store'], rollout_state['bootstrap'], rollout_state['current'], rollout_state['pin'])] == [0o500, 0o500, 0o400, 0o400]
    assert json.loads(journal.read_text())['status'] == 'selected'


def test_adapter_reboot_uses_prevalidated_config_and_only_owned_kamal_lock(tmp_path, monkeypatch):
    calls = []
    remote_calls = []
    monkeypatch.setattr(deploy, 'profile', lambda: {'state_dir': '/srv/private'})
    monkeypatch.setattr(deploy, 'remote', lambda action, data=None: remote_calls.append((action, data)))
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return type('Result', (), {'returncode': 0})()
    monkeypatch.setattr(deploy.subprocess, 'run', run)
    deploy.kamal_rollout_reboot(tmp_path / 'deploy.yml', 'd' * 32,
                                '/srv/private/deployment/anonymous-docker-config')
    assert remote_calls == [('memoryd-rollout-lock-check', {'rollout_id': 'd' * 32})]
    argv, options = calls[0]
    assert argv[-5:-2] == ['accessory', 'reboot', 'memoryd-mcp']
    assert options['env']['KAMAL_LOCK'] == 'true'
    assert options['env']['KAMAL_PUBLIC_DOCKER_CONFIG'] == '/srv/private/deployment/anonymous-docker-config'


def test_adapter_reboot_reports_unknown_and_never_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, 'profile', lambda: {'state_dir': '/srv/private'})
    monkeypatch.setattr(deploy, 'remote', lambda *_args: None)
    calls = []
    def fail(argv, **kwargs):
        calls.append(argv)
        return type('Result', (), {'returncode': 1})()
    monkeypatch.setattr(deploy.subprocess, 'run', fail)
    with pytest.raises(RuntimeError, match='outcome unknown'):
        deploy.kamal_rollout_reboot(tmp_path / 'deploy.yml', 'd' * 32,
                                    '/srv/private/deployment/anonymous-docker-config')
    assert len(calls) == 1


@pytest.mark.parametrize('argv', [
    [b'/usr/bin/docker', b'exec', b'fixture'],
    [b'/usr/bin/scp', b'fixture'],
    [b'/usr/lib/openssh/sftp-server'],
    [b'/bin/sh', b'-c', b'docker cp fixture'],
    [b'/usr/bin/ruby', b'/opt/gems/kamal'],
    [b'python3', b'-c', b"'<mcp-controller>'", b'memoryd-import-bundles'],
])
def test_worker_inventory_refuses_active_mutators(tmp_path, monkeypatch, argv):
    proc = tmp_path / 'proc'
    process = proc / '99999999'
    process.mkdir(parents=True)
    (process / 'cmdline').write_bytes(b'\0'.join(argv) + b'\0')
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: True)
    monkeypatch.setattr(host, '_memoryd_rollout_execs_clear', lambda: True)
    assert host._memoryd_rollout_workers_clear(proc=proc) is False


def test_worker_inventory_allows_only_its_deployment_lock_holder(tmp_path, monkeypatch):
    proc = tmp_path / 'proc'
    process = proc / '99999999'
    process.mkdir(parents=True)
    (process / 'cmdline').write_bytes(b'python3\0-c\0<mcp-controller>\0lock\0')
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: True)
    monkeypatch.setattr(host, '_memoryd_rollout_execs_clear', lambda: True)
    assert host._memoryd_rollout_workers_clear(proc=proc) is True


def test_update_uses_existing_image_and_executes_only_one_adapter_reboot(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    script = root / 'scripts/codex_memoryd_mcp.py'
    script.parent.mkdir(parents=True)
    script.write_bytes(b'synthetic adapter')
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    image = 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'a' * 64
    original = 'b' * 64
    baseline = {'authority': 'kamal', 'identity': 'fixture', 'inventory': {}, 'tunnel_count': 1}
    health = {'status': 'PASS', 'adapter_sha256': original, 'adapter_image': image,
              'memoryd_image': host.MEMORYD_IMAGE}
    seen = []
    snapshots = [baseline, baseline]
    healths = [health, {**health, 'adapter_sha256': digest}]
    def remote(action, data=None):
        seen.append(action)
        if action == 'status': return {'authority': 'kamal', 'healthy': True, 'tunnel_count': 1}
        if action == 'snapshot': return snapshots.pop(0)
        if action == 'current': return {'authority': 'kamal', 'identity': 'fixture', 'manifest': {}}
        if action == 'memoryd-health': return healths.pop(0)
        if action == 'memoryd-registration-check': return {'registration_verified': True}
        if action == 'memoryd-adapter-prepare':
            return {'directory': '/srv/private/memoryd-adapter/' + digest,
                    'adapter_sha256': digest, 'needs_upload': False}
        if action == 'anonymous-docker-config': return {'path': '/srv/private/deployment/anonymous-docker-config'}
        if action == 'memoryd-rollout-accept': return {'status': 'accepted', 'executor': {'status': 'PASS'}}
        if action == 'memoryd-rollout-finish': return {'status': 'complete'}
        if action == 'memoryd-rollout-release-check': return {'safe_to_release': True}
        return {}
    configs, kamal = [], []
    monkeypatch.setattr(deploy, 'ROOT', root)
    monkeypatch.setattr(deploy, 'profile', lambda: {'state_dir': '/srv/private'})
    monkeypatch.setattr(deploy, 'remote', remote)
    monkeypatch.setattr(deploy, 'configuration', lambda _dir, _manifest, **kw: configs.append(kw) or 'fixture-config')
    monkeypatch.setattr(deploy, 'kamal_rollout_lock', lambda _cfg, op, _id, _dc: kamal.append(('lock', op)))
    monkeypatch.setattr(deploy, 'kamal_rollout_reboot', lambda *_args: kamal.append(('reboot', 'memoryd-mcp')))
    monkeypatch.setattr(deploy, 'smoke', lambda _: {'memoryd_discovery': 'PASS'})
    result = deploy.upgrade_memoryd_adapter('c' * 40, tmp_path)
    assert result['status'] == 'PASS'
    assert kamal == [('lock', 'acquire'), ('reboot', 'memoryd-mcp'), ('lock', 'release')]
    assert configs[0]['memoryd_recovery']['adapter_image'] == image
    assert configs[0]['memoryd_recovery']['adapter_sha256'] == digest
    assert seen.index('memoryd-rollout-accept') < seen.index('memoryd-rollout-finish')


def test_recovery_never_reboots_when_the_new_container_is_missing(tmp_path, monkeypatch):
    calls=[]
    def remote(action, data=None):
        calls.append(action)
        if action == 'memoryd-rollout-reconcile': return {'status': 'fenced', 'pin': 'old'}
        if action == 'memoryd-rollout-wait': raise ValueError('container absent')
        raise AssertionError(action)
    monkeypatch.setattr(deploy, 'remote', remote)
    monkeypatch.setattr(deploy, 'kamal_rollout_reboot', lambda *_args: pytest.fail('unexpected reboot'))
    monkeypatch.setattr(deploy, 'release_memoryd_rollout', lambda *_args: pytest.fail('unexpected release'))
    with pytest.raises(ValueError, match='container absent'):
        deploy.recover_memoryd_rollout('memoryd-rollout-complete', 'd' * 32, tmp_path)
    assert calls == ['memoryd-rollout-reconcile', 'memoryd-rollout-wait']
