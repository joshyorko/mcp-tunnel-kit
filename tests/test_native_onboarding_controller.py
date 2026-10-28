import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import native_onboarding_controller as c


def connection(monkeypatch):
    instance = json.loads((Path(__file__).parents[1] / 'config/instance.example.json').read_text())
    monkeypatch.setattr(c.deploy, 'INSTANCE', instance)
    return c.Connection()


def test_adoption_does_not_reboot_or_require_native_tuple(monkeypatch):
    conn = connection(monkeypatch)
    monkeypatch.setattr(c.deploy, 'lock', __import__('contextlib').nullcontext)
    rpc = Mock(side_effect=[{'changed': False}, {'changed': False, 'transaction_id': None}, {'verified': True}])
    monkeypatch.setattr(conn, '_call', rpc)
    reboot = Mock()
    monkeypatch.setattr(c.deploy, 'kamal', reboot)
    result = conn.register({'name': 'cpu'})
    assert result['changed'] is False
    assert [x.args[0] for x in rpc.call_args_list] == ['plan', 'apply', 'verify']
    reboot.assert_not_called()


def test_changed_registration_requires_original_native_acceptance_before_apply(monkeypatch):
    conn = connection(monkeypatch)
    monkeypatch.setattr(c.deploy, 'lock', __import__('contextlib').nullcontext)
    rpc = Mock(return_value={'changed': True})
    monkeypatch.setattr(conn, '_call', rpc)
    with pytest.raises(ValueError, match='native'):
        conn.register({'name': 'cpu'})
    assert rpc.call_count == 1


def test_ci_requires_descriptor_and_both_native_fields():
    with pytest.raises(SystemExit):
        c.parser().parse_args(['--descriptor', 'foo', '--native-cwd', '/tmp/a'])


def test_verify_rejects_nested_action_errors():
    with pytest.raises(RuntimeError, match='action'):
        c.action_result({'isError': False, 'structuredContent': {'result': None, 'error': 'failed'}})


def test_verify_requires_structured_success():
    with pytest.raises(RuntimeError):
        c.action_result({'content': []})


def test_failed_controller_request_reports_failure_on_stderr(monkeypatch, capsys):
    import subprocess
    monkeypatch.setattr(c, '_remote_source', lambda: 'source')
    monkeypatch.setattr(c.deploy, 'INSTANCE', {})
    monkeypatch.setattr(c.instance_profile, 'encode', lambda _instance: 'profile')
    monkeypatch.setattr(c.deploy, 'ssh_args', lambda _command: ['ssh'])
    monkeypatch.setattr(c.subprocess, 'run', lambda *args, **kwargs: subprocess.CompletedProcess(
        ['ssh'], 1, '', 'ValueError: remote failure'))
    with pytest.raises(RuntimeError, match='remote failure'):
        c.Connection().info()
    captured = capsys.readouterr()
    assert not captured.out
    assert 'Reading controller identity: failed' in captured.err
    assert 'Reading controller identity: done' not in captured.err


@pytest.fixture
def changed(monkeypatch):
    conn = connection(monkeypatch)
    monkeypatch.setattr(c.deploy, 'lock', __import__('contextlib').nullcontext)
    snapshot = {'authority': 'kamal', 'identity': 'retained', 'tunnel_count': 1,
                'inventory': {'cas': {'image': 'pinned'}}}
    current = {'authority': 'kamal', 'identity': 'retained', 'manifest': {'pin': 'unchanged'}}
    def remote(action, data=None):
        return current if action == 'current' else snapshot
    monkeypatch.setattr(c.deploy, 'remote', remote)
    monkeypatch.setattr(c.deploy, 'configuration', lambda directory, manifest: Path(directory) / 'deploy.yml')
    smoke = Mock()
    monkeypatch.setattr(c.deploy, 'smoke', smoke)
    monkeypatch.setattr(conn, '_bundle', Mock())
    refresh = Mock()
    monkeypatch.setattr(conn, '_refresh', refresh)
    native = {'target': 'local', 'cwd': '/work/original', 'thread_id': '019b0000-0000-7000-8000-000000000000'}
    return conn, native, smoke, refresh


def test_changed_success_refreshes_only_cas_and_completes_after_both_gates(changed, monkeypatch):
    conn, native, smoke, refresh = changed
    rpc = Mock(side_effect=[{'changed': True}, {'changed': True, 'transaction_id': 'a' * 32},
                            {'verified': True}, {'status': 'complete'}])
    monkeypatch.setattr(conn, '_call', rpc)
    assert conn.register({'name': 'cpu'}, native)['verified']
    assert [call.args[0] for call in rpc.call_args_list] == ['plan', 'apply', 'verify', 'complete']
    assert smoke.call_count == 2
    assert all(call.kwargs == {'require_native': True} for call in smoke.call_args_list)
    refresh.assert_called_once()


def test_failed_new_target_verification_restores_files_and_recreates_cas(changed, monkeypatch):
    conn, native, smoke, refresh = changed
    rpc = Mock(side_effect=[{'changed': True}, {'changed': True, 'transaction_id': 'a' * 32},
                            RuntimeError('new endpoint unavailable'), {'status': 'rolled_back'}])
    monkeypatch.setattr(conn, '_call', rpc)
    with pytest.raises(RuntimeError, match='previous CAS configuration restored'):
        conn.register({'name': 'cpu'}, native)
    assert [call.args[0] for call in rpc.call_args_list] == ['plan', 'apply', 'verify', 'rollback']
    assert refresh.call_count == 2


def test_apply_transport_failure_recovers_published_transaction(changed, monkeypatch):
    conn, native, smoke, refresh = changed
    rpc = Mock(side_effect=[{'changed': True}, RuntimeError('transport lost'),
                            {'pending_transaction_id': 'a' * 32}, {'status': 'rolled_back'}])
    monkeypatch.setattr(conn, '_call', rpc)
    with pytest.raises(RuntimeError, match='transport lost'):
        conn.register({'name': 'cpu'}, native)
    assert [call.args[0] for call in rpc.call_args_list] == ['plan', 'apply', 'plan', 'rollback']
    refresh.assert_called_once()


def test_rerun_recovers_same_target_interrupted_transaction(changed, monkeypatch):
    conn, native, smoke, refresh = changed
    rpc = Mock(side_effect=[{'changed': False, 'pending_transaction_id': 'a' * 32, 'pending_name': 'cpu'},
                            {'status': 'rolled_back'}, {'changed': True},
                            {'changed': True, 'transaction_id': 'b' * 32}, {'verified': True}, {'status': 'complete'}])
    monkeypatch.setattr(conn, '_call', rpc)
    assert conn.register({'name': 'cpu'}, native)['verified']
    assert refresh.call_count == 2


def test_rerun_does_not_recover_a_different_target(changed, monkeypatch):
    conn, native, _, refresh = changed
    rpc = Mock(return_value={'changed': False, 'pending_transaction_id': 'a' * 32, 'pending_name': 'other'})
    monkeypatch.setattr(conn, '_call', rpc)
    with pytest.raises(ValueError, match='Another native target'):
        conn.register({'name': 'cpu'}, native)
    assert rpc.call_count == 1
    refresh.assert_not_called()


def test_lost_completion_response_does_not_rollback_committed_state(changed, monkeypatch):
    conn, native, _, refresh = changed
    rpc = Mock(side_effect=[{'changed': True}, {'changed': True, 'transaction_id': 'a' * 32},
                            {'verified': True}, RuntimeError('completion response lost'),
                            {'changed': False, 'pending_transaction_id': None}])
    monkeypatch.setattr(conn, '_call', rpc)
    assert conn.register({'name': 'cpu'}, native)['verified']
    assert [call.args[0] for call in rpc.call_args_list] == ['plan', 'apply', 'verify', 'complete', 'plan']
    refresh.assert_called_once()


def test_lifecycle_rename_passes_pre_and_post_acceptance_and_verifies_before_complete(changed, monkeypatch):
    conn, native, smoke, refresh = changed
    accepted = {**native, 'target': 'dakota-nvidia'}
    monkeypatch.setattr(c.deploy, 'native_codex_tuple', lambda args: {
        'target': args.native_target, 'cwd': args.native_cwd,
        'thread_id': args.native_thread_id})
    rpc = Mock(side_effect=[{'pending': None},
                            {'changed': True, 'targets_before': {'local': {}},
                             'targets_after': {'local': {}, 'dakota-nvidia': {}}},
                            {'changed': True, 'transaction_id': 'b' * 32,
                             'pending_transaction_id': 'b' * 32, 'pending_name': 'dakota',
                             'pending_operation': 'rename'},
                            {'verified': True}, {'status': 'complete'}])
    monkeypatch.setattr(conn, '_call', rpc)
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': 'SHA256:' + 'a' * 43})
    result = conn.lifecycle({'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia'}, accepted)
    assert result['verified']
    assert result['status'] == 'complete'
    assert all(result[key] is None for key in ('pending_transaction_id', 'pending_name', 'pending_operation'))
    assert [call.args[0] for call in rpc.call_args_list] == [
        'pending', 'lifecycle-plan', 'lifecycle-apply', 'verify-lifecycle', 'complete']
    plan_request = rpc.call_args_list[1].args[1]
    assert plan_request['native_before'] == {**accepted, 'target': 'dakota'}
    assert plan_request['native_after'] == accepted
    assert smoke.call_args_list[0].args[0]['target'] == 'dakota'
    assert smoke.call_args_list[1].args[0]['target'] == 'dakota-nvidia'
    refresh.assert_called_once()


def test_lifecycle_pending_rename_recovers_using_journaled_native_before(changed, monkeypatch):
    conn, native, _, refresh = changed
    conn._call = Mock(side_effect=[
        {'pending': {'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia',
                     'controller_fingerprint': 'SHA256:' + 'a' * 43, 'transaction_id': 'c' * 32,
                     'native_before': native, 'native_after': {**native, 'target': 'dakota-nvidia'}}},
        {'changed': False, 'targets_before': {'local': {}}, 'targets_after': {'local': {}}},
        {'verified': True},
    ])
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': 'SHA256:' + 'a' * 43})
    monkeypatch.setattr(c.deploy, 'native_codex_tuple', lambda args: {
        'target': args.native_target, 'cwd': args.native_cwd,
        'thread_id': args.native_thread_id})
    monkeypatch.setattr(c.deploy, 'remote', lambda action, data=None: (
        {'manifest': {}, 'authority': 'kamal'} if action == 'current' else {'identity': 'same'}))
    monkeypatch.setattr(conn, '_bundle', Mock())
    monkeypatch.setattr(conn, '_recover', Mock())
    monkeypatch.setattr(conn, 'verify_lifecycle', Mock(return_value={'verified': True}))
    result = conn.lifecycle({'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia'})
    assert result['verified']
    conn._recover.assert_called_once_with('c' * 32, {'manifest': {}, 'authority': 'kamal'}, native)
    assert [call.args[0] for call in conn._call.call_args_list] == ['pending', 'lifecycle-plan']
    refresh.assert_not_called()


def test_lifecycle_rejects_pending_transaction_for_other_operation(changed, monkeypatch):
    conn, _, _, refresh = changed
    conn._call = Mock(return_value={'pending': {'operation': 'remove', 'name': 'other',
                                                'controller_fingerprint': 'SHA256:' + 'a' * 43,
                                                'transaction_id': 'd' * 32}})
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': 'SHA256:' + 'a' * 43})
    with pytest.raises(ValueError, match='unfinished'):
        conn.lifecycle({'operation': 'remove', 'name': 'dakota'})
    assert conn._call.call_count == 1
    refresh.assert_not_called()


def test_lifecycle_no_change_verifies_without_native_gate_or_reboot(changed, monkeypatch):
    conn, _, smoke, refresh = changed
    fingerprint = 'SHA256:' + 'a' * 43
    rpc = Mock(side_effect=[{'pending': None}, {'changed': False, 'targets_after': {'local': {}}}])
    monkeypatch.setattr(conn, '_call', rpc)
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': fingerprint})
    monkeypatch.setattr(conn, 'verify_lifecycle', lambda plan: {'verified': True})
    assert conn.lifecycle({'operation': 'remove', 'name': 'gone'}, {
        'target': 'local', 'cwd': '/work', 'thread_id': '019b0000-0000-7000-8000-000000000000'})['verified']
    assert [call.args[0] for call in rpc.call_args_list] == ['pending', 'lifecycle-plan']
    smoke.assert_not_called()
    refresh.assert_not_called()


def test_lifecycle_apply_transport_failure_recovers_from_pending_journal_before_replan(changed, monkeypatch):
    conn, native, _, refresh = changed
    fingerprint = 'SHA256:' + 'a' * 43
    accepted = {**native, 'target': 'dakota-nvidia'}
    journal = {'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia',
               'controller_fingerprint': fingerprint, 'transaction_id': 'e' * 32,
               'native_before': {**accepted, 'target': 'dakota'}, 'native_after': accepted}
    rpc = Mock(side_effect=[{'pending': None}, {'changed': True}, RuntimeError('transport lost'),
                            {'pending': journal}])
    monkeypatch.setattr(conn, '_call', rpc)
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': fingerprint})
    monkeypatch.setattr(c.deploy, 'native_codex_tuple', lambda args: {
        'target': args.native_target, 'cwd': args.native_cwd,
        'thread_id': args.native_thread_id})
    monkeypatch.setattr(c.deploy, 'remote', lambda action, data=None: (
        {'manifest': {}, 'authority': 'kamal', 'identity': 'retained'} if action == 'current' else
        {'authority': 'kamal', 'identity': 'retained', 'tunnel_count': 1, 'inventory': {}}))
    recover = Mock()
    monkeypatch.setattr(conn, '_recover', recover)
    with pytest.raises(RuntimeError, match='transport lost'):
        conn.lifecycle({'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia'}, accepted)
    assert [call.args[0] for call in rpc.call_args_list] == [
        'pending', 'lifecycle-plan', 'lifecycle-apply', 'pending']
    recover.assert_called_once_with('e' * 32,
                                    {'manifest': {}, 'authority': 'kamal', 'identity': 'retained'},
                                    journal['native_before'])
    refresh.assert_not_called()


def test_lifecycle_lost_completion_response_confirms_commit_without_rollback(changed, monkeypatch):
    conn, native, _, refresh = changed
    fingerprint = 'SHA256:' + 'a' * 43
    accepted = {**native, 'target': 'dakota-nvidia'}
    final_plan = {'changed': False, 'targets_before': {'local': {}}, 'targets_after': {'local': {}}}
    rpc = Mock(side_effect=[{'pending': None}, {'changed': True},
                            {'changed': True, 'transaction_id': 'f' * 32,
                             'targets_after': {'local': {}, 'dakota-nvidia': {}}},
                            RuntimeError('completion response lost'), {'pending': None}, final_plan])
    monkeypatch.setattr(conn, '_call', rpc)
    monkeypatch.setattr(conn, 'info', lambda: {'controller_fingerprint': fingerprint})
    monkeypatch.setattr(c.deploy, 'native_codex_tuple', lambda args: {
        'target': args.native_target, 'cwd': args.native_cwd,
        'thread_id': args.native_thread_id})
    monkeypatch.setattr(conn, 'verify_lifecycle', lambda plan: {'verified': True})
    assert conn.lifecycle({'operation': 'rename', 'name': 'dakota', 'new_name': 'dakota-nvidia'}, accepted)['verified']
    assert [call.args[0] for call in rpc.call_args_list] == [
        'pending', 'lifecycle-plan', 'lifecycle-apply', 'complete', 'pending', 'lifecycle-plan']
    assert refresh.call_count == 1


def test_native_acceptance_allows_named_target(monkeypatch):
    conn = connection(monkeypatch)
    monkeypatch.setattr(c.deploy, 'native_codex_tuple', lambda args: {
        'target': args.native_target, 'cwd': args.native_cwd,
        'thread_id': args.native_thread_id})
    assert conn._native({'target': 'dakota-nvidia', 'cwd': '/work', 'thread_id': 'thread'}) == {
        'target': 'dakota-nvidia', 'cwd': '/work', 'thread_id': 'thread'}


def test_lifecycle_cli_accepts_remove_and_rename_without_registration_descriptor():
    assert c.parser().parse_args(['--operation', 'remove', '--name', 'dakota', '--native-target', 'local',
                                 '--native-cwd', '/work', '--native-thread-id', '019b0000-0000-7000-8000-000000000000']).operation == 'remove'
    assert c.parser().parse_args(['--operation', 'rename', '--name', 'dakota', '--new-name', 'dakota-nvidia',
                                 '--native-target', 'dakota-nvidia', '--native-cwd', '/work',
                                 '--native-thread-id', '019b0000-0000-7000-8000-000000000000']).new_name == 'dakota-nvidia'


@pytest.mark.parametrize('operation,name,new_name,accepted', [
    ('remove', 'dakota', None, 'local'),
    ('rename', 'dakota', 'dakota-nvidia', 'dakota-nvidia'),
])
def test_lifecycle_controller_payloads_match_real_registration_dispatch(
        tmp_path, monkeypatch, operation, name, new_name, accepted):
    import native_registration

    fingerprint = 'SHA256:' + 'a' * 43
    state, native_dir = tmp_path / 'state', tmp_path / 'ssh'
    state.mkdir(mode=0o700)
    native_dir.mkdir(mode=0o700)

    def write(path, data):
        path.write_text(data)
        path.chmod(0o600)

    original = {'local': {'transport': 'ssh', 'destination': 'local-native'},
                'dakota': {'transport': 'ssh', 'destination': 'dakota-native'}}
    write(state / 'cas-targets.json', json.dumps({'targets': original}))
    write(native_dir / 'ssh_config.native', 'Host dakota-native\n  HostName 100.81.124.110\n')
    write(native_dir / 'known_hosts.native', '[100.81.124.110]:22222 ssh-ed25519 AAAA\n')
    profile = {'deploy_host': {'host_key_fingerprint': fingerprint},
               'vm': {'state_dir': str(state), 'native_ssh_dir': str(native_dir)}}
    conn = connection(monkeypatch)
    monkeypatch.setattr(c.deploy, 'lock', __import__('contextlib').nullcontext)
    snapshot = {'authority': 'kamal', 'identity': 'retained', 'tunnel_count': 1,
                'inventory': {'cas': {'image': 'pinned'}}}
    current = {'authority': 'kamal', 'identity': 'retained', 'manifest': {'pin': 'unchanged'}}
    monkeypatch.setattr(c.deploy, 'remote', lambda action, data=None: (
        current if action == 'current' else snapshot))
    monkeypatch.setattr(c.deploy, 'smoke', Mock())
    monkeypatch.setattr(conn, '_bundle', Mock())
    monkeypatch.setattr(conn, '_refresh', Mock())
    monkeypatch.setattr(c.deploy, 'configuration', lambda directory, manifest: Path(directory) / 'deploy.yml')
    monkeypatch.setattr(conn, 'verify_lifecycle', lambda plan: {'verified': True})
    conn.info = lambda: {'controller_fingerprint': fingerprint}
    conn._call = lambda action, data=None: native_registration.dispatch(action, data or {}, profile)
    native = {'target': accepted, 'cwd': '/work/tree',
              'thread_id': '019b0000-0000-7000-8000-000000000000'}
    result = conn.lifecycle({'operation': operation, 'name': name, 'new_name': new_name}
                            if new_name else {'operation': operation, 'name': name}, native)
    assert result['verified']
    targets = json.loads((state / 'cas-targets.json').read_text())['targets']
    if operation == 'remove':
        assert targets == {'local': original['local']}
    else:
        assert targets == {'local': original['local'], 'dakota-nvidia': original['dakota']}


@pytest.mark.parametrize('operation', ['remove', 'rename'])
@pytest.mark.parametrize('inventory', ['expected', 'dynamic', 'missing', 'removed'])
def test_lifecycle_verifier_consumes_real_registration_plan(tmp_path, monkeypatch, operation, inventory):
    import re
    import sys
    from types import SimpleNamespace
    import native_registration

    fingerprint = 'SHA256:' + 'a' * 43
    state, native_dir = tmp_path / 'state', tmp_path / 'ssh'
    state.mkdir(mode=0o700)
    native_dir.mkdir(mode=0o700)
    target = {'transport': 'ssh', 'destination': 'dakota-native',
              'codex_bin': '/usr/bin/codex', 'socket_path': '/run/codex.sock',
              'ssh_config': '/run/codex-ssh/ssh_config',
              'known_hosts': '/run/codex-ssh/known_hosts'}
    targets = {'local': {'transport': 'local'}, 'dakota': target}
    for path, content in ((state / 'cas-targets.json', json.dumps({'targets': targets})),
                          (native_dir / 'ssh_config.native', 'Host dakota-native\n'),
                          (native_dir / 'known_hosts.native', 'known host\n')):
        path.write_text(content)
        path.chmod(0o600)
    instance = {'deploy_host': {'host_key_fingerprint': fingerprint},
                'vm': {'state_dir': str(state), 'native_ssh_dir': str(native_dir),
                       'repo_dir': str(tmp_path), 'network': {'gateway': '127.0.0.1'}}}
    reg = native_registration.Registration(instance)
    before = {'target': 'local' if operation == 'remove' else 'dakota',
              'cwd': '/work', 'thread_id': '019b0000-0000-7000-8000-000000000000'}
    after = {'target': 'local' if operation == 'remove' else 'dakota-nvidia',
             'cwd': '/work', 'thread_id': '019b0000-0000-7000-8000-000000000000'}
    request = {'operation': operation, 'name': 'dakota', 'controller_fingerprint': fingerprint,
               'native_before': before, 'native_after': after}
    if operation == 'rename':
        request['new_name'] = 'dakota-nvidia'
    plan = reg.lifecycle_plan(request)
    expected_names = set(plan['targets_after'])
    if inventory == 'dynamic':
        # Worker registry discoveries coexist with the operator's static map.
        expected_names.add('runtime-worker')
    elif inventory == 'missing':
        expected_names.remove(sorted(expected_names)[0])
    elif inventory == 'removed':
        expected_names.add('dakota')

    def structured(value):
        return {'structuredContent': {'result': value}}

    class FakeMcp:
        def __init__(self, *_args):
            pass

        def call(self, _method, payload):
            action = payload['name']
            target_name = payload.get('arguments', {}).get('payload', {}).get('target')
            if action == 'list_targets':
                return structured({'targets': [{'name': name} for name in sorted(expected_names)]})
            if action == 'inspect_target':
                entry = plan['targets_after'][target_name]
                return structured({'destination': entry.get('destination'),
                                   'codex_bin': entry.get('codex_bin'),
                                   'socket': entry.get('socket_path')})
            return structured({'models': []})

    class FakeExecutor:
        def call(self, _method, payload):
            code = payload['arguments']['code']
            action = re.search(r'tools\.codex\.(\w+)\(', code).group(1)
            argument_text = code.split('(', 1)[1].rsplit(');', 1)[0]
            arguments = json.loads(argument_text)
            target_name = arguments.get('payload', {}).get('target')
            if action == 'list_targets':
                value = {'targets': [{'name': name} for name in sorted(expected_names)]}
            elif action == 'inspect_target':
                entry = plan['targets_after'][target_name]
                value = {'destination': entry.get('destination'), 'codex_bin': entry.get('codex_bin'),
                         'socket': entry.get('socket_path')}
            else:
                value = {'models': []}
            return {'status': 'completed', 'execution': {'ok': True, 'value': structured(value)}}

    fake_control = SimpleNamespace(Http=lambda _origin: object(), Mcp=FakeMcp,
                                   executor_session=lambda: (None, FakeExecutor()),
                                   execution=lambda result: result)
    monkeypatch.setitem(sys.modules, 'compose_control', fake_control)
    if inventory in ('missing', 'removed'):
        with pytest.raises(RuntimeError, match='omitted|still exposes'):
            c.verify_lifecycle_remote(instance, plan)
        return
    result = c.verify_lifecycle_remote(instance, plan)
    assert result == {'verified': True, 'operation': operation, 'name': 'dakota',
                      'new_name': plan.get('new_name'), 'cas': 'PASS', 'executor': 'PASS'}


def test_remote_source_embeds_lifecycle_verifier_dispatch():
    import base64
    import re
    import zlib
    source = c._remote_source()
    payload = re.search(r"b64decode\('([^']+)'\)", source).group(1)
    source = zlib.decompress(base64.b64decode(payload)).decode()
    assert "elif action == 'verify-lifecycle':" in source
    assert 'def verify_lifecycle_remote(instance, plan):' in source
    compile(source, '<remote-controller>', 'exec')
