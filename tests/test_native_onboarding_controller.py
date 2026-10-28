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
