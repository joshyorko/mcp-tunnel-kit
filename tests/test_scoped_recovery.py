"""Reconcile without effects; a fresh, rechecked intent may provision once."""
import json
import threading
import time

import pytest

from test_worker_scope import manager

NAME = 'cas-worker-01'
CREDENTIAL = 'Bearer fixture-owner-secret'


def proof(name, scope):
    return {'kind': 'absent', 'observed_at': time.time(), 'namespace_uid': 'namespace-uid',
            'kubernetes_context': 'ror', 'namespace': 'devsy', 'workspace_absent': True,
            'provider_resources_absent': True, 'lifecycle_processes_absent': True}


def stuck(tmp_path, invoke=None):
    module, scope, calls = manager(tmp_path, invoke)
    scope.absence = proof
    scope.root()
    original = {'name': NAME, 'operation_id': 'original-operation', 'request_id': 'original-request',
                'operation': 'create', 'status': 'outcome_unknown', 'retry_safe': False,
                'error_code': 'lifecycle_outcome_unknown'}
    scope.write(NAME, original)
    return module, scope, calls, original


def status(scope):
    return scope.call('workspace_status_scoped', {'name': NAME}, CREDENTIAL)


def create(scope, request):
    return scope.call('workspace_create_scoped', {'name': NAME, 'request_id': request}, CREDENTIAL)


def test_status_reconciles_absence_and_preserves_original_without_creating(tmp_path):
    _, scope, calls, original = stuck(tmp_path)
    result = status(scope)
    assert result['status'] == 'failed'
    assert result['new_request_allowed'] is True
    assert result['retry_safe'] is False
    assert result['unreconciled_receipt'] == original
    assert scope.read(NAME)['reconciliation']['kind'] == 'absent'
    assert calls == []


def test_new_intent_archives_receipt_and_old_ids_never_replay_after_restart(tmp_path):
    _, scope, calls, original = stuck(tmp_path)
    status(scope)
    assert create(scope, 'original-request')['operation_id'] == original['operation_id']
    assert calls == []
    accepted = create(scope, 'recovery-request')
    assert accepted['status'] == 'accepted'
    assert accepted['operation_id'] != original['operation_id']
    scope.wait()
    assert status(scope)['status'] == 'completed'
    history = list(scope.state.glob('history-*.json'))
    assert len(history) == 1
    archived = json.loads(history[0].read_text())
    assert archived['unreconciled_receipt'] == original
    _, restarted, restarted_calls = manager(tmp_path)
    restarted.absence = proof
    replay = create(restarted, 'original-request')
    assert replay['operation_id'] == original['operation_id']
    assert replay['new_request_allowed'] is False
    assert create(restarted, 'recovery-request')['operation_id'] == accepted['operation_id']
    assert restarted_calls == []
    assert calls == [('create', NAME)]


def test_provider_change_after_poll_refuses_new_create(tmp_path):
    _, scope, calls, _ = stuck(tmp_path)
    assert status(scope)['new_request_allowed'] is True
    def unavailable(*args):
        raise RuntimeError('private provider details')
    scope.absence = unavailable
    refused = create(scope, 'recovery-request')
    assert refused['status'] == 'outcome_unknown'
    assert refused['new_request_allowed'] is False
    assert 'private provider details' not in json.dumps(refused)
    assert calls == []


@pytest.mark.parametrize('bad', [{}, {'kind': 'absent'}, {**proof(None, None), 'lifecycle_processes_absent': False}])
def test_incomplete_reconciliation_never_unlocks(tmp_path, bad):
    _, scope, calls, _ = stuck(tmp_path)
    scope.absence = lambda *args: bad
    result = status(scope)
    assert result['status'] == 'outcome_unknown'
    assert result['new_request_allowed'] is False
    assert create(scope, 'new-request')['status'] == 'outcome_unknown'
    assert calls == []


def test_mutation_alone_does_not_recover_unknown_operation(tmp_path):
    _, scope, calls, original = stuck(tmp_path)
    assert create(scope, 'new-request')['operation_id'] == original['operation_id']
    assert calls == []


def test_concurrent_fresh_requests_after_reconciliation_submit_once(tmp_path):
    entered, release = threading.Event(), threading.Event()
    def block(*args):
        entered.set()
        assert release.wait(3)
    _, scope, calls, _ = stuck(tmp_path, block)
    status(scope)
    accepted = create(scope, 'recovery-1')
    assert entered.wait(2)
    def must_not_reconcile(*args):
        pytest.fail('Live job must not be reconciled')
    scope.absence = must_not_reconcile
    assert status(scope)['status'] == 'running'
    assert create(scope, 'recovery-2')['operation_id'] == accepted['operation_id']
    release.set()
    scope.wait()
    assert calls == [('create', NAME)]


def test_missing_proof_callback_cannot_reuse_persisted_admission(tmp_path):
    _, scope, calls, _ = stuck(tmp_path)
    assert status(scope)['new_request_allowed'] is True
    scope.absence = None
    refused = create(scope, 'fresh-request')
    assert refused['new_request_allowed'] is False
    assert refused['status'] == 'outcome_unknown'
    assert calls == []


@pytest.mark.parametrize('phase,expected', [('inventory', 'inventory'), ('SECRET', 'validation')])
def test_reconciliation_retains_only_safe_failure_phase(tmp_path, phase, expected):
    _, scope, calls, _ = stuck(tmp_path)
    def blocked(*args):
        error = RuntimeError('private provider details')
        error.phase = phase
        raise error
    scope.absence = blocked
    result = status(scope)
    assert result['reconciliation']['phase'] == expected
    assert 'SECRET' not in json.dumps(result)
    assert 'private provider details' not in json.dumps(result)
    assert calls == []


def test_recovery_uses_original_operation_time_after_grant_renewal(tmp_path):
    _, scope, calls, _ = stuck(tmp_path)
    record = scope.read(NAME)
    record['accepted_at'] = 100.0
    record['grant_issued_at'] = 90.0
    scope.write(NAME, record)
    config = json.loads(scope.config.read_text())
    config['issued_at'] = 200.0
    scope.config.write_text(json.dumps(config))
    observed = []
    def bounded(name, approved):
        observed.append(approved.get('recovery_cutoff'))
        return proof(name, approved)
    scope.absence = bounded
    status(scope)
    assert observed == [90.0]
    assert calls == []


def test_legacy_receipt_never_borrows_current_grant_as_cutoff(tmp_path):
    _, scope, _, _ = stuck(tmp_path)
    config = json.loads(scope.config.read_text())
    config['issued_at'] = 200.0
    scope.config.write_text(json.dumps(config))
    observed = []
    def bounded(name, approved):
        observed.append(approved.get('recovery_cutoff'))
        return proof(name, approved)
    scope.absence = bounded
    status(scope)
    assert observed == [None]
