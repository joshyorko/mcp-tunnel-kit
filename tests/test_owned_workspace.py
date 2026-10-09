"""Only journal-owned, immutable worker identities gain dynamic diagnostics."""
import json

import pytest
from test_worker_scope import manager

NAME = 'cas-worker-01'
UID = 'default-ca-11111'
TOKEN = 'Bearer fixture-owner-secret'


def owned(tmp_path):
    import hashlib
    module, scope, _ = manager(tmp_path)
    config = json.loads(scope.config.read_text())
    kube = tmp_path / 'kubeconfig'
    kube.write_text('fixture')
    config['bindings'] = {str(kube): hashlib.sha256(kube.read_bytes()).hexdigest()}
    scope.config.write_text(json.dumps(config))
    execution = {'context': config['context'], 'provider': config['provider'],
                 'kubernetes_context': config['kubernetes_context'], 'namespace': config['namespace'],
                 'repository': config['repository'], 'revision': 'c' * 40,
                 'recipe': '.devcontainer/remote-worker/devcontainer.json'}
    row = {'id': NAME, 'uid': UID, 'context': 'default',
           'source': {'gitRepository': config['repository'], 'gitCommit': execution['revision']},
           'devContainerPath': execution['recipe'],
           'provider': {'name': 'kubernetes', 'options': {
               'KUBERNETES_CONTEXT': {'value': 'ror'}, 'KUBERNETES_NAMESPACE': {'value': 'devsy'},
               'KUBERNETES_CONFIG': {'value': str(kube)}}}}
    scope.root()
    scope.write(NAME, {'name': NAME, 'operation_id': 'owned-operation', 'operation': 'create',
                       'status': 'running', 'request_id': 'original',
                       'execution_context': execution})
    scope.metadata = lambda name: row
    return module, scope, row


def test_running_owned_workspace_gains_uid_pinned_diagnostics_without_target_edits(tmp_path):
    _, scope, row = owned(tmp_path)
    result = scope.owned_workspace(NAME, UID, TOKEN)
    assert result['workspace'] == NAME and result['workspace_uid'] == UID
    assert result['namespace'] == 'devsy' and result['kubernetes_context'] == 'ror'
    assert scope.read(NAME)['status'] == 'running'
    assert list(scope.state.glob('identity-*.json'))
    row['uid'] = 'default-ca-22222'
    with pytest.raises(Exception, match='identity'):
        scope.owned_workspace(NAME, row['uid'], TOKEN)


@pytest.mark.parametrize('change', ['no_record', 'wrong_name', 'wrong_uid', 'wrong_commit', 'wrong_recipe', 'no_token', 'unbound_kubeconfig'])
def test_unowned_or_changed_workspace_cannot_gain_diagnostics(tmp_path, change):
    module, scope, row = owned(tmp_path)
    name, uid, token = NAME, UID, TOKEN
    if change == 'no_record':
        (scope.state / (NAME + '.json')).unlink()
    elif change == 'wrong_name':
        name = 'codex-action-server'
    elif change == 'wrong_uid':
        uid = 'default-ca-22222'
    elif change == 'wrong_commit':
        row['source']['gitCommit'] = 'different'
    elif change == 'wrong_recipe':
        row['devContainerPath'] = 'other.json'
    elif change == 'no_token':
        token = None
    else:
        row['provider']['options']['KUBERNETES_CONFIG']['value'] = '/unbound'
    with pytest.raises(module.ScopeError):
        scope.owned_workspace(name, uid, token)
    assert not list(scope.state.glob('identity-*.json'))


def test_lifecycle_completion_cannot_replace_previously_observed_uid(tmp_path):
    _, scope, row = owned(tmp_path)
    scope.owned_workspace(NAME, UID, TOKEN)
    record = scope.read(NAME)
    row['uid'] = 'default-ca-22222'
    scope.invoke = lambda *args: None
    scope.run(record, scope.load(), None)
    assert scope.read(NAME)['status'] == 'outcome_unknown'
    assert scope.read(NAME).get('workspace_uid') != row['uid']


def test_unknown_unpinned_operation_cannot_adopt_later_workspace(tmp_path):
    module, scope, _ = owned(tmp_path)
    record = scope.read(NAME)
    record['status'] = 'outcome_unknown'
    scope.write(NAME, record)
    with pytest.raises(module.ScopeError):
        scope.owned_workspace(NAME, UID, TOKEN)


def test_authority_revocation_and_uid_changes_fail_closed(tmp_path):
    _, scope, _ = owned(tmp_path)
    scope.owned_workspace(NAME, UID, TOKEN)
    assert scope.worker_authorized(NAME, UID, 'owned-operation') is True
    assert scope.worker_authorized(NAME, 'other', 'owned-operation') is False
    assert scope.worker_authorized(NAME, UID, 'other-operation') is False
    config = json.loads(scope.config.read_text())
    config['enabled'] = False
    scope.config.write_text(json.dumps(config))
    assert scope.worker_authorized(NAME, UID, 'owned-operation') is False
