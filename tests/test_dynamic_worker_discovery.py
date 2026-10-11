"""Scoped status publishes only verified workers into the separate CAS registry."""
import json
from pathlib import Path
from test_devsy_bridge import scoped_fixture
from test_owned_workspace import owned, NAME, UID, TOKEN


def test_scoped_poll_discovers_owned_uid_and_publishes_without_rebinding_static_targets(tmp_path):
    _, scope, row = owned(tmp_path)
    source = tmp_path / 'targets.json'
    static = {'targets': {'local': {'transport': 'local'}, 'devsy': {'workspace': 'old-worker', 'workspace_uid': 'old-uid'}}}
    source.write_text(json.dumps(static)); source.chmod(0o600)
    fixture_root = tmp_path / 'bridge'
    fixture_root.mkdir()
    devsy, _ = scoped_fixture(fixture_root, 'raise SystemExit(0)\n')
    devsy.scope = scope
    devsy.scope_source = scope.config
    devsy.targets_source = str(source)
    registry = tmp_path / 'registry'
    registry.mkdir(mode=0o700)
    devsy.registry_source = str(registry / 'targets.json')
    # A running worker is still owned even when its CLI has not returned yet.
    class Active:
        def is_alive(self): return True
    scope.threads[NAME] = Active()
    devsy.scoped_metadata = lambda name: row
    result = devsy.call('workspace_status_scoped', {'name': NAME}, TOKEN)['structuredContent']
    assert result['workspace_uid'] == UID
    assert result['identity_verified'] is True
    assert result['cas_target'] == NAME
    assert result['status'] == 'running'
    published = json.loads((registry / 'targets.json').read_text())
    assert published['targets'][NAME]['workspace_uid'] == UID
    assert published['targets'][NAME]['transport'] == 'devsy-kubernetes'
    assert json.loads(source.read_text()) == static



def registered(tmp_path):
    test_scoped_poll_discovers_owned_uid_and_publishes_without_rebinding_static_targets(tmp_path)
    # A fresh bridge object and persisted journal simulate restart.
    from test_devsy_bridge import scoped_fixture
    import importlib.util
    root = tmp_path / 'restart'; root.mkdir()
    devsy, _ = scoped_fixture(root, 'raise SystemExit(0)\n')
    module_path = Path(__file__).resolve().parents[1] / 'scripts/worker_scope.py'
    spec = importlib.util.spec_from_file_location('restart_scope', module_path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    devsy.scope = module.WorkerScope(tmp_path / 'scope.json', tmp_path / 'state',
        lambda: [], lambda name: None, lambda *args: None)
    # Use the original fixture's persisted state location.
    identities = list(tmp_path.rglob('identity-*.json'))
    devsy.scope.state = identities[0].parent
    devsy.targets_source = str(tmp_path / 'targets.json')
    devsy.registry_source = str(tmp_path / 'registry/targets.json')
    return devsy


def test_restart_reconciliation_removes_absent_target_and_keeps_static(tmp_path):
    devsy = registered(tmp_path)
    static = open(devsy.targets_source, 'rb').read()
    devsy.target_absence = lambda target, scope: {"kind": "absent", "workspace_uid": UID}
    devsy.reconcile_registry()
    actual = json.load(open(devsy.registry_source))
    assert actual['targets'] == {} and actual['owners'] == {}
    assert actual['history'][-1]['removed_reason'] == 'workspace_absent'
    assert open(devsy.targets_source, 'rb').read() == static
    first = open(devsy.registry_source, 'rb').read()
    devsy.reconcile_registry()
    assert open(devsy.registry_source, 'rb').read() == first


def test_transient_provider_failure_does_not_unregister(tmp_path):
    devsy = registered(tmp_path)
    original = open(devsy.registry_source, 'rb').read()
    def unavailable(*args): raise TimeoutError('SECRET')
    devsy.target_absence = unavailable
    devsy.reconcile_registry()
    assert open(devsy.registry_source, 'rb').read() == original


def test_explicit_revocation_unregisters_without_provider_calls(tmp_path):
    devsy = registered(tmp_path)
    config = json.loads(devsy.scope.config.read_text()); config['enabled'] = False
    devsy.scope.config.write_text(json.dumps(config))
    def forbidden(*args): raise AssertionError('provider must not run')
    devsy.target_absence = forbidden
    devsy.reconcile_registry()
    actual = json.load(open(devsy.registry_source))
    assert actual['targets'] == {}
    assert actual['history'][-1]['removed_reason'] == 'authority_revoked'


def test_unreadable_scope_is_unknown_and_preserves_target(tmp_path):
    devsy = registered(tmp_path)
    original = open(devsy.registry_source, 'rb').read()
    devsy.scope.config.write_text('{')
    devsy.reconcile_registry()
    assert open(devsy.registry_source, 'rb').read() == original


def test_valid_worker_republishes_from_journal_after_restart(tmp_path):
    devsy = registered(tmp_path)
    # Recover the persisted pin and the provider row from the original journal.
    record = devsy.scope.read(NAME)
    config = devsy.scope.load()
    execution = record['execution_context']
    row = {'id': NAME, 'uid': UID, 'context': config['context'],
           'source': {'gitRepository': config['repository'], 'gitCommit': execution['revision']},
           'devContainerPath': execution['recipe'],
           'provider': {'name': 'kubernetes', 'options': {
               'KUBERNETES_CONTEXT': {'value': config['kubernetes_context']},
               'KUBERNETES_NAMESPACE': {'value': config['namespace']},
               'KUBERNETES_CONFIG': {'value': next(iter(config['bindings']))}}}}
    record['status'] = 'completed'; record['workspace_uid'] = UID
    devsy.scope.write(NAME, record)
    devsy.scope.metadata = lambda name: row
    devsy.scoped_metadata = lambda name: row
    def present(*args): raise RuntimeError('workspace present; absence not proven')
    devsy.target_absence = present
    registry = json.load(open(devsy.registry_source))
    registry['targets'] = {}; registry['owners'] = {}
    Path(devsy.registry_source).write_text(json.dumps(registry))
    result = devsy.call('workspace_status_scoped', {'name': NAME}, TOKEN)['structuredContent']
    assert result['cas_target'] == NAME
    assert json.load(open(devsy.registry_source))['targets'][NAME]['workspace_uid'] == UID


def test_reconciliation_requires_exact_journal_pin(tmp_path):
    devsy = registered(tmp_path)
    original = open(devsy.registry_source, 'rb').read()
    record = devsy.scope.read(NAME); record['operation_id'] = 'replacement-operation'
    devsy.scope.write(NAME, record)
    devsy.target_absence = lambda *args: {'kind': 'absent', 'workspace_uid': UID}
    devsy.reconcile_registry()
    assert open(devsy.registry_source, 'rb').read() == original


def test_expired_scope_removes_only_its_owned_registration(tmp_path):
    devsy = registered(tmp_path)
    config = json.loads(devsy.scope.config.read_text()); config['expires_at'] = 1
    devsy.scope.config.write_text(json.dumps(config))
    devsy.reconcile_registry()
    assert json.load(open(devsy.registry_source))['targets'] == {}


def test_catalog_runs_reconciliation_after_upstream_discovery(tmp_path, monkeypatch):
    devsy = registered(tmp_path)
    from contextlib import contextmanager
    @contextmanager
    def session(**kwargs): yield object()
    devsy.session = session
    devsy.discover = lambda session: []
    devsy.target_absence = lambda *args: {'kind': 'absent', 'workspace_uid': UID}
    devsy.catalog()
    assert json.load(open(devsy.registry_source))['targets'] == {}
