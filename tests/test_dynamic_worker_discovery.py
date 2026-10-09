"""Scoped status publishes only verified workers into the separate CAS registry."""
import json
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
