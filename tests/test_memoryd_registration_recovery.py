"""Interrupted MemoryD registration must recover without adopting unrelated apps."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import urlsplit
import urllib.request

import pytest

import compose_control as control
import deploy_control_plane as deploy
import vm_deploy_host as host


TRANSFER_ID = 'a' * 64
REQUEST = {'transfer_manifest_sha256': TRANSFER_ID}
URL = 'http://172.30.86.1:8090/mcp'


class ExecutorFixture:
    def __init__(self):
        self.organization = 'org_test'
        self.apps = [{'id': 'app_codex', 'slug': 'codex', 'name': 'Codex'}]
        self.source_url = URL
        self.source = None
        self.source_files = None
        self.imports = 0
        self.keys = {name: name.encode() for name in ('auth-secret.key', 'encryption.key', 'install-id')}

    def request(self, method, path, body=None):
        if path == '/api/context':
            return {'organization': self.organization}, {}
        prefix = '/api/organizations/' + self.organization
        if path == prefix + '/inventory':
            return {'apps': list(self.apps)}, {}
        if method == 'POST' and path == prefix + '/apps/import':
            self.imports += 1
            self.source_url = body['source']['url']
            app = {'id': 'app_memoryd', 'slug': 'memoryd', 'name': 'MemoryD',
                   'activeDeployment': 'deployment_1'}
            self.apps.append(app)
            return app, {}
        if path == prefix + '/apps/app_memoryd/source':
            if self.source_files is not None:
                return {'files': self.source_files}, {}
            return {'files': [{'path': 'index.ts', 'content': self.source or
                                control.devsy_app_source(self.source_url)}]}, {}
        raise AssertionError((method, path))

    def urlopen(self, request, timeout):
        data, _ = self.request('GET', urlsplit(request.full_url).path)
        return io.BytesIO(json.dumps(data).encode())

    def run(self, args, **kwargs):
        assert args[:2] == ['docker', 'cp']
        name = args[2].rsplit('/', 1)[-1]
        data = self.keys[name]
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w') as archive:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        return out.getvalue()


@pytest.fixture
def registration(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    secrets = tmp_path / 'secrets'
    secrets.mkdir(mode=0o700)
    for name in ('control-plane-api-key', 'control-plane-tunnel-id', 'executor-auth-header', 'executor-pat'):
        (secrets / name).write_text('synthetic-' + name)
        (secrets / name).chmod(0o600)
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'ROOT', Path(__file__).resolve().parents[1])
    monkeypatch.setattr(host, 'NETWORK', {'gateway': '172.30.86.1'})
    monkeypatch.setattr(host, '_memoryd_record_count', lambda: 2)
    monkeypatch.setattr(host, 'memoryd_health', lambda: {'status': 'PASS'})
    host.write(host._memoryd_receipt_path(TRANSFER_ID), {
        'status': 'complete', 'transfer_manifest_sha256': TRANSFER_ID,
        'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
        'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
        'imported_record_count': 2,
    })
    executor = ExecutorFixture()
    monkeypatch.setattr(urllib.request, 'urlopen', executor.urlopen)
    monkeypatch.setattr(host, 'run', executor.run)
    monkeypatch.setattr(control, 'executor_session', lambda: (executor, object()))
    monkeypatch.setattr(control, 'verify_compact', lambda session: None)
    monkeypatch.setattr(control, 'search_memoryd', lambda session: None)
    monkeypatch.setattr(control, 'probe_memoryd_reads', lambda session: {'status': 'PASS'})
    monkeypatch.setattr(control, 'probe_memoryd_denials', lambda url: {'write_blocked': True})
    class Upstream:
        def __init__(self, *args):
            pass
        def tools(self):
            return [{'name': name, 'annotations': {'readOnlyHint': True, 'destructiveHint': False},
                     'inputSchema': {'properties': {}, 'additionalProperties': False}}
                    for name in ('memory_status', 'memory_recall', 'memory_search')]
    monkeypatch.setattr(control, 'Mcp', Upstream)
    monkeypatch.setenv('EXECUTOR_URL', 'http://127.0.0.1:4312')
    monkeypatch.setenv('EXECUTOR_PAT_FILE', str(secrets / 'executor-pat'))
    store=tmp_path/'deployment';store.mkdir(mode=0o700)
    monkeypatch.setattr(host,'STORE',store)
    host.write(store/'current.json',{'authority':'kamal',
        'identity':host.identity(host.NAMES['kamal']['executor'],exclude_memoryd=True)})
    return executor, tmp_path


def interrupt_before_receipt(registration, monkeypatch):
    executor, state = registration
    original_write = control.write_private
    def crash(path, value):
        if path.name == 'memoryd-integration.json':
            raise RuntimeError('simulated process death after import')
        original_write(path, value)
    monkeypatch.setattr(control, 'write_private', crash)
    with pytest.raises(RuntimeError, match='simulated process death'):
        host.register_memoryd_app(REQUEST)
    monkeypatch.setattr(control, 'write_private', original_write)
    assert executor.imports == 1
    assert not (state / 'bootstrap/memoryd-integration.json').exists()


def test_interrupted_import_recovers_without_a_second_app(registration, monkeypatch):
    executor, state = registration
    original = host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)
    interrupt_before_receipt(registration, monkeypatch)
    pending = state / 'bootstrap/memoryd-registration-pending.json'
    assert pending.stat().st_mode & 0o777 == 0o600

    assert host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True) == original
    result = host.register_memoryd_app(REQUEST)

    assert result['app_id'] == 'app_memoryd'
    assert executor.imports == 1
    assert json.loads(host.private(state / 'bootstrap/memoryd-integration.json')) == {
        'organization': 'org_test', 'id': 'app_memoryd', 'url': URL}
    assert not pending.exists()
    assert host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True) == original
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1


def test_controller_retries_interrupted_import_and_reconciles_original_identity(registration, monkeypatch):
    executor, state = registration
    store = state / 'deployment'
    baseline = host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)
    host.write(store / 'current.json', {'authority': 'kamal', 'identity': baseline})
    interrupt_before_receipt(registration, monkeypatch)

    def remote(action, data=None):
        if action == 'status':
            return {'authority': 'kamal', 'healthy': True, 'tunnel_count': 1}
        if action == 'snapshot':
            return {'identity': host.identity(host.NAMES['kamal']['executor']),
                    'inventory': {'executor': {}}, 'tunnel_count': 1}
        if action == 'memoryd-base-identity':
            return {'identity': host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)}
        if action == 'memoryd-app-register':
            return host.register_memoryd_app(data)
        if action == 'memoryd-identity-reconcile':
            return host.memoryd_reconcile_identity(data)
        if action == 'current':
            return json.loads(host.private(store / 'current.json'))
        if action == 'memoryd-health':
            return {'status': 'PASS'}
        raise AssertionError(action)

    monkeypatch.setattr(deploy, 'remote', remote)
    monkeypatch.setattr(deploy, 'memoryd_transfer_payload', lambda: {'manifest_sha256': TRANSFER_ID})
    monkeypatch.setattr(deploy, 'smoke', lambda native: {'memoryd_discovery': 'PASS'})
    result = deploy.finish_memoryd('memoryd-register')
    assert result['status'] == 'PASS'
    assert result['identity_receipt']['prior_identity_preserved'] is True
    assert host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True) == baseline
    assert executor.imports == 1


@pytest.mark.parametrize('drift', ['duplicate', 'unrelated_source', 'owner_source', 'duplicate_source', 'extra_app',
                                  'organization', 'key', 'credential', 'transfer', 'pending_mode'])
def test_interrupted_import_refuses_unrelated_or_changed_state(registration, monkeypatch, drift):
    executor, state = registration
    interrupt_before_receipt(registration, monkeypatch)
    if drift == 'duplicate':
        executor.apps.append({**executor.apps[-1], 'id': 'app_other'})
    elif drift == 'unrelated_source':
        executor.source = control.devsy_app_source('http://172.30.86.2:8090/mcp')
    elif drift == 'owner_source':
        executor.source = control.owner_devsy_app_source(URL)
    elif drift == 'duplicate_source':
        executor.source_files = [{'path': 'index.ts', 'content': control.devsy_app_source(URL)}] * 2
    elif drift == 'extra_app':
        executor.apps.append({'id': 'app_other', 'slug': 'other', 'name': 'Other'})
    elif drift == 'organization':
        executor.organization = 'org_other'
    elif drift == 'key':
        executor.keys['install-id'] = b'changed'
    elif drift == 'credential':
        (state / 'secrets/control-plane-api-key').write_text('changed')
    elif drift == 'transfer':
        receipt = host._memoryd_receipt_path(TRANSFER_ID)
        payload = json.loads(host.private(receipt))
        payload['source_database_sha256'] = hashlib.sha256(b'changed').hexdigest()
        host.write(receipt, payload)
    elif drift == 'pending_mode':
        (state / 'bootstrap/memoryd-registration-pending.json').chmod(0o644)
    with pytest.raises((ValueError, control.ControlError)):
        host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)
    with pytest.raises((ValueError, control.ControlError)):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 1
    assert not (state / 'bootstrap/memoryd-integration.json').exists()


def test_unreceipted_app_without_intent_is_never_adopted(registration):
    executor, state = registration
    executor.apps.append({'id': 'app_memoryd', 'slug': 'memoryd', 'name': 'MemoryD',
                          'activeDeployment': 'deployment_1'})
    with pytest.raises((ValueError, control.ControlError)):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    assert not (state / 'bootstrap/memoryd-integration.json').exists()


def test_registration_refuses_recorded_identity_drift_before_import(registration,monkeypatch):
    executor,state=registration
    store=state/'deployment'
    host.write(store/'current.json',{'authority':'kamal','identity':'different'})
    with pytest.raises(ValueError,match='identity drift'):
        host.register_memoryd_app(REQUEST)
    assert executor.imports==0
    assert not (state/'bootstrap/memoryd-registration-pending.json').exists()


def test_pending_import_without_a_visible_app_never_reimports(registration, monkeypatch):
    executor, state = registration
    request = executor.request
    def fail_import(method, path, body=None):
        if method == 'POST' and path.endswith('/apps/import'):
            raise RuntimeError('simulated ambiguous import')
        return request(method, path, body)
    monkeypatch.setattr(executor, 'request', fail_import)
    with pytest.raises(RuntimeError, match='simulated ambiguous import'):
        host.register_memoryd_app(REQUEST)
    monkeypatch.setattr(executor, 'request', request)
    with pytest.raises(ValueError, match='no unique imported app'):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    assert not (state / 'bootstrap/memoryd-integration.json').exists()


def interrupted_before_post(registration, monkeypatch):
    executor, state = registration
    request = executor.request
    def fail_import(method, path, body=None):
        if method == 'POST' and path.endswith('/apps/import'):
            raise RuntimeError('process stopped before POST')
        return request(method, path, body)
    monkeypatch.setattr(executor, 'request', fail_import)
    with pytest.raises(RuntimeError, match='process stopped before POST'):
        host.register_memoryd_app(REQUEST)
    monkeypatch.setattr(executor, 'request', request)
    return state / 'bootstrap/memoryd-registration-pending.json'


@pytest.mark.parametrize('attestation', [None, False, 'true'])
def test_operator_reconciliation_requires_explicit_attestation(registration, monkeypatch, attestation):
    executor, state = registration
    pending = interrupted_before_post(registration, monkeypatch)
    original = host.private(pending)
    with pytest.raises(ValueError):
        host.memoryd_reconcile_pending_registration({'confirm_import_quiescent': attestation})
    assert host.private(pending) == original
    assert list((state / 'bootstrap').glob('memoryd-registration-intent-backup-*.json')) == []
    assert executor.imports == 0


def test_attested_reconciliation_backs_up_before_retrying_once(registration, monkeypatch):
    executor, state = registration
    pending = interrupted_before_post(registration, monkeypatch)
    original = host.private(pending)
    assert json.loads(original)['status'] == 'importing'

    result = host.memoryd_reconcile_pending_registration({'confirm_import_quiescent': True})

    backup = Path(result['backup'])
    assert host.private(backup) == original
    assert backup.stat().st_mode & 0o777 == 0o600
    assert json.loads(host.private(pending))['status'] == 'prepared'
    assert executor.imports == 0
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1
    assert (state / 'bootstrap/memoryd-integration.json').exists()


def test_interrupted_reconciliation_preserves_backup_and_can_resume(registration, monkeypatch):
    executor, state = registration
    pending = interrupted_before_post(registration, monkeypatch)
    original = host.private(pending)
    write = control.write_private
    def fail_reset(path, value):
        if path == pending:
            raise RuntimeError('simulated reset interruption')
        return write(path, value)
    monkeypatch.setattr(control, 'write_private', fail_reset)
    with pytest.raises(RuntimeError, match='simulated reset interruption'):
        host.memoryd_reconcile_pending_registration({'confirm_import_quiescent': True})
    backups = list((state / 'bootstrap').glob('memoryd-registration-intent-backup-*.json'))
    assert len(backups) == 1 and host.private(backups[0]) == original
    assert host.private(pending) == original and executor.imports == 0
    monkeypatch.setattr(control, 'write_private', write)
    result = host.memoryd_reconcile_pending_registration({'confirm_import_quiescent': True})
    assert host.private(Path(result['backup'])) == original
    assert json.loads(host.private(pending))['status'] == 'prepared'
    assert executor.imports == 0


@pytest.mark.parametrize('drift', ['matching_app', 'duplicate_apps', 'other_app', 'key',
                                  'credential', 'recorded_base', 'organization', 'transfer', 'marker'])
def test_operator_reconciliation_refuses_changed_state(registration, monkeypatch, drift):
    executor, state = registration
    pending = interrupted_before_post(registration, monkeypatch)
    original = host.private(pending)
    app = {'id': 'app_memoryd', 'slug': 'memoryd', 'name': 'MemoryD', 'activeDeployment': 'deployment_1'}
    if drift == 'matching_app':
        executor.apps.append(app)
    elif drift == 'duplicate_apps':
        executor.apps.extend([app, {**app, 'id': 'other_memoryd'}])
    elif drift == 'other_app':
        executor.apps.append({'id': 'app_extra', 'slug': 'extra', 'name': 'Extra'})
    elif drift == 'key':
        executor.keys['install-id'] = b'changed'
    elif drift == 'credential':
        (state / 'secrets/control-plane-api-key').write_text('changed')
    elif drift == 'recorded_base':
        host.write(state / 'deployment/current.json', {'authority': 'kamal', 'identity': 'changed'})
    elif drift == 'organization':
        executor.organization = 'org_other'
    elif drift == 'transfer':
        path = host._memoryd_receipt_path(TRANSFER_ID)
        receipt = json.loads(host.private(path))
        receipt['source_database_sha256'] = hashlib.sha256(b'drift').hexdigest()
        host.write(path, receipt)
    elif drift == 'marker':
        host.write(state / 'bootstrap/memoryd-integration.json', {'id': 'other'})
    with pytest.raises((ValueError, control.ControlError)):
        host.memoryd_reconcile_pending_registration({'confirm_import_quiescent': True})
    assert host.private(pending) == original
    assert list((state / 'bootstrap').glob('memoryd-registration-intent-backup-*.json')) == []
    assert executor.imports == 0


def test_reconciliation_controller_requires_attestation_and_holds_deployment_lock(monkeypatch):
    calls = []
    locked = False
    @contextmanager
    def lock():
        nonlocal locked
        locked = True
        try:
            yield
        finally:
            locked = False
    def remote(action, data=None):
        assert locked
        calls.append((action, data))
        return {'status': 'prepared'}
    monkeypatch.setattr(deploy, 'INSTANCE', {})
    monkeypatch.setattr(deploy, 'LOCAL_CONFIGURED', True)
    monkeypatch.setattr(deploy, 'trusted_context', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(deploy, 'lock', lock)
    monkeypatch.setattr(deploy, 'remote', remote)
    monkeypatch.setenv('GITHUB_SHA', 'b' * 40)
    args = SimpleNamespace(operation='memoryd-registration-reconcile', local=True,
                           approve_full_stack=False, confirm_import_quiescent=False)
    with pytest.raises(ValueError, match='quiescent'):
        deploy.execute(args)
    assert calls == []
    args.confirm_import_quiescent = True
    assert deploy.execute(args) == {'status': 'prepared'}
    assert calls == [('memoryd-registration-reconcile', {'confirm_import_quiescent': True})]
    calls.clear()
    @contextmanager
    def unavailable_lock():
        raise RuntimeError('deployment lock unavailable')
        yield
    monkeypatch.setattr(deploy, 'lock', unavailable_lock)
    with pytest.raises(RuntimeError, match='deployment lock unavailable'):
        deploy.execute(args)
    assert calls == []


def test_import_with_lost_response_recovers_without_a_second_post(registration, monkeypatch):
    executor, _ = registration
    request = executor.request
    def lose_response(method, path, body=None):
        result = request(method, path, body)
        if method == 'POST' and path.endswith('/apps/import'):
            raise TimeoutError('simulated lost response')
        return result
    monkeypatch.setattr(executor, 'request', lose_response)
    with pytest.raises(TimeoutError, match='simulated lost response'):
        host.register_memoryd_app(REQUEST)
    monkeypatch.setattr(executor, 'request', request)
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1


@pytest.mark.parametrize('value', [None, {'status': 'pending'}])
def test_invalid_pending_intent_is_not_overwritten(registration, value):
    executor, state = registration
    pending = state / 'bootstrap/memoryd-registration-pending.json'
    host.write(pending, value)
    with pytest.raises(ValueError):
        host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)
    with pytest.raises(ValueError):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    assert json.loads(host.private(pending)) == value


def test_invalid_existing_receipt_is_not_replaced_during_recovery(registration, monkeypatch):
    executor, state = registration
    interrupt_before_receipt(registration, monkeypatch)
    marker = state / 'bootstrap/memoryd-integration.json'
    host.write(marker, None)
    with pytest.raises(ValueError):
        host.identity(host.NAMES['kamal']['executor'], exclude_memoryd=True)
    with pytest.raises(ValueError):
        host.register_memoryd_app(REQUEST)
    assert json.loads(host.private(marker)) is None
    assert executor.imports == 1


@pytest.mark.parametrize('value', [None, {}, {'id': 'app_memoryd'}])
def test_invalid_receipt_without_an_app_never_triggers_import(registration, value):
    executor, state = registration
    marker = state / 'bootstrap/memoryd-integration.json'
    host.write(marker, value)
    with pytest.raises(ValueError):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    assert json.loads(host.private(marker)) == value


@pytest.mark.parametrize('change', ['organization', 'app'])
def test_import_refuses_new_app_or_organization_after_intent(registration, monkeypatch, change):
    executor, state = registration
    verify = control.verify_memoryd_catalog
    def change_during_preflight(tools):
        verify(tools)
        if change == 'organization':
            executor.organization = 'org_other'
        else:
            executor.apps.append({'id': 'app_memoryd', 'slug': 'memoryd', 'name': 'MemoryD',
                                  'activeDeployment': 'deployment_1'})
    monkeypatch.setattr(control, 'verify_memoryd_catalog', change_during_preflight)
    with pytest.raises(control.ControlError):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    assert not (state / 'bootstrap/memoryd-integration.json').exists()
    if change == 'app':
        monkeypatch.setattr(control, 'verify_memoryd_catalog', verify)
        with pytest.raises((ValueError, control.ControlError)):
            host.register_memoryd_app(REQUEST)
        assert not (state / 'bootstrap/memoryd-integration.json').exists()


def test_pre_import_preflight_failure_can_retry_when_no_app_exists(registration, monkeypatch):
    executor, state = registration
    verify = control.verify_memoryd_catalog
    def fail_preflight(tools):
        raise control.ControlError('simulated preflight failure')
    monkeypatch.setattr(control, 'verify_memoryd_catalog', fail_preflight)
    with pytest.raises(control.ControlError, match='simulated preflight failure'):
        host.register_memoryd_app(REQUEST)
    assert executor.imports == 0
    monkeypatch.setattr(control, 'verify_memoryd_catalog', verify)
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1


def test_retry_after_receipt_write_finishes_pending_cleanup(registration, monkeypatch):
    executor, state = registration
    pending = state / 'bootstrap/memoryd-registration-pending.json'
    unlink = Path.unlink
    def crash(path, *args, **kwargs):
        if path == pending:
            raise RuntimeError('simulated death after receipt')
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', crash)
    with pytest.raises(RuntimeError, match='simulated death after receipt'):
        host.register_memoryd_app(REQUEST)
    monkeypatch.setattr(Path, 'unlink', unlink)
    assert (state / 'bootstrap/memoryd-integration.json').exists()
    assert pending.exists()
    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1
    assert not pending.exists()


def test_interrupted_receipt_write_does_not_block_recovery(registration, monkeypatch):
    executor, state = registration
    interrupt_before_receipt(registration, monkeypatch)
    orphan = state / 'bootstrap/memoryd-integration.new'
    orphan.write_text('incomplete')
    orphan.chmod(0o600)

    assert host.register_memoryd_app(REQUEST)['app_id'] == 'app_memoryd'
    assert executor.imports == 1
