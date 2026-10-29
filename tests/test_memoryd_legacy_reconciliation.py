"""Synthetic evidence and crash tests for the abandoned MemoryD transfer."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import zipfile

import pytest

import deploy_control_plane as deploy
import vm_deploy_host as host
from test_memoryd_deploy import FIXTURE_INSTANCE, write_transfer_fixture, write_legacy_transfer_fixture


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    home, source = tmp_path / 'home', tmp_path / 'source'
    active = write_transfer_fixture(home, source, ['active'], ['archived'])
    write_legacy_transfer_fixture(home, active, ['active', 'archived'])
    monkeypatch.setattr(deploy, '_verify_frozen_bundle_payloads', lambda _transfer: None)
    monkeypatch.setattr(deploy, '_verify_frozen_backup', lambda _transfer: None)
    payload = deploy.memoryd_legacy_reconciliation_payload(home)
    payload['approved'] = True
    old = deploy.load_memoryd_transfer_set(home, include_archived=True)
    new = deploy.load_memoryd_transfer_set(home)
    state = tmp_path / 'state'
    bootstrap = state / 'bootstrap'
    bootstrap.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    store = state / 'deployment'
    store.mkdir(mode=0o700)
    root = state / 'memoryd-transfer'
    root.mkdir(mode=0o700)
    for transfer in (old, new):
        stage = root / transfer['manifest_sha256'][:16]
        stage.mkdir(mode=0o700)
        host.write(stage / 'transfer.json', transfer['remote_manifest'])
        for path in transfer['bundle_paths']:
            shutil.copyfile(path, stage / path.name)
            (stage / path.name).chmod(0o600)
    base = {'schema_version': 1, 'source_database_sha256': active['source_database_sha256'],
            'source_instance_id': FIXTURE_INSTANCE, 'source_profile': 'personal',
            'source_workspace': 'dakota-codex-only', 'target_profile': 'personal',
            'target_workspace': 'dakota-codex-only', 'target_backup': {'path': '/data/fixture'},
            'bundles': {}}
    receipt = bootstrap / 'memoryd-transfer.json'
    host.write(receipt, {**base, 'status': 'in_progress', 'transfer_manifest_sha256': old['manifest_sha256']})
    complete = bootstrap / ('memoryd-transfer-' + new['manifest_sha256'] + '.json')
    host.write(complete, {**base, 'status': 'complete', 'transfer_manifest_sha256': new['manifest_sha256'],
                          'destination_instance_id': FIXTURE_INSTANCE, 'imported_record_count': 1,
                          'completed_at_ns': time.time_ns(), 'bundles': {'one.bundle': {
                              'sha256': new['remote_manifest']['bundles'][0]['sha256'],
                              'manifest_digest': new['remote_manifest']['bundles'][0]['manifest_digest'],
                              'receipt_id': 'fixture'}}})
    database = tmp_path / 'snapshot.db'
    with sqlite3.connect(database) as db:
        db.executescript('''
          CREATE TABLE instance_metadata (singleton_key TEXT, instance_id TEXT);
          CREATE TABLE memory_records (profile_id TEXT, workspace_id TEXT, archived INTEGER);
          CREATE TABLE bundle_import_receipts (bundle_id TEXT, destination_instance_id TEXT, status TEXT);
          INSERT INTO instance_metadata VALUES ('default', 'cmi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
          INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 0);
        ''')
    monkeypatch.setattr(host, 'STATE', state)
    monkeypatch.setattr(host, 'STORE', store)
    monkeypatch.setattr(host, 'memoryd_health', lambda: {'status': 'PASS', 'memoryd_image': host.MEMORYD_IMAGE,
                        'adapter_image': 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'f' * 64,
                        'adapter_sha256': 'b' * 64})
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: True)
    def snapshot(_image, stream):
        stream.write(database.read_bytes())
        stream.flush()
        stream.seek(0)
    monkeypatch.setattr(host, '_memoryd_capture_readonly_snapshot', snapshot)
    def save_backup(path, _health):
        assert receipt.stat().st_mode & 0o777 == 0o600
        path.mkdir(mode=0o700)
        shutil.copyfile(database, path / 'backup.db')
        (path / 'backup.db').chmod(0o600)
        (path / 'backup.db.manifest.json').write_bytes(b'fixture manifest')
        (path / 'backup.db.manifest.json').chmod(0o600)
    def validate_backup(path):
        backup = path / 'backup.db'
        manifest = path / 'backup.db.manifest.json'
        return {'backup_sha256': hashlib.sha256(backup.read_bytes()).hexdigest(),
                'backup_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
                'backup_size_bytes': backup.stat().st_size, 'source_instance_id': FIXTURE_INSTANCE,
                'active_record_count': 1, 'archived_record_count': 0, 'adapter_sha256': 'b' * 64}
    monkeypatch.setattr(host, '_memoryd_snapshot_files', save_backup)
    monkeypatch.setattr(host, '_validate_memoryd_capture', validate_backup)
    return {'payload': payload, 'old': old, 'new': new, 'receipt': receipt,
            'state': state, 'bootstrap': bootstrap, 'database': database}


def test_abandon_fences_original_receipt_and_is_idempotent(legacy):
    before = legacy['receipt'].read_bytes()
    result = host.memoryd_abandon_legacy_transfer(legacy['payload'])
    guard = result['legacy_guard']
    assert guard['legacy_transfer_id'] == legacy['old']['manifest_sha256']
    assert legacy['receipt'].read_bytes() == before
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o400
    backup = legacy['bootstrap'] / ('memoryd-legacy-receipt-' + guard['legacy_transfer_id'] + '.json')
    assert backup.read_bytes() == before
    assert backup.stat().st_ino != legacy['receipt'].stat().st_ino
    assert backup.stat().st_mode & 0o777 == 0o600
    marker = legacy['bootstrap'] / ('memoryd-abandonment-' + guard['legacy_transfer_id'] + '.json')
    before_marker = marker.read_bytes()
    attestation = json.loads(before_marker)
    pre_fence = legacy['state'] / 'deployment/backups' / ('memoryd-pre-abandon-' + guard['legacy_transfer_id'])
    assert attestation['pre_fence_backup_sha256'] == hashlib.sha256((pre_fence / 'backup.db').read_bytes()).hexdigest()
    assert hashlib.sha256(before_marker).hexdigest() == guard['attestation_sha256']
    assert host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard'] == guard
    assert marker.read_bytes() == before_marker


def test_abandon_refuses_an_interrupted_prefence_backup(legacy):
    transfer_id = legacy['old']['manifest_sha256']
    path = legacy['bootstrap'] / ('memoryd-pre-fence-' + transfer_id + '.json')
    host.write(path, {'schema_version': 1, 'legacy_transfer_id': transfer_id})
    with pytest.raises(ValueError, match='backup'):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


def test_retry_after_crash_before_attestation_keeps_the_fence(legacy, monkeypatch):
    real_publish = host._memoryd_publish_once
    def interrupted(path, raw):
        if path.name.startswith('memoryd-abandonment-'):
            raise OSError('synthetic crash')
        return real_publish(path, raw)
    monkeypatch.setattr(host, '_memoryd_publish_once', interrupted)
    before = legacy['receipt'].read_bytes()
    with pytest.raises(OSError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].read_bytes() == before
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o400
    monkeypatch.setattr(host, '_memoryd_publish_once', real_publish)
    assert host.memoryd_abandon_legacy_transfer(legacy['payload'])['status'] == 'abandoned'
    assert legacy['receipt'].read_bytes() == before


def test_retry_finishes_interrupted_atomic_attestation_publication(legacy):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    marker = legacy['bootstrap'] / ('memoryd-abandonment-' + guard['legacy_transfer_id'] + '.json')
    orphan = marker.parent / ('.' + marker.name + '.interrupted')
    os.link(marker, orphan)
    assert host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard'] == guard
    assert not orphan.exists()
    assert marker.stat().st_nlink == 1


def test_abandon_never_chmods_a_replaced_legacy_receipt(legacy, monkeypatch):
    real_backup = host._memoryd_pre_fence_backup
    def replace_after_backup(evidence, health):
        result = real_backup(evidence, health)
        host.write(legacy['receipt'], {'status': 'unrelated replacement'})
        return result
    monkeypatch.setattr(host, '_memoryd_pre_fence_backup', replace_after_backup)
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


def test_abandon_detects_a_late_worker_replacing_the_fence(legacy, monkeypatch):
    checks = []
    def quiescent():
        checks.append(1)
        if len(checks) == 6:
            host.write(legacy['receipt'], {'status': 'late worker replacement'})
        return True
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', quiescent)
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


def test_first_abandon_rejects_postpublication_count_drift_but_retry_allows_it(legacy, monkeypatch):
    real_snapshot = host._memoryd_legacy_snapshot
    calls = []
    def snapshot(*args):
        calls.append(1)
        if len(calls) == 3:
            with sqlite3.connect(legacy['database']) as db:
                db.execute("INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 0)")
        return real_snapshot(*args)
    monkeypatch.setattr(host, '_memoryd_legacy_snapshot', snapshot)
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o400
    assert len(list(legacy['bootstrap'].glob('memoryd-abandonment-*'))) == 1
    monkeypatch.setattr(host, '_memoryd_legacy_snapshot', real_snapshot)
    assert host.memoryd_abandon_legacy_transfer(legacy['payload'])['mutated'] is False


@pytest.mark.parametrize('change', ['same_id_receipt', 'staged_bundle', 'active_receipt', 'source_proof', 'active_import'])
def test_abandon_refuses_ambiguous_evidence_without_fencing(legacy, monkeypatch, change):
    before = legacy['receipt'].read_bytes()
    if change == 'same_id_receipt':
        host.write(legacy['bootstrap'] / ('memoryd-transfer-' + legacy['old']['manifest_sha256'] + '.json'), {})
    elif change == 'staged_bundle':
        (legacy['state'] / 'memoryd-transfer' / legacy['old']['manifest_sha256'][:16] / 'legacy.bundle').write_bytes(b'changed')
    elif change == 'active_receipt':
        host.write(legacy['bootstrap'] / ('memoryd-transfer-' + legacy['new']['manifest_sha256'] + '.json'), {})
    elif change == 'source_proof':
        legacy['payload']['source_proof']['legacy_selection_sha256'] = 'f' * 64
    else:
        monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: False)
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].read_bytes() == before
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


def test_abandon_retains_fence_if_an_import_appears_after_chmod(legacy, monkeypatch):
    calls = []
    def quiescent():
        calls.append(1)
        return len(calls) != 4
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', quiescent)
    with pytest.raises(ValueError, match='active'):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o400
    assert not list(legacy['bootstrap'].glob('memoryd-abandonment-*'))


def test_abandon_refuses_legacy_bundle_over_recovery_limit_before_fencing(legacy):
    old = legacy['old']['manifest_sha256']
    stage = legacy['state'] / 'memoryd-transfer' / old[:16]
    bundle = stage / 'legacy.bundle'
    with zipfile.ZipFile(bundle) as archive:
        manifest = archive.read('manifest.json')
    with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('manifest.json', manifest)
        archive.writestr('fixture-padding', b'x' * (24 * 1024 * 1024 + 1))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    source = json.loads(legacy['payload']['legacy_manifest'])
    source['bundles'][0].update(size_bytes=bundle.stat().st_size, sha256=digest)
    source_text = json.dumps(source)
    new_id = hashlib.sha256(source_text.encode()).hexdigest()
    legacy['payload']['legacy_manifest'] = source_text
    staged = json.loads((stage / 'transfer.json').read_bytes())
    staged['transfer_manifest_sha256'] = new_id
    staged['bundles'][0].update(size_bytes=bundle.stat().st_size, sha256=digest)
    host.write(stage / 'transfer.json', staged)
    stage.rename(stage.parent / new_id[:16])
    receipt = json.loads(legacy['receipt'].read_bytes())
    receipt['transfer_manifest_sha256'] = new_id
    host.write(legacy['receipt'], receipt)
    before = legacy['receipt'].read_bytes()
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].read_bytes() == before
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600
    assert not list(legacy['bootstrap'].glob('memoryd-abandonment-*'))


@pytest.mark.parametrize('invalid', ['malformed_id', 'duplicate_id'])
def test_legacy_stage_validation_requires_recoverable_bundle_ids(legacy, invalid):
    manifest = json.loads(json.dumps(legacy['old']['remote_manifest']))
    bundle = manifest['bundles'][0]
    if invalid == 'malformed_id':
        bundle['bundle_id'] = 'sha256:malformed'
    else:
        bundle['root_count'] = 1
        manifest['bundles'].append({**bundle, 'path': 'another.bundle'})
    with pytest.raises(ValueError):
        host._validate_memoryd_transfer_manifest(manifest, include_archived=True)


@pytest.mark.parametrize('receipt_name,key,value', [
    ('legacy', 'schema_version', True), ('active', 'schema_version', True),
    ('active', 'imported_record_count', True),
])
def test_abandon_refuses_boolean_receipt_fields_before_fencing(legacy, receipt_name, key, value):
    path = legacy['receipt'] if receipt_name == 'legacy' else legacy['bootstrap'] / (
        'memoryd-transfer-' + legacy['new']['manifest_sha256'] + '.json')
    receipt = json.loads(path.read_bytes())
    receipt[key] = value
    host.write(path, receipt)
    before = legacy['receipt'].read_bytes()
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].read_bytes() == before
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('key,value', [
    ('schema_version', True), ('imported_record_count', True),
    ('source_database_sha256', 'f' * 64), ('source_instance_id', 'cmi_' + 'f' * 32),
    ('source_profile', 'other'), ('source_workspace', 'other'),
    ('target_profile', 'other'), ('target_workspace', 'other'),
    ('destination_instance_id', 'cmi_' + 'f' * 32),
])
def test_guard_rejects_completed_receipt_inconsistent_with_attestation(legacy, key, value):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    marker_path = legacy['bootstrap'] / ('memoryd-abandonment-' + guard['legacy_transfer_id'] + '.json')
    marker = json.loads(marker_path.read_bytes())
    active_path = legacy['bootstrap'] / ('memoryd-transfer-' + marker['active_transfer_id'] + '.json')
    active = json.loads(active_path.read_bytes())
    active[key] = value
    host.write(active_path, active)
    marker['active_receipt_sha256'] = hashlib.sha256(active_path.read_bytes()).hexdigest()
    host.write(marker_path, marker)
    with pytest.raises(ValueError):
        host._memoryd_verify_abandonment(guard['legacy_transfer_id'])


def test_guard_rejects_boolean_legacy_receipt_schema(legacy):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    marker_path = legacy['bootstrap'] / ('memoryd-abandonment-' + guard['legacy_transfer_id'] + '.json')
    marker = json.loads(marker_path.read_bytes())
    receipt = json.loads(legacy['receipt'].read_bytes())
    receipt['schema_version'] = True
    host.write(legacy['receipt'], receipt)
    legacy['receipt'].chmod(0o400)
    backup = legacy['bootstrap'] / ('memoryd-legacy-receipt-' + guard['legacy_transfer_id'] + '.json')
    host.write(backup, receipt)
    digest = hashlib.sha256(legacy['receipt'].read_bytes()).hexdigest()
    marker.update(legacy_receipt_sha256=digest, legacy_receipt_backup_sha256=digest)
    host.write(marker_path, marker)
    with pytest.raises(ValueError):
        host._memoryd_verify_abandonment(guard['legacy_transfer_id'])


def test_guard_refuses_oversized_legacy_bundle_even_without_local_stage(legacy, tmp_path):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    stage = legacy['state'] / 'memoryd-transfer' / guard['legacy_transfer_id'][:16]
    stage.rename(tmp_path / 'retained-stage')
    marker_path = legacy['bootstrap'] / ('memoryd-abandonment-' + guard['legacy_transfer_id'] + '.json')
    marker = json.loads(marker_path.read_bytes())
    marker['legacy_bundles'][0]['size_bytes'] = 24 * 1024 * 1024 + 1
    host.write(marker_path, marker)
    with pytest.raises(ValueError):
        host._memoryd_verify_abandonment(guard['legacy_transfer_id'])


def test_abandon_refuses_a_legacy_bundle_receipt(legacy):
    bundle_id = legacy['old']['remote_manifest']['bundles'][0]['bundle_id']
    with sqlite3.connect(legacy['database']) as db:
        db.execute('INSERT INTO bundle_import_receipts VALUES (?, ?, ?)', (bundle_id, FIXTURE_INSTANCE, 'applied'))
    with pytest.raises(ValueError):
        host.memoryd_abandon_legacy_transfer(legacy['payload'])
    assert legacy['receipt'].stat().st_mode & 0o777 == 0o600


def test_fenced_receipt_is_rejected_by_the_historical_importer(legacy):
    host.memoryd_abandon_legacy_transfer(legacy['payload'])
    source = (Path(__file__).parent / 'fixtures/legacy_memoryd_importer_6aca9c4.py').read_text()
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in ('private', 'memoryd_import_bundles')]
    namespace = {'STATE': legacy['state'], 'os': os, 're': __import__('re'), 'json': json,
                 'memoryd_transfer_preflight': lambda: {'ready': True},
                 '_validate_memoryd_transfer_manifest': lambda _manifest: None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<historical-importer>', 'exec'), namespace)
    with pytest.raises(ValueError, match='Private file ownership/mode mismatch'):
        namespace['memoryd_import_bundles']({'transfer_manifest_sha256': legacy['old']['manifest_sha256']})


def test_capture_reports_guard_and_rejects_changed_abandoned_bundle(legacy, monkeypatch):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    host.write(legacy['bootstrap'] / 'memoryd-integration.json',
               {'organization': 'fixture', 'id': 'fixture', 'url': 'fixture'})
    monkeypatch.setattr(host, 'memoryd_status', lambda: {'status': 'HEALTHY', 'volume_exists': True,
                        'app_registered': True, 'adapter_sha256': 'b' * 64})
    monkeypatch.setattr(host, 'memoryd_health', lambda: {'status': 'PASS', 'persistent_volume': host.MEMORYD_VOLUME,
                        'adapter_sha256': 'b' * 64})
    monkeypatch.setattr(host, 'identity', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: b'mcp-control-plane-memoryd\n')
    assert host.memoryd_capture_preflight()['legacy_guard'] == guard
    bundle = legacy['state'] / 'memoryd-transfer' / guard['legacy_transfer_id'][:16] / 'legacy.bundle'
    bundle.write_bytes(b'changed')
    with pytest.raises(ValueError):
        host.memoryd_capture_preflight()


def test_captured_backup_rejects_legacy_bundle_import(legacy):
    guard = host.memoryd_abandon_legacy_transfer(legacy['payload'])['legacy_guard']
    old_id = legacy['old']['remote_manifest']['bundles'][0]['bundle_id']
    host._memoryd_guard_snapshot(legacy['database'], guard)
    with sqlite3.connect(legacy['database']) as db:
        db.execute('INSERT INTO bundle_import_receipts VALUES (?, ?, ?)', (old_id, FIXTURE_INSTANCE, 'applied'))
    with pytest.raises(ValueError):
        host._memoryd_guard_snapshot(legacy['database'], guard)
