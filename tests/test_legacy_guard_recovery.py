"""Recovery preserves an explicitly abandoned legacy import fence."""
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tarfile

import pytest

import control_plane_recovery as encryption
import prepare_recovery_generation as generation
import transfer_recovery_generation as transfer
from test_prepare_recovery_memoryd import (BACKEND_IMAGE, INSTANCE_ID, captured_fixture,
                                           refresh_backup_hashes)
from test_prepare_recovery_generation import write_private

LEGACY_ID = 'a' * 64
ACTIVE_ID = 'b' * 64
LEGACY_BUNDLE = 'sha256:' + 'c' * 64


def encoded(value):
    return json.dumps(value, sort_keys=True).encode() + b'\n'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def guarded_fixture(tmp_path):
    receipt = {
        'schema_version': 1, 'status': 'in_progress', 'transfer_manifest_sha256': LEGACY_ID,
        'source_database_sha256': 'd' * 64, 'source_instance_id': 'cmi_' + 'e' * 32,
        'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
        'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
        'bundles': {},
    }
    receipt_bytes = encoded(receipt)
    marker = {
        'schema_version': 1, 'status': 'abandoned', 'policy': 'active_only',
        'legacy_transfer_id': LEGACY_ID, 'legacy_receipt_sha256': digest(receipt_bytes),
        'legacy_receipt_backup_sha256': digest(receipt_bytes), 'legacy_staged_manifest_sha256': 'f' * 64,
        'legacy_bundles': [{'path': 'legacy.bundle', 'size_bytes': 42, 'sha256': '1' * 64,
                            'bundle_id': LEGACY_BUNDLE, 'manifest_digest': 'sha256:' + '2' * 64,
                            'root_count': 3}],
        'legacy_source_record_count': 3, 'active_source_record_count': 2,
        'source_database_record_count': 3, 'excluded_archived_record_count': 1,
        'active_transfer_id': ACTIVE_ID, 'active_receipt_sha256': '3' * 64,
        'active_staged_manifest_sha256': '4' * 64, 'source_database_sha256': 'd' * 64,
        'source_instance_id': 'cmi_' + 'e' * 32, 'source_profile': 'personal',
        'source_workspace': 'dakota-codex-only', 'target_profile': 'personal',
        'target_workspace': 'dakota-codex-only', 'destination_instance_id': INSTANCE_ID,
        'verification_snapshot_sha256': '5' * 64, 'verification_active_count': 2,
        'verification_archived_count': 0, 'legacy_import_receipt_count': 0,
        'memoryd_image': BACKEND_IMAGE, 'verified_at_ns': 123456789,
        'source_backup_manifest_sha256': '6' * 64, 'legacy_selection_sha256': '7' * 64,
        'active_selection_sha256': '8' * 64, 'excluded_archived_selection_sha256': '9' * 64,
        'pre_fence_backup_sha256': 'a' * 64, 'pre_fence_manifest_sha256': 'b' * 64,
        'pre_fence_backup_size_bytes': 12345,
    }
    marker_bytes = encoded(marker)
    guard = {'legacy_transfer_id': LEGACY_ID, 'receipt_sha256': digest(receipt_bytes),
             'attestation_sha256': digest(marker_bytes)}
    changes = [
        ('bootstrap/memoryd-transfer.json', 'file', receipt_bytes, 0o400),
        (f'bootstrap/memoryd-legacy-receipt-{LEGACY_ID}.json', 'file', receipt_bytes, 0o600),
        (f'bootstrap/memoryd-abandonment-{LEGACY_ID}.json', 'file', marker_bytes, 0o600),
    ]
    restored, _ = captured_fixture(tmp_path, essential_changes=changes)
    backup = restored / 'vm-snapshot/memoryd/backup.db'
    with sqlite3.connect(backup) as db:
        db.execute('CREATE TABLE bundle_import_receipts (bundle_id TEXT, status TEXT)')
    refresh_backup_hashes(restored)
    path = restored / 'capture-receipt'
    value = json.loads(path.read_bytes())
    value.update(schema_version=3, legacy_guard=guard)
    write_private(path, encoded(value))
    return restored, guard


def test_guarded_generation_preserves_receipt_and_version(tmp_path):
    restored, guard = guarded_fixture(tmp_path)
    prepared = tmp_path / 'prepared'
    result = generation.prepare_generation(restored, prepared)
    assert result['schema_version'] == 3
    assert result['legacy_guard'] == guard
    assert json.loads((prepared / 'generation.json').read_bytes())['legacy_guard'] == guard
    assert stat.S_IMODE((prepared / 'state/bootstrap/memoryd-transfer.json').stat().st_mode) == 0o400
    assert generation.validate_generation(prepared) == result


def rewrite_member(path, name, *, content=None, mode=None, remove=False):
    with tarfile.open(path, 'r:') as archive:
        rows = [(entry, archive.extractfile(entry).read() if entry.isfile() else None) for entry in archive]
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as archive:
        for entry, body in rows:
            if entry.name == name:
                if remove:
                    continue
                if content is not None:
                    body = content
                    entry.size = len(body)
                if mode is not None:
                    entry.mode = mode
            archive.addfile(entry, io.BytesIO(body) if body is not None else None)
    path.chmod(0o600)


def replace_guard_marker(restored, update):
    archive_path = restored / 'vm-snapshot/essential.tar'
    name = f'bootstrap/memoryd-abandonment-{LEGACY_ID}.json'
    with tarfile.open(archive_path, 'r:') as archive:
        marker = json.load(archive.extractfile(name))
    update(marker)
    raw = encoded(marker)
    rewrite_member(archive_path, name, content=raw)
    path = restored / 'capture-receipt'
    receipt = json.loads(path.read_bytes())
    receipt['legacy_guard']['attestation_sha256'] = digest(raw)
    write_private(path, encoded(receipt))


@pytest.mark.parametrize('alteration', ['downgrade', 'downgrade_writable', 'missing_marker', 'wrong_marker_hash', 'writable_latch',
                                        'wrong_backup', 'foreign_readonly', 'wrong_destination', 'wrong_roots',
                                        'ledger_receipt', 'same_id_receipt', 'raw_legacy_bundle', 'bad_pre_fence'])
def test_guard_tampering_fails_before_prepared_output(tmp_path, alteration):
    restored, _ = guarded_fixture(tmp_path)
    archive = restored / 'vm-snapshot/essential.tar'
    marker = f'bootstrap/memoryd-abandonment-{LEGACY_ID}.json'
    if alteration in ('downgrade', 'downgrade_writable'):
        path = restored / 'capture-receipt'
        receipt = json.loads(path.read_bytes())
        receipt['schema_version'] = 2
        receipt.pop('legacy_guard')
        write_private(path, encoded(receipt))
        if alteration == 'downgrade_writable':
            rewrite_member(archive, 'bootstrap/memoryd-transfer.json', mode=0o600)
    elif alteration == 'missing_marker':
        rewrite_member(archive, marker, remove=True)
    elif alteration == 'wrong_marker_hash':
        rewrite_member(archive, marker, content=b'{}\n')
    elif alteration == 'writable_latch':
        rewrite_member(archive, 'bootstrap/memoryd-transfer.json', mode=0o600)
    elif alteration == 'wrong_backup':
        rewrite_member(archive, f'bootstrap/memoryd-legacy-receipt-{LEGACY_ID}.json', content=b'{}\n')
    elif alteration == 'foreign_readonly':
        rewrite_member(archive, 'bootstrap/codex-integration.json', mode=0o400)
    elif alteration == 'wrong_destination':
        replace_guard_marker(restored, lambda m: m.update(destination_instance_id='cmi_' + '0' * 32))
    elif alteration == 'wrong_roots':
        replace_guard_marker(restored, lambda m: m['legacy_bundles'][0].update(root_count=2))
    elif alteration == 'bad_pre_fence':
        replace_guard_marker(restored, lambda m: m.update(pre_fence_backup_size_bytes=0))
    elif alteration == 'ledger_receipt':
        backup = restored / 'vm-snapshot/memoryd/backup.db'
        with sqlite3.connect(backup) as db:
            db.execute('INSERT INTO bundle_import_receipts VALUES (?, ?)', (LEGACY_BUNDLE, 'any-status'))
        refresh_backup_hashes(restored)
    elif alteration == 'same_id_receipt':
        with tarfile.open(archive, 'a') as output:
            member = tarfile.TarInfo(f'bootstrap/memoryd-transfer-{LEGACY_ID}.json')
            member.mode = 0o600
            member.size = 3
            output.addfile(member, io.BytesIO(b'{}\n'))
    elif alteration == 'raw_legacy_bundle':
        with tarfile.open(archive, 'a') as output:
            member = tarfile.TarInfo('bootstrap/legacy.bundle')
            member.mode = 0o600
            member.size = 3
            output.addfile(member, io.BytesIO(b'raw'))
    output = tmp_path / 'prepared'
    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)
    assert not output.exists()


def test_prepared_latch_cannot_be_made_writable_even_if_inventory_is_rewritten(tmp_path):
    restored, _ = guarded_fixture(tmp_path)
    prepared = tmp_path / 'prepared'
    generation.prepare_generation(restored, prepared)
    latch = prepared / 'state/bootstrap/memoryd-transfer.json'
    latch.chmod(0o600)
    manifest = prepared / 'prepared-manifest.json'
    value = json.loads(manifest.read_bytes())
    next(row for row in value['inventory'] if row['path'] == 'state/bootstrap/memoryd-transfer.json')['mode'] = 0o600
    write_private(manifest, encoded(value))
    with pytest.raises(generation.GenerationError):
        generation.validate_generation(prepared)


def test_encrypted_guard_roundtrip_and_local_transfer_keep_readonly_mode(tmp_path):
    restored, guard = guarded_fixture(tmp_path)
    identity = tmp_path / 'fixture.agekey'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    identity.chmod(0o600)
    recipient = tmp_path / 'recipient.txt'
    recipient.write_text(encryption.recipient_from_identity(identity))
    recipient.chmod(0o600)
    manifest = tmp_path / 'bundle-manifest.json'
    members = [{'name': name, 'source': str(restored / name), 'required': True} for name in
               ('native-endpoint', 'instance-config', 'operator-ssh', 'vm-snapshot', 'capture-receipt')]
    write_private(manifest, encoded({'version': 1, 'bundle_id': 'synthetic-guard', 'members': members}))
    bundle = tmp_path / 'recovery.age'
    encryption.export_bundle(manifest, recipient, bundle, exclude_identity=identity)
    assert encryption.verify_bundle(bundle, identity)['verified'] is True
    staged = tmp_path / 'decrypted'
    encryption.restore_bundle(bundle, identity, staged)
    prepared = tmp_path / 'prepared'
    assert generation.prepare_generation(staged, prepared)['legacy_guard'] == guard

    home = tmp_path / 'isolated-home'
    home.mkdir(mode=0o700)
    destination = home / '.local/state/mcp-control-plane-recovery-staging/fixture'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        archive.add(prepared, arcname='generation')
    validator = (Path(generation.__file__)).read_text()
    result = subprocess.run(['python3', '-c', transfer.REMOTE, str(destination), validator],
                            input=stream.getvalue(), env={**os.environ, 'HOME': str(home)}, capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    latch = destination / 'state/bootstrap/memoryd-transfer.json'
    assert stat.S_IMODE(latch.stat().st_mode) == 0o400
    assert generation.validate_generation(destination)['legacy_guard'] == guard


@pytest.mark.parametrize('corrupt', [False, True, 'missing_guard'])
def test_collector_binds_only_verified_transported_guard(tmp_path, monkeypatch, corrupt):
    from contextlib import nullcontext
    import collect_recovery as collector

    restored, guard = guarded_fixture(tmp_path)
    original = json.loads((restored / 'capture-receipt').read_bytes())
    memoryd = original['memoryd']
    executor = restored / 'vm-snapshot/executor.tar'
    live = {'authority': 'kamal', 'identity': 'fixture', 'source_sha': 'a' * 40, 'tunnel_count': 1}
    current = {key: live[key] for key in ('authority', 'identity', 'source_sha')}
    snapshot = {'backup': '/vm/state/deployment/backups/123', 'executor_sha256': digest(executor.read_bytes()),
                'memoryd': memoryd, 'legacy_guard': guard}
    if corrupt is True:
        snapshot['legacy_guard'] = {**guard, 'attestation_sha256': '0' * 64}
    elif corrupt == 'missing_guard':
        snapshot.pop('legacy_guard')
    requirements = tmp_path / 'requirements.json'
    write_private(requirements, b'{}\n')
    monkeypatch.setattr(collector.deploy, 'configure_local', lambda *_: None)
    monkeypatch.setattr(collector.deploy, 'trusted_context', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, 'load_native_profile', lambda *_: {'state_dir': str(tmp_path)})
    monkeypatch.setattr(collector, 'copy_private', lambda *_: None)
    monkeypatch.setattr(collector.deploy, 'lock', lambda: nullcontext())
    monkeypatch.setattr(collector.deploy, 'INSTANCE', {'vm': {'state_dir': '/vm/state'}})
    monkeypatch.setattr(collector.deploy, 'remote', lambda action, *_: {
        'current': current, 'snapshot': live, 'backup': snapshot}[action])
    monkeypatch.setattr(collector.deploy, 'ssh_args', lambda _: ['fixture'])
    monkeypatch.setattr(collector, 'validate_memoryd_snapshot', lambda *_: memoryd)
    def transport(_command, stdout, **_kwargs):
        with tarfile.open(fileobj=stdout, mode='w') as archive:
            archive.add(restored / 'vm-snapshot', arcname='vm-snapshot')
        return type('Result', (), {'returncode': 0})()
    monkeypatch.setattr(collector.subprocess, 'run', transport)
    destination = tmp_path / 'capture'
    if corrupt:
        with pytest.raises(ValueError, match='guard'):
            collector.collect('/unused', '/unused', '/unused', destination, requirements)
        assert not destination.exists()
    else:
        collector.collect('/unused', '/unused', '/unused', destination, requirements)
        result = json.loads((destination / 'capture-receipt.json').read_bytes())
        assert result['schema_version'] == 3 and result['legacy_guard'] == guard


def test_unrelated_import_receipt_does_not_block_guarded_restore(tmp_path):
    restored, _ = guarded_fixture(tmp_path)
    backup = restored / 'vm-snapshot/memoryd/backup.db'
    with sqlite3.connect(backup) as db:
        db.execute('INSERT INTO bundle_import_receipts VALUES (?, ?)', ('sha256:' + 'f' * 64, 'applied'))
    refresh_backup_hashes(restored)
    assert generation.prepare_generation(restored, tmp_path / 'prepared')['schema_version'] == 3


def test_prepared_downgrade_with_guard_artifacts_is_refused(tmp_path):
    restored, _ = guarded_fixture(tmp_path)
    prepared = tmp_path / 'prepared'
    generation.prepare_generation(restored, prepared)
    latch = prepared / 'state/bootstrap/memoryd-transfer.json'
    latch.chmod(0o600)
    generation_path = prepared / 'generation.json'
    doc = json.loads(generation_path.read_bytes())
    doc['schema_version'] = 2
    doc.pop('legacy_guard')
    write_private(generation_path, encoded(doc))
    manifest = prepared / 'prepared-manifest.json'
    data = json.loads(manifest.read_bytes())
    data['schema_version'] = 2
    data.pop('legacy_guard')
    for row in data['inventory']:
        if row['path'] == 'state/bootstrap/memoryd-transfer.json':
            row['mode'] = 0o600
        elif row['path'] == 'generation.json':
            row['size'] = generation_path.stat().st_size
            row['sha256'] = digest(generation_path.read_bytes())
    write_private(manifest, encoded(data))
    with pytest.raises(generation.GenerationError):
        generation.validate_generation(prepared)


@pytest.mark.parametrize('interruption', ['staging', 'recorded_bundle'])
def test_abandoned_receipt_cannot_claim_an_interrupted_import(tmp_path, interruption):
    restored, _ = guarded_fixture(tmp_path)
    archive_path = restored / 'vm-snapshot/essential.tar'
    with tarfile.open(archive_path, 'r:') as archive:
        receipt = json.load(archive.extractfile('bootstrap/memoryd-transfer.json'))
    if interruption == 'staging':
        receipt['staging'] = {'path': '/tmp/fixture'}
    else:
        receipt['bundles'] = {'legacy.bundle': {'receipt_id': 'fixture'}}
    raw = encoded(receipt)
    for name in ('bootstrap/memoryd-transfer.json', f'bootstrap/memoryd-legacy-receipt-{LEGACY_ID}.json'):
        rewrite_member(archive_path, name, content=raw)
    replace_guard_marker(restored, lambda m: m.update(legacy_receipt_sha256=digest(raw),
                                                     legacy_receipt_backup_sha256=digest(raw)))
    path = restored / 'capture-receipt'
    capture = json.loads(path.read_bytes())
    capture['legacy_guard']['receipt_sha256'] = digest(raw)
    write_private(path, encoded(capture))
    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, tmp_path / 'prepared')
