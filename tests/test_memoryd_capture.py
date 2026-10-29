"""Synthetic-only checks for complete MemoryD recovery captures."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest

import vm_deploy_host as host
from collect_recovery import validate_memoryd_snapshot


def test_capture_preflight_proves_true_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_inventory', lambda: {
        'status': 'ABSENT', 'services': {}, 'volume_exists': False, 'app_registered': False,
    })
    checks = []
    monkeypatch.setattr(host, 'identity', lambda *args, **kwargs: checks.append(kwargs))

    assert host.memoryd_capture_preflight() == {'status': 'absent'}
    assert checks == [{'exclude_memoryd': True, 'require_memoryd_absent': True}]


@pytest.mark.parametrize('status', ['PARTIAL', 'VOLUME_ONLY', 'STOPPED', 'UNHEALTHY'])
def test_capture_preflight_rejects_incomplete_memoryd(tmp_path, monkeypatch, status):
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_status', lambda: {'status': status})
    monkeypatch.setattr(host, 'memoryd_inventory', lambda: {'status': status})

    with pytest.raises(ValueError):
        host.memoryd_capture_preflight()


def test_capture_preflight_rejects_pending_registration(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'
    bootstrap.mkdir()
    (bootstrap / 'memoryd-registration-pending.json').write_text('{}')
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_inventory', lambda: {
        'status': 'ABSENT', 'services': {}, 'volume_exists': False, 'app_registered': False,
    })
    monkeypatch.setattr(host, 'identity', lambda *args, **kwargs: None)

    with pytest.raises(ValueError):
        host.memoryd_capture_preflight()


def test_backup_refuses_incomplete_memoryd_before_pausing_executor(monkeypatch):
    monkeypatch.setattr(host, 'validate_profile', lambda: None)
    monkeypatch.setattr(host, 'recorded_runtime_source_sha', lambda: 'a' * 40)
    def reject():
        raise ValueError('MemoryD incomplete')
    monkeypatch.setattr(host, 'memoryd_capture_preflight', reject)
    monkeypatch.setattr(host, 'inspect', lambda: pytest.fail('backup must not inspect or pause Executor'))
    with pytest.raises(ValueError, match='MemoryD incomplete'):
        host.backup(include_memoryd=True)


def test_capture_absence_rejects_a_retained_adapter_pin(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'
    bootstrap.mkdir()
    (bootstrap / 'memoryd-adapter-image.json').write_text('{}')
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_inventory', lambda: {
        'status': 'ABSENT', 'services': {}, 'volume_exists': False, 'app_registered': False,
    })
    monkeypatch.setattr(host, 'identity', lambda *args, **kwargs: pytest.fail('absence was not proven'))
    with pytest.raises(ValueError, match='absence'):
        host.memoryd_capture_preflight()


def test_capture_refuses_another_container_using_the_memoryd_volume(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'
    bootstrap.mkdir()
    marker = bootstrap / 'memoryd-integration.json'
    marker.write_text(json.dumps({'organization': 'fixture', 'id': 'fixture', 'url': 'fixture'}))
    marker.chmod(0o600)
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_status', lambda: {
        'status': 'HEALTHY', 'volume_exists': True, 'app_registered': True, 'adapter_sha256': 'a' * 64,
    })
    monkeypatch.setattr(host, 'memoryd_health', lambda: {
        'status': 'PASS', 'persistent_volume': host.MEMORYD_VOLUME, 'adapter_sha256': 'a' * 64,
    })
    monkeypatch.setattr(host, 'identity', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: b'mcp-control-plane-memoryd\nother-writer\n')
    with pytest.raises(ValueError, match='volume'):
        host.memoryd_capture_preflight()


@pytest.mark.parametrize('apps', [[], [{'slug': 'memoryd', 'name': 'MemoryD'}],
                                   [{'slug': 'memoryd', 'name': 'MemoryD', 'activeDeployment': None}]])
def test_capture_rejects_missing_or_inactive_memoryd_app(apps):
    with pytest.raises(ValueError, match='active'):
        host._memoryd_require_active_app(apps)


def test_capture_accepts_exactly_one_active_memoryd_app():
    host._memoryd_require_active_app([
        {'slug': 'memoryd', 'name': 'MemoryD', 'activeDeployment': {'id': 'fixture'}},
    ])


def setup_superseded_transfer(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'
    bootstrap.mkdir(mode=0o700)
    marker = bootstrap / 'memoryd-integration.json'
    marker.write_text(json.dumps({'organization': 'fixture', 'id': 'fixture', 'url': 'fixture'}))
    marker.chmod(0o600)
    legacy = {
        'schema_version': 1, 'status': 'in_progress', 'transfer_manifest_sha256': 'a' * 64,
        'source_database_sha256': 'b' * 64, 'source_instance_id': 'cmi_' + 'c' * 32,
        'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
        'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
        'target_backup': {'path': 'synthetic'}, 'bundles': {},
    }
    complete = {**legacy, 'status': 'complete', 'transfer_manifest_sha256': 'd' * 64,
                'bundles': {'fixture': {'status': 'complete'}}, 'completed_at_ns': time.time_ns(),
                'imported_record_count': 1}
    legacy_path = bootstrap / 'memoryd-transfer.json'
    complete_path = bootstrap / ('memoryd-transfer-' + 'd' * 64 + '.json')
    def write(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    write(legacy_path, legacy)
    os.utime(legacy_path, ns=(1_000_000_000, 1_000_000_000))
    write(complete_path, complete)
    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'memoryd_status', lambda: {
        'status': 'HEALTHY', 'volume_exists': True, 'app_registered': True, 'adapter_sha256': 'e' * 64,
    })
    monkeypatch.setattr(host, 'memoryd_health', lambda: {
        'status': 'PASS', 'persistent_volume': host.MEMORYD_VOLUME, 'adapter_sha256': 'e' * 64,
    })
    monkeypatch.setattr(host, 'identity', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: b'mcp-control-plane-memoryd\n')
    monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: True, raising=False)
    return legacy_path, complete_path, legacy, complete, write


def test_capture_accepts_only_a_proven_superseded_legacy_receipt(tmp_path, monkeypatch):
    legacy_path, complete_path, _, _, _ = setup_superseded_transfer(tmp_path, monkeypatch)
    before = (legacy_path.read_bytes(), legacy_path.stat().st_mtime_ns, complete_path.read_bytes())
    assert host.memoryd_capture_preflight()['status'] == 'healthy'
    assert (legacy_path.read_bytes(), legacy_path.stat().st_mtime_ns, complete_path.read_bytes()) == before


def test_capture_allows_unrelated_completed_history(tmp_path, monkeypatch):
    _, complete_path, _, complete, write = setup_superseded_transfer(tmp_path, monkeypatch)
    write(complete_path.parent / ('memoryd-transfer-' + 'e' * 64 + '.json'),
          {**complete, 'transfer_manifest_sha256': 'e' * 64, 'source_database_sha256': 'f' * 64})
    assert host.memoryd_capture_preflight()['status'] == 'healthy'


@pytest.mark.parametrize('conflict', ['missing_complete', 'different_source', 'different_instance',
                                      'different_source_scope', 'different_target_scope',
                                      'legacy_staging', 'legacy_bundles', 'legacy_directory',
                                      'active_import', 'older_complete', 'ambiguous_complete',
                                      'malformed_duplicate'])
def test_capture_refuses_ambiguous_superseded_legacy_receipt(tmp_path, monkeypatch, conflict):
    legacy_path, complete_path, legacy, complete, write = setup_superseded_transfer(tmp_path, monkeypatch)
    if conflict == 'missing_complete':
        complete_path.unlink()
    elif conflict == 'different_source':
        write(complete_path, {**complete, 'source_database_sha256': 'f' * 64})
    elif conflict == 'different_instance':
        write(complete_path, {**complete, 'source_instance_id': 'cmi_' + 'f' * 32})
    elif conflict == 'different_source_scope':
        write(complete_path, {**complete, 'source_workspace': 'other'})
    elif conflict == 'different_target_scope':
        write(complete_path, {**complete, 'target_workspace': 'other'})
    elif conflict == 'legacy_staging':
        write(legacy_path, {**legacy, 'staging': {'path': 'synthetic'}})
    elif conflict == 'legacy_bundles':
        write(legacy_path, {**legacy, 'bundles': {'fixture': {}}})
    elif conflict == 'legacy_directory':
        (tmp_path / 'memoryd-transfer' / ('a' * 16)).mkdir(parents=True)
    elif conflict == 'active_import':
        monkeypatch.setattr(host, '_memoryd_capture_import_quiescent', lambda: False, raising=False)
    elif conflict == 'older_complete':
        write(complete_path, {**complete, 'completed_at_ns': 1})
    elif conflict == 'ambiguous_complete':
        write(complete_path.parent / ('memoryd-transfer-' + 'e' * 64 + '.json'),
              {**complete, 'transfer_manifest_sha256': 'e' * 64})
    else:
        write(complete_path.parent / ('memoryd-transfer-' + 'e' * 64 + '.json'),
              {**complete, 'transfer_manifest_sha256': 'e' * 64, 'completed_at_ns': None})
    with pytest.raises((ValueError, OSError)):
        host.memoryd_capture_preflight()


@pytest.mark.parametrize('command,expected', [
    (b'/usr/local/bin/codex-memoryd\0serve\0', False),
    (b'/usr/local/bin/codex-memoryd\0--local\0bundle\0import\0--apply\0', True),
    (b'python3\0-c\0fixture\0memoryd-import-bundles\0', True),
    (b'docker\0exec\0memoryd\0/usr/local/bin/codex-memoryd\0bundle\0import\0', True),
])
def test_capture_recognizes_active_import_commands(command, expected):
    assert host._memoryd_import_process_active(command.split(b'\0')) is expected


def test_capture_proves_import_quiescence_in_host_and_container(tmp_path, monkeypatch):
    process = tmp_path / '123'
    process.mkdir()
    (process / 'cmdline').write_bytes(b'python3\0-c\0fixture\0memoryd-import-bundles\0')
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: b'PID COMMAND\n1 codex-memoryd serve\n')
    assert host._memoryd_capture_import_quiescent(proc=tmp_path) is False
    (process / 'cmdline').write_bytes(b'python3\0-c\0fixture\0other\0')
    assert host._memoryd_capture_import_quiescent(proc=tmp_path) is True
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs:
                        b'PID COMMAND\n1 codex-memoryd serve\n2 codex-memoryd --local bundle import --apply\n')
    assert host._memoryd_capture_import_quiescent(proc=tmp_path) is False
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: b'not a process listing')
    with pytest.raises(ValueError):
        host._memoryd_capture_import_quiescent(proc=tmp_path)


def synthetic_snapshot(root):
    root.mkdir(mode=0o700)
    adapter = root / 'adapter'
    adapter.mkdir(mode=0o700)
    payload = b'# synthetic adapter\n'
    digest = hashlib.sha256(payload).hexdigest()
    (adapter / 'codex_memoryd_mcp.py').write_bytes(payload)
    (adapter / 'artifact.json').write_text(json.dumps({
        'adapter_sha256': digest, 'size_bytes': len(payload), 'controller_sha': 'b' * 40,
    }))
    database = root / 'backup.db'
    tables = ('memory_records', 'conclusions', 'checkpoints', 'subjects', 'episodes',
              'subject_aliases', 'relations', 'evidence_ledger', 'procedures',
              'memory_sources', 'dream_runs', 'policy_events')
    with sqlite3.connect(database) as connection:
        connection.executescript('''
          CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT);
          INSERT INTO schema_meta VALUES ('schema_version', '13');
          CREATE TABLE instance_metadata (singleton_key TEXT PRIMARY KEY, instance_id TEXT);
          INSERT INTO instance_metadata VALUES ('default', 'cmi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
          CREATE TABLE memory_records (profile_id TEXT, workspace_id TEXT, archived INTEGER);
          INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 0);
          INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 1);
          CREATE TABLE workspaces (profile_id TEXT, id TEXT);
          CREATE TABLE fixture_workspace_only (workspace_id TEXT);
          CREATE TABLE sessions (profile_id TEXT, workspace_id TEXT);
          CREATE TABLE visible_turns (session_id TEXT, content TEXT);
        ''')
        for table in tables[1:]:
            if table in ('subjects', 'policy_events'):
                connection.execute(f'CREATE TABLE {table} (profile_id TEXT, workspace_id TEXT)')
            else:
                connection.execute(f'CREATE TABLE {table} (value TEXT)')
    raw = database.read_bytes()
    manifest = {
        'manifest_version': 1, 'tool_version': '0.1.0', 'created_at': '2026-10-29T00:00:00Z',
        'database_file': 'backup.db', 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
        'size_bytes': len(raw), 'schema_version': 13, 'expected_schema_version': 13,
        'tables': [{'table': table, 'rows': 2 if table == 'memory_records' else 0} for table in tables],
    }
    (root / 'backup.db.manifest.json').write_text(json.dumps(manifest))
    for file in root.rglob('*'):
        if file.is_file():
            file.chmod(0o600)
    return manifest


def test_capture_facts_are_derived_from_database_and_manifest(tmp_path):
    root = tmp_path / 'memoryd'
    manifest = synthetic_snapshot(root)

    facts = host._validate_memoryd_capture(root)
    assert facts['source_instance_id'] == 'cmi_' + 'a' * 32
    assert (facts['record_count'], facts['active_record_count'], facts['archived_record_count']) == (2, 1, 1)
    assert facts['backup_sha256'] == manifest['sha256'][7:]
    assert facts['profile'] == 'personal' and facts['workspace'] == 'dakota-codex-only'


@pytest.mark.parametrize('bad', ['scope', 'schema', 'manifest_digest', 'adapter', 'extra_file',
                                 'subject_scope', 'global_policy_event', 'profile_only', 'workspace_only',
                                 'workspace_catalog', 'raw_session', 'raw_turn'])
def test_capture_validation_rejects_inconsistent_artifacts(tmp_path, bad):
    root = tmp_path / 'memoryd'
    manifest = synthetic_snapshot(root)
    if bad in {'scope', 'schema', 'subject_scope', 'global_policy_event', 'profile_only',
               'workspace_only', 'workspace_catalog', 'raw_session', 'raw_turn'}:
        with sqlite3.connect(root / 'backup.db') as connection:
            if bad == 'scope':
                connection.execute("UPDATE memory_records SET workspace_id='other' WHERE archived=1")
            elif bad == 'schema':
                connection.execute("UPDATE schema_meta SET value='999'")
            elif bad in {'subject_scope', 'global_policy_event'}:
                table = 'subjects' if bad == 'subject_scope' else 'policy_events'
                connection.execute(f'INSERT INTO {table} VALUES (?, ?)',
                                   ('personal', 'other') if bad == 'subject_scope' else (None, None))
                next(item for item in manifest['tables'] if item['table'] == table)['rows'] = 1
            elif bad == 'profile_only':
                connection.execute("INSERT INTO workspaces VALUES ('work', 'dakota-codex-only')")
            elif bad == 'workspace_only':
                connection.execute('INSERT INTO fixture_workspace_only VALUES (NULL)')
            elif bad == 'raw_session':
                connection.execute("INSERT INTO sessions VALUES ('personal', 'dakota-codex-only')")
            elif bad == 'raw_turn':
                connection.execute("INSERT INTO visible_turns VALUES ('synthetic', 'synthetic')")
            else:
                connection.execute("INSERT INTO workspaces VALUES ('personal', 'other')")
        raw = (root / 'backup.db').read_bytes()
        manifest['sha256'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        (root / 'backup.db.manifest.json').write_text(json.dumps(manifest))
    elif bad == 'manifest_digest':
        manifest['sha256'] = 'sha256:' + '0' * 64
        (root / 'backup.db.manifest.json').write_text(json.dumps(manifest))
    elif bad == 'adapter':
        (root / 'adapter/codex_memoryd_mcp.py').write_bytes(b'changed')
    else:
        (root / 'unexpected').write_bytes(b'')

    with pytest.raises(ValueError):
        host._validate_memoryd_capture(root)


def test_capture_absent_does_not_create_memoryd_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(host, 'memoryd_capture_preflight', lambda: {'status': 'absent'})
    result = host.capture_memoryd(tmp_path / 'memoryd')
    assert result == {'status': 'absent'}
    assert not (tmp_path / 'memoryd').exists()


def test_capture_binds_artifact_facts_and_refuses_state_change(tmp_path, monkeypatch):
    root = tmp_path / 'memoryd'
    adapter_digest = hashlib.sha256(b'# synthetic adapter\n').hexdigest()
    health = {'status': 'PASS', 'memoryd_image': host.MEMORYD_IMAGE,
              'adapter_image': 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'c' * 64,
              'adapter_sha256': adapter_digest}
    before = {'status': 'healthy', 'health': health}
    checks = iter((before, before))
    monkeypatch.setattr(host, 'memoryd_capture_preflight', lambda: next(checks))
    monkeypatch.setattr(host, '_memoryd_snapshot_files', lambda directory, _health: synthetic_snapshot(directory))
    result = host.capture_memoryd(root)
    assert result['status'] == 'captured'
    assert result['backend_image'] == host.MEMORYD_IMAGE
    assert result['adapter_image'] == health['adapter_image']
    assert result['adapter_sha256'] == adapter_digest
    assert result['captured_at'] == '2026-10-29T00:00:00Z'
    assert set(result) == {'status', 'backend_image', 'adapter_image', 'adapter_sha256',
                           'backup_sha256', 'backup_manifest_sha256', 'backup_size_bytes',
                           'source_instance_id', 'record_count', 'active_record_count',
                           'archived_record_count', 'profile', 'workspace', 'captured_at'}
    assert validate_memoryd_snapshot(tmp_path, result) == result
    with pytest.raises(ValueError, match='descriptor'):
        validate_memoryd_snapshot(tmp_path, {**result, 'record_count': 999})

    changed = iter((before, {'status': 'absent'}))
    monkeypatch.setattr(host, 'memoryd_capture_preflight', lambda: next(changed))
    with pytest.raises(ValueError):
        host.capture_memoryd(tmp_path / 'other')


def test_snapshot_uses_scratch_verification_and_detects_mutation(tmp_path, monkeypatch):
    fixture = tmp_path / 'fixture'
    manifest = synthetic_snapshot(fixture)
    volume = tmp_path / 'volume'
    volume.mkdir()
    shutil.copyfile(fixture / 'backup.db', volume / 'memory.db')
    adapter_sha = hashlib.sha256((fixture / 'adapter/codex_memoryd_mcp.py').read_bytes()).hexdigest()
    state = tmp_path / 'state'
    staged_adapter = state / 'memoryd-adapter' / adapter_sha
    staged_adapter.parent.mkdir(parents=True, mode=0o700)
    shutil.copytree(fixture / 'adapter', staged_adapter)
    monkeypatch.setattr(host, 'STATE', state)
    calls = []
    mutate = [False]
    change_source = [False]

    def path(value):
        assert value.startswith('/data/')
        return volume / value.removeprefix('/data/')

    def run(command, **_kwargs):
        operation = command[5:]
        calls.append(operation)
        if operation[:2] == ['sh', '-c']:
            return f'{(volume / "memory.db").stat().st_size}\n0\n'.encode()
        if operation[:2] == ['df', '-Pk']:
            return b'Filesystem 1024-blocks Used Available Capacity Mounted\nvolume 100000 1 99999 1% /data\n'
        if operation[0] == 'stat':
            if operation[-1] == '/data/memory.db':
                identity = '1:2' if change_source[0] and any(row[:3] == ['cli', 'backup', 'create'] for row in calls) else '1:1'
                return (identity + '\n').encode()
            return ''.join(f'{path(value).stat().st_size}\n' for value in operation[-2:]).encode()
        if operation[0] == 'mkdir':
            path(operation[-1]).mkdir(mode=0o700)
        elif operation[0] == 'cp':
            shutil.copyfile(path(operation[-2]), path(operation[-1]))
        elif operation[0] == 'sha256sum':
            return (hashlib.sha256(path(operation[-1]).read_bytes()).hexdigest() + '  file\n').encode()
        else:
            raise AssertionError(operation)
        return b''

    def cli(stage, args):
        calls.append(['cli', *args])
        if args[:2] == ['backup', 'create']:
            dest = args[-1]
            shutil.copyfile(path(stage + '/source.db'), path(dest))
            path(dest + '.manifest.json').write_text(json.dumps(manifest))
            return {'ok': True, 'database_path': dest, 'manifest_path': dest + '.manifest.json',
                    'manifest': manifest}
        assert args[:2] == ['backup', 'verify'] and '/scratch/' in args[-1]
        if mutate[0]:
            with path(args[-1]).open('ab') as file:
                file.write(b'x')
        return {'ok': True, 'digest_matches': True, 'integrity_ok': True,
                'schema_matches': True, 'manifest': manifest}

    def copy(source, target, _limit):
        shutil.copyfile(path(source), target)
        target.chmod(0o600)

    def readonly_snapshot(_image, spool):
        spool.write((volume / 'memory.db').read_bytes())
        spool.seek(0)

    def stage_input(stage, spool):
        with path(stage + '/source.db').open('xb') as output:
            shutil.copyfileobj(spool, output)

    monkeypatch.setattr(host, 'run', run)
    monkeypatch.setattr(host, '_memoryd_capture_cli', cli)
    monkeypatch.setattr(host, '_memoryd_capture_copy', copy)
    monkeypatch.setattr(host, '_memoryd_capture_readonly_snapshot', readonly_snapshot)
    monkeypatch.setattr(host, '_memoryd_capture_stage_input', stage_input)
    health = {'adapter_sha256': adapter_sha,
              'adapter_image': 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'c' * 64}
    host._memoryd_snapshot_files(tmp_path / 'captured', health)
    assert host._validate_memoryd_capture(tmp_path / 'captured')['record_count'] == 2
    creates = [row for row in calls if row[:3] == ['cli', 'backup', 'create']]
    verifies = [row for row in calls if row[:3] == ['cli', 'backup', 'verify']]
    assert len(creates) == len(verifies) == 1
    assert '/scratch/' not in creates[0][-1] and '/scratch/' in verifies[0][-1]
    assert creates[0][-1].endswith('/backup.db')

    mutate[0] = True
    with pytest.raises(ValueError, match='verification changed'):
        host._memoryd_snapshot_files(tmp_path / 'rejected', health)
    assert not (tmp_path / 'rejected').exists()

    calls.clear()
    mutate[0] = False
    change_source[0] = True
    with pytest.raises(ValueError, match='source changed'):
        host._memoryd_snapshot_files(tmp_path / 'changed-source', health)
    assert not (tmp_path / 'changed-source').exists()


def test_snapshot_rejects_oversized_source_before_staging_or_helper(tmp_path, monkeypatch):
    calls = []
    def run(command, **_kwargs):
        calls.append(command)
        if command[-2:] == ['df', '-Pk']:
            raise AssertionError('unexpected command')
        if 'df' in command:
            return b'Filesystem 1024-blocks Used Available Capacity Mounted\nvolume 999999 1 999998 1% /data\n'
        return f'{host.MEMORYD_CAPTURE_MAX_BYTES}\n1\n'.encode()
    monkeypatch.setattr(host, 'run', run)
    monkeypatch.setattr(host, '_memoryd_capture_cli', lambda *_args: pytest.fail('helper must not start'))
    with pytest.raises(ValueError, match='capacity bound'):
        host._memoryd_snapshot_files(tmp_path / 'capture', {})
    assert len(calls) == 2
    assert not (tmp_path / 'capture').exists()


def test_snapshot_rejects_insufficient_memory_before_helper(tmp_path, monkeypatch):
    monkeypatch.setattr(host, 'memoryd_resource_gate', lambda _raw: {'mem_available_kb': 100})
    monkeypatch.setattr(host, 'run', lambda *_args, **_kwargs: pytest.fail('container must not be touched'))
    monkeypatch.setattr(host, '_memoryd_capture_readonly_snapshot', lambda *_args: pytest.fail('helper must not start'))
    with pytest.raises(ValueError, match='memory'):
        host._memoryd_snapshot_files(tmp_path / 'capture', {})


def test_capture_cli_uses_a_pinned_isolated_helper_without_daemon_restart(monkeypatch):
    calls = []
    def fake(command, **kwargs):
        calls.append((command, kwargs))
        return type('Result', (), {'returncode': 0, 'stdout': b'{"ok":true}'})()
    monkeypatch.setattr(host.subprocess, 'run', fake)
    stage = '/data/.memoryd-recovery-' + 'a' * 32
    assert host._memoryd_capture_cli(stage, ['backup', 'verify', '--path', stage + '/scratch/backup.db']) == {'ok': True}
    command = calls[0][0]
    assert command[:2] == ['docker', 'run']
    assert '--network=none' in command and '--pull=never' in command
    assert '--read-only' in command and host.MEMORYD_IMAGE in command
    assert '--memory' in command and '--memory-swap' in command
    assert stage + '/source.db' in command
    assert all('/data/memory.db' not in part for part in command)
    assert 'restart' not in command and 'stop' not in command


def test_readonly_snapshot_helper_mounts_the_source_volume_readonly(tmp_path, monkeypatch):
    calls = []
    def fake(command, stdout, **_kwargs):
        calls.append(command)
        stdout.write(b'synthetic snapshot bytes')
        return type('Result', (), {'returncode': 0})()
    monkeypatch.setattr(host.subprocess, 'run', fake)
    image = 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'c' * 64
    with tempfile.TemporaryFile(dir=tmp_path) as spool:
        host._memoryd_capture_readonly_snapshot(image, spool)
        assert spool.read() == b'synthetic snapshot bytes'
    command = calls[0]
    assert 'type=volume,source=codex-memoryd-data,target=/data,readonly' in command
    assert '--read-only' in command and '--network=none' in command and '--pull=never' in command
    assert image in command and '/data/memory.db' in command


def test_readonly_snapshot_includes_committed_wal_and_never_writes_source(tmp_path):
    source_dir = tmp_path / 'source'
    source_dir.mkdir(mode=0o700)
    source = source_dir / 'memory.db'
    writer = sqlite3.connect(source)
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute('CREATE TABLE synthetic (value TEXT)')
    writer.execute("INSERT INTO synthetic VALUES ('committed')")
    writer.commit()
    wal = source_dir / 'memory.db-wal'
    assert wal.exists() and wal.stat().st_size > 0
    original = {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in source_dir.iterdir()}
    for file in source_dir.iterdir():
        file.chmod(0o400)
    source_dir.chmod(0o500)
    output = tmp_path / 'snapshot.db'
    try:
        with output.open('xb') as stream:
            result = subprocess.run([sys.executable, '-c', host.MEMORYD_READONLY_SNAPSHOT_CODE,
                                     str(source), str(host.MEMORYD_CAPTURE_MAX_BYTES)],
                                    stdout=stream, stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0
        with sqlite3.connect(output) as snapshot:
            assert snapshot.execute('SELECT count(*) FROM synthetic').fetchone() == (1,)
        assert {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in source_dir.iterdir()} == original
    finally:
        source_dir.chmod(0o700)
        for file in source_dir.iterdir():
            file.chmod(0o600)
        writer.close()


def test_readonly_snapshot_rejects_missing_source_without_creating_it(tmp_path):
    missing = tmp_path / 'missing.db'
    result = subprocess.run([sys.executable, '-c', host.MEMORYD_READONLY_SNAPSHOT_CODE,
                             str(missing), str(host.MEMORYD_CAPTURE_MAX_BYTES)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode != 0
    assert result.stdout == b'' and not missing.exists()


@pytest.mark.skipif(not os.environ.get('CODEX_MEMORYD_TEST_BINARY'), reason='release binary not configured')
def test_released_binary_snapshot_passes_capture_validation(tmp_path):
    binary = os.environ['CODEX_MEMORYD_TEST_BINARY']
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    source = tmp_path / 'source.db'
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'CODEX_MEMORYD_HOME': str(home / 'memoryd'),
           'CODEX_MEMORYD_DB': str(source), 'CODEX_MEMORYD_LOG': 'error'}
    def call(*args):
        return subprocess.run([binary, '--local', '--db', str(source), *args], env=env,
                              capture_output=True, text=True, check=True, timeout=30)
    call('conclude', '--profile', 'personal', '--workspace', 'dakota-codex-only',
         '--content', 'synthetic recovery fixture')
    writer = sqlite3.connect(source)
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute('CREATE TABLE fixture_live_wal (value TEXT)')
    writer.execute("INSERT INTO fixture_live_wal VALUES ('committed')")
    writer.commit()
    isolated = tmp_path / 'isolated.db'
    with isolated.open('xb') as stream:
        helper = subprocess.run([sys.executable, '-c', host.MEMORYD_READONLY_SNAPSHOT_CODE,
                                 str(source), str(host.MEMORYD_CAPTURE_MAX_BYTES)],
                                stdout=stream, stderr=subprocess.PIPE, timeout=30)
    writer.close()
    assert helper.returncode == 0
    source = isolated
    env['CODEX_MEMORYD_DB'] = str(source)
    source_before = hashlib.sha256(source.read_bytes()).hexdigest()
    root = tmp_path / 'snapshot'
    root.mkdir(mode=0o700)
    created = json.loads(call('backup', 'create', '--dest', str(root / 'backup.db')).stdout)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_before
    fixture = tmp_path / 'fixture'
    synthetic_snapshot(fixture)
    shutil.copytree(fixture / 'adapter', root / 'adapter')
    for file in root.rglob('*'):
        if file.is_file():
            file.chmod(0o600)
    scratch = tmp_path / 'scratch'
    scratch.mkdir(mode=0o700)
    for name in ('backup.db', 'backup.db.manifest.json'):
        shutil.copyfile(root / name, scratch / name)
    before = hashlib.sha256((scratch / 'backup.db').read_bytes()).hexdigest()
    verified = json.loads(call('backup', 'verify', '--path', str(scratch / 'backup.db')).stdout)
    facts = host._validate_memoryd_capture(root)
    assert verified['ok'] is True and before == hashlib.sha256((scratch / 'backup.db').read_bytes()).hexdigest()
    assert facts['backup_sha256'] == created['manifest']['sha256'][7:]
    assert facts['record_count'] >= 1 and facts['profile'] == 'personal'
    with sqlite3.connect(source) as original:
        assert original.execute("SELECT instance_id FROM instance_metadata WHERE singleton_key='default'").fetchone() == (facts['source_instance_id'],)
    with sqlite3.connect(root / 'backup.db') as restored:
        assert restored.execute('SELECT count(*) FROM fixture_live_wal').fetchone() == (1,)
