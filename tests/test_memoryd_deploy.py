"""Capacity and non-disruption gates for the additive MemoryD deployment."""
import sys
import hashlib
import json
from pathlib import Path
import sqlite3
import shutil
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import vm_deploy_host
import deploy_control_plane

FIXTURE_INSTANCE = 'cmi_' + 'a' * 32


def public_memory_id(record_id):
    return 'mr_' + hashlib.sha256(b'mr_\x1f' + record_id.encode()).hexdigest()[:32]


def meminfo(*, total_kb, available_kb):
    return f"MemTotal: {total_kb} kB\nMemAvailable: {available_kb} kB\nSwapTotal: 0 kB\n"


def write_transfer_fixture(home, source_root, selected_ids):
    home.mkdir(mode=0o700)
    (home / 'exports').mkdir(mode=0o700)
    (home / 'backups').mkdir(mode=0o700)
    source_root.mkdir(mode=0o700)
    memory_file = source_root / 'fixture.md'
    memory_file.write_text('# Transfer fixture\n')
    file_hash = hashlib.sha256(memory_file.read_bytes()).hexdigest()
    source_manifest_hash = hashlib.sha256(f'{file_hash}  fixture.md'.encode()).hexdigest()
    db = sqlite3.connect(home / 'memory.db')
    db.execute('CREATE TABLE memory_records (id TEXT, profile_id TEXT, workspace_id TEXT, archived INTEGER)')
    db.executemany('INSERT INTO memory_records VALUES (?, ?, ?, 0)', [(item, 'personal', 'dakota-codex-only') for item in selected_ids])
    db.commit()
    db.close()
    (home / 'memory.db').chmod(0o600)
    backup = home / 'backups/pre-transfer.db'
    shutil.copyfile(home / 'memory.db', backup)
    backup.chmod(0o600)
    bundle = home / 'exports/one.bundle'
    bundle_manifest = {
        'bundle_id': 'sha256:bundle-fixture',
        'producer': {'instance_id': FIXTURE_INSTANCE},
        'source_scope': {'profile': 'personal', 'workspace': 'dakota-codex-only', 'repo_id': None},
        'intent': {
            'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
            'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
        },
        'selection': {'record_ids': [public_memory_id(item) for item in selected_ids], 'include_archived': True},
        'counts': {'root_memories': len(selected_ids)},
    }
    with zipfile.ZipFile(bundle, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(bundle_manifest))
    bundle.chmod(0o600)
    backup_sha = hashlib.sha256(backup.read_bytes()).hexdigest()
    backup_manifest = {
        'tool_version': '0.1.0', 'schema_version': 13, 'expected_schema_version': 13,
        'sha256': f'sha256:{backup_sha}',
        'size_bytes': backup.stat().st_size,
        'integrity_ok': True,
        'tables': [{'table': 'memory_records', 'rows': len(selected_ids)}],
    }
    (home / 'backups/pre-transfer.db.manifest.json').write_text(json.dumps(backup_manifest))
    (home / 'backups/pre-transfer.db.manifest.json').chmod(0o600)
    metadata = {
        'schema_version': 1,
        'tool_version': '0.1.0',
        'source_profile': 'personal',
        'source_workspace': 'dakota-codex-only',
        'source_instance_id': FIXTURE_INSTANCE,
        'source_snapshot_kind': 'codex-memoryd-backup',
        'source_cutoff_at': '2026-10-29T00:00:00Z',
        'source_database_sha256': backup_sha,
        'source_record_count': len(selected_ids),
        'source_database_record_count': len(selected_ids),
        'source_markdown_file_count': 1,
        'source_markdown_manifest_sha256': source_manifest_hash,
        'source_sync_cursor': {
            'status': 'synced', 'unsynced_count': 0,
            'source_root': str(source_root), 'last_completed_at': '2026-10-29T00:00:00Z',
        },
        'verified_source_backup': {
            'path': 'backups/pre-transfer.db',
            'sha256': f'sha256:{backup_sha}',
            'size_bytes': backup.stat().st_size,
            'verified': True,
        },
        'bundles': [{
            'path': bundle.name,
            'sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(),
            'size_bytes': bundle.stat().st_size,
            'bundle_id': bundle_manifest['bundle_id'],
            'manifest_digest': 'sha256:fixture',
            'source_instance_id': FIXTURE_INSTANCE,
            'source_scope': bundle_manifest['source_scope'],
            'destination_scope': {'profile': 'personal', 'workspace': 'dakota-codex-only', 'repo_id': None},
            'integrity_status': 'verified',
            'signature_status': 'absent',
            'counts': {'discovered': len(selected_ids), 'validated': len(selected_ids), 'rejected': 0, 'conflicts': 0},
            'omissions': {'secret_blocked': 0, 'boundary': 0, 'portability': 0},
        }],
    }
    (home / 'exports/kamal-test-deploy-transfer-manifest.json').write_text(json.dumps(metadata))
    (home / 'exports/kamal-test-deploy-transfer-manifest.json').chmod(0o600)
    return metadata


def test_memoryd_gate_blocks_below_threshold_and_reports_minimum_vm_size():
    result = vm_deploy_host.memoryd_resource_gate(
        meminfo(total_kb=8_131_080, available_kb=1_226_960)
    )

    assert result == {
        "ready": False,
        "reason": "insufficient_available_memory",
        "mem_total_kb": 8_131_080,
        "mem_available_kb": 1_226_960,
        "required_available_kb": 1_572_864,
        "swap_total_kb": 0,
        "minimum_vm_ram_gib": 9,
    }


def test_memoryd_gate_accepts_only_when_available_memory_preserves_reserve():
    result = vm_deploy_host.memoryd_resource_gate(
        meminfo(total_kb=9_437_184, available_kb=1_572_864)
    )

    assert result["ready"] is True
    assert result["reason"] == "ready"
    assert result["minimum_vm_ram_gib"] is None


def test_memoryd_listener_parser_uses_listening_local_addresses_not_queue_depths():
    addresses = vm_deploy_host.memoryd_listener_addresses(
        "tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:*\n"
        "tcp LISTEN 0 5 172.30.86.1:8090 0.0.0.0:*\n"
        "udp UNCONN 0 0 0.0.0.0:8090 0.0.0.0:*\n"
        "tcp LISTEN 0 4096 127.0.0.1:4312 0.0.0.0:*\n"
    )

    assert addresses == {"127.0.0.1:8787", "172.30.86.1:8090"}


def test_memoryd_preflight_is_read_only_and_stops_on_low_available_memory(monkeypatch):
    commands = []
    monkeypatch.setattr(vm_deploy_host, 'status', lambda: {
        'authority': 'kamal', 'healthy': True, 'tunnel_count': 1,
    })
    monkeypatch.setattr(Path, 'read_text', lambda _self: meminfo(
        total_kb=8_131_080, available_kb=1_226_960))

    def run(args, **_kwargs):
        commands.append(args)
        if args[:3] == ['docker', 'ps', '-aq']:
            return b''
        if args[:3] == ['docker', 'volume', 'ls']:
            return b''
        if args[:2] == ['ss', '-Hln']:
            return b''
        raise AssertionError(f'preflight attempted an unapproved operation: {args[1:]}')

    monkeypatch.setattr(vm_deploy_host, 'run', run)
    result = vm_deploy_host.memoryd_preflight()

    assert result['ready'] is False
    assert result['mutated'] is False
    assert result['reason'] == 'insufficient_available_memory'
    assert result['existing_services_healthy'] is True
    assert result['tunnel_count'] == 1
    assert result['target_container_count'] == 0
    assert result['target_volume_exists'] is False
    assert result['target_listeners'] == []
    assert all(args[0] in ('docker', 'ss') for args in commands)


def test_memoryd_status_reports_absent_without_creating_a_volume_or_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    monkeypatch.setattr(vm_deploy_host, 'run', lambda args, **_kwargs: b'')

    result = vm_deploy_host.memoryd_status()

    assert result == {
        'status': 'ABSENT', 'services': {}, 'volume_exists': False, 'app_registered': False,
    }
    assert list(tmp_path.iterdir()) == []


def sample_remote_manifest():
    return {
        'schema_version': 1,
        'include_archived': True,
        'transfer_manifest_sha256': 'a' * 64,
        'source_database_sha256': 'b' * 64,
        'source_record_count': 2,
        'source_database_record_count': 2,
        'source_cutoff_at': '2026-10-29T00:00:00Z',
        'source_instance_id': FIXTURE_INSTANCE,
        'source_profile': 'personal',
        'source_workspace': 'dakota-codex-only',
        'target_profile': 'personal',
        'target_workspace': 'dakota-codex-only',
        'bundles': [{
            'path': 'chunk-01.bundle', 'sha256': hashlib.sha256(b'fixture').hexdigest(),
            'size_bytes': len(b'fixture'), 'bundle_id': 'sha256:fixture',
            'manifest_digest': 'sha256:' + 'c' * 64, 'root_count': 2,
        }],
    }


def test_memoryd_transfer_preflight_requires_live_capacity_and_all_services(monkeypatch):
    monkeypatch.setattr(vm_deploy_host, 'status', lambda: {
        'authority': 'kamal', 'healthy': True, 'tunnel_count': 1,
    })
    monkeypatch.setattr(vm_deploy_host, 'memoryd_resource_gate', lambda _info: {
        'ready': True, 'reason': 'ready', 'mem_available_kb': 2_000_000,
        'required_available_kb': 1_572_864,
    })
    monkeypatch.setattr(vm_deploy_host, 'memoryd_status', lambda: {'status': 'HEALTHY'})
    monkeypatch.setattr(Path, 'read_text', lambda _self: 'MemAvailable: 2000000 kB')

    result = vm_deploy_host.memoryd_transfer_preflight()

    assert result['ready'] is True
    assert result['mutated'] is False
    assert result['tunnel_count'] == 1
    assert result['memoryd_status'] == 'HEALTHY'


def test_memoryd_transfer_prepare_is_private_idempotent_and_hash_checked(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    manifest = sample_remote_manifest()

    prepared = vm_deploy_host.memoryd_transfer_prepare(manifest)
    assert prepared['missing_bundles'] == ['chunk-01.bundle']
    directory = Path(prepared['directory'])
    assert directory.stat().st_mode & 0o777 == 0o700
    (directory / 'chunk-01.bundle').write_bytes(b'fixture')
    (directory / 'chunk-01.bundle').chmod(0o600)

    replay = vm_deploy_host.memoryd_transfer_prepare(manifest)
    assert replay['present_bundles'] == ['chunk-01.bundle']
    assert replay['missing_bundles'] == []

    (directory / 'chunk-01.bundle').write_bytes(b'changed')
    with pytest.raises(ValueError, match='bundle file hash mismatch'):
        vm_deploy_host.memoryd_transfer_prepare(manifest)


def test_memoryd_adapter_stage_is_content_addressed_and_owner_only(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    payload=b'fixed adapter fixture'
    digest=hashlib.sha256(payload).hexdigest()
    request={'adapter_sha256':digest,'size_bytes':len(payload),'controller_sha':'a'*40}
    prepared=vm_deploy_host.memoryd_adapter_prepare(request)
    assert prepared['needs_upload'] is True
    artifact=Path(prepared['path'])
    assert artifact.parent.name==digest
    artifact.write_bytes(payload)
    artifact.chmod(0o644)

    finalized=vm_deploy_host.memoryd_adapter_finalize(request)

    assert finalized=={'staged':True,'adapter_sha256':digest,'size_bytes':len(payload)}
    assert artifact.stat().st_mode&0o777==0o600
    assert vm_deploy_host.memoryd_adapter_prepare(request)['present'] is True
    changed={**request,'adapter_sha256':'b'*64}
    next_version=vm_deploy_host.memoryd_adapter_prepare(changed)
    assert next_version['needs_upload'] is True
    assert next_version['directory']!=prepared['directory']


def test_memoryd_import_applies_preview_plans_backs_up_checks_replay_and_preserves_scope(tmp_path, monkeypatch):
    state=tmp_path
    state.chmod(0o700)
    bootstrap=state/'bootstrap';bootstrap.mkdir(mode=0o700)
    transfer_id='d'*64
    directory=state/'memoryd-transfer'/transfer_id[:16]
    directory.mkdir(mode=0o700,parents=True)
    bundle_bytes=b'fixture bundle bytes'
    bundle_name='fixture-01.bundle'
    bundle_path=directory/bundle_name
    bundle_path.write_bytes(bundle_bytes);bundle_path.chmod(0o600)
    manifest={
        'schema_version':1,'transfer_manifest_sha256':transfer_id,
            'source_database_sha256':'e'*64,'source_record_count':2,
            'source_database_record_count':2,'source_cutoff_at':'2026-10-29T00:00:00Z',
            'include_archived':True,
        'source_instance_id':FIXTURE_INSTANCE,'source_profile':'personal',
        'source_workspace':'dakota-codex-only','target_profile':'personal',
        'target_workspace':'dakota-codex-only','bundles':[{
            'path':bundle_name,'sha256':hashlib.sha256(bundle_bytes).hexdigest(),
            'size_bytes':len(bundle_bytes),'bundle_id':'sha256:bundle-fixture',
            'manifest_digest':'sha256:'+'f'*64,'root_count':2,
        }],
    }
    vm_deploy_host.write(directory/'transfer.json',manifest)
    monkeypatch.setattr(vm_deploy_host,'STATE',state)
    monkeypatch.setattr(vm_deploy_host,'memoryd_transfer_preflight',lambda:{'ready':True})
    counts=iter([0,2,2])
    monkeypatch.setattr(vm_deploy_host,'_memoryd_record_count',lambda:next(counts))
    previews=iter([
        {'create':2,'validated':2,'rejected':0,'conflicts':0,'reuse_identity_exact':0,'reuse_content_exact':0},
        {'create':0,'validated':2,'rejected':0,'conflicts':0,'reuse_identity_exact':2,'reuse_content_exact':0},
    ])
    def cli_json(args,**_kwargs):
        if args[:2]==['backup','create']:
            return {'manifest':{'sha256':'sha256:backup','size_bytes':128}}
        if args[:2]==['backup','verify']:
            return {'ok':True,'manifest':{'sha256':'sha256:backup'}}
        if args[:2]==['bundle','inspect']:
            return {'integrity_status':'verified','bundle_id':'sha256:bundle-fixture',
                    'manifest_digest':'sha256:'+'f'*64,'source_instance_id':FIXTURE_INSTANCE,
                    'source_scope':{'profile':'personal','workspace':'dakota-codex-only'},
                    'destination_scope':{'profile':'personal','workspace':'dakota-codex-only'}}
        if args[:2]==['bundle','import'] and '--preview' in args:
            return {'safe_to_apply':True,'integrity_status':'verified','source_instance_id':FIXTURE_INSTANCE,
                    'source_scope':{'profile':'personal','workspace':'dakota-codex-only'},
                    'destination_scope':{'profile':'personal','workspace':'dakota-codex-only'},
                    'counts':next(previews),'plan_id':'plan_fixture','destination_instance_id':'cmi_target'}
        if args[:2]==['bundle','import'] and '--apply' in args:
            return {'receipt':{'status':'applied','receipt_id':'receipt_fixture'}}
        if args[:1]==['status']:
            return {'data':{'active_profiles':['personal'],'active_workspaces':['dakota-codex-only']}}
        raise AssertionError(f'unexpected MemoryD CLI command: {args[:2]}')
    monkeypatch.setattr(vm_deploy_host,'_memoryd_cli_json',cli_json)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_cli',lambda _args,**_kwargs:json.dumps({
        'facts':[{},{}],'citations':[{},{}],'policy':{'authority':'recall_not_authority'}
    }).encode())
    monkeypatch.setattr(vm_deploy_host,'run',lambda _args,**_kwargs:b'')

    result=vm_deploy_host.memoryd_import_bundles({'transfer_manifest_sha256':transfer_id})

    assert result['status']=='complete'
    assert result['source_record_count']==2
    assert result['idempotency'][0]['creates']==0
    assert result['recall_facts']==2
    assert json.loads(vm_deploy_host.private(bootstrap/'memoryd-transfer.json'))['status']=='complete'


def test_memoryd_transfer_set_checks_database_cursor_bundle_scope_and_integrity(tmp_path):
    home = tmp_path / 'profile'
    source_root = tmp_path / 'codex-memories'
    expected = write_transfer_fixture(home, source_root, ['mem_one', 'mem_two'])

    (source_root / 'fixture.md').write_text('# Newer live source, beyond the frozen cutoff\n')
    transfer = deploy_control_plane.load_memoryd_transfer_set(home)

    assert transfer['manifest']['source_instance_id'] == FIXTURE_INSTANCE
    assert transfer['manifest']['source_record_count'] == 2
    assert len(transfer['bundle_paths']) == 1
    assert len(transfer['remote_manifest']['bundles']) == 1
    assert transfer['remote_manifest']['include_archived'] is True
    assert transfer['manifest_sha256'] == hashlib.sha256(
        (home / 'exports/kamal-test-deploy-transfer-manifest.json').read_bytes()
    ).hexdigest()


def test_memoryd_transfer_set_rejects_a_bundle_selection_that_omits_source_records(tmp_path):
    home = tmp_path / 'profile'
    source_root = tmp_path / 'codex-memories'
    metadata = write_transfer_fixture(home, source_root, ['mem_one', 'mem_two'])
    bundle_path = home / 'exports/one.bundle'
    with zipfile.ZipFile(bundle_path, 'w') as archive:
        archive.writestr('manifest.json', json.dumps({
            'bundle_id': 'sha256:bundle-fixture',
            'producer': {'instance_id': FIXTURE_INSTANCE},
            'source_scope': {'profile': 'personal', 'workspace': 'dakota-codex-only', 'repo_id': None},
            'intent': {
                'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
                'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
            },
                'selection': {'record_ids': [public_memory_id('mem_one')], 'include_archived': True},
                'counts': {'root_memories': 1},
        }))
    metadata['bundles'][0]['sha256'] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    metadata['bundles'][0]['size_bytes'] = bundle_path.stat().st_size
    (home / 'exports/kamal-test-deploy-transfer-manifest.json').write_text(json.dumps(metadata))

    with pytest.raises(ValueError, match='root selection does not exactly cover'):
        deploy_control_plane.load_memoryd_transfer_set(home)


def test_memoryd_deploy_returns_blocked_without_sync_or_kamal_when_capacity_is_low(tmp_path, monkeypatch):
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "status":
            return {"authority": "kamal", "healthy": True, "tunnel_count": 1}
        if action == "snapshot":
            return {"authority": "kamal", "identity": "existing-executor", "inventory": {"executor": {}}, "tunnel_count": 1}
        if action == "memoryd-preflight":
            return {"ready": False, "reason": "insufficient_available_memory", "mem_available_kb": 1_226_960,
                    "target_container_count": 0, "target_volume_exists": False, "target_listeners": []}
        raise AssertionError(f"unexpected mutating or unplanned operation: {action}")

    monkeypatch.setattr(deploy_control_plane, "remote", remote)
    monkeypatch.setattr(deploy_control_plane, "sync_source", lambda _sha: pytest.fail("source sync must not run"))
    monkeypatch.setattr(deploy_control_plane, "kamal", lambda *_args: pytest.fail("Kamal must not run"))

    result = deploy_control_plane.deploy_memoryd("a" * 40, tmp_path)

    assert result["status"] == "BLOCKED"
    assert result["mutated"] is False
    assert result["preflight"]["reason"] == "insufficient_available_memory"
    assert calls == ["status", "snapshot", "memoryd-preflight"]


def test_memoryd_deploy_adds_only_its_accessories_then_reboots_executor_without_touching_tunnel(tmp_path, monkeypatch):
    calls=[]
    inventory={'executor':{'state':'running'},'schema-proxy':{'state':'running'},
               'cas':{'state':'running'},'tunnel':{'state':'running'}}
    snapshot={'authority':'kamal','identity':'executor-identity','inventory':inventory,'tunnel_count':1}
    current={'authority':'kamal','identity':'executor-identity','manifest':{'images':{}}}

    def remote(action,data=None):
        calls.append(('remote',action))
        if action=='status':return {'authority':'kamal','healthy':True,'tunnel_count':1,'inventory':inventory}
        if action=='snapshot':return snapshot
        if action=='memoryd-preflight':return {'ready':True,'mutated':False}
        if action=='memoryd-adapter-prepare':
            return {'directory':f"/srv/control-plane/memoryd-adapter/{data['adapter_sha256']}",
                    'needs_upload':True,'adapter_sha256':data['adapter_sha256']}
        if action=='memoryd-adapter-finalize':return {'staged':True,'adapter_sha256':data['adapter_sha256']}
        if action=='current':return current
        if action=='memoryd-wait':return {'status':'PASS'}
        if action=='memoryd-health':return {'status':'PASS','adapter_sha256':adapter_hash}
        return {'status':'PASS'}

    adapter_hash=hashlib.sha256((Path(deploy_control_plane.ROOT)/'scripts/codex_memoryd_mcp.py').read_bytes()).hexdigest()

    def kamal(_config,action,name):
        calls.append(('kamal',action,name))

    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    monkeypatch.setattr(deploy_control_plane,'profile',lambda:{'network':{'name':'mcp-control-plane'},'state_dir':'/srv/control-plane'})
    monkeypatch.setattr(deploy_control_plane,'configuration',lambda *_args,**_kwargs:tmp_path/'deploy.yml')
    monkeypatch.setattr(deploy_control_plane,'sync_source',lambda _sha:calls.append(('sync',)))
    monkeypatch.setattr(deploy_control_plane,'kamal',kamal)
    monkeypatch.setattr(deploy_control_plane.subprocess,'run',lambda *args,**kwargs:type('Result',(),{'returncode':0})())
    monkeypatch.setattr(deploy_control_plane,'smoke',lambda _native:{'catalog':'PASS','devsy_reads':'PASS','memoryd_discovery':'UNREGISTERED'})

    result=deploy_control_plane.deploy_memoryd('a'*40,tmp_path)

    assert result['status']=='PASS'
    assert [item for item in calls if item[0]=='kamal']==[
        ('kamal','boot','memoryd'),('kamal','boot','memoryd-mcp'),('kamal','reboot','executor')]
    assert ('sync',) not in calls
    assert ('kamal','reboot','tunnel') not in calls
    assert result['executor_app_registered'] is False
    assert result['existing_identity_preserved'] is True
    assert result['existing_inventory_preserved'] is True


def test_memoryd_transfer_imports_before_executor_registration_and_preserves_existing_identity(tmp_path, monkeypatch):
    calls=[]
    manifest_sha='a'*64
    files=[]
    for index in range(1,4):
        path=tmp_path/f'bundle-{index}.bundle'
        path.write_bytes(b'portable bundle')
        path.chmod(0o600)
        files.append(path)
    transfer={
        'manifest':{'source_database_sha256':'b'*64,'source_instance_id':FIXTURE_INSTANCE},
        'manifest_sha256':manifest_sha,
        'remote_manifest':{},
        'bundle_paths':files,
    }
    state_dir='/srv/control-plane'
    remote_dir=f'{state_dir}/memoryd-transfer/{manifest_sha[:16]}'
    before_snapshot={'authority':'kamal','identity':'executor-identity','inventory':{'executor':{}},'tunnel_count':1}

    def remote(action,data=None):
        calls.append(action)
        if action=='status':
            return {'authority':'kamal','healthy':True,'tunnel_count':1}
        if action=='snapshot':
            return before_snapshot
        if action=='memoryd-status':
            return {'status':'HEALTHY'}
        if action=='memoryd-transfer-preflight':
            return {'ready':True,'mem_available_kb':2_000_000}
        if action=='memoryd-transfer-prepare':
            return {'directory':remote_dir,'missing_bundles':[p.name for p in files]}
        if action=='memoryd-import-bundles':
            return {'status':'complete','source_record_count':3}
        if action=='memoryd-app-register':
            return {'registered':True,'tool_count':3}
        if action=='memoryd-health':
            return {'status':'PASS'}
        raise AssertionError(f'unexpected remote action: {action}')

    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    monkeypatch.setattr(deploy_control_plane,'profile',lambda:{'state_dir':state_dir})
    monkeypatch.setattr(deploy_control_plane,'memoryd_transfer_payload',lambda:transfer)
    monkeypatch.setattr(deploy_control_plane,'smoke',lambda _native: {'memoryd_discovery':'PASS'})
    monkeypatch.setattr(deploy_control_plane.subprocess,'run',lambda *args,**kwargs:type('Result',(),{'returncode':0})())

    result=deploy_control_plane.transfer_memoryd(tmp_path)

    assert result['status']=='PASS'
    assert calls.index('memoryd-import-bundles') < calls.index('memoryd-app-register')
    assert result['existing_identity_preserved'] is True
    assert result['tunnel_count']==1
