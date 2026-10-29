"""Capacity and non-disruption gates for the additive MemoryD deployment."""
import sys
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import shutil
import stat
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import vm_deploy_host
import deploy_control_plane
import compose_control

FIXTURE_INSTANCE = 'cmi_' + 'a' * 32


def public_memory_id(record_id):
    return 'mr_' + hashlib.sha256(b'mr_\x1f' + record_id.encode()).hexdigest()[:32]


def meminfo(*, total_kb, available_kb):
    return f"MemTotal: {total_kb} kB\nMemAvailable: {available_kb} kB\nSwapTotal: 0 kB\n"


def write_transfer_fixture(home, source_root, selected_ids, archived_ids=()):
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
    db.executemany('INSERT INTO memory_records VALUES (?, ?, ?, 1)', [(item, 'personal', 'dakota-codex-only') for item in archived_ids])
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
        'selection': {'record_ids': [public_memory_id(item) for item in selected_ids], 'include_archived': False},
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
        'tables': [{'table': 'memory_records', 'rows': len(selected_ids) + len(archived_ids)}],
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
        'source_database_record_count': len(selected_ids) + len(archived_ids),
        'include_archived': False,
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
    (home / 'exports/kamal-test-deploy-transfer-manifest-active.json').write_text(json.dumps(metadata))
    (home / 'exports/kamal-test-deploy-transfer-manifest-active.json').chmod(0o600)
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


def test_memoryd_import_step_failure_reports_safe_phase(monkeypatch):
    def fail(args, **_kwargs):
        return vm_deploy_host.subprocess.CompletedProcess(
            args, 1, b'', b'permission denied at /private/source.bundle')

    monkeypatch.setattr(vm_deploy_host.subprocess, 'run', fail)

    with pytest.raises(ValueError, match=r'^MemoryD import step bundle copy failed \(permission_denied\)$') as error:
        vm_deploy_host._memoryd_run_step('bundle copy', ['docker', 'cp', 'private.bundle', 'container:/tmp/private.bundle'])
    assert '/private/source.bundle' not in str(error.value)


def test_memoryd_receipt_write_survives_an_orphaned_old_temp_file(tmp_path):
    tmp_path.chmod(0o700)
    receipt=tmp_path/'memoryd-transfer-fixture.json'
    orphan=receipt.with_suffix('.new')
    orphan.write_text('previous interrupted write');orphan.chmod(0o600)
    vm_deploy_host.write(receipt,{'status':'in_progress'})
    assert json.loads(vm_deploy_host.private(receipt))=={'status':'in_progress'}
    assert orphan.read_text()=='previous interrupted write'


@pytest.mark.parametrize('writer',['vm','registration'])
def test_memoryd_receipt_write_fsyncs_directory_after_replace(tmp_path,monkeypatch,writer):
    tmp_path.chmod(0o700);events=[]
    real_fsync=os.fsync;real_replace=os.replace
    def sync(fd):
        events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
        return real_fsync(fd)
    def replace(source,target):
        events.append('replace');return real_replace(source,target)
    monkeypatch.setattr(os,'fsync',sync);monkeypatch.setattr(os,'replace',replace)
    path=tmp_path/'receipt.json'
    if writer=='vm':vm_deploy_host.write(path,{'status':'pending'})
    else:compose_control.write_private(path,'{"status":"pending"}\n')
    assert events.index('file')<events.index('replace')<events.index('directory')


def test_memoryd_reconciles_only_a_dead_imports_owned_staging_file(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    transfer_id='a'*64
    target='/tmp/memoryd-transfer-'+transfer_id[:12]+'-'+'b'*32+'-01-apply.bundle'
    receipt={'status':'in_progress','staging':{'path':target,'pid':123,'start_ticks':456,
        'boot_id':'12345678-1234-1234-1234-123456789abc'}}
    path=tmp_path/'transfer.json';vm_deploy_host.write(path,receipt)
    calls=[]
    monkeypatch.setattr(vm_deploy_host,'_memoryd_staging_owner_alive',lambda _owner:False,raising=False)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_staging_in_use',lambda _path:False,raising=False)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_run_step',lambda label,args,**kwargs:calls.append((label,args)))
    vm_deploy_host._memoryd_reconcile_staging(receipt,path,transfer_id)
    assert 'staging' not in json.loads(vm_deploy_host.private(path))
    assert calls[0][1][-1]==target


@pytest.mark.parametrize('alive,in_use',[(True,False),(False,True)])
def test_memoryd_never_cleans_staging_owned_by_a_live_import(tmp_path,monkeypatch,alive,in_use):
    tmp_path.chmod(0o700)
    transfer_id='a'*64
    target='/tmp/memoryd-transfer-'+transfer_id[:12]+'-'+'b'*32+'-01-apply.bundle'
    receipt={'staging':{'path':target,'pid':123,'start_ticks':456,
        'boot_id':'12345678-1234-1234-1234-123456789abc'}}
    path=tmp_path/'transfer.json';vm_deploy_host.write(path,receipt)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_staging_owner_alive',lambda _owner:alive,raising=False)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_staging_in_use',lambda _path:in_use,raising=False)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_run_step',lambda *_args,**_kwargs:pytest.fail('live staging must remain'))
    with pytest.raises(ValueError,match='still active'):
        vm_deploy_host._memoryd_reconcile_staging(receipt,path,transfer_id)


def test_memoryd_rejects_an_unowned_staging_path(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    receipt={'staging':{'path':'/data/memory.db','pid':123,'start_ticks':456,
        'boot_id':'12345678-1234-1234-1234-123456789abc'}}
    path=tmp_path/'transfer.json';vm_deploy_host.write(path,receipt)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_run_step',lambda *_args,**_kwargs:pytest.fail('unowned path must remain'))
    with pytest.raises(ValueError,match='staging receipt is invalid'):
        vm_deploy_host._memoryd_reconcile_staging(receipt,path,'a'*64)


def test_memoryd_detects_a_container_process_using_staging(monkeypatch):
    target='/tmp/memoryd-transfer-fixture.bundle'
    monkeypatch.setattr(vm_deploy_host,'run',lambda args,**kwargs:('PID COMMAND\n123 import '+target).encode())
    assert vm_deploy_host._memoryd_staging_in_use(target) is True


def test_memoryd_stages_only_hash_verified_bytes_through_container_stdin(tmp_path, monkeypatch):
    path=tmp_path/'fixture.bundle'
    path.write_bytes(b'portable fixture');path.chmod(0o600)
    expected={'size_bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    calls=[]
    def stage(label,args,**kwargs):
        calls.append((label,args,kwargs['stdin'].read()))
        return b''
    monkeypatch.setattr(vm_deploy_host,'_memoryd_run_step',stage)

    vm_deploy_host._memoryd_stage_bundle(path,'/tmp/fixture.bundle',expected)

    assert calls[0][0]=='bundle copy'
    assert calls[0][1][:4]==['docker','exec','-i','--user']
    assert calls[0][2]==b'portable fixture'
    path.write_bytes(b'tampered fixture')
    with pytest.raises(ValueError,match='hash check'):
        vm_deploy_host._memoryd_stage_bundle(path,'/tmp/fixture.bundle',expected)
    assert len(calls)==1


def test_memoryd_registration_requires_a_completed_matching_transfer(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:pytest.fail('registration must stay gated'))
    with pytest.raises(ValueError,match='completed MemoryD transfer'):
        vm_deploy_host.register_memoryd_app({'transfer_manifest_sha256':'a'*64})


def test_memoryd_firewall_rule_is_limited_to_the_owned_private_bridge():
    network={'name':'mcp-control-plane','subnet':'172.30.86.0/24','gateway':'172.30.86.1'}
    check,allow=vm_deploy_host._memoryd_firewall_commands(network,'br-123456789abc')
    assert check==['sudo','-n','iptables','-C','ufw-user-input','-i','br-123456789abc',
        '-s','172.30.86.0/24','-d','172.30.86.1','-p','tcp','--dport','8090','-j','ACCEPT']
    assert allow==['sudo','-n','ufw','allow','in','on','br-123456789abc','from','172.30.86.0/24',
        'to','172.30.86.1','port','8090','proto','tcp','comment','mcp-control-plane MemoryD private bridge']
    with pytest.raises(ValueError,match='private bridge'):
        vm_deploy_host._memoryd_firewall_commands({**network,'subnet':'0.0.0.0/0'},'br-123456789abc')
    with pytest.raises(ValueError,match='private bridge'):
        vm_deploy_host._memoryd_firewall_commands(network,'eth0;bad')


def test_memoryd_firewall_allow_is_idempotent_and_requires_owned_bridge(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    network={'name':'mcp-control-plane','subnet':'172.30.86.0/24','gateway':'172.30.86.1'}
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'NETWORK',network)
    monkeypatch.setattr(vm_deploy_host,'_require_completed_memoryd_transfer',
        lambda _data:{'transfer_manifest_sha256':'a'*64})
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:{'status':'PASS'})
    monkeypatch.setattr(vm_deploy_host,'network_check',lambda _network:True)
    present={'value':False};calls=[]
    def run(args,**_kwargs):
        calls.append(args)
        if args[:3]==['docker','network','inspect']:
            return json.dumps([{'Id':'123456789abc'+'0'*52,'Options':{}}]).encode()
        if args[:4]==['ip','-j','-4','address']:
            return json.dumps([{'addr_info':[{'local':'172.30.86.1','prefixlen':24}]}]).encode()
        if args[:4]==['sudo','-n','ufw','status']:return b'Status: active\n'
        if args[:4]==['sudo','-n','iptables','-S']:return b''
        if args[:4]==['sudo','-n','ufw','allow']:
            present['value']=True;return b''
        if args[:2]==['docker','exec']:return b''
        raise AssertionError(args)
    def check(args,**_kwargs):
        return vm_deploy_host.subprocess.CompletedProcess(args,0 if present['value'] else 1,b'',b'')
    monkeypatch.setattr(vm_deploy_host,'run',run)
    monkeypatch.setattr(vm_deploy_host.subprocess,'run',check)
    first=vm_deploy_host.memoryd_network_allow({'transfer_manifest_sha256':'a'*64})
    second=vm_deploy_host.memoryd_network_allow({'transfer_manifest_sha256':'a'*64})
    assert first['rule_created'] is True and first['bridge_reachable'] is True
    assert second['rule_created'] is False and second['rule_owned'] is True
    assert sum(args[:4]==['sudo','-n','ufw','allow'] for args in calls)==1


def test_memoryd_identity_transition_preserves_receipts_and_is_idempotent(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    store=tmp_path/'deployment';store.mkdir(mode=0o700)
    current={'authority':'kamal','identity':'old-identity','source_sha':'current'}
    previous={'authority':'kamal','identity':'old-identity','source_sha':'previous'}
    vm_deploy_host.write(store/'current.json',current)
    vm_deploy_host.write(store/'previous.json',previous)
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'STORE',store)
    monkeypatch.setattr(vm_deploy_host,'_require_completed_memoryd_transfer',
        lambda _data:{'transfer_manifest_sha256':'a'*64})
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:{'status':'PASS'})
    monkeypatch.setattr(vm_deploy_host,'_verify_registered_memoryd_app',lambda:{'id':'app_memoryd'})
    monkeypatch.setattr(vm_deploy_host,'identity',
        lambda _name,exclude_memoryd=False:'old-identity' if exclude_memoryd else 'new-identity')

    first=vm_deploy_host.memoryd_reconcile_identity({'transfer_manifest_sha256':'a'*64})
    second=vm_deploy_host.memoryd_reconcile_identity({'transfer_manifest_sha256':'a'*64})

    assert first['identity_updated'] is True and second['identity_updated'] is False
    assert json.loads(vm_deploy_host.private(store/'current.json'))['identity']=='new-identity'
    assert json.loads(vm_deploy_host.private(store/'previous.json'))['identity']=='new-identity'
    assert json.loads(vm_deploy_host.private(store/('pre-memoryd-current-'+'a'*64+'.json')))==current
    assert json.loads(vm_deploy_host.private(store/('pre-memoryd-previous-'+'a'*64+'.json')))==previous


def test_memoryd_base_identity_excludes_only_the_receipted_unique_app():
    apps=[{'id':'existing','slug':'codex','name':'Codex'},
          {'id':'memory','slug':'memoryd','name':'MemoryD'}]
    marker={'id':'memory','organization':'org','url':'http://172.30.86.1:8090/mcp'}
    assert vm_deploy_host._memoryd_base_apps(apps,'org',marker,'172.30.86.1')==apps[:1]
    with pytest.raises(ValueError,match='app identity'):
        vm_deploy_host._memoryd_base_apps(apps,'org',{**marker,'id':'different'},'172.30.86.1')
    with pytest.raises(ValueError,match='app identity'):
        vm_deploy_host._memoryd_base_apps(apps+[apps[1]],'org',marker,'172.30.86.1')


def test_memoryd_identity_transition_refuses_existing_identity_drift(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    store=tmp_path/'deployment';store.mkdir(mode=0o700)
    current={'authority':'kamal','identity':'unexpected'}
    vm_deploy_host.write(store/'current.json',current)
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'STORE',store)
    monkeypatch.setattr(vm_deploy_host,'_require_completed_memoryd_transfer',
        lambda _data:{'transfer_manifest_sha256':'a'*64})
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:{'status':'PASS'})
    monkeypatch.setattr(vm_deploy_host,'_verify_registered_memoryd_app',lambda:{'id':'app_memoryd'})
    monkeypatch.setattr(vm_deploy_host,'identity',
        lambda _name,exclude_memoryd=False:'old-identity' if exclude_memoryd else 'new-identity')
    with pytest.raises(ValueError,match='identity drift'):
        vm_deploy_host.memoryd_reconcile_identity({'transfer_manifest_sha256':'a'*64})
    assert json.loads(vm_deploy_host.private(store/'current.json'))==current


def test_memoryd_identity_transition_resumes_after_one_receipt_was_updated(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    store=tmp_path/'deployment';store.mkdir(mode=0o700)
    transfer_id='a'*64
    original={'authority':'kamal','identity':'old-identity'}
    vm_deploy_host.write(store/'current.json',{**original,'identity':'new-identity'})
    vm_deploy_host.write(store/'previous.json',original)
    for name in ('current','previous'):
        vm_deploy_host.write(store/f'pre-memoryd-{name}-{transfer_id}.json',original)
    vm_deploy_host.write(store/f'memoryd-identity-{transfer_id}.json',{
        'transfer_manifest_sha256':transfer_id,'previous_identity':'old-identity',
        'updated_identity':'new-identity','memoryd_app_id':'app_memoryd',
        'has_previous':True,'status':'pending'})
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'STORE',store)
    monkeypatch.setattr(vm_deploy_host,'_require_completed_memoryd_transfer',
        lambda _data:{'transfer_manifest_sha256':transfer_id})
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:{'status':'PASS'})
    monkeypatch.setattr(vm_deploy_host,'_verify_registered_memoryd_app',lambda:{'id':'app_memoryd'})
    monkeypatch.setattr(vm_deploy_host,'identity',
        lambda _name,exclude_memoryd=False:'old-identity' if exclude_memoryd else 'new-identity')
    result=vm_deploy_host.memoryd_reconcile_identity({'transfer_manifest_sha256':transfer_id})
    assert result['identity_updated'] is True
    assert json.loads(vm_deploy_host.private(store/'previous.json'))['identity']=='new-identity'
    assert json.loads(vm_deploy_host.private(store/f'memoryd-identity-{transfer_id}.json'))['status']=='complete'


def test_memoryd_registration_accepts_only_the_receipted_app_inventory_change(monkeypatch):
    snapshots=iter([{'identity':'before','inventory':{'executor':{}},'tunnel_count':1},
                    {'identity':'after','inventory':{'executor':{}},'tunnel_count':1}])
    def remote(action,_data=None):
        if action=='status':return {'authority':'kamal','healthy':True,'tunnel_count':1}
        if action=='snapshot':return next(snapshots)
        if action=='memoryd-base-identity':return {'identity':'unchanged-existing-apps-and-keys'}
        if action=='memoryd-app-register':return {'registered':True}
        if action=='memoryd-identity-reconcile':return {'prior_identity_preserved':True}
        if action=='current':return {'identity':'after'}
        if action=='memoryd-health':return {'status':'PASS'}
        raise AssertionError(action)
    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    monkeypatch.setattr(deploy_control_plane,'memoryd_transfer_payload',lambda:{'manifest_sha256':'a'*64})
    monkeypatch.setattr(deploy_control_plane,'smoke',lambda _native:{'memoryd_discovery':'PASS'})
    result=deploy_control_plane.finish_memoryd('memoryd-register')
    assert result['status']=='PASS' and result['existing_identity_preserved'] is True


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


def test_memoryd_adapter_image_remains_pinned_when_cas_is_upgraded():
    old='ghcr.io/joshyorko/codex-action-server@sha256:'+'a'*64
    current={'manifest':{'images':{'cas':{'repository':'ghcr.io/joshyorko/codex-action-server',
                                          'digest':'sha256:'+'b'*64}}}}
    receipt={'schema_version':1,'image':old,'adapter_sha256':'c'*64}
    assert vm_deploy_host._memoryd_adapter_image(current,receipt)==old
    assert vm_deploy_host._memoryd_adapter_image(current,None).endswith('b'*64)
    with pytest.raises(ValueError,match='adapter image receipt'):
        vm_deploy_host._memoryd_adapter_image(current,{**receipt,'image':'docker.io/foreign:latest'})


@pytest.mark.parametrize('marker', [
    {}, None, [],
    {'organization': 'org', 'id': '', 'url': 'http://172.30.86.1:8090/mcp'},
    {'organization': 'org', 'id': 'app'},
    {'organization': 'org', 'id': 'app', 'url': 'http://172.30.86.1:8090/mcp', 'extra': True},
])
def test_invalid_memoryd_registration_receipt_refuses_without_executor_access(tmp_path, monkeypatch, marker):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    vm_deploy_host.write(tmp_path/'bootstrap/memoryd-integration.json', marker)
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append('executor access')
        raise AssertionError('Invalid receipt reached Executor')

    monkeypatch.setattr(compose_control, 'executor_session', forbidden)
    monkeypatch.setattr(compose_control, 'ensure_memoryd_app', forbidden)
    monkeypatch.setenv('EXECUTOR_URL', 'fixture')
    monkeypatch.setenv('EXECUTOR_PAT_FILE', 'fixture')
    with pytest.raises(ValueError, match='MemoryD app receipt is invalid'):
        vm_deploy_host._verify_registered_memoryd_app()
    assert calls == []


def test_memoryd_adapter_image_pin_is_private_and_idempotent(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    image='ghcr.io/joshyorko/codex-action-server@sha256:'+'a'*64
    monkeypatch.setattr(vm_deploy_host,'memoryd_health',lambda:{'adapter_image':image,'adapter_sha256':'b'*64})
    first=vm_deploy_host.memoryd_pin_adapter_image()
    second=vm_deploy_host.memoryd_pin_adapter_image()
    receipt=tmp_path/'bootstrap/memoryd-adapter-image.json'
    assert first['created'] is True and second['created'] is False
    assert receipt.stat().st_mode&0o777==0o600
    assert json.loads(vm_deploy_host.private(receipt))['image']==image


def test_core_upgrade_pins_existing_memoryd_before_changing_cas(monkeypatch):
    calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=='memoryd-inventory':return {'status':'UNVERIFIED'}
        if action=='memoryd-adapter-pin-check':return {'pinned':False}
        if action=='memoryd-status':return {'status':'HEALTHY'}
        if action=='memoryd-pin-adapter-image':return {'adapter_image_pinned':True}
        raise AssertionError(action)
    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    deploy_control_plane._pin_memoryd_before_core_change()
    assert calls==['memoryd-inventory','memoryd-adapter-pin-check','memoryd-status','memoryd-pin-adapter-image']


def test_core_rollback_accepts_an_already_pinned_stopped_memoryd(monkeypatch):
    calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=='memoryd-inventory':return {'status':'STOPPED'}
        if action=='memoryd-adapter-pin-check':return {'pinned':True}
        raise AssertionError(action)
    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    deploy_control_plane._pin_memoryd_before_core_change()
    assert calls==['memoryd-inventory','memoryd-adapter-pin-check']


def test_stopped_adapter_pin_check_verifies_its_own_image_and_artifact(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    artifact_bytes=b'fixture adapter';digest=hashlib.sha256(artifact_bytes).hexdigest()
    directory=tmp_path/'memoryd-adapter'/digest;directory.mkdir(mode=0o700,parents=True);directory.parent.chmod(0o700)
    artifact=directory/'codex_memoryd_mcp.py';artifact.write_bytes(artifact_bytes);artifact.chmod(0o600)
    image='ghcr.io/joshyorko/codex-action-server@sha256:'+'a'*64
    vm_deploy_host.write(tmp_path/'bootstrap/memoryd-adapter-image.json',
        {'schema_version':1,'image':image,'adapter_sha256':digest})
    row={'Name':'/mcp-control-plane-memoryd-mcp','Config':{'Image':image,
         'Labels':{'service':'mcp-control-plane-memoryd-mcp'}},'Mounts':[
         {'Destination':'/opt/tunnel-kit/codex_memoryd_mcp.py','Source':str(artifact),'RW':False}]}
    monkeypatch.setattr(vm_deploy_host,'STATE',tmp_path)
    monkeypatch.setattr(vm_deploy_host,'run',lambda args,**kwargs:json.dumps([row]).encode())
    assert vm_deploy_host.memoryd_adapter_pin_check()=={'pinned':True}
    row['Config']['Image']='ghcr.io/joshyorko/codex-action-server@sha256:'+'b'*64
    with pytest.raises(ValueError,match='pinned image'):
        vm_deploy_host.memoryd_adapter_pin_check()


def test_core_upgrade_refuses_unverified_stopped_memoryd(monkeypatch):
    monkeypatch.setattr(deploy_control_plane,'remote',lambda action,data=None:{'status':'STOPPED'})
    with pytest.raises(ValueError,match='Start and verify MemoryD'):
        deploy_control_plane._pin_memoryd_before_core_change()


@pytest.mark.parametrize('name,label', [
    ('/unrelated-container', 'mcp-control-plane-memoryd'),
    ('/mcp-control-plane-memoryd', 'unrelated-service'),
    ('/mcp-control-plane-memoryd-mcp', 'mcp-control-plane-memoryd'),
])
def test_memoryd_inventory_rejects_mismatched_container_name_or_label(tmp_path, monkeypatch, name, label):
    row = {'Name': name, 'Config': {'Labels': {'service': label}},
           'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}

    def run(args, **_kwargs):
        if args == ['docker', 'ps', '-aq']:
            return b'container'
        if args == ['docker', 'inspect', 'container']:
            return json.dumps([row]).encode()
        if args == ['docker', 'volume', 'ls', '--format', '{{.Name}}']:
            return b'codex-memoryd-data'
        raise AssertionError(f'unexpected command: {args}')

    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    monkeypatch.setattr(vm_deploy_host, 'run', run)
    with pytest.raises(ValueError, match='MemoryD accessory identity'):
        vm_deploy_host.memoryd_inventory()


def test_memoryd_inventory_action_is_read_only_when_core_is_unavailable(tmp_path, monkeypatch, capsys):
    rows = [
        {'Name': '/mcp-control-plane-memoryd',
         'Config': {'Labels': {'service': 'mcp-control-plane-memoryd'}},
         'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}},
        {'Name': '/mcp-control-plane-memoryd-mcp',
         'Config': {'Labels': {'service': 'mcp-control-plane-memoryd-mcp'}},
         'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}},
    ]

    def run(args, **_kwargs):
        if args == ['docker', 'ps', '-aq']:
            return b'db bridge'
        if args == ['docker', 'inspect', 'db', 'bridge']:
            return json.dumps(rows).encode()
        if args == ['docker', 'volume', 'ls', '--format', '{{.Name}}']:
            return b'codex-memoryd-data'
        raise AssertionError(f'unexpected command: {args}')

    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    monkeypatch.setattr(vm_deploy_host, 'STORE', tmp_path / 'missing-store')
    monkeypatch.setattr(vm_deploy_host, 'run', run)
    monkeypatch.setattr(vm_deploy_host, 'invocation_profile', lambda: ('memoryd-inventory', {}))
    monkeypatch.setattr(vm_deploy_host, 'configure_profile', lambda _profile: None)
    monkeypatch.setattr(vm_deploy_host.os, 'umask', lambda _mask: None)
    def core_unavailable():
        raise ValueError('core unavailable')
    monkeypatch.setattr(vm_deploy_host, 'memoryd_health', core_unavailable)

    vm_deploy_host.main()

    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'UNVERIFIED'
    assert set(result['services']) == {'mcp-control-plane-memoryd', 'mcp-control-plane-memoryd-mcp'}
    assert result['volume_exists'] is True
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError, match='core unavailable'):
        vm_deploy_host.memoryd_status()


def sample_remote_manifest():
    return {
        'schema_version': 1,
        'include_archived': False,
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


def test_memoryd_transfer_rejects_a_bundle_larger_than_temporary_storage():
    manifest=sample_remote_manifest()
    manifest['bundles'][0]['size_bytes']=24*1024*1024+1
    with pytest.raises(ValueError,match='size or root limit'):
        vm_deploy_host._validate_memoryd_transfer_manifest(manifest)


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
            'include_archived':False,
        'source_instance_id':FIXTURE_INSTANCE,'source_profile':'personal',
        'source_workspace':'dakota-codex-only','target_profile':'personal',
        'target_workspace':'dakota-codex-only','bundles':[{
            'path':bundle_name,'sha256':hashlib.sha256(bundle_bytes).hexdigest(),
            'size_bytes':len(bundle_bytes),'bundle_id':'sha256:bundle-fixture',
            'manifest_digest':'sha256:'+'f'*64,'root_count':2,
        }],
    }
    vm_deploy_host.write(directory/'transfer.json',manifest)
    legacy=bootstrap/'memoryd-transfer.json'
    vm_deploy_host.write(legacy,{'status':'in_progress','transfer_manifest_sha256':'a'*64,
        'source_database_sha256':'e'*64,'bundles':{}})
    legacy_before=legacy.read_bytes()
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
            return {'active_profiles':['personal'],'active_workspaces':['dakota-codex-only']}
        raise AssertionError(f'unexpected MemoryD CLI command: {args[:2]}')
    monkeypatch.setattr(vm_deploy_host,'_memoryd_cli_json',cli_json)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_cli',lambda _args,**_kwargs:json.dumps({
        'facts':[{},{}],'citations':[{},{}],'policy':{'authority':'recall_not_authority'}
    }).encode())
    staged=[];active=set()
    def stage(_source,target,_bundle):
        assert not active
        active.add(target);staged.append(target)
    def step(label,args,**_kwargs):
        if label=='bundle cleanup':
            for target in args[7:]:active.remove(target)
        return b''
    monkeypatch.setattr(vm_deploy_host,'_memoryd_run_step',step)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_stage_bundle',stage)
    monkeypatch.setattr(vm_deploy_host,'_memoryd_tmp_available',lambda:32*1024*1024,raising=False)

    result=vm_deploy_host.memoryd_import_bundles({'transfer_manifest_sha256':transfer_id})

    assert result['status']=='complete'
    assert result['source_record_count']==2
    assert result['idempotency'][0]['creates']==0
    assert result['recall_facts']==2
    assert len(staged)==2 and not active
    assert json.loads(vm_deploy_host.private(bootstrap/f'memoryd-transfer-{transfer_id}.json'))['status']=='complete'
    assert legacy.read_bytes()==legacy_before


def test_memoryd_transfer_set_checks_database_cursor_bundle_scope_and_integrity(tmp_path):
    home = tmp_path / 'profile'
    source_root = tmp_path / 'codex-memories'
    expected = write_transfer_fixture(home, source_root, ['mem_one', 'mem_two'], ['mem_archived'])

    (source_root / 'fixture.md').write_text('# Newer live source, beyond the frozen cutoff\n')
    transfer = deploy_control_plane.load_memoryd_transfer_set(home)

    assert transfer['manifest']['source_instance_id'] == FIXTURE_INSTANCE
    assert transfer['manifest']['source_record_count'] == 2
    assert len(transfer['bundle_paths']) == 1
    assert len(transfer['remote_manifest']['bundles']) == 1
    assert transfer['remote_manifest']['source_database_record_count'] == 3
    assert transfer['remote_manifest']['include_archived'] is False
    assert transfer['manifest_sha256'] == hashlib.sha256(
        (home / 'exports/kamal-test-deploy-transfer-manifest-active.json').read_bytes()
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
                'selection': {'record_ids': [public_memory_id('mem_one')], 'include_archived': False},
                'counts': {'root_memories': 1},
        }))
    metadata['bundles'][0]['sha256'] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    metadata['bundles'][0]['size_bytes'] = bundle_path.stat().st_size
    (home / 'exports/kamal-test-deploy-transfer-manifest-active.json').write_text(json.dumps(metadata))

    with pytest.raises(ValueError, match='root selection does not exactly cover'):
        deploy_control_plane.load_memoryd_transfer_set(home)


def test_memoryd_transfer_set_rejects_substitution_of_an_archived_root(tmp_path):
    home=tmp_path/'profile'
    metadata=write_transfer_fixture(home,tmp_path/'codex-memories',['active'],['archived'])
    bundle=home/'exports/one.bundle'
    with zipfile.ZipFile(bundle) as archive:
        manifest=json.loads(archive.read('manifest.json'))
    manifest['selection']['record_ids']=[public_memory_id('archived')]
    with zipfile.ZipFile(bundle,'w') as archive:
        archive.writestr('manifest.json',json.dumps(manifest))
    metadata['bundles'][0]['sha256']=hashlib.sha256(bundle.read_bytes()).hexdigest()
    metadata['bundles'][0]['size_bytes']=bundle.stat().st_size
    (home/'exports/kamal-test-deploy-transfer-manifest-active.json').write_text(json.dumps(metadata))
    with pytest.raises(ValueError,match='root selection does not exactly cover'):
        deploy_control_plane.load_memoryd_transfer_set(home)


def test_frozen_bundle_comparison_rejects_changed_content_with_same_record_ids():
    original={'selection':{'record_ids':['mr_same'],'include_archived':False},
              'descriptors':[{'path':'objects/memory.jsonl','digest':'sha256:old'}],
              'producer':{'instance_id':FIXTURE_INSTANCE},'intent':{'source_profile':'personal'},
              'counts':{'root_memories':1},'policy':{'boundary_decision':'allow'},
              'required_features':[],'format_version':1,'media_type':'fixture'}
    changed={**original,'descriptors':[{'path':'objects/memory.jsonl','digest':'sha256:new'}]}
    with pytest.raises(ValueError,match='frozen backup'):
        deploy_control_plane._verify_frozen_manifest(original,changed)


def test_frozen_proof_accepts_an_explicit_verified_release_binary(tmp_path,monkeypatch):
    binary=tmp_path/'released-codex-memoryd'
    binary.write_bytes(b'published release fixture')
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setenv('CODEX_MEMORYD_RELEASE_BIN',str(binary))
    monkeypatch.setattr(deploy_control_plane,'MEMORYD_RELEASE_BINARY_SHA256',{digest},raising=False)
    monkeypatch.setattr(deploy_control_plane.subprocess,'run',
        lambda args,**kwargs:deploy_control_plane.subprocess.CompletedProcess(args,0,'codex-memoryd 0.1.0\n',''))
    assert deploy_control_plane._memoryd_release_binary()==binary
    binary.write_bytes(b'tampered release fixture')
    with pytest.raises(ValueError,match='codex-memoryd v0.1.0'):
        deploy_control_plane._memoryd_release_binary()


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
        if action=='memoryd-pin-adapter-image':return {'adapter_image_pinned':True}
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


def test_memoryd_deploy_reuses_healthy_registered_accessories_without_restarts(tmp_path,monkeypatch):
    calls=[]
    inventory={'executor':{'state':'running'},'schema-proxy':{'state':'running'},
               'cas':{'state':'running'},'tunnel':{'state':'running'}}
    snapshot={'authority':'kamal','identity':'existing','inventory':inventory,'tunnel_count':1}
    adapter_hash=hashlib.sha256((Path(deploy_control_plane.ROOT)/'scripts/codex_memoryd_mcp.py').read_bytes()).hexdigest()
    def remote(action,data=None):
        calls.append(action)
        if action=='status':return {'authority':'kamal','healthy':True,'tunnel_count':1}
        if action=='snapshot':return snapshot
        if action=='memoryd-preflight':return {'ready':False,'blockers':[
            'memoryd_container_state_already_exists','memoryd_volume_already_exists',
            'memoryd_listener_port_already_in_use'],'existing_services_healthy':True,'tunnel_count':1,
            'target_container_count':2,'target_volume_exists':True,
            'target_listeners':['127.0.0.1:8787','172.30.86.1:8090']}
        if action=='memoryd-status':return {'status':'HEALTHY','app_registered':True,'adapter_sha256':adapter_hash}
        if action=='current':return {'authority':'kamal','identity':'existing','manifest':{'images':{}}}
        if action=='memoryd-registration-check':return {'registration_verified':True}
        if action=='memoryd-executor-origin-check':return {'memoryd_origin_allowed':True}
        if action=='memoryd-health':return {'status':'PASS','adapter_sha256':adapter_hash}
        if action=='memoryd-pin-adapter-image':return {'adapter_image_pinned':True}
        if action in ('profile','network-check'):return {'status':'PASS'}
        raise AssertionError(action)
    monkeypatch.setattr(deploy_control_plane,'INSTANCE',{'vm':{'network':{'gateway':'172.30.86.1'}}})
    monkeypatch.setattr(deploy_control_plane,'remote',remote)
    monkeypatch.setattr(deploy_control_plane,'profile',lambda:{'network':{'gateway':'172.30.86.1'}})
    monkeypatch.setattr(deploy_control_plane,'configuration',lambda *_args,**_kwargs:tmp_path/'deploy.yml')
    monkeypatch.setattr(deploy_control_plane,'kamal',lambda *_args:pytest.fail('existing accessories must not restart'))
    monkeypatch.setattr(deploy_control_plane,'smoke',lambda _native:{'catalog':'PASS','devsy_reads':'PASS','memoryd_discovery':'PASS'})
    result=deploy_control_plane.deploy_memoryd('a'*40,tmp_path)
    assert result['status']=='PASS' and result['executor_app_registered'] is True
    assert result['memoryd_already_running'] is True
    assert 'memoryd-registration-check' in calls


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
        if action=='memoryd-base-identity':
            return {'identity':'executor-identity'}
        if action=='current':
            return {'identity':'executor-identity'}
        if action=='memoryd-status':
            return {'status':'HEALTHY'}
        if action=='memoryd-transfer-preflight':
            return {'ready':True,'mem_available_kb':2_000_000}
        if action=='memoryd-transfer-prepare':
            return {'directory':remote_dir,'missing_bundles':[p.name for p in files]}
        if action=='memoryd-import-bundles':
            return {'status':'complete','source_record_count':3}
        if action=='memoryd-network-allow':
            return {'status':'PASS','bridge_reachable':True}
        if action=='memoryd-app-register':
            return {'registered':True,'tool_count':3}
        if action=='memoryd-identity-reconcile':
            return {'prior_identity_preserved':True}
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
    assert calls.index('memoryd-import-bundles') < calls.index('memoryd-network-allow') < calls.index('memoryd-app-register')
    assert result['existing_identity_preserved'] is True
    assert result['tunnel_count']==1
