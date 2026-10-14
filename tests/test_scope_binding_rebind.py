"""One-time owner binding repair never widens the lifecycle capability."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))


def module():
    path=ROOT/'scripts/scope_binding_rebind.py'
    assert path.exists(), 'One-time guarded scope repair is missing'
    spec=importlib.util.spec_from_file_location('scope_rebind_test',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def fixture():
    document=json.loads((ROOT/'docs/devsy-worker-scope.proposed.json').read_text())
    scope={**document,'enabled':True,'expires_at':None,'capability_sha256':hashlib.sha256(b'fixture-owner-capability').hexdigest(),'bindings':{'/fixture/provider':hashlib.sha256(b'old-provider').hexdigest(),'/fixture/kubeconfig':hashlib.sha256(b'unchanged-kubeconfig').hexdigest()}}
    raw=(json.dumps(scope)+'\n').encode()
    approval={'scope_before_sha256':hashlib.sha256(raw).hexdigest(),'provider_before_sha256':scope['bindings']['/fixture/provider'],'provider_after_sha256':hashlib.sha256(b'new-provider').hexdigest()}
    return scope,raw,approval,document


def test_only_provider_binding_changes_and_owner_policy_is_retained():
    m=module();scope,raw,approval,document=fixture()
    updated=m.approved_update(raw,'/fixture/provider',{'/fixture/provider':b'new-provider','/fixture/kubeconfig':b'unchanged-kubeconfig'},approval,document)
    expected=copy.deepcopy(scope);expected['bindings']['/fixture/provider']=approval['provider_after_sha256']
    assert json.loads(updated)==expected


@pytest.mark.parametrize('change',['scope','provider','kubeconfig','revocation','policy','expiry','capability','missing-binding'])
def test_drift_refuses_without_producing_replacement(change):
    m=module();scope,raw,approval,document=fixture()
    bindings={'/fixture/provider':b'new-provider','/fixture/kubeconfig':b'unchanged-kubeconfig'}
    if change=='scope':raw+=b' '
    elif change=='provider':bindings['/fixture/provider']=b'wrong'
    elif change=='kubeconfig':bindings['/fixture/kubeconfig']=b'wrong'
    else:
        if change=='revocation':scope['enabled']=False
        if change=='policy':scope['namespace']='other'
        if change=='expiry':scope['expires_at']=1
        if change=='capability':scope['capability_sha256']='bad'
        if change=='missing-binding':del scope['bindings']['/fixture/provider']
        raw=json.dumps(scope).encode();approval['scope_before_sha256']=hashlib.sha256(raw).hexdigest()
    with pytest.raises(m.RebindError):m.approved_update(raw,'/fixture/provider',bindings,approval,document)


def test_replay_does_not_reauthorize_changed_scope():
    m=module();scope,raw,approval,document=fixture()
    bound={'/fixture/provider':b'new-provider','/fixture/kubeconfig':b'unchanged-kubeconfig'}
    replacement=m.approved_update(raw,'/fixture/provider',bound,approval,document)
    with pytest.raises(m.RebindError):m.approved_update(replacement,'/fixture/provider',bound,approval,document)


@pytest.mark.parametrize('scoped,legacy', [('running','reconciled_scoped'),('outcome_unknown','reconciled_scoped'),('retired','outcome_unknown'),('completed','reconciled_scoped')])
def test_ambiguous_or_live_records_refuse(scoped,legacy):
    m=module()
    with pytest.raises(m.RebindError):m.verify_records([{'status':scoped,'operation':'create','new_request_allowed':True}], [{'status':legacy}])


def test_reconciled_history_is_retained_without_adoption():
    m=module()
    m.verify_records([{'status':'retired','operation':'create','new_request_allowed':True,'retired_receipt':{'status':'completed'}}],[{'status':'reconciled_scoped'}])


def disk_fixture(tmp_path):
    from types import SimpleNamespace
    m=module();scope,raw,a,doc=fixture()
    state=tmp_path/'state';state.mkdir(mode=0o700)
    store=state/'deployment';store.mkdir(mode=0o700)
    bridge=state/'devsy-bridge';bridge.mkdir(mode=0o700)
    jobs=bridge/'scoped-jobs';jobs.mkdir(mode=0o700)
    legacy=bridge/'creation-receipts';legacy.mkdir(mode=0o700)
    owner=state/'owner';owner.mkdir(mode=0o700)
    backup=store/'backup';backup.mkdir(mode=0o700)
    provider=tmp_path/'provider';kube=tmp_path/'kubeconfig'
    def write(path,value):
        path.write_bytes(value);path.chmod(0o600)
    write(provider,b'new-provider');write(kube,b'unchanged-kubeconfig')
    scope['bindings']={str(provider):a['provider_before_sha256'],str(kube):hashlib.sha256(kube.read_bytes()).hexdigest()}
    scope_path=owner/'scope.json';raw=json.dumps(scope).encode();write(scope_path,raw)
    a['scope_before_sha256']=hashlib.sha256(raw).hexdigest()
    write(owner/'capability',b'fixture-owner-capability')
    write(bridge/'config.json',json.dumps({'scope_source':str(scope_path),'gateway':'127.0.0.1'}).encode())
    write(bridge/'process.json',b'{}')
    write(jobs/'admission.lock',b'')
    write(jobs/'cas-worker-01.json',json.dumps({'status':'retired','operation':'create','new_request_allowed':True}).encode())
    write(legacy/'legacy.json',b'{"status":"reconciled_scoped"}')
    write(backup/'devsy_config.bin',b'old-provider')
    write(state/'cas-targets.json',b'protected-mapping')
    a['cas_mapping_sha256']=hashlib.sha256(b'protected-mapping').hexdigest()
    receipt=json.dumps({'source_sha':'a'*40,'backup_dir':str(backup)}).encode()
    write(store/'devsy-host-current.json',receipt)
    a.update(host_apply_receipt_sha256=hashlib.sha256(receipt).hexdigest(),host_apply_source_sha='a'*40,approval_id='test-incident')
    commands=[]
    b=SimpleNamespace(profile={'state_dir':str(state),'repo_dir':str(ROOT),'devsy':{'config_source':str(provider)}},
                      assert_current=lambda:{'status':'current'},process_probe=lambda *x:True,health_probe=lambda *x:True,
                      _command=lambda args:commands.append(args))
    repair=m.ScopeBindingRebind(b,a,doc)
    # Native load/authenticate runs; the live HTTP part is replaced only in synthetic tests.
    def authenticate(value):
        import worker_scope
        manager=worker_scope.WorkerScope(value['scope_path'],jobs,None,None,None)
        manager.authenticate('Bearer '+value['token'])
    repair.authenticate=authenticate
    return m,repair,scope_path,raw,commands


def test_plan_is_read_only_and_apply_updates_only_digest_once(tmp_path):
    m,repair,path,raw,commands=disk_fixture(tmp_path)
    before={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    plan=repair.plan();assert plan['ready'] and not plan['mutated']
    assert before=={str(p):p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    result=repair.apply(approved=True,controller_sha='b'*40)
    assert result['status']=='applied' and result['authenticated_scope_load']=='PASS'
    assert commands==[['sudo','-n','systemctl',op,'codex-control-plane-devsy'] for op in ('stop','start')]
    old=json.loads(raw);new=json.loads(path.read_bytes())
    old['bindings'][repair.bootstrap.profile['devsy']['config_source']]=repair.approval['provider_after_sha256']
    assert old==new
    for name,content in before.items():
        if name!=str(path):assert Path(name).read_bytes()==content
    with pytest.raises(m.RebindError,match='already attempted'):repair.apply(approved=True,controller_sha='b'*40)
    assert len(commands)==2


def test_failed_auth_restores_byte_exact_scope_and_marks_consumed(tmp_path):
    m,repair,path,raw,commands=disk_fixture(tmp_path)
    def refuse(_):raise RuntimeError('synthetic private diagnostic MUST NOT escape')
    repair.authenticate=refuse
    with pytest.raises(m.RebindError,match='prior scope restored') as caught:
        repair.apply(approved=True,controller_sha='b'*40)
    assert 'synthetic' not in str(caught.value)
    assert path.read_bytes()==raw
    assert json.loads((repair.journal/'receipt.json').read_bytes())['status']=='rolled-back'
    assert [row[3] for row in commands]==['stop','start','stop','start']


@pytest.mark.parametrize('change',['receipt','cas','capability','unsafe-input','active-record','locked-admission','approval'])
def test_apply_refuses_before_stop_or_scope_write(tmp_path,change):
    import fcntl
    import os
    m,repair,path,raw,commands=disk_fixture(tmp_path)
    fd=None;approved=True
    if change=='receipt':(repair.store/'devsy-host-current.json').write_bytes(b'{}')
    if change=='cas':(repair.state/'cas-targets.json').write_bytes(b'changed')
    if change=='capability':(path.parent/'capability').write_bytes(b'other-owner')
    if change=='unsafe-input':path.chmod(0o644)
    if change=='active-record':(repair.state/'devsy-bridge/scoped-jobs/cas-worker-01.json').write_bytes(b'{"status":"running"}')
    if change=='approval':approved=False
    if change=='locked-admission':
        fd=os.open(repair.state/'devsy-bridge/scoped-jobs/admission.lock',os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        with pytest.raises((m.RebindError,BlockingIOError)):
            repair.apply(approved=approved,controller_sha='b'*40)
    finally:
        if fd is not None:os.close(fd)
    assert path.read_bytes()==raw and not commands and not repair.journal.exists()


def test_rollback_failure_is_explicit_and_never_hidden(tmp_path):
    m,repair,path,raw,commands=disk_fixture(tmp_path)
    def fail_start(args):
        commands.append(args)
        if args[3]=='start':raise RuntimeError('secret-raw-detail')
    repair.bootstrap._command=fail_start
    with pytest.raises(m.RebindError,match='rollback FAILED') as caught:
        repair.apply(approved=True,controller_sha='b'*40)
    assert 'secret-raw-detail' not in str(caught.value)
    assert path.read_bytes()==raw


def test_workflow_exposes_only_explicit_default_false_incident_approval():
    text=(ROOT/'.github/workflows/deploy-control-plane.yml').read_text()
    assert 'devsy-scope-rebind-check, devsy-scope-rebind' in text
    assert 'approve_scope_binding_rebind:' in text
    assert 'SCOPE_BINDING_APPROVAL: ${{ inputs.approve_scope_binding_rebind }}' in text
    assert 'args+=(--approve-scope-binding-rebind)' in text


@pytest.mark.parametrize('local,approval,thread', [(True,True,True),(False,False,True),(False,True,False)])
def test_controller_refuses_unprotected_or_unapproved_invocations(local,approval,thread):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from unittest.mock import patch
    import deploy_control_plane as d
    args=SimpleNamespace(operation='devsy-scope-rebind',local=local,approve_scope_binding_rebind=approval,
                         native_target='local' if thread else None,native_cwd='/fixture' if thread else None,
                         native_thread_id='12345678-1234-5678-9abc-def012345678' if thread else None)
    with patch.object(d,'INSTANCE',json.loads((ROOT/'config/instance.example.json').read_text())), \
         patch.object(d,'trusted_context'),patch.object(d,'lock',return_value=nullcontext()), \
         patch.object(d,'scope_binding_operation') as apply:
        with pytest.raises(ValueError):d.execute(args)
    apply.assert_not_called()


def test_controller_preserves_source_and_all_accessories_without_sync():
    from unittest.mock import patch
    import deploy_control_plane as d
    before={'authority':'kamal','tunnel_count':1,'identity':'protected','source_sha':'61e26875306bbd7c9e4facd5cccbdc2e7dae0c99'}
    calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=='snapshot':return before
        if action=='current':return {'identity':'protected','source_sha':before['source_sha']}
        if action=='devsy-scope-rebind':return {'operation':action,'status':'applied'}
        return {}
    with patch.object(d,'remote',side_effect=remote),patch.object(d,'smoke') as smoke, \
         patch.object(d,'devsy_payload',return_value={}),patch.object(d,'sync_source') as sync:
        result=d.scope_binding_operation({'target':'local'},'b'*40,apply=True)
    assert result['source_unchanged'] and result['accessories_unchanged']
    assert calls==['snapshot','current','lifecycle-check','profile','devsy-scope-rebind','snapshot','lifecycle-check']
    assert smoke.call_count==2
    assert all(c.kwargs.get('require_native') is True for c in smoke.call_args_list)
    sync.assert_not_called()
