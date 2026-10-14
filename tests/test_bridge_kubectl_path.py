"""Bridge-only PATH repair cannot mutate scope or deploy control-plane services."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))

def module():
    path=ROOT/'scripts/bridge_kubectl_path.py'
    assert path.exists(), 'Guarded bridge-only kubectl environment repair is missing'
    spec=importlib.util.spec_from_file_location('bridge_path_test',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def test_path_only_prepends_the_verified_private_directory():
    m=module();old='/usr/bin:/bin';approval={'bridge_path_before_sha256':hashlib.sha256(old.encode()).hexdigest()}
    result=m.path_value(old,Path('/private/state/bin/kubectl'),approval)
    assert result=='/private/state/bin:'+old
    assert m.dropin_bytes(result)==b'[Service]\nEnvironment="PATH=/private/state/bin:/usr/bin:/bin"\n'

@pytest.mark.parametrize('path',['/different','/usr/bin::/bin','relative:/bin','/usr/bin\nother','/usr/%u','/usr/"quote','/usr/\\escape'])
def test_changed_or_unsafe_path_refuses(path):
    m=module();approval={'bridge_path_before_sha256':hashlib.sha256((path if path!='/different' else '/usr/bin:/bin').encode()).hexdigest()}
    with pytest.raises(m.PathRepairError):m.path_value(path,Path('/private/bin/kubectl'),approval)


def disk_fixture(tmp_path,monkeypatch):
    import json,shutil
    from types import SimpleNamespace
    m=module();state=tmp_path/'state';state.mkdir(mode=0o700)
    store=state/'deployment';store.mkdir(mode=0o700)
    bridge=state/'devsy-bridge';bridge.mkdir(mode=0o700)
    jobs=bridge/'scoped-jobs';jobs.mkdir(mode=0o700)
    legacy=bridge/'creation-receipts';legacy.mkdir(mode=0o700)
    rebind=store/'issue27-scope-binding-rebind';rebind.mkdir(mode=0o700)
    binary=state/'bin/kubectl';binary.parent.mkdir(mode=0o700);binary.write_bytes(b'fixture-binary');binary.chmod(0o755)
    dropin=tmp_path/'etc/unit.d/30-pinned-kubectl-path.conf'
    monkeypatch.setattr(m,'DROPIN',dropin)
    monkeypatch.setattr(m,'root_dropin_matches',lambda content:dropin.read_bytes()==content)
    def write(p,v):p.write_bytes(v);p.chmod(0o600)
    scope=state/'scope.json';write(scope,b'{"owner":"unchanged"}')
    write(jobs/'cas-worker-01.json',b'{"status":"retired","new_request_allowed":false}')
    write(jobs/'admission.lock',b'')
    write(store/'devsy-host-current.json',b'host-receipt')
    write(rebind/'receipt.json',b'scope-receipt')
    unit=tmp_path/'unit.service';unit.write_bytes(b'unchanged-managed-unit')
    env={'PATH':'/usr/bin:/bin'};commands=[]
    def command(args,**_):
        commands.append(args)
        if args[0]=='systemctl':return SimpleNamespace(stdout='')
        assert args[:2]==['sudo','-n']
        a=args[2:]
        if a[:2]==['install','-d']:dropin.parent.mkdir(parents=True)
        elif a[0]=='install':shutil.copyfile(a[-2],a[-1])
        elif a[0]=='rm':dropin.unlink()
        elif a[0]=='rmdir':dropin.parent.rmdir()
        elif a==['systemctl','start',m.UNIT]:
            env['PATH']=dropin.read_text().split('PATH=',1)[1].split('"',1)[0] if dropin.exists() else '/usr/bin:/bin'
        return SimpleNamespace(stdout='')
    b=SimpleNamespace(profile={'state_dir':str(state),'repo_dir':str(ROOT)},unit_path=unit,
                      assert_current=lambda:None,_command=command,
                      _kubectl_state=lambda:{'status':'verified','sha256':m.digest(binary.read_bytes()),'path':binary})
    a={'approval_id':'fixture','bridge_path_before_sha256':m.digest(env['PATH'].encode()),
       'scope_sha256':m.digest(scope.read_bytes()),'unit_sha256':m.digest(unit.read_bytes()),
       'host_apply_receipt_sha256':m.digest(b'host-receipt'),'scope_rebind_receipt_sha256':m.digest(b'scope-receipt'),
       'kubectl_sha256':m.digest(binary.read_bytes())}
    repair=m.BridgeKubectlPath(b,a,control_plane_probe=lambda:{'identity':'unchanged'})
    a['records_sha256']=repair.records()
    repair.runtime=lambda:({'scope_source':str(scope)},dict(env),{})
    repair.absence=lambda *_:None
    return m,repair,scope,env,commands,dropin


def test_plan_is_read_only_and_apply_changes_only_fixed_dropin(tmp_path,monkeypatch):
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch)
    before={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert r.plan()['native_prospective_absence']=='PASS'
    assert before=={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    result=r.apply(approved=True,controller_sha='a'*40)
    assert result['native_actual_environment_absence']=='PASS'
    assert env['PATH'].startswith(str(r.b._kubectl_state()['path'].parent)+':')
    assert all(p.read_bytes()==v for p,v in before.items())
    assert [a[3:] for a in commands if a[:3]==['sudo','-n','systemctl'] and a[3]!='daemon-reload']==[['stop',m.UNIT],['start',m.UNIT]]
    with pytest.raises(m.PathRepairError,match='already attempted'):r.apply(approved=True,controller_sha='a'*40)


def test_actual_environment_failure_restores_previous_environment(tmp_path,monkeypatch):
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch)
    old=scope.read_bytes();calls=[]
    def proof(*_):
        calls.append(1)
        if len(calls)>1:raise RuntimeError('PRIVATE failure never emitted')
    r.absence=proof
    with pytest.raises(m.PathRepairError,match='prior environment restored') as caught:r.apply(approved=True,controller_sha='a'*40)
    assert 'PRIVATE' not in str(caught.value)
    assert not dropin.exists() and not dropin.parent.exists()
    assert env['PATH']=='/usr/bin:/bin' and scope.read_bytes()==old


@pytest.mark.parametrize('change',['records','scope','unit','receipt','checksum','dropin','path','approval'])
def test_wrong_baseline_refuses_before_restart_or_install(tmp_path,monkeypatch,change):
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch);approved=True
    if change=='records':
        extra=r.state/'devsy-bridge/scoped-jobs/unknown.json';extra.write_bytes(b'{}');extra.chmod(0o600)
    if change=='scope':scope.write_bytes(b'other')
    if change=='unit':r.b.unit_path.write_bytes(b'other')
    if change=='receipt':(r.store/'devsy-host-current.json').write_bytes(b'other')
    if change=='checksum':r.approval['kubectl_sha256']='0'*64
    if change=='dropin':dropin.parent.mkdir(parents=True)
    if change=='path':env['PATH']='/other'
    if change=='approval':approved=False
    with pytest.raises(m.PathRepairError):r.apply(approved=approved,controller_sha='a'*40)
    assert not r.journal.exists() and not any(c[:2]==['sudo','-n'] for c in commands)


def test_live_absence_failure_blocks_restart_and_persistence(tmp_path,monkeypatch):
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch)
    def refuse(*_):raise m.PathRepairError('Absence refused')
    r.absence=refuse
    with pytest.raises(m.PathRepairError,match='Absence refused'):r.apply(approved=True,controller_sha='a'*40)
    assert not r.journal.exists() and not dropin.exists()
    assert not any(c[:2]==['sudo','-n'] for c in commands)


def test_workflow_has_separate_default_false_bridge_only_approval():
    s=(ROOT/'.github/workflows/deploy-control-plane.yml').read_text()
    assert 'devsy-bridge-path-check, devsy-bridge-path-apply' in s
    assert 'BRIDGE_KUBECTL_PATH_APPROVAL: ${{ inputs.approve_bridge_kubectl_path }}' in s
    assert 'args+=(--approve-bridge-kubectl-path)' in s


def test_admission_lock_blocks_mutation(tmp_path,monkeypatch):
    import fcntl,os
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch)
    fd=os.open(r.state/'devsy-bridge/scoped-jobs/admission.lock',os.O_RDWR)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):r.apply(approved=True,controller_sha='a'*40)
    finally:os.close(fd)
    assert not r.journal.exists() and not commands


def test_failed_restart_reports_failed_rollback_without_private_detail(tmp_path,monkeypatch):
    m,r,scope,env,commands,dropin=disk_fixture(tmp_path,monkeypatch)
    actual=r.b._command
    def fail(args,**kwargs):
        if args==['sudo','-n','systemctl','start',m.UNIT]:raise RuntimeError('PRIVATE-details')
        return actual(args,**kwargs)
    r.b._command=fail
    with pytest.raises(m.PathRepairError,match='rollback FAILED') as caught:r.apply(approved=True,controller_sha='a'*40)
    assert 'PRIVATE' not in str(caught.value)
    assert not dropin.exists() and scope.read_bytes()==b'{"owner":"unchanged"}'


@pytest.mark.parametrize('local,approval,native',[(True,True,True),(False,False,True),(False,True,False)])
def test_controller_requires_pi_approval_and_idle_native_tuple(local,approval,native):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from unittest.mock import patch
    import deploy_control_plane as d,json
    args=SimpleNamespace(operation='devsy-bridge-path-apply',local=local,approve_bridge_kubectl_path=approval,
        native_target='local' if native else None,native_cwd='/fixture' if native else None,
        native_thread_id='12345678-1234-5678-9abc-def012345678' if native else None)
    with patch.object(d,'INSTANCE',json.loads((ROOT/'config/instance.example.json').read_text())), \
         patch.object(d,'trusted_context'),patch.object(d,'lock',return_value=nullcontext()), \
         patch.object(d,'scope_binding_operation') as execute:
        with pytest.raises(ValueError):d.execute(args)
    execute.assert_not_called()
