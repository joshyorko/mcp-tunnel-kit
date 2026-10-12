import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deploy_control_plane as d
import vm_deploy_host as h


def test_wrong_source_or_runner_context_is_refused_before_ssh():
    good={'GITHUB_REPOSITORY':'joshyorko/mcp-tunnel-kit','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','RUNNER_NAME':'pi5-01-mcp-control-plane'}
    with patch.object(d.socket,'gethostname',return_value='pi5-01'),patch.object(d.os,'uname',return_value=type('U',(),{'machine':'aarch64'})()):
        for key in good:
            with pytest.raises(ValueError,match='Untrusted'):
                d.trusted_context({**good,key:'untrusted'})


def test_bad_cas_digest_revision_and_repository_are_rejected():
    m=json.loads((ROOT/'config/deploy-images.json').read_text())
    for digest,revision in [('latest','a'*40),('sha256:'+'a'*64,''),('sha256:'+'a'*64,'wrong')]:
        with pytest.raises(ValueError):d.choose_manifest(m,digest,revision)
    m['images']['cas']['repository']='evil.example/image'
    with pytest.raises(ValueError):d.choose_manifest(m,'','')


def test_cas_only_selection_does_not_change_other_images():
    m=json.loads((ROOT/'config/deploy-images.json').read_text())
    result=d.choose_manifest(m,'sha256:'+'a'*64,'a'*40)
    assert result['images']['cas']['digest']!=m['images']['cas']['digest']
    assert all(result['images'][k]==m['images'][k] for k in ('executor','schema_proxy','tunnel'))


def test_kamal_cannot_invoke_unrelated_apps_or_registry(tmp_path):
    for operation,name in [('deploy','cas'),('reboot','fizzy'),('registry','executor')]:
        with pytest.raises(ValueError):d.kamal(tmp_path/'config','invalid' if operation=='registry' else operation,name)


def test_private_generation_files_refuse_open_modes_and_symlinks(tmp_path):
    p=tmp_path/'state';p.write_text('{}');p.chmod(0o644)
    with pytest.raises(ValueError):h.private(p)
    p.chmod(0o600);q=tmp_path/'link';q.symlink_to(p)
    with pytest.raises(ValueError):h.private(q)


def test_duplicate_executor_writer_blocks_before_identity_queries():
    def row(name):
        return {'Name':name,'State':{'Running':True},'Config':{'Image':'executor'},'Mounts':[{'Name':'codex-control-plane_executor-data'}]}
    rows=[row('/codex-control-plane-executor-1'),row('/other-writer')]
    with patch.object(h,'run',side_effect=[b'a b',json.dumps(rows).encode()]),patch.object(h,'private') as private:
        with pytest.raises(ValueError,match='Duplicate Executor'):h.inspect()
        private.assert_not_called()


def test_duplicate_tunnel_registration_blocks():
    rows=[{'Name':name,'Id':str(i),'State':{'Running':True},'Config':{'Image':'ghcr.io/openai/tunnel-client'},'Mounts':[]} for i,name in enumerate(['/codex-control-plane-tunnel-client-1','/other-tunnel'])]
    with patch.object(h,'run',side_effect=[b'a b',json.dumps(rows).encode(),b'CONTROL_PLANE_TUNNEL_ID=private\0',b'CONTROL_PLANE_TUNNEL_ID=private\0']),patch.object(h,'private',return_value=b'private'):
        with pytest.raises(ValueError,match='Duplicate production tunnel'):h.inspect()


def test_failed_kamal_health_rolls_back_before_accepting():
    before={'authority':'kamal','identity':'identity','source_sha':'a'*40,'inventory':{key:{'image':'image'} for key in ('executor','schema-proxy','cas','tunnel')}}
    current={**before,'manifest':json.loads((ROOT/'config/deploy-images.json').read_text())}
    calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=='snapshot':return before
        if action=='current':return current
        if action=='image-check':return {'image_ids':{key:'image' for key in ('cas','executor','schema_proxy','tunnel')}}
        if action=='wait':raise RuntimeError('health failure')
        return {}
    from contextlib import nullcontext
    args=type('A',(),{'local':False,'operation':'cas','cas_digest':'','cas_revision':'','approve_full_stack':False})()
    with patch.object(d,'prove_images',return_value={}),patch.object(d,'trusted_context'),patch.object(d,'lock',return_value=nullcontext()),patch.object(d,'remote',side_effect=remote),patch.object(d,'kamal'),patch.object(d,'sync_source'),patch.object(d,'restore_cas') as restore,patch.dict(os.environ,{'GITHUB_SHA':'b'*40}):
        with pytest.raises(RuntimeError,match='previous generation restored'):d.execute(args)
        restore.assert_called_once()
        assert 'commit' not in calls


def test_missing_production_secret_is_a_blocker(tmp_path):
    with pytest.raises(FileNotFoundError):h.private(tmp_path/'missing-secret')


def test_kamal_ledger_disables_old_compose_autostart(tmp_path):
    spec=importlib.util.spec_from_file_location('compose_guard',ROOT/'scripts/compose_control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    folder=tmp_path/'deployment';folder.mkdir();r=folder/'current.json';r.write_text('{"authority":"kamal"}');r.chmod(0o600)
    config={'x-operator':{'devsy_state':str(tmp_path/'devsy-bridge')}}
    with patch.object(c,'config',return_value=config),patch.object(c,'command') as command:
        with pytest.raises(c.ControlError,match='Kamal owns'):c.guard_kamal_owner('up')
        command.assert_not_called()


def test_existing_kamal_containers_refuse_compose_before_pull(tmp_path):
    spec=importlib.util.spec_from_file_location('compose_guard',ROOT/'scripts/compose_control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    with patch.object(c,'config',return_value={'x-operator':{'devsy_state':str(tmp_path/'devsy-bridge')}}),patch.object(c,'command',return_value='container'):
        with pytest.raises(c.ControlError,match='competing'):c.guard_kamal_owner('up')


def test_wrong_ssh_fingerprint_is_refused_for_both_ssh_clients(tmp_path):
    import base64
    key=tmp_path/'identity';known=tmp_path/'known_hosts';config=tmp_path/'ssh_config'
    known.write_text('kamal-test-deploy,10.10.10.106 ssh-ed25519 '+base64.b64encode(b'wrong-key').decode()+'\n')
    config.write_text(f'''Host kamal-test-deploy
HostName 10.10.10.106
User kdlocpanda
IdentityFile {key}
IdentitiesOnly yes
BatchMode yes
ForwardAgent no
StrictHostKeyChecking yes
UserKnownHostsFile {known}
GlobalKnownHostsFile /dev/null
PreferredAuthentications publickey
''')
    with pytest.raises(ValueError,match='fingerprint mismatch'):d.validate_ssh_config(config,key,known)
    config.write_text(config.read_text().replace('StrictHostKeyChecking yes','StrictHostKeyChecking no'))
    with pytest.raises(ValueError,match='not strictly pinned'):d.validate_ssh_config(config,key,known)
