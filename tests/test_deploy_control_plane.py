import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deploy_control_plane as d
import vm_deploy_host as h


def cas_promotion_fixture():
    from test_cas_promotion import receipt, proof, locator, run_proof
    current=json.loads((ROOT/'config/deploy-images.json').read_text())
    handoff=receipt()
    promoted,publisher_proof=d.cas_promotion.promote_manifest(
        current,handoff,verifier=lambda manifest,**_kwargs:proof(manifest),
        run_verifier=run_proof,candidate_verifier=lambda *_args:None)
    evidence=d.cas_promotion.build_evidence(current,promoted,handoff,publisher_proof,locator())
    return current,promoted,evidence


def test_wrong_source_or_runner_context_is_refused_before_ssh():
    good={'GITHUB_REPOSITORY':'joshyorko/mcp-tunnel-kit','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','RUNNER_NAME':'pi5-01-mcp-control-plane'}
    with patch.object(d.socket,'gethostname',return_value='pi5-01'),patch.object(d.os,'uname',return_value=type('U',(),{'machine':'aarch64'})()):
        for key in good:
            with pytest.raises(ValueError,match='Untrusted'):
                d.trusted_context({**good,key:'untrusted'})


def test_execute_requires_private_profile_before_runner_checks_or_transport(tmp_path):
    args=type('A',(),{'local':False,'operation':'preflight','approve_full_stack':False})()
    missing=tmp_path/'missing-instance.json'
    with patch.object(d,'INSTANCE',None),patch.dict(os.environ,{'KAMAL_INSTANCE_PROFILE':str(missing)}), \
         patch.object(d,'trusted_context') as trusted,patch.object(d,'remote') as remote:
        with pytest.raises(ValueError,match='Private instance profile is missing'):
            d.execute(args)
    trusted.assert_not_called()
    remote.assert_not_called()


def test_private_profile_drives_rendered_and_remote_paths(tmp_path):
    instance=json.loads((ROOT/'config/instance.example.json').read_text())
    d.configure_instance(instance)
    value=d.profile()
    assert value['host']==instance['deploy_host']['alias']
    assert value['repo_dir']==instance['vm']['repo_dir']
    assert value['state_dir']==instance['vm']['state_dir']
    assert value['network']==instance['vm']['network']
    assert value['cas_identity_source']==str(Path(instance['vm']['native_ssh_dir'])/'identity')


def test_native_codex_read_requires_an_explicit_verified_tuple():
    tuple_value = {
        "target": "local",
        "cwd": "/home/operator/worktree/mcp-tunnel-kit",
        "thread_id": "12345678-1234-5678-9abc-def012345678",
    }
    assert d.native_codex_tuple(SimpleNamespace(
        native_target=tuple_value["target"], native_cwd=tuple_value["cwd"],
        native_thread_id=tuple_value["thread_id"])) == tuple_value
    named = {**tuple_value, "target": "dakota-nvidia"}
    assert d.native_codex_tuple(SimpleNamespace(
        native_target=named["target"], native_cwd=named["cwd"],
        native_thread_id=named["thread_id"])) == named
    assert d.native_codex_tuple(SimpleNamespace(
        native_target=None, native_cwd=None, native_thread_id=None)) is None
    partial = SimpleNamespace(native_target="local", native_cwd=None, native_thread_id=None)
    assert d.native_codex_tuple(partial, require_valid=False) == {
        "target": "local", "cwd": None, "thread_id": None,
    }
    for values in (
        {"native_target": "bad target", "native_cwd": tuple_value["cwd"],
         "native_thread_id": tuple_value["thread_id"]},
        {"native_target": "local", "native_cwd": "relative/worktree",
         "native_thread_id": tuple_value["thread_id"]},
        {"native_target": "local", "native_cwd": tuple_value["cwd"],
         "native_thread_id": "obsolete-global-id"},
        {"native_target": "local", "native_cwd": tuple_value["cwd"] + "/../other",
         "native_thread_id": tuple_value["thread_id"]},
    ):
        with pytest.raises(ValueError, match="native Codex tuple"):
            d.native_codex_tuple(SimpleNamespace(**values))


def test_protected_workflow_accepts_operator_native_tuple_without_echoing_it():
    workflow = (ROOT / ".github/workflows/deploy-control-plane.yml").read_text()
    assert "native_target:" in workflow
    assert "native_cwd:" in workflow
    assert "native_thread_id:" in workflow
    assert "NATIVE_TARGET: ${{ inputs.native_target }}" in workflow
    assert "NATIVE_CWD: ${{ inputs.native_cwd }}" in workflow
    assert "NATIVE_THREAD_ID: ${{ inputs.native_thread_id }}" in workflow
    assert 'printf \'Native target' not in workflow
    assert 'printf \'Native CWD' not in workflow


def test_protected_workflow_has_separate_host_devsy_plan_and_approved_apply():
    workflow = (ROOT / ".github/workflows/deploy-control-plane.yml").read_text()
    assert "devsy-check" in workflow
    assert "devsy-apply" in workflow
    assert "devsy-rollback" in workflow
    assert "approve_host_devsy_apply:" in workflow
    assert "approve_host_devsy_rollback:" in workflow
    assert "HOST_DEVSY_APPLY_APPROVAL: ${{ inputs.approve_host_devsy_apply }}" in workflow
    assert "args+=(--approve-host-devsy-apply)" in workflow
    assert "HOST_DEVSY_ROLLBACK_APPROVAL: ${{ inputs.approve_host_devsy_rollback }}" in workflow
    assert "args+=(--approve-host-devsy-rollback)" in workflow


def test_protected_workflow_has_one_time_tap_reconciliation_and_rollback_approvals():
    workflow = (ROOT / ".github/workflows/deploy-control-plane.yml").read_text()
    for operation in (
        "devsy-tap-reconcile-check", "devsy-tap-reconcile",
        "devsy-tap-rollback-check", "devsy-tap-rollback",
    ):
        assert operation in workflow
    assert "approve_host_tap_reconciliation:" in workflow
    assert "approve_host_tap_rollback:" in workflow
    assert "HOST_TAP_RECONCILIATION_APPROVAL: ${{ inputs.approve_host_tap_reconciliation }}" in workflow
    assert "HOST_TAP_ROLLBACK_APPROVAL: ${{ inputs.approve_host_tap_rollback }}" in workflow
    assert "args+=(--approve-host-tap-reconciliation)" in workflow
    assert "args+=(--approve-host-tap-rollback)" in workflow


def test_cas_workflow_resolves_merged_pins_and_has_no_manual_digest_or_native_upgrade_input():
    workflow = (ROOT / ".github/workflows/deploy-control-plane.yml").read_text()
    assert "native-reconcile" in workflow
    assert "cas_digest:" not in workflow
    assert "cas_revision:" not in workflow
    assert "CAS_DIGEST" not in workflow
    assert "CAS_REVISION" not in workflow
    assert "workflow_dispatch" in workflow
    assert "cas-promotion.json" in (ROOT / "scripts/deploy_control_plane.py").read_text()


def test_deployment_candidate_rechecks_receipt_provenance_and_rejects_unrelated_image_change():
    current,manifest,evidence=cas_promotion_fixture()
    verified={key:{"digest":manifest["images"]["cas"]["digest"],
                   "revision":manifest["images"]["cas"]["revision"],
                   "platform":"linux/amd64"}
              for key in ("cas","schema_proxy")}
    with patch.object(d.cas_promotion,"verify_handoff_source") as source, \
         patch.object(d.cas_promotion,"verify_candidate_is_current_or_newer") as ancestry, \
         patch.object(d.cas_promotion,"verify_action_runs",return_value={
             "publication_artifact": evidence["handoff_source"]["artifact"]
         }) as runs, \
         patch.object(d.cas_promotion,"verify_publisher",return_value=verified) as publisher:
        source.return_value={"artifact":evidence["handoff_source"]["artifact"]}
        assert d._verified_cas_candidate(current,manifest,evidence)==evidence
        source.assert_called_once()
    ancestry.assert_called_once()
    runs.assert_called_once_with(evidence["handoff"])
    publisher.assert_called_once_with(evidence["handoff"])
    unrelated=json.loads(json.dumps(manifest))
    unrelated["images"]["executor"]["digest"]="sha256:"+"1"*64
    with pytest.raises(ValueError,match="unrelated production image"):
        d._verified_cas_candidate(current,unrelated,evidence)


def test_tap_reconciliation_requires_approval_and_native_tuple_before_vm_operations():
    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    args = SimpleNamespace(
        operation="devsy-tap-reconcile", local=False,
        approve_full_stack=False, approve_host_tap_reconciliation=False,
        approve_host_tap_rollback=False, native_target="local",
        native_cwd="/home/operator/mcp-tunnel-kit",
        native_thread_id="12345678-1234-5678-9abc-def012345678",
    )
    with patch.object(d, "INSTANCE", instance), patch.object(d, "trusted_context"), \
            patch.object(d, "lock", return_value=nullcontext()), \
            patch.object(d, "remote") as remote, \
            patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(ValueError, match="explicit Homebrew tap reconciliation approval"):
            d.execute(args)
    remote.assert_not_called()


def test_tap_reconciliation_dispatch_uses_current_sha_and_exact_native_tuple():
    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    args = SimpleNamespace(
        operation="devsy-tap-reconcile", local=False,
        approve_full_stack=False, approve_host_tap_reconciliation=True,
        approve_host_tap_rollback=False, native_target="local",
        native_cwd="/home/operator/mcp-tunnel-kit",
        native_thread_id="12345678-1234-5678-9abc-def012345678",
    )
    expected_native = {
        "target": "local", "cwd": "/home/operator/mcp-tunnel-kit",
        "thread_id": "12345678-1234-5678-9abc-def012345678",
    }
    with patch.object(d, "INSTANCE", instance), patch.object(d, "trusted_context"), \
            patch.object(d, "lock", return_value=nullcontext()), \
            patch.object(d, "_reconcile_host_tap", return_value={"operation": "devsy-tap-reconcile"}) as reconcile, \
            patch.dict(os.environ, {"GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "38610000005",
                                    "GITHUB_RUN_ATTEMPT": "2"}):
        result = d.execute(args)

    assert result == {"operation": "devsy-tap-reconcile"}
    reconcile.assert_called_once_with(expected_native, "b" * 40, "38610000005", "2")


def test_remote_source_receives_only_validated_profile_over_pinned_alias():
    from instance_profile import decode
    instance=json.loads((ROOT/'config/instance.example.json').read_text())
    d.configure_instance(instance)
    result=type('Result',(),{'returncode':0,'stdout':'{}','stderr':''})()
    with patch.object(d.subprocess,'run',return_value=result) as run:
        assert d.remote('status')=={}
    argv=run.call_args.args[0]
    assert argv[-2]==instance['deploy_host']['alias']
    remote_argv=shlex.split(argv[-1])
    assert remote_argv[-2]=='status'
    assert decode(remote_argv[-1])==instance


def test_remote_streams_large_controller_source_without_ssh_argument_overflow(monkeypatch):
    instance=json.loads((ROOT/'config/instance.example.json').read_text())
    d.configure_instance(instance)
    source='x'*200000
    monkeypatch.setattr(d,'remote_source',lambda:source)
    captured={}
    def run(argv,**kwargs):
        captured.update(argv=argv,input=kwargs['input'])
        return type('Result',(),{'returncode':0,'stdout':'{}','stderr':''})()
    monkeypatch.setattr(d.subprocess,'run',run)
    assert d.remote('status',{'fixture':True})=={}
    assert len(captured['argv'][-1])<10000
    assert captured['input']==source+'\n'+json.dumps({'fixture':True})


def test_remote_stdin_bootstrap_preserves_following_json():
    source="import json,sys; print(json.dumps(json.load(sys.stdin)))"
    result=subprocess.run([sys.executable,'-c',d.REMOTE_STDIN_BOOTSTRAP],
        input=source+'\n'+json.dumps({'fixture':True}),capture_output=True,text=True,check=True)
    assert json.loads(result.stdout)=={'fixture':True}


def test_remote_source_injects_stdlib_generation_validator_without_target_install():
    names=("instance_profile","prepare_recovery_generation","devsy_vm_bootstrap",
           "scope_binding_rebind","bridge_kubectl_path","compose_control","native_drift")
    previous={name:sys.modules.get(name) for name in names}
    try:
        namespace={"__name__":"remote_source_test"}
        exec(compile(d.remote_source(),"<remote-source-test>","exec"),namespace)
        assert callable(sys.modules["prepare_recovery_generation"].validate_generation)
        assert callable(sys.modules["devsy_vm_bootstrap"].VMDevsyBootstrap)
    finally:
        for name,module in previous.items():
            if module is None:sys.modules.pop(name,None)
            else:sys.modules[name]=module


def test_native_reconcile_is_read_only_and_reports_separate_versions_and_qualification():
    from test_cas_promotion import receipt as handoff_fixture, proof as proof_fixture, locator, run_proof
    deployed_manifest = json.loads((ROOT / "config/deploy-images.json").read_text())
    handoff = handoff_fixture()
    promoted, proof = d.cas_promotion.promote_manifest(
        deployed_manifest, handoff,
        verifier=lambda manifest, **_kwargs: proof_fixture(manifest),
        run_verifier=run_proof, candidate_verifier=lambda *_args: None)
    promotion_receipt = d.cas_promotion.build_evidence(deployed_manifest, promoted, handoff, proof, locator())
    current = {"manifest":promoted,"cas_promotion":promotion_receipt}
    native = {"mutated":False,"targets":{
        "dakota-cpu":{"installed_cli":{"version":"0.172.0"},
                       "running_daemon":{"version":"0.171.0"},
                       "version_drift":"cli_daemon_drift"},
        "dakota-nvidia":{"installed_cli":{"version":"0.171.0"},
                          "running_daemon":{"version":"0.171.0"},
                          "version_drift":"in_sync"}}}
    calls=[]
    def remote(action,data=None):
        calls.append((action,data))
        if action=="current":return current
        if action=="native-drift":return native
        raise AssertionError("unexpected VM action: "+action)
    args=SimpleNamespace(local=False,operation="native-reconcile")
    with patch.object(d,"INSTANCE",json.loads((ROOT/"config/instance.example.json").read_text())), \
         patch.object(d,"trusted_context"),patch.object(d,"lock",return_value=nullcontext()), \
         patch.object(d,"remote",side_effect=remote),patch.dict(os.environ,{"GITHUB_SHA":"b"*40}):
        result=d.execute(args)
    assert result["mutated"] is False
    assert result["native_drift"]["targets"]["dakota-cpu"]["installed_cli"]["version"]=="0.172.0"
    assert result["native_drift"]["targets"]["dakota-cpu"]["running_daemon"]["version"]=="0.171.0"
    assert result["cas_method_qualification"]["status"]=="QUALIFIED"
    assert result["cas_method_qualification"]["qualified_methods"]==handoff["qualification"]["method_verdicts"]
    assert calls==[("current",None),("native-drift",{})]


def test_cas_rollback_reboots_only_pair_and_checks_unrelated_container_identity(tmp_path):
    manifest=json.loads((ROOT/"config/deploy-images.json").read_text())
    previous={"authority":"kamal","identity":"executor-identity","source_sha":"a"*40,
              "manifest":manifest}
    inventory={
        "executor":{"container_id":"executor-id","started_at":"executor-start","image":"executor-image"},
        "tunnel":{"container_id":"tunnel-id","started_at":"tunnel-start","image":"tunnel-image"},
        "cas":{"container_id":"cas-old","started_at":"cas-old-start","image":"cas-image","state":"running","health":"healthy"},
        "schema-proxy":{"container_id":"schema-old","started_at":"schema-old-start","image":"schema-image","state":"running","health":"healthy"}}
    before={"identity":"executor-identity","source_sha":"a"*40,"inventory":inventory}
    after={**before,"inventory":{**inventory,
        "cas":{"container_id":"cas-rollback","started_at":"cas-rollback-start","image":"cas-image","state":"running","health":"healthy"},
        "schema-proxy":{"container_id":"schema-rollback","started_at":"schema-rollback-start","image":"schema-image","state":"running","health":"healthy"}}}
    calls=[]
    def remote(action,data=None):
        calls.append((action,data))
        if action=="snapshot":return after
        if action=="image-check":return {"image_ids":{"cas":"cas-image","schema_proxy":"schema-image"}}
        if action=="set-current":return {"generation_restored":True}
        return {}
    with patch.object(d,"configuration",return_value=tmp_path/"deploy.yml"), \
         patch.object(d,"remote",side_effect=remote),patch.object(d,"kamal") as kamal, \
         patch.object(d,"smoke"):
        d.restore_cas(previous,tmp_path,None,before=before)
    assert [call.args[2] for call in kamal.call_args_list]==["schema-proxy","cas"]
    assert [data for action,data in calls if action=="wait"]==[
        {"owner":"kamal","service":"schema-proxy"},
        {"owner":"kamal","service":"cas"}]
    assert calls[-1]==("set-current",previous)


def test_cas_rollback_refuses_to_accept_changed_executor_or_tunnel(tmp_path):
    previous={"authority":"kamal","identity":"executor-identity","source_sha":"a"*40,
              "manifest":json.loads((ROOT/"config/deploy-images.json").read_text())}
    old={"executor":{"container_id":"old-e","started_at":"e0","image":"e"},
         "tunnel":{"container_id":"old-t","started_at":"t0","image":"t"}}
    after={"inventory":{"executor":{"container_id":"new-e","started_at":"e1","image":"e"},
                        "tunnel":old["tunnel"]}}
    ids={"cas":"c","schema_proxy":"s"}
    with pytest.raises(RuntimeError,match="unrelated service: executor"):
        d._assert_cas_pair_rollout({"inventory":old},after,ids)


def test_cas_deploy_updates_pair_and_rolls_back_after_receipt_commit_failure(tmp_path):
    import json as json_module
    current_manifest,candidate_manifest,evidence=cas_promotion_fixture()
    repo=tmp_path/"repo";config=repo/"config";config.mkdir(parents=True)
    (config/"deploy-images.json").write_text(json_module.dumps(candidate_manifest))
    (config/"cas-promotion.json").write_text(json_module.dumps(evidence))
    monkeypatch_root=d.ROOT
    d.ROOT=repo
    before_inventory={
        "executor":{"container_id":"exec-id","started_at":"exec-start","image":"exec-image"},
        "tunnel":{"container_id":"tunnel-id","started_at":"tunnel-start","image":"tunnel-image"},
        "cas":{"container_id":"old-cas","started_at":"cas-old-start","image":"old-cas-image","state":"running","health":"healthy"},
        "schema-proxy":{"container_id":"old-schema","started_at":"schema-old-start","image":"old-schema-image","state":"running","health":"healthy"}}
    before={"authority":"kamal","identity":"exec-identity","source_sha":"a"*40,
            "inventory":before_inventory}
    promoted_inventory={**before_inventory,
        "cas":{"container_id":"new-cas","started_at":"cas-new-start","image":"new-cas-image","state":"running","health":"healthy"},
        "schema-proxy":{"container_id":"new-schema","started_at":"schema-new-start","image":"new-schema-image","state":"running","health":"healthy"}}
    deployed={**before,"inventory":promoted_inventory}
    rollback_inventory={**before_inventory,
        "cas":{"container_id":"rollback-cas","started_at":"rollback-cas-start","image":"old-cas-image","state":"running","health":"healthy"},
        "schema-proxy":{"container_id":"rollback-schema","started_at":"rollback-schema-start","image":"old-schema-image","state":"running","health":"healthy"}}
    restored={**before,"inventory":rollback_inventory}
    generation={"authority":"kamal","identity":"exec-identity","source_sha":"a"*40,
                "manifest":current_manifest}
    old_ids={"cas":"old-cas-image","schema_proxy":"old-schema-image",
             "executor":"exec-image","tunnel":"tunnel-image"}
    new_ids={"cas":"new-cas-image","schema_proxy":"new-schema-image",
             "executor":"exec-image","tunnel":"tunnel-image"}
    snapshots=iter((before,deployed,restored));image_checks=iter((old_ids,new_ids,old_ids));calls=[]
    def remote(action,data=None):
        calls.append((action,data))
        if action=="snapshot":return next(snapshots)
        if action=="current":return generation
        if action=="image-check":return {"image_ids":next(image_checks)}
        if action=="images":return {"image_ids":new_ids}
        if action=="commit":raise RuntimeError("fixture receipt commit failure")
        return {}
    args=SimpleNamespace(local=False,operation="cas",native_target=None,native_cwd=None,
                         native_thread_id=None,approve_full_stack=False)
    try:
        with patch.object(d,"INSTANCE",json.loads((ROOT/"config/instance.example.json").read_text())), \
             patch.object(d,"trusted_context"),patch.object(d,"lock",return_value=nullcontext()), \
             patch.object(d,"remote",side_effect=remote),patch.object(d,"configuration",return_value=tmp_path/"deploy.yml"), \
             patch.object(d,"devsy_payload",return_value={}), \
             patch.object(d,"prove_images",return_value={}),patch.object(d,"_verified_cas_candidate",return_value=evidence), \
             patch.object(d,"_pin_memoryd_before_core_change"),patch.object(d,"kamal") as kamal, \
             patch.object(d,"smoke",side_effect=[{},{},{}]), \
             patch.dict(os.environ,{"GITHUB_SHA":"b"*40}):
            with pytest.raises(RuntimeError) as caught:
                d.execute(args)
        receipt=json_module.loads(str(caught.value))
        assert receipt["automatic_rollback"]=="restored"
        assert receipt["deployment_receipt"]["rollback_digest"]==current_manifest["images"]["cas"]["digest"]
        assert receipt["deployment_receipt"]["rollback_source_revision"]==current_manifest["images"]["cas"]["revision"]
        assert [call.args[2] for call in kamal.call_args_list]==[
            "schema-proxy","cas","schema-proxy","cas"]
        assert sum(action=="commit" for action,_data in calls)==1
        assert calls[-1]==("set-current",generation)
    finally:
        d.ROOT=monkeypatch_root


def test_devsy_payload_contains_reviewed_nonsecret_inputs_and_vm_starter_path():
    instance=json.loads((ROOT/'config/instance.example.json').read_text())
    previous=(d.INSTANCE,d.HOST,d.VMROOT,d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        payload=d.devsy_payload()
    finally:
        d.INSTANCE,d.HOST,d.VMROOT,d.VM_HOST_PIN=previous
    assert set(payload)=={"policy","unit_template","starter_source"}
    assert payload["policy"]["devsy"]["version"]=="1.23.2"
    assert "@DEVSY_BIN@" in payload["unit_template"]
    assert str(Path(instance["vm"]["repo_dir"])/"scripts") in payload["starter_source"]
    assert "kubeconfig" not in payload["starter_source"]


def test_deployment_cli_rejects_manual_cas_digest_and_revision_inputs():
    result=subprocess.run([sys.executable,str(ROOT/'scripts/deploy_control_plane.py'),
        'cas','--cas-digest','sha256:'+'a'*64,'--cas-revision','a'*40],
        capture_output=True,text=True)
    assert result.returncode==2
    assert 'unrecognized arguments' in result.stderr


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
    instance=json.loads((ROOT/'config/instance.example.json').read_text())
    d.configure_instance(instance)
    alias=instance['deploy_host']['alias'];address=instance['deploy_host']['address'];user=instance['deploy_host']['user']
    known.write_text(alias+','+address+' ssh-ed25519 '+base64.b64encode(b'wrong-key').decode()+'\n')
    config.write_text(f'''Host {alias}
HostName {address}
User {user}
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


def test_bootstrap_container_checks_mounted_authority_without_docker(tmp_path):
    spec=importlib.util.spec_from_file_location('compose_container_guard',ROOT/'scripts/compose_control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    r=tmp_path/'current.json';r.write_text('{"authority":"kamal"}');r.chmod(0o600)
    with patch.dict(os.environ,{'CONTROL_PLANE_AUTHORITY_FILE':str(r)}),patch.object(c,'config',side_effect=AssertionError('Bootstrap container has no Docker')):
        with pytest.raises(c.ControlError,match='bootstrap refused'):c.guard_kamal_owner('bootstrap')
        r.write_text('{"authority":"compose"}')
        c.guard_kamal_owner('bootstrap')


def test_network_check_handles_host_and_null_networks_without_stopping_production():
    rows=[{'Name':'host','IPAM':{'Config':None}},{'Name':'none','IPAM':{'Config':None}}]
    with patch.object(h,'run',side_effect=[b'a b',json.dumps(rows).encode(),b'[]']):
        assert h.network_check(d.profile()['network']) is False
