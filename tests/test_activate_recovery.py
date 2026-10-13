"""A preserved VM generation activates only after a read-only empty-target plan."""

import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
from contextlib import nullcontext
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import activate_recovery as activation
import deploy_control_plane as deploy
import vm_deploy_host as host
from instance_profile import encode


def generation():
    return {
        "authority": "kamal",
        "identity": "fixture-preserved-identity",
        "manifest": json.loads((ROOT / "config/deploy-images.json").read_text()),
        "publication_proof": {"cas": {}, "schema_proxy": {}},
        "source_sha": "a" * 40,
    }


def plan_value():
    value = generation()
    return {
        "ready": True,
        "generation": value,
        "expected_identity": value["identity"],
        "prepared_manifest_sha256": "b" * 64,
        "inventory_count": 42,
        "repo_source_sha": value["source_sha"],
    }


def cli_args(**overrides):
    values = {
        "local_config": "/private/local.env",
        "instance_profile": "/private/instance.json",
        "generation_dir": "/private/prepared-generation",
        "original_stopped": False,
        "approve_activation": False,
    }
    values.update(overrides)
    return type("Args", (), values)()


def controller_setup():
    deploy.configure_instance(json.loads((ROOT / "config/instance.example.json").read_text()))


def controller_patches():
    return (
        patch.object(deploy, "configure_local"),
        patch.object(deploy, "trusted_context"),
        patch.object(deploy, "prove_images", return_value={"cas": {}, "schema_proxy": {}}),
    )


def test_default_invocation_is_read_only_plan(tmp_path):
    controller_setup()
    calls = [];events=[]

    def remote(action, data=None):
        calls.append((action, data));events.append(action)
        return plan_value()

    configure, trust, proof = controller_patches()
    with configure, trust, proof, patch.object(deploy, "remote", side_effect=remote), \
         patch.object(deploy, "lock") as lock, patch.dict(os.environ, {}):
        result = activation.execute(cli_args())

    assert result == {
        "mode": "PLAN", "target_ready": True, "source_sha": "a" * 40,
        "generation_files": 42, "image_provenance": "PASS", "image_proof_count": 2,
        "original_stopped_attestation_required": True, "approve_activation_required": True,
    }
    assert calls == [("activation-plan", {"generation_dir": "/private/prepared-generation"})]
    lock.assert_not_called()


def test_one_activation_flag_fails_before_connecting():
    with patch.object(deploy, "configure_local") as configure, patch.object(deploy, "remote") as remote:
        with pytest.raises(ValueError, match="requires both"):
            activation.execute(cli_args(original_stopped=True))
    configure.assert_not_called()
    remote.assert_not_called()


def test_relative_generation_dir_fails_before_connecting():
    args=cli_args(generation_dir="relative/stage")
    with patch.object(deploy,"configure_local") as configure,patch.object(deploy,"remote") as remote:
        with pytest.raises(ValueError,match="absolute VM path"):
            activation.plan(args)
    configure.assert_not_called()
    remote.assert_not_called()


def test_successful_activation_checks_identity_before_tunnel_and_tunnel_is_last(tmp_path):
    controller_setup()
    calls = [];events=[]
    def remote(action, data=None):
        calls.append((action, data));events.append(action)
        if action == "activation-plan":return plan_value()
        if action == "activation-preflight":
            return {"ready": True, "expected_identity": generation()["identity"],
                    "prepared_manifest_sha256": "b" * 64}
        if action == "activation-identity":return {"identity_preserved": True}
        if action == "snapshot":return {"authority": "kamal", "identity": generation()["identity"], "tunnel_count": 1}
        return {}

    booted=[]
    def kamal(_config,op,name):
        booted.append((op,name));events.append("kamal:"+name)
    configure, trust, proof = controller_patches()
    with configure, trust, proof, patch.object(deploy, "remote", side_effect=remote), \
         patch.object(deploy, "lock", return_value=nullcontext()), \
         patch.object(deploy, "kamal", side_effect=kamal):
        result=activation.execute(cli_args(original_stopped=True,approve_activation=True))

    assert result["mode"]=="ACTIVATED" and result["single_tunnel"] is True
    assert booted==[("boot","executor"),("boot","schema-proxy"),("boot","cas"),("boot","tunnel")]
    names=[action for action,_ in calls]
    assert events.index("activation-identity") < events.index("kamal:tunnel")
    assert events.index("activation-identity") < events.index("activation-record")
    assert names.index("smoke") < names.index("activation-identity")
    assert names.index("snapshot") < names.index("activation-record")
    assert "compose-start" not in names and "compose-stop" not in names


def test_identity_mismatch_never_boots_tunnel_and_cleans_only_new_accessories():
    controller_setup()
    calls=[];booted=[]
    def remote(action,data=None):
        calls.append(action)
        if action=="activation-plan":return plan_value()
        if action=="activation-preflight":return {"ready":True,"expected_identity":generation()["identity"],"prepared_manifest_sha256":"b"*64}
        if action=="activation-identity":return {"identity_preserved":False}
        return {}
    configure,trust,proof=controller_patches()
    with configure,trust,proof,patch.object(deploy,"remote",side_effect=remote), \
         patch.object(deploy,"lock",return_value=nullcontext()), \
         patch.object(deploy,"kamal",side_effect=lambda _c,_op,name:booted.append(name)):
        with pytest.raises(RuntimeError,match="restored data and any created Executor volume were retained"):
            activation.execute(cli_args(original_stopped=True,approve_activation=True))
    assert booted==["executor","schema-proxy","cas"]
    assert "activation-cleanup" in calls
    assert "activation-record" not in calls


def test_final_tunnel_or_identity_mismatch_cleans_new_services_without_recording():
    controller_setup();calls=[];booted=[]
    def remote(action,data=None):
        calls.append(action)
        if action=="activation-plan":return plan_value()
        if action=="activation-preflight":return {"ready":True,"expected_identity":generation()["identity"],"prepared_manifest_sha256":"b"*64}
        if action=="activation-identity":return {"identity_preserved":True}
        if action=="snapshot":return {"authority":"kamal","identity":"wrong-identity","tunnel_count":2}
        return {}
    configure,trust,proof=controller_patches()
    with configure,trust,proof,patch.object(deploy,"remote",side_effect=remote), \
         patch.object(deploy,"lock",return_value=nullcontext()), \
         patch.object(deploy,"kamal",side_effect=lambda _c,_op,name:booted.append(name)):
        with pytest.raises(RuntimeError,match="restored data and any created Executor volume were retained"):
            activation.execute(cli_args(original_stopped=True,approve_activation=True))
    assert booted==["executor","schema-proxy","cas","tunnel"]
    assert calls[-1]=="activation-cleanup"
    assert "activation-record" not in calls


def test_boot_failure_preserves_recovered_data_and_never_starts_compose():
    controller_setup();calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=="activation-plan":return plan_value()
        if action=="activation-preflight":return {"ready":True,"expected_identity":generation()["identity"],"prepared_manifest_sha256":"b"*64}
        return {}
    configure,trust,proof=controller_patches()
    with configure,trust,proof,patch.object(deploy,"remote",side_effect=remote), \
         patch.object(deploy,"lock",return_value=nullcontext()), \
         patch.object(deploy,"kamal",side_effect=RuntimeError("fixture boot failure")):
        with pytest.raises(RuntimeError,match="restored data and any created Executor volume were retained"):
            activation.execute(cli_args(original_stopped=True,approve_activation=True))
    assert "activation-cleanup" in calls
    assert "compose-start" not in calls


def generation_tree(tmp_path, *, lock=True):
    root=tmp_path/"prepared";root.mkdir(mode=0o700)
    rows=[]
    def directory(relative):
        (root/relative).mkdir(parents=True,exist_ok=True,mode=0o700)
        rows.append({"path":relative,"type":"directory","mode":0o700,"size":0})
    def file(relative,content,mode=0o600):
        path=root/relative;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(content);path.chmod(mode)
        rows.append({"path":relative,"type":"file","mode":mode,"size":len(content),"sha256":hashlib.sha256(content).hexdigest()})
    directory("state");directory("state/secrets");directory("state/deployment")
    file("state/secrets/control-plane-api-key",b"synthetic\n")
    file("state/deployment/current.json",b'{"authority":"kamal"}\n')
    directory("native-ssh");file("native-ssh/identity",b"native key\n")
    file("vm.env",b"SECRET=value\n")
    rows.sort(key=lambda row:row["path"])
    manifest=root/"prepared-manifest.json";manifest.write_text("{}\n");manifest.chmod(0o600)
    prepared={"schema_version":1,"generation_file":"generation.json","generation":generation(),
              "expected_identity":generation()["identity"],"inventory":rows}
    profile=json.loads((ROOT/"config/instance.example.json").read_text())
    parent=tmp_path/"target-parent";parent.mkdir(mode=0o700)
    native_parent=tmp_path/"native-parent";native_parent.mkdir(mode=0o700)
    repo=tmp_path/"repo";repo.mkdir(mode=0o700)
    profile["vm"].update(repo_dir=str(repo),state_dir=str(parent/"state"),native_ssh_dir=str(native_parent/"native-ssh"))
    host.configure_profile(profile)
    if lock:
        host.STATE.mkdir(mode=0o700);host.STORE.mkdir(mode=0o700)
        lockfile=host.STORE/"deploy.lock";lockfile.write_bytes(b"");lockfile.chmod(0o600)
        start_activation_marker()
    return root,prepared,profile


def start_activation_marker(activation_id="c"*32):
    host.STATE.mkdir(mode=0o700,exist_ok=True);host.STORE.mkdir(mode=0o700,exist_ok=True)
    lockfile=host.STORE/"deploy.lock"
    if not lockfile.exists():lockfile.write_bytes(b"");lockfile.chmod(0o600)
    marker=host.STORE/"activation-in-progress.json"
    marker.write_text(json.dumps({"schema_version":1,"activation_id":activation_id,"status":"installing",
        "source_sha":"a"*40,"expected_identity":generation()["identity"],"prepared_manifest_sha256":"b"*64,
        "original_stopped_attested":True,"started_services":[]}))
    marker.chmod(0o600)


def safe_vm_run(command):
    if command[:3]==["git","-C",str(host.ROOT)]:
        return b"" if command[3]=="status" else b"a"*40
    if command[:3]==["docker","ps","-aq"]:return b""
    if command[:3]==["docker","volume","ls"]:return b""
    if command[:2]==["systemctl","show"]:return b"loaded\n"
    if command[:2]==["docker","network"]:return b""
    raise AssertionError(f"Unexpected non-read-only preflight command: {command}")


def test_vm_activation_plan_is_read_only_and_refuses_existing_stopped_project_container(tmp_path,monkeypatch):
    prepared_dir,prepared,profile=generation_tree(tmp_path,lock=False)
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"run",safe_vm_run)
    monkeypatch.setattr(host,"network_check",lambda _network:False)
    result=host.activation_plan(prepared_dir)
    assert result["ready"] is True
    assert not host.STATE.exists() and not host.NATIVE_SSH.exists()
    row={"Name":"/mcp-control-plane-executor-1","Config":{"Image":"executor","Labels":{"service":"mcp-control-plane-executor"}},"Mounts":[],"State":{"Status":"exited"}}
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[row])
    with pytest.raises(ValueError,match="already has control-plane"):
        host.activation_plan(prepared_dir)
    assert not host.STATE.exists()


def test_vm_main_remote_activation_plan_does_not_create_store(tmp_path,monkeypatch):
    prepared_dir,prepared,profile=generation_tree(tmp_path,lock=False)
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"run",safe_vm_run)
    monkeypatch.setattr(host,"network_check",lambda _network:False)
    monkeypatch.setattr(sys,"argv",["-c","activation-plan",encode(profile)])
    monkeypatch.setattr(sys,"stdin",StringIO(json.dumps({"generation_dir":str(prepared_dir)})))
    output=StringIO();monkeypatch.setattr(sys,"stdout",output)
    previous_umask=os.umask(0o077)
    try:status=host.main()
    finally:os.umask(previous_umask)
    assert status is None
    assert json.loads(output.getvalue())["ready"] is True
    assert not host.STATE.exists() and not host.NATIVE_SSH.exists()


@pytest.mark.parametrize("owner",["uid","gid"])
def test_vm_activation_plan_requires_executor_compatible_operator_identity(tmp_path,monkeypatch,owner):
    _prepared_dir,_prepared,_profile=generation_tree(tmp_path,lock=False)
    if owner=="uid":monkeypatch.setattr(host.os,"getuid",lambda:2000)
    else:monkeypatch.setattr(host.os,"getgid",lambda:2000)
    with pytest.raises(ValueError,match="UID/GID must be 1000"):
        host._target_preflight()
    assert not host.STATE.exists()


def test_vm_activation_plan_refuses_source_revision_mismatch_before_mutation(tmp_path,monkeypatch):
    prepared_dir,prepared,_profile=generation_tree(tmp_path,lock=False)
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[])
    monkeypatch.setattr(host,"run",lambda command: b"" if command[3]=="status" else b"f"*40)
    monkeypatch.setattr(host,"network_check",lambda _network:False)
    with pytest.raises(ValueError,match="captured source revision"):
        host.activation_plan(prepared_dir)
    assert not host.STATE.exists()


@pytest.mark.parametrize("conflict",["volume","network","state"])
def test_vm_activation_preflight_refuses_volume_network_or_nonempty_state(tmp_path,monkeypatch,conflict):
    prepared_dir,prepared,profile=generation_tree(tmp_path,lock=False)
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[])
    if conflict=="state":
        host.STATE.mkdir(mode=0o700);(host.STATE/"existing").write_text("preserve")
    def run(command):
        if command[:3]==["docker","volume","ls"] and conflict=="volume":return b"codex-control-plane_executor-data\n"
        return safe_vm_run(command)
    monkeypatch.setattr(host,"run",run)
    monkeypatch.setattr(host,"network_check",lambda _network: (_ for _ in ()).throw(ValueError("network overlap")) if conflict=="network" else False)
    with pytest.raises(ValueError):host.activation_plan(prepared_dir)


def test_vm_install_rechecks_then_copies_only_verified_files_without_overwrite(tmp_path,monkeypatch):
    prepared_dir,prepared,profile=generation_tree(tmp_path,lock=True)
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[])
    monkeypatch.setattr(host,"run",safe_vm_run)
    monkeypatch.setattr(host,"network_check",lambda _network:False)
    digest=hashlib.sha256((prepared_dir/"prepared-manifest.json").read_bytes()).hexdigest()
    result=host.activation_install(prepared_dir,digest,"c"*32)
    assert result["state_installed"] and result["native_ssh_installed"]
    assert (host.STATE/"secrets/control-plane-api-key").read_bytes()==b"synthetic\n"
    assert (host.STATE/"deployment/current.json").read_bytes()==b'{"authority":"kamal"}\n'
    assert (host.NATIVE_SSH/"identity").read_bytes()==b"native key\n"
    assert (host.ROOT/".env").read_bytes()==b"SECRET=value\n"
    with pytest.raises(ValueError,match="already exists"):
        host.activation_install(prepared_dir,digest,"c"*32)


def test_executor_volume_seed_never_starts_helper_and_preserves_volume_on_copy_failure(tmp_path,monkeypatch):
    prepared_dir,prepared,_profile=generation_tree(tmp_path,lock=False)
    start_activation_marker()
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[])
    monkeypatch.setattr(host,"images",lambda _manifest,pull=False:{"executor":"image"})
    monkeypatch.setattr(host.uuid,"uuid4",lambda:type("UUID",(),{"hex":"c"*32})())
    calls=[]
    activation_label=None
    def run(command,*_args,**_kwargs):
        nonlocal activation_label
        calls.append(command)
        if command[:3]==["docker","volume","ls"]:return b""
        if command[:3]==["docker","volume","create"]:
            activation_label=command[command.index("--label")+1].split("=",1)[1]
            return b"codex-control-plane_executor-data\n"
        if command[:3]==["docker","volume","inspect"]:
            return json.dumps([{"Name":"codex-control-plane_executor-data","Labels":{"mcp-control-plane.recovery-activation":activation_label}}]).encode()
        if command[:2]==["docker","create"]:return b"helper-id\n"
        if command[:2]==["docker","inspect"]:return b'[{"State":{"Running":false}}]'
        if command[:2]==["docker","cp"]:return b""
        if command[:2]==["docker","rm"]:return b""
        raise AssertionError(command)
    monkeypatch.setattr(host,"run",run)
    manifest=prepared["generation"]["manifest"]
    digest=hashlib.sha256((prepared_dir/"prepared-manifest.json").read_bytes()).hexdigest()
    result=host.activation_seed(prepared_dir,digest,manifest,"c"*32)
    assert result["helper_started"] is False
    assert any("volume-nocopy" in arg for command in calls for arg in command)
    assert any(command[:3]==["docker","cp","--archive"] for command in calls)
    assert not any(command[:2]==["docker","start"] or command[:2]==["docker","volume","rm"] for command in calls)


def test_seed_copy_failure_removes_only_stopped_helper_and_keeps_created_volume(tmp_path,monkeypatch):
    prepared_dir,prepared,_profile=generation_tree(tmp_path,lock=False)
    start_activation_marker()
    monkeypatch.setattr(host,"_recovery_validator",lambda:lambda _path:prepared)
    monkeypatch.setattr(host,"_activation_container_rows",lambda:[])
    monkeypatch.setattr(host,"images",lambda _manifest,pull=False:{"executor":"image"})
    monkeypatch.setattr(host.uuid,"uuid4",lambda:type("UUID",(),{"hex":"d"*32})())
    calls=[];activation_label=None
    def run(command,*_args,**_kwargs):
        nonlocal activation_label
        calls.append(command)
        if command[:3]==["docker","volume","ls"]:return b""
        if command[:3]==["docker","volume","create"]:
            activation_label=command[command.index("--label")+1].split("=",1)[1];return b"volume\n"
        if command[:3]==["docker","volume","inspect"]:
            return json.dumps([{"Name":"codex-control-plane_executor-data","Labels":{"mcp-control-plane.recovery-activation":activation_label}}]).encode()
        if command[:2]==["docker","create"]:return b"helper-id\n"
        if command[:2]==["docker","inspect"]:return b'[{"State":{"Running":false}}]'
        if command[:2]==["docker","cp"]:raise RuntimeError("fixture copy error")
        if command[:2]==["docker","rm"]:return b""
        raise AssertionError(command)
    monkeypatch.setattr(host,"run",run)
    manifest=prepared["generation"]["manifest"]
    digest=hashlib.sha256((prepared_dir/"prepared-manifest.json").read_bytes()).hexdigest()
    with pytest.raises(RuntimeError,match="fixture copy error"):
        host.activation_seed(prepared_dir,digest,manifest,"c"*32)
    assert any(command[:2]==["docker","rm"] for command in calls)
    assert not any(command[:2]==["docker","start"] or command[:2]==["docker","volume","rm"] for command in calls)


def test_cleanup_removes_only_containers_created_with_kamal_ownership(tmp_path,monkeypatch):
    generation_tree(tmp_path,lock=True)
    rows=[]
    for name in ("mcp-control-plane-executor","mcp-control-plane-tunnel"):
        rows.append({"Name":"/"+name,"Id":name,"Config":{"Labels":{"service":name}},"State":{"Running":True},"Mounts":[]})
    monkeypatch.setattr(host,"_activation_container_rows",lambda:rows)
    calls=[];monkeypatch.setattr(host,"run",lambda command,*_args,**_kwargs:calls.append(command) or b"")
    result=host.activation_cleanup("c"*32,["executor","tunnel"])
    assert result["new_accessories_removed"]==2
    assert [(command[1],command[-1]) for command in calls]==[
        ("stop","mcp-control-plane-tunnel"),("rm","mcp-control-plane-tunnel"),
        ("stop","mcp-control-plane-executor"),("rm","mcp-control-plane-executor"),
    ]


def test_cleanup_refuses_foreign_compose_container_before_removing_anything(tmp_path,monkeypatch):
    generation_tree(tmp_path,lock=True)
    rows=[{"Name":"/codex-control-plane-executor-1","Id":"foreign","Config":{"Labels":{"com.docker.compose.project":"codex-control-plane"}},"State":{"Running":True},"Mounts":[]}]
    monkeypatch.setattr(host,"_activation_container_rows",lambda:rows)
    with patch.object(host,"run") as run:
        with pytest.raises(ValueError,match="foreign control-plane"):
            host.activation_cleanup("c"*32,["executor"])
    run.assert_not_called()
