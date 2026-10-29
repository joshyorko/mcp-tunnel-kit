"""Regression tests for deployment failure isolation and rollback."""

import json
import os
import sqlite3
import subprocess
import sys
import tarfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compose_control as c
import deploy_control_plane as d
import vm_deploy_host as h
from instance_profile import encode


def generation(authority="kamal", source_sha="a" * 40):
    return {
        "authority": authority,
        "identity": "executor-identity",
        "source_sha": source_sha,
        "manifest": json.loads((ROOT / "config/deploy-images.json").read_text()),
        "inventory": {
            name: {"image": "image-" + name}
            for name in ("executor", "schema-proxy", "cas", "tunnel")
        },
    }


def args(operation, *, approve=False, host_approve=False, host_rollback=False, native=None):
    native = native or {}
    return type("Args", (), {
        "local": False,
        "operation": operation,
        "cas_digest": "",
        "cas_revision": "",
        "approve_full_stack": approve,
        "approve_host_devsy_apply": host_approve,
        "approve_host_devsy_rollback": host_rollback,
        "native_target": native.get("target"),
        "native_cwd": native.get("cwd"),
        "native_thread_id": native.get("thread_id"),
    })()


def missing_pinned_kubectl_plan():
    policy = json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text())
    kubectl = policy["kubectl"]
    architecture = "x86_64"
    return {
        "ready": False,
        "status": "blocked",
        "changes": ["install-pinned-kubectl"],
        "cluster": {
            "ready": False, "status": "blocked",
            "reason": "pinned kubectl is missing; ROR admission preflight was not run",
        },
        "observed": {"kubectl": {
            "status": "missing", "platform": architecture,
            "version": kubectl["version"], "sha256": None,
            "target_sha256": kubectl["artifact_sha256"][architecture],
            "install_location": kubectl["install_location"],
            "managed_path_present": False,
        }},
    }


def runtime_repo(tmp_path):
    repo=tmp_path/"runtime-source";repo.mkdir()
    real_run=subprocess.run
    for command in (["git","init","--quiet",str(repo)],
                    ["git","-C",str(repo),"config","user.name","fixture"],
                    ["git","-C",str(repo),"config","user.email","fixture@example.invalid"]):
        real_run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (repo/".gitignore").write_text(".env\n")
    (repo/"runtime.py").write_text("runtime fixture\n")
    real_run(["git","-C",str(repo),"add",".gitignore","runtime.py"],check=True,stdout=subprocess.DEVNULL)
    real_run(["git","-C",str(repo),"commit","--quiet","-m","fixture"],check=True,stdout=subprocess.DEVNULL)
    source_sha=real_run(["git","-C",str(repo),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
    profile=json.loads((ROOT/"config/instance.example.json").read_text())
    state=tmp_path/"state";state.mkdir(mode=0o700)
    deployment=state/"deployment";deployment.mkdir(mode=0o700)
    current=deployment/"current.json";current.write_text(json.dumps({"authority":"kamal","source_sha":source_sha})+"\n");current.chmod(0o600)
    parent=tmp_path/"native-state";parent.mkdir(mode=0o700)
    profile["vm"].update(repo_dir=str(repo),state_dir=str(state),native_ssh_dir=str(parent/"native-ssh"))
    h.configure_profile(profile)
    return repo,source_sha


def test_cas_failure_restores_only_cas_and_uses_cas_backup():
    before = generation()
    current = dict(before)
    after = dict(before)
    calls = []
    smoke_count = 0

    def remote(action, data=None):
        nonlocal smoke_count
        calls.append((action, data))
        if action == 'memoryd-inventory':
            return {'status':'ABSENT'}
        if action == "snapshot":
            return before if calls.count(("snapshot", None)) == 1 else after
        if action == "current":
            return current
        if action in {"backup-cas", "profile", "network-check", "wait", "set-current"}:
            return {}
        if action == "devsy-check":
            return {"status": "current"}
        if action in {"image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "smoke":
            smoke_count += 1
            if smoke_count == 2:
                raise RuntimeError("new CAS smoke failed")
            return {"native_read": {"status": "PASS"}}
        raise AssertionError(f"Unexpected VM action: {action}")

    kamal_calls = []
    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "prove_images", return_value={}), \
         patch.object(d, "kamal", side_effect=lambda config, operation, name: kamal_calls.append((operation, name))), \
         patch.object(d, "sync_source") as sync_source, \
         patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(RuntimeError, match="previous generation restored"):
            d.execute(args("cas", native={
                "target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
                "thread_id": "12345678-1234-5678-9abc-def012345678",
            }))

    assert ("backup-cas", None) in calls
    assert ("backup", None) not in calls
    assert kamal_calls == [("reboot", "cas"), ("reboot", "cas")]
    assert not {"compose-stop", "compose-start", "devsy-start"} & {action for action, _ in calls}
    sync_source.assert_not_called()


def test_preflight_returns_devsy_plan_when_native_thread_tuple_is_mismatched(tmp_path):
    before = generation()
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        if action == "snapshot":
            return before
        if action == "current":
            return None
        if action == "image-check":
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "devsy-plan":
            return {"ready": True, "status": "changes-required", "changes": ["provider"]}
        if action == "smoke":
            return {"devsy_reads": "PASS", "native_read": {
                "status": "FAIL", "error_code": "THREAD_WORKSTREAM_MISMATCH"}}
        return {}

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "prove_images", return_value={}), \
             patch.object(d, "configuration", return_value=tmp_path / "deploy.yml"), \
             patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            result = d.execute(args("preflight"))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert result["devsy_plan"]["status"] == "changes-required"
    assert result["smoke"]["native_read"]["error_code"] == "THREAD_WORKSTREAM_MISMATCH"
    assert ("smoke", {"native_codex": None, "require_native": False}) in calls


def test_deploy_fails_closed_on_missing_native_tuple_before_backup_or_reboot(tmp_path):
    before = generation()
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        if action == "snapshot":
            return before
        if action == "current":
            return before
        if action == "image-check":
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "smoke":
            return {"native_read": {"status": "UNCONFIGURED"}}
        return {}

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    kamal_calls = []
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "prove_images", return_value={}), \
             patch.object(d, "configuration", return_value=tmp_path / "deploy.yml"), \
             patch.object(d, "kamal", side_effect=lambda *args: kamal_calls.append(args)), \
             patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            with pytest.raises(RuntimeError, match="Qualified native read failed"):
                d.execute(args("deploy", approve=True))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert not any(action in {"backup", "backup-cas", "images"} for action, _ in calls)
    assert kamal_calls == []


def test_devsy_check_only_returns_the_host_plan(tmp_path):
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        return {"ready": True, "status": "changes-required", "changes": ["install-tap-devsy"]}

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote):
            result = d.execute(args("devsy-check"))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert result["plan"]["changes"] == ["install-tap-devsy"]
    assert calls == [("devsy-plan", d.devsy_payload())]


def test_devsy_apply_requires_explicit_host_apply_approval_before_vm_reads():
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        return {}

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote):
            with pytest.raises(ValueError, match="explicit Host Devsy apply approval"):
                d.execute(args("devsy-apply"))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert calls == []


def test_devsy_apply_stops_on_blocked_plan_before_native_read_or_source_sync(tmp_path):
    before = generation()
    before.update(authority="kamal", tunnel_count=1, source_sha="b" * 40)
    current = {**before, "publication_proof": {}}
    calls = []
    smoke_calls = []
    sync = []

    def remote(action, data=None):
        calls.append(action)
        if action == "snapshot":
            return before
        if action == "lifecycle-check":
            return {"healthy": True}
        if action == "current":
            return current
        if action == "previous":
            return None
        if action == "devsy-plan":
            return {"ready": False, "status": "blocked",
                    "cluster": {"reason": "ROR has no eligible worker node"}}
        raise AssertionError(f"unexpected VM action after blocked plan: {action}")

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    native = {"target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
              "thread_id": "12345678-1234-5678-9abc-def012345678"}
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "smoke", side_effect=lambda *_args, **_kwargs: smoke_calls.append(True)), \
             patch.object(d, "sync_source", side_effect=lambda sha: sync.append(sha)), \
             patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
            with pytest.raises(ValueError, match="Host Devsy plan is blocked"):
                d.execute(args("devsy-apply", host_approve=True, native=native))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert calls == ["snapshot", "lifecycle-check", "current", "previous", "devsy-plan"]
    assert smoke_calls == []
    assert sync == []


def test_devsy_apply_accepts_only_the_exact_attested_missing_kubectl_case():
    policy = json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text())
    plan = missing_pinned_kubectl_plan()
    assert d._attested_missing_kubectl_plan(plan, policy) is True

    variants = []
    wrong_reason = json.loads(json.dumps(plan))
    wrong_reason["cluster"]["reason"] = "ROR has no eligible worker node"
    variants.append(wrong_reason)
    wrong_digest = json.loads(json.dumps(plan))
    wrong_digest["observed"]["kubectl"]["target_sha256"] = "0" * 64
    variants.append(wrong_digest)
    found_candidate = json.loads(json.dumps(plan))
    found_candidate["observed"]["kubectl"]["managed_path_present"] = True
    variants.append(found_candidate)
    missing_marker = json.loads(json.dumps(plan))
    missing_marker["changes"] = []
    variants.append(missing_marker)
    wrong_platform = json.loads(json.dumps(plan))
    wrong_platform["observed"]["kubectl"]["platform"] = "aarch64"
    wrong_platform["observed"]["kubectl"]["target_sha256"] = (
        policy["kubectl"]["artifact_sha256"]["aarch64"]
    )
    variants.append(wrong_platform)
    falsely_ready = json.loads(json.dumps(plan))
    falsely_ready["ready"] = True
    variants.append(falsely_ready)

    assert all(not d._attested_missing_kubectl_plan(item, policy) for item in variants)


def test_devsy_rollback_requires_explicit_approval_before_vm_reads():
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        return {}

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote):
            with pytest.raises(ValueError, match="explicit Host Devsy rollback approval"):
                d.execute(args("devsy-rollback"))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert calls == []


def test_devsy_rollback_restores_only_host_generation_and_reports_native_status(tmp_path):
    before = generation()
    before.update(authority="kamal", tunnel_count=1, source_sha="b" * 40)
    after = {**before, "source_sha": "a" * 40}
    current = {**before, "publication_proof": {}}
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        if action == "snapshot":
            return before if calls.count(("snapshot", None)) == 1 else after
        if action == "current":
            return current
        if action == "lifecycle-check":
            return {"healthy": True}
        if action == "devsy-rollback-plan":
            return {"ready": True, "source_sha": "a" * 40, "devsy_version": "1.23.0"}
        if action == "devsy-rollback":
            return {"restored": True, "source_sha": "a" * 40}
        if action == "devsy-plan":
            return {"ready": True, "status": "changes-required", "changes": ["install-tap-devsy"]}
        if action == "smoke":
            return {"native_read": {"status": "FAIL", "error_code": "NATIVE_THREAD_NOT_DISCOVERED"}}
        if action == "commit":
            return {"generation_committed": True}
        raise AssertionError(f"unexpected VM action: {action}")

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    payload = d.devsy_payload()
    native = {"target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
              "thread_id": "12345678-1234-5678-9abc-def012345678"}
    sync = []
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "sync_source", side_effect=lambda sha: sync.append(sha)), \
             patch.object(d, "prove_images", return_value={}), \
             patch.dict(os.environ, {"GITHUB_SHA": "c" * 40}):
            result = d.execute(args("devsy-rollback", host_rollback=True, native=native))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert result["host_devsy"]["restored"] is True
    assert result["native_read"]["native_read"]["status"] == "FAIL"
    assert result["identity_preserved"] is True
    assert sync == ["a" * 40]
    assert ("devsy-rollback", payload) in calls
    assert not {"images", "backup", "backup-cas"} & {action for action, _ in calls}


def test_devsy_apply_changes_only_host_state_and_records_merged_source(tmp_path):
    before = generation()
    before.update(authority="kamal", tunnel_count=1)
    after = {**before, "source_sha": "b" * 40}
    current = {**before, "publication_proof": {}}
    plan = missing_pinned_kubectl_plan()
    plan.update({"changes": ["install-pinned-kubectl", "install-tap-devsy"],
                 "devsy_current_version": "1.23.0", "provider": {"requests": {"cpu": "1"}},
                 "systemd_unit": "legacy", "bridge_starter": "legacy",
                 "service_active": True, "service_enabled": True, "tap_revision": "old"})
    verified = {**plan, "ready": True, "status": "current", "changes": [],
                "devsy_current_version": "1.23.2",
                "systemd_unit": "managed", "bridge_starter": "managed", "tap_revision": "new"}
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        if action == "snapshot":
            return before if calls.count(("snapshot", None)) == 1 else after
        if action == "current":
            return current
        if action == "previous":
            return None
        if action == "devsy-plan":
            return plan
        if action == "devsy-apply":
            return {"operation": "apply", "changed": True, "rollback_ready": True}
        if action == "devsy-check":
            return verified
        if action == "smoke":
            return {"native_read": {"status": "PASS"}}
        if action == "commit":
            return {"generation_committed": True}
        if action == "lifecycle-check":
            return {"healthy": True}
        raise AssertionError(f"unexpected VM action: {action}")

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    native = {"target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
              "thread_id": "12345678-1234-5678-9abc-def012345678"}
    sync = []
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "sync_source", side_effect=lambda sha: sync.append(sha)), \
             patch.object(d, "prove_images", return_value={}), \
             patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            result = d.execute(args("devsy-apply", host_approve=True, native=native))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert result["identity_preserved"] is True
    assert result["accessories_unchanged"] is True
    assert result["native_read"] == "PASS"
    assert sync == ["b" * 40]
    assert [action for action, _ in calls].count("commit") == 1
    assert not {"images", "backup", "backup-cas"} & {action for action, _ in calls}


def test_devsy_apply_rolls_back_host_and_source_when_drift_check_fails(tmp_path):
    before = generation()
    before.update(authority="kamal", tunnel_count=1)
    current = {**before, "publication_proof": {}}
    plan = {"ready": True, "status": "changes-required", "changes": ["install-tap-devsy"],
            "devsy_current_version": "1.23.0", "provider": {"requests": {"cpu": "1"}},
            "systemd_unit": "legacy", "bridge_starter": "legacy",
            "service_active": True, "service_enabled": True, "tap_revision": "old"}
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        if action == "snapshot":
            return before
        if action == "current":
            return current
        if action == "previous":
            return None
        if action == "devsy-plan":
            return plan
        if action == "devsy-apply":
            return {"operation": "apply", "changed": True, "rollback_ready": True}
        if action == "devsy-check":
            return {**plan, "status": "changes-required"}
        if action == "smoke":
            return {"native_read": {"status": "PASS"}}
        if action in {"devsy-rollback", "rollback-commit"}:
            return {"restored": True}
        if action == "lifecycle-check":
            return {"healthy": True}
        raise AssertionError(f"unexpected VM action: {action}")

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    payload = d.devsy_payload()
    native = {"target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
              "thread_id": "12345678-1234-5678-9abc-def012345678"}
    sync = []
    try:
        with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
             patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "sync_source", side_effect=lambda sha: sync.append(sha)), \
             patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            with pytest.raises(RuntimeError, match="previous host state restored"):
                d.execute(args("devsy-apply", host_approve=True, native=native))
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert ("devsy-rollback", payload) in calls
    assert ("rollback-commit", {"current": current, "previous": None}) in calls
    assert sync == ["b" * 40, before["source_sha"]]
    assert "commit" not in [action for action, _ in calls]


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_source_sync_failure_is_inside_protected_deployment_path(rollback_fails):
    before = generation()
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == 'memoryd-inventory':
            return {'status':'ABSENT'}
        if action == "snapshot":
            return before
        if action == "current":
            return before
        if action in {"network-check", "image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "devsy-check":
            return {"status": "current"}
        if action == "smoke":
            return {"native_read": {"status": "PASS"}}
        return {}

    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), \
         patch.object(d, "prove_images", return_value={}), \
         patch.object(d, "sync_source", side_effect=RuntimeError("secret-source-detail")), \
         patch.object(d, "restore", side_effect=RuntimeError("secret-rollback-detail") if rollback_fails else None) as restore, patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(RuntimeError, match="Deployment failed at source-sync") as error:
            d.execute(args("deploy", approve=True, native={
                "target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
                "thread_id": "12345678-1234-5678-9abc-def012345678",
            }))

    restore.assert_called_once()
    assert "secret" not in str(error.value)
    assert ("automatic rollback FAILED" if rollback_fails else "previous generation restored") in str(error.value)


def test_adoption_network_conflict_is_rejected_before_stopping_compose():
    before = generation(authority="compose")
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "snapshot":
            return before
        if action == "current":
            return before
        if action == "network-check":
            raise ValueError("foreign network conflict")
        if action in {"image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        return {}

    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), \
         patch.object(d, "prove_images", return_value={}), \
         patch.object(d, "sync_source"), patch.object(d, "restore"), \
         patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(ValueError, match="foreign network conflict"):
            d.execute(args("adopt", approve=True, native={
                "target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
                "thread_id": "12345678-1234-5678-9abc-def012345678",
            }))

    assert "compose-stop" not in calls


def test_adoption_network_check_precedes_compose_stop():
    before = generation(authority="compose")
    after = generation(authority="kamal")
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == 'memoryd-inventory':
            return {'status':'ABSENT'}
        if action == "snapshot":
            return before if calls.count("snapshot") == 1 else after
        if action == "current":
            return before
        if action in {"image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "devsy-check":
            return {"status": "current"}
        if action == "smoke":
            return {"native_read": {"status": "PASS"}}
        return {}

    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), patch.object(d, "sync_source"), \
         patch.object(d, "prove_images", return_value={}), patch.object(d, "kamal"), \
         patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        d.execute(args("adopt", approve=True, native={
            "target": "local", "cwd": "/home/operator/worktree/mcp-tunnel-kit",
            "thread_id": "12345678-1234-5678-9abc-def012345678",
        }))

    assert calls.index("network-check") < calls.index("compose-stop")


def test_compose_rollback_keeps_foreign_network_and_restarts_compose(tmp_path):
    previous = generation(authority="compose")
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "inventory":
            return {"kamal_present": []}
        if action == "remove-network":
            return {"skipped_foreign": True}
        if action == "snapshot":
            return previous
        return {}

    with patch.object(d, "remote", side_effect=remote), patch.object(d, "sync_source") as sync_source:
        restored = d.restore(previous, tmp_path)

    sync_source.assert_called_once_with(previous["source_sha"])
    assert restored["identity"] == previous["identity"]
    assert calls.index("remove-network") < calls.index("compose-start")
    assert calls.count("compose-start") == 1


def test_kamal_rollback_restores_previous_source_sha(tmp_path):
    previous = generation(source_sha="a" * 40)
    current = generation(source_sha="b" * 40)
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "inventory":
            return {"kamal_present": []}
        if action == "snapshot":
            return previous
        return {}

    with patch.object(d, "remote", side_effect=remote), patch.object(d, "sync_source") as sync_source, \
         patch.object(d, "kamal"):
        d.restore(previous, tmp_path)

    sync_source.assert_called_once_with(previous["source_sha"])
    assert "smoke" in calls


def test_bootstrap_is_blocked_when_kamal_owns_deployment(tmp_path):
    state = tmp_path / "deployment"
    state.mkdir()
    receipt = state / "current.json"
    receipt.write_text('{"authority":"kamal"}')
    receipt.chmod(0o600)
    config = {"x-operator": {"devsy_state": str(tmp_path / "devsy-bridge")}}

    with patch.object(c, "config", return_value=config), patch.object(c, "command") as command:
        with pytest.raises(c.ControlError, match="Kamal owns"):
            c.guard_kamal_owner("bootstrap")

    command.assert_not_called()


def test_cas_backup_does_not_pause_or_copy_executor(tmp_path):
    state = tmp_path / "state"
    database = state / "cas/runtime/server.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE proof (value TEXT)")
        connection.execute("INSERT INTO proof VALUES ('cas-only')")
    (state / "cas-targets.json").write_text("{}")

    with patch.object(h, "STATE", state), patch.object(h, "STORE", tmp_path / "store"), \
         patch.object(h, "run") as run:
        result = h.backup_cas()

    run.assert_not_called()
    assert result["executor_untouched"] is True
    with tarfile.open(Path(result["cas_backup"]) / "cas-essential.tar") as archive:
        members = {member.name for member in archive.getmembers()}
        mapping = json.load(archive.extractfile("databases/manifest.json"))
    assert "cas-targets.json" in members
    assert any(name.startswith("databases/") for name in members)
    assert mapping["databases"] == [{"relative_path": "cas/runtime/server.db", "snapshot": mapping["databases"][0]["snapshot"]}]
    assert not any("executor" in name or "tunnel" in name for name in members)


def test_full_backup_captures_recovery_inputs_and_consistent_database_map(tmp_path):
    instance=json.loads((ROOT / "config/instance.example.json").read_text())
    state=tmp_path/"state";repo=tmp_path/"repo";native=tmp_path/"native-ssh"
    devsy=tmp_path/"devsy";context=devsy/"contexts/default"
    for directory in (state/"cas/runtime",state/"cas",state/"cas/receipts",state/"secrets",
                      state/"bootstrap",state/"deployment",repo,native,context):directory.mkdir(parents=True,exist_ok=True)
    real_subprocess_run=subprocess.run
    for command in (["git","init","--quiet",str(repo)],
                    ["git","-C",str(repo),"config","user.name","fixture"],
                    ["git","-C",str(repo),"config","user.email","fixture@example.invalid"]):
        real_subprocess_run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (repo/".gitignore").write_text(".env\n")
    (repo/"runtime.py").write_text("runtime fixture\n")
    real_subprocess_run(["git","-C",str(repo),"add",".gitignore","runtime.py"],check=True,stdout=subprocess.DEVNULL)
    real_subprocess_run(["git","-C",str(repo),"commit","--quiet","-m","fixture"],check=True,stdout=subprocess.DEVNULL)
    source_sha=real_subprocess_run(["git","-C",str(repo),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
    instance["vm"].update(repo_dir=str(repo),state_dir=str(state),native_ssh_dir=str(native))
    instance["vm"]["devsy"]={"config_source":str(devsy/"config.yaml"),"context_dir":str(context),
        "kubeconfig_source":str(devsy/"operator-kubeconfig.json"),"context":"default"}
    for path in (state/"cas-targets.json",devsy/"config.yaml",devsy/"operator-kubeconfig.json",
                 context/"connection.json",state/"start-host-devsy.py",repo/".env"):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text("fixture\n");path.chmod(0o600)
    for name in ("ssh_config.native","known_hosts.native","identity"):
        path=native/name;path.write_text("fixture\n");path.chmod(0o600)
    current=state/"deployment/current.json";current.write_text(json.dumps({"authority":"kamal","source_sha":source_sha})+"\n");current.chmod(0o600)
    previous=state/"deployment/previous.json";previous.write_text('{"generation":1}\n');previous.chmod(0o600)
    database=state/"cas/runtime/server.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE proof (value TEXT)")
        connection.execute("INSERT INTO proof VALUES ('consistent-copy')")
    h.configure_profile(instance)
    events=[]
    class Guard:
        def terminate(self):events.append("guard-terminate")
        def wait(self,timeout=None):events.append("guard-wait")
    def run(command,*args,**kwargs):
        if command and command[0]=="git":
            return real_subprocess_run(command,capture_output=True,check=True).stdout
        events.append(command[1] if command[:1]==["docker"] else "run")
        return b""
    def cp(command,stdout=None,**kwargs):
        events.append("docker-cp")
        return type("Result",(),{"returncode":0})()
    with patch.object(h,"inspect",return_value=("kamal",{"kamal":{"executor":{"Id":"executor-id"}}},[])), \
         patch.object(h,"run",side_effect=run), \
         patch.object(h,"subprocess",SimpleNamespace(Popen=lambda *args,**kwargs:Guard(),run=cp,DEVNULL=subprocess.DEVNULL)):
        result=h.backup()
    assert "memoryd" not in result
    assert events.index("pause") < events.index("docker-cp") < events.index("unpause")
    assert events[-2:]==["guard-terminate","guard-wait"]
    backup=Path(result["backup"])
    bundle=backup/"runtime-source.bundle"
    assert bundle.is_file() and bundle.stat().st_mode&0o777==0o600
    heads=real_subprocess_run(["git","-C",str(repo),"bundle","list-heads",str(bundle)],check=True,capture_output=True,text=True).stdout.split()
    assert heads==[source_sha,"HEAD"]
    with tarfile.open(backup/"essential.tar") as archive:
        members=set(archive.getnames())
        mapping=json.load(archive.extractfile("cas-databases/manifest.json"))
    assert {"native-ssh/identity","devsy-operator/config.yaml",
            "devsy-operator/contexts/default/connection.json","devsy-operator/operator-kubeconfig.json",
            "start-host-devsy.py","deployment/current.json","deployment/previous.json",
            "cas/receipts"} <= members
    assert mapping["databases"]==[{"relative_path":"cas/runtime/server.db","snapshot":mapping["databases"][0]["snapshot"]}]
    copied=backup/"cas-databases"/mapping["databases"][0]["snapshot"]
    with sqlite3.connect(copied) as connection:
        assert connection.execute("SELECT value FROM proof").fetchone()==("consistent-copy",)
    assert "cas/runtime/server.db" not in members
    assert not any("runtime-source.bundle" in name for name in members)

    memoryd_state = {"status": "absent"}
    events.clear()
    def wait_for_executor(owner, name):
        assert (owner, name) == ("kamal", "executor")
        events.append("executor-ready")
    def capture_after_health(*_args, **_kwargs):
        events.append("memoryd-capture")
        return memoryd_state
    with patch.object(h,"inspect",return_value=("kamal",{"kamal":{"executor":{"Id":"executor-id"}}},[])), \
         patch.object(h,"run",side_effect=run), \
         patch.object(h,"subprocess",SimpleNamespace(Popen=lambda *args,**kwargs:Guard(),run=cp,DEVNULL=subprocess.DEVNULL)), \
         patch.object(h,"memoryd_capture_preflight",return_value=memoryd_state), \
         patch.object(h,"wait_service",side_effect=wait_for_executor), \
         patch.object(h,"capture_memoryd",side_effect=capture_after_health) as capture:
        recovery=h.backup(include_memoryd=True)
    assert recovery["memoryd"] == memoryd_state
    assert events.index("unpause") < events.index("executor-ready") < events.index("memoryd-capture")
    capture.assert_called_once_with(Path(recovery["backup"])/"memoryd", expected=memoryd_state)

    events.clear()
    with patch.object(h,"inspect",return_value=("kamal",{"kamal":{"executor":{"Id":"executor-id"}}},[])), \
         patch.object(h,"run",side_effect=run), \
         patch.object(h,"subprocess",SimpleNamespace(Popen=lambda *args,**kwargs:Guard(),run=cp,DEVNULL=subprocess.DEVNULL)), \
         patch.object(h,"memoryd_capture_preflight",return_value=memoryd_state), \
         patch.object(h,"wait_service",side_effect=ValueError("health deadline")), \
         patch.object(h,"capture_memoryd") as capture:
        with pytest.raises(ValueError,match="health deadline"):
            h.backup(include_memoryd=True)
    assert "unpause" in events
    capture.assert_not_called()


def test_runtime_source_bundle_is_clonable_at_the_recorded_clean_revision(tmp_path):
    repo,source_sha=runtime_repo(tmp_path)
    directory=tmp_path/"snapshot";directory.mkdir(mode=0o700)
    assert h.recorded_runtime_source_sha()==source_sha
    bundle=h.create_runtime_source_bundle(directory,source_sha)
    clone=tmp_path/"offline-clone"
    subprocess.run(["git","clone",str(bundle),str(clone)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    actual=subprocess.run(["git","-C",str(clone),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
    assert actual==source_sha
    assert subprocess.run(["git","-C",str(clone),"status","--porcelain"],check=True,capture_output=True,text=True).stdout==""


@pytest.mark.parametrize("drift",["dirty","head"])
def test_full_backup_refuses_source_drift_before_inspect_or_snapshot(tmp_path,drift):
    repo,source_sha=runtime_repo(tmp_path)
    if drift=="dirty":
        (repo/"runtime.py").write_text("uncommitted runtime change\n")
    else:
        (repo/"runtime.py").write_text("different committed runtime\n")
        subprocess.run(["git","-C",str(repo),"add","runtime.py"],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(["git","-C",str(repo),"commit","--quiet","-m","drift"],check=True,stdout=subprocess.DEVNULL)
    with patch.object(h,"validate_profile"),patch.object(h,"inspect") as inspect:
        with pytest.raises(ValueError,match="Runtime source checkout"):
            h.backup()
    inspect.assert_not_called()
    assert not (h.STORE/"backups").exists()


def test_remove_network_leaves_foreign_network_untouched(tmp_path, monkeypatch):
    instance=json.loads((ROOT / "config/instance.example.json").read_text())
    instance["vm"]["state_dir"]=str(tmp_path / "state")
    Path(instance["vm"]["state_dir"]).mkdir()
    foreign = [{"Name": "mcp-control-plane", "Id": "foreign-id", "Labels": {"owner": "someone-else"},
                "Containers": {}}]
    docker_calls = []

    def run(command, *args, **kwargs):
        docker_calls.append(command)
        if command[:4] == ["docker", "network", "ls", "--filter"]:
            return b"foreign-id"
        if command[:3] == ["docker", "network", "inspect"]:
            return json.dumps(foreign).encode()
        raise AssertionError(f"Unexpected host command: {command}")

    monkeypatch.setattr(h, "run", run)
    monkeypatch.setattr(sys, "argv", ["-c", "remove-network", encode(instance)])

    old_umask = os.umask(0o077)
    try:
        h.main()
    finally:
        os.umask(old_umask)

    assert not any(command[:3] == ["docker", "network", "rm"] for command in docker_calls)


def test_vm_operator_entrypoint_loads_default_and_explicit_profiles(tmp_path):
    instance=json.loads((ROOT / "config/instance.example.json").read_text())
    with patch.object(h,"load_instance_profile",return_value=instance) as loader:
        action,value=h.invocation_profile(["vm_deploy_host.py","status"])
    assert (action,value)==("status",instance)
    loader.assert_called_once_with(None)

    profile_path=tmp_path/"instance.json"
    profile_path.write_text(json.dumps(instance));profile_path.chmod(0o600)
    with patch.object(h,"load_instance_profile",return_value=instance) as loader:
        action,value=h.invocation_profile(["vm_deploy_host.py","restart-local","--instance-profile",str(profile_path)])
    assert (action,value)==("restart-local",instance)
    loader.assert_called_once_with(str(profile_path))


def test_missing_local_profile_fails_before_vm_state_creation(tmp_path,monkeypatch):
    state=tmp_path/"must-not-create"
    monkeypatch.setattr(sys,"argv",["vm_deploy_host.py","status","--instance-profile",str(tmp_path/"missing.json")])
    with patch.object(h,"STORE",state),patch.object(h,"load_instance_profile",side_effect=ValueError("Private instance profile is missing")), \
         patch.object(h,"configure_profile") as configure:
        with pytest.raises(ValueError,match="Private instance profile is missing"):
            h.main()
    configure.assert_not_called()
    assert not state.exists()


def test_remote_encoded_profile_path_remains_supported():
    instance=json.loads((ROOT / "config/instance.example.json").read_text())
    action,value=h.invocation_profile(["-c","status",encode(instance)])
    assert action=="status"
    assert value==instance


def test_explicit_rollback_recovers_unhealthy_generation_without_healthy_precondition():
    previous=generation(authority='kamal');calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action=='memoryd-inventory':return {'status':'ABSENT'}
        if action in ('current','rollback-target'):return previous
        if action=='status':return {'inventory':{'executor':{'state':'running'},'cas':{'state':'exited'}},'healthy':False}
        if action=='snapshot':raise AssertionError('Broken deployment cannot satisfy healthy snapshot')
        return {}
    with patch.object(d,'trusted_context'),patch.object(d,'lock',return_value=nullcontext()),patch.object(d,'remote',side_effect=remote),patch.object(d,'prove_images',return_value={}),patch.object(d,'restore',return_value=previous) as restore,patch.dict(os.environ,{'GITHUB_SHA':'b'*40}):
        result=d.execute(args('rollback',approve=True))
    assert result['identity_preserved'] is True
    restore.assert_called_once()
    assert 'snapshot' not in calls and 'rollback-commit' in calls


@pytest.mark.parametrize(("failure", "expected_stage"), [
    ("host-apply-preflight", "source-restore"),
    ("source-restore", "source-restore"),
    ("host-devsy-restore", "host-devsy-restore"),
    ("control-plane-snapshot", "control-plane-snapshot"),
    ("control-plane-snapshot-invalid", "control-plane-snapshot"),
    ("devsy-plan", "devsy-plan"),
    ("devsy-plan-service-active", "devsy-plan:service_active"),
    ("generation-commit", "generation-commit"),
    ("source-and-plan", "source-restore,devsy-plan"),
    ("snapshot-and-plan", "control-plane-snapshot,devsy-plan"),
    ("source-snapshot-plan",
     "source-restore,control-plane-snapshot,devsy-plan"),
])
def test_host_devsy_apply_reports_outer_rollback_stage_without_remote_details(
        failure, expected_stage):
    before = generation(source_sha="a" * 40)
    before.update(authority="kamal", tunnel_count=1)
    current = {**before, "publication_proof": {}}
    plan = missing_pinned_kubectl_plan()
    calls = []
    snapshot_count = 0
    plan_count = 0
    sync_count = 0

    def remote(action, data=None):
        nonlocal snapshot_count, plan_count
        calls.append(action)
        if action == "snapshot":
            snapshot_count += 1
            if failure == "control-plane-snapshot" and snapshot_count == 2:
                raise RuntimeError("secret-snapshot-detail")
            if failure in {
                    "control-plane-snapshot-invalid", "snapshot-and-plan",
                    "source-snapshot-plan"} and snapshot_count == 2:
                return None
            return before
        if action == "lifecycle-check":
            return {"healthy": True}
        if action == "current":
            return current
        if action == "previous":
            return None
        if action == "devsy-plan":
            plan_count += 1
            if failure == "devsy-plan-service-active" and plan_count == 2:
                return {**plan, "service_active": False}
            if failure in {
                    "devsy-plan", "source-and-plan", "snapshot-and-plan",
                    "source-snapshot-plan"} and plan_count == 2:
                raise RuntimeError("secret-plan-detail")
            return plan
        if action == "devsy-apply":
            if failure == "host-apply-preflight":
                raise RuntimeError(
                    "VM devsy-apply refused; Deployment boundary refused: "
                    "Devsy apply stopped before provider or Devsy changes: "
                    "ROR Kubernetes authentication failed; staged kubectl was rolled back"
                )
            if failure == "host-devsy-restore":
                return {"operation": "apply", "changed": True}
            raise RuntimeError("secret-apply-detail")
        if action == "devsy-check":
            raise RuntimeError("secret-drift-detail")
        if action == "devsy-rollback":
            if failure == "host-devsy-restore":
                raise RuntimeError("secret-host-rollback-detail")
            return {"restored": True}
        if action == "rollback-commit":
            if failure == "generation-commit":
                raise RuntimeError("secret-generation-detail")
            return {"rollback_committed": True}
        raise AssertionError(f"unexpected VM action: {action}")

    def sync_source(_sha):
        nonlocal sync_count
        sync_count += 1
        if failure in {
                "host-apply-preflight", "source-restore", "source-and-plan",
                "source-snapshot-plan"} \
                and sync_count == 2:
            raise RuntimeError("secret-source-detail")

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "sync_source", side_effect=sync_source), \
             patch.object(d, "smoke", return_value={}):
            with pytest.raises(RuntimeError, match="automatic rollback FAILED") as error:
                d._apply_host_devsy(
                    {"target": "local", "cwd": "/work/mcp-tunnel-kit",
                     "thread_id": "12345678-1234-5678-9abc-def012345678"},
                    "b" * 40,
                )
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert f"automatic rollback FAILED at {expected_stage}" in str(error.value)
    if failure == "host-devsy-restore":
        assert "host-apply-phase=" not in str(error.value)
    elif failure == "host-apply-preflight":
        assert "host-apply-phase=ror-kubectl:authentication" in str(error.value)
    else:
        assert "host-apply-phase=unclassified" in str(error.value)
    assert "secret-" not in str(error.value)
    assert calls[0] == "snapshot"


@pytest.mark.parametrize(("detail", "expected"), [
    ("pinned Kubernetes kubectl source is unavailable", "kubectl-download:source-unavailable"),
    ("pinned Kubernetes kubectl download timed out", "kubectl-download:timeout"),
    ("pinned Kubernetes kubectl exceeds its size limit", "kubectl-artifact:size-limit"),
    ("pinned Kubernetes kubectl checksum mismatch", "kubectl-artifact:checksum-mismatch"),
    ("kubectl candidate failed pinned source/hash validation", "kubectl-path:untrusted-existing"),
    ("installed pinned kubectl failed source/hash verification", "kubectl-path:verification-failed"),
    ("ROR Kubernetes authentication failed", "ror-kubectl:authentication"),
    ("ROR Kubernetes authorization failed", "ror-kubectl:authorization"),
    ("ROR Kubernetes connection failed", "ror-kubectl:connection"),
    ("ROR Kubernetes connection timed out", "ror-kubectl:connection-timeout"),
    ("ROR Kubernetes admission request rejected", "ror-admission:rejected"),
    ("ROR Kubernetes command failed; raw output withheld", "ror-kubectl:unclassified"),
    ("ROR admission preflight remains blocked: ROR has no ready worker node matching the Devsy selector",
     "ror-admission:no-ready-worker"),
    ("authorized ROR namespace devsy is unavailable", "ror-admission:namespace-unavailable"),
    ("ROR devsy quota or LimitRange changed; resource admission needs review",
     "ror-admission:constraints-changed"),
    ("ROR has no ready worker node matching the Devsy selector",
     "ror-admission:no-ready-worker"),
    ("ROR worker allocatable capacity cannot admit the bounded Devsy request",
     "ror-admission:capacity-insufficient"),
    ("ROR default storage class drift; PVC admission needs review",
     "ror-admission:storage-class-drift"),
    ("ROR returned invalid Kubernetes inventory", "ror-admission:invalid-inventory"),
])
def test_host_devsy_apply_failure_code_classifies_allowlisted_preflight_reasons(detail, expected):
    error = RuntimeError(
        "VM devsy-apply refused; Deployment boundary refused: "
        "Devsy apply stopped before provider or Devsy changes: "
        f"{detail}; staged kubectl was rolled back"
    )

    assert d._host_devsy_apply_failure_code(error) == expected


def test_host_devsy_apply_failure_code_redacts_unknown_and_secret_like_preflight_errors():
    error = RuntimeError(
        "VM devsy-apply refused; Deployment boundary refused: "
        "Devsy apply stopped before provider or Devsy changes: "
        "failed at /private/host/kubeconfig token=secret-value; staged kubectl was rolled back"
    )

    assert d._host_devsy_apply_failure_code(error) == "preflight:unclassified"
    assert "secret-value" not in d._host_devsy_apply_failure_code(error)
    assert d._host_devsy_apply_failure_code(RuntimeError("secret remote detail")) == "unclassified"


def test_host_devsy_apply_failure_code_labels_staging_rollback_failure():
    error = RuntimeError(
        "VM devsy-apply refused; Deployment boundary refused: "
        "Devsy apply stopped before provider or Devsy changes; staged kubectl rollback failed"
    )

    assert d._host_devsy_apply_failure_code(error) == "kubectl-staging:rollback-failed"


def test_host_devsy_apply_failure_code_preserves_existing_allowlisted_phase():
    error = RuntimeError(
        "VM devsy-apply refused; Deployment boundary refused: "
        "Devsy apply failed at provider-readback: "
        "ROR provider readback did not match the approved resource policy; "
        "previous host state restored"
    )

    assert d._host_devsy_apply_failure_code(error) == (
        "provider-readback:provider-policy-mismatch"
    )
    assert d._host_devsy_apply_failure_code(RuntimeError("secret remote detail")) == "unclassified"


def test_host_devsy_apply_successful_outer_rollback_reports_safe_preflight_code():
    before = generation(source_sha="a" * 40)
    before.update(authority="kamal", tunnel_count=1)
    current = {**before, "publication_proof": {}}
    plan = missing_pinned_kubectl_plan()
    calls = []
    snapshot_count = 0
    plan_count = 0
    sync_count = 0

    def remote(action, data=None):
        nonlocal snapshot_count, plan_count
        calls.append(action)
        if action == "snapshot":
            snapshot_count += 1
            return before
        if action == "lifecycle-check":
            return {"healthy": True}
        if action == "current":
            return current
        if action == "previous":
            return None
        if action == "devsy-plan":
            plan_count += 1
            return plan
        if action == "devsy-apply":
            raise RuntimeError(
                "VM devsy-apply refused; Deployment boundary refused: "
                "Devsy apply stopped before provider or Devsy changes: "
                "ROR Kubernetes authorization failed; staged kubectl was rolled back"
            )
        if action == "rollback-commit":
            return {"rollback_committed": True}
        raise AssertionError(f"unexpected VM action: {action}")

    def sync_source(_sha):
        nonlocal sync_count
        sync_count += 1

    instance = json.loads((ROOT / "config/instance.example.json").read_text())
    previous = (d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN)
    d.configure_instance(instance)
    try:
        with patch.object(d, "remote", side_effect=remote), \
             patch.object(d, "sync_source", side_effect=sync_source), \
             patch.object(d, "smoke", return_value={}):
            with pytest.raises(RuntimeError, match="previous host state restored") as error:
                d._apply_host_devsy(
                    {"target": "local", "cwd": "/work/mcp-tunnel-kit",
                     "thread_id": "12345678-1234-5678-9abc-def012345678"},
                    "b" * 40,
                )
    finally:
        d.INSTANCE, d.HOST, d.VMROOT, d.VM_HOST_PIN = previous

    assert "host-apply-phase=ror-kubectl:authorization" in str(error.value)
    assert "secret-" not in str(error.value)
    assert snapshot_count == 2
    assert plan_count == 2
    assert sync_count == 2
    assert calls[-1] == "rollback-commit"
