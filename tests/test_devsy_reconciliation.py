"""Absence admission proofs use synthetic commands and process/provider fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def proof(tmp_path, monkeypatch):
    path = ROOT / "scripts/devsy_reconciliation.py"
    assert path.exists(), "Guarded absence reconciliation is missing"
    spec = importlib.util.spec_from_file_location("devsy_reconciliation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proc = tmp_path / "proc"
    proc.mkdir()
    monkeypatch.setattr(module, "PROC_ROOT", proc)
    kube = tmp_path / ".kube/config"
    kube.parent.mkdir()
    kube.write_text("approved fixture")
    kubectl = tmp_path / "kubectl"
    kubectl.write_text("#!/bin/sh\nexit 99\n")
    kubectl.chmod(0o700)
    env = {"HOME": str(tmp_path), "PATH": str(tmp_path), "DEVSY_HOME": str(tmp_path / "devsy")}
    scope = {"context": "default", "provider": "kubernetes", "kubernetes_context": "ror",
             "namespace": "devsy", "allowed_new_names": ["cas-worker-01"],
             "issued_at": 1791482322.0680528,
             "recovery_cutoff": 1791482322.0680528,
             "protected_names": ["codex-action-server"],
             "bindings": {str(kube): hashlib.sha256(kube.read_bytes()).hexdigest()}}
    outputs = {"inventory": [], "namespace": {"metadata": {"uid": "namespace-123", "name": "devsy"}},
               "resources": {"items": []}, "volumes": {"items": []},
               "auxiliary_resources": "ConfigMap kube-root-ca.crt 00000000-0000-4000-8000-000000000001 2026-09-09T00:00:00Z\nServiceAccount default 00000000-0000-4000-8000-000000000002 2026-09-09T00:00:00Z\n"}
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs["env"] == env and kwargs["cwd"] == str(tmp_path)
        assert 0 < kwargs["timeout"] <= 15
        if args[0] == "/fixture/devsy":
            assert args == ["/fixture/devsy", "--context", "default", "--result-format", "json",
                            "workspace", "list", "--skip-pro"]
            key = "inventory"
        else:
            assert args[0] == str(kubectl)
            assert args[1:6] == ["--kubeconfig", str(kube), "--context", "ror", "--request-timeout=5s"]
            assert args[-2:] == ["-o", "json"] or args[-3:] == ["-o", "custom-columns=KIND:.kind,NAME:.metadata.name,UID:.metadata.uid,CREATED:.metadata.creationTimestamp", "--no-headers"]
            if "namespace" in args:
                key = "namespace"
            elif "persistentvolumes" in args:
                key = "volumes"
            elif args[-1] == "--no-headers":
                assert args[args.index("get") + 1] == "secrets,configmaps,roles,rolebindings,serviceaccounts"
                assert "--namespace" in args and args[args.index("--namespace") + 1] == "devsy"
                key = "auxiliary_resources"
            else:
                assert "--namespace" in args and args[args.index("--namespace") + 1] == "devsy"
                for resource in ("pods", "persistentvolumeclaims", "jobs", "deployments", "statefulsets",
                                 "daemonsets", "replicasets", "cronjobs", "services", "replicationcontrollers"):
                    assert resource in args[args.index("get") + 1].split(",")
                key = "resources"
        value = outputs[key]
        if callable(value):
            value = value()
        if isinstance(value, Exception):
            raise value
        return SimpleNamespace(returncode=0, stdout=value if key == "auxiliary_resources" else json.dumps(value), stderr="SECRET")

    monkeypatch.setattr(module.subprocess, "run", run)
    return SimpleNamespace(module=module, root=tmp_path, proc=proc, kube=kube, env=env,
                           scope=scope, outputs=outputs, calls=calls,
                           check=lambda: module.absence_proof("/fixture/devsy", str(tmp_path), env, scope, "cas-worker-01"))


def test_empty_bound_provider_and_inventory_prove_absence(proof):
    result = proof.check()
    assert result["kind"] == "absent"
    assert result["namespace_uid"] == "namespace-123"
    assert result["kubernetes_context"] == "ror" and result["namespace"] == "devsy"
    assert result["workspace_absent"] is True and result["provider_resources_absent"] is True
    assert result["lifecycle_processes_absent"] is True
    assert result["observed_at"] > 0
    assert "SECRET" not in json.dumps(result)
    assert any(args[-1] == "--no-headers" for args in proof.calls)
    assert result["preexisting_auxiliary_count"] == 0
    assert result["recovery_cutoff"] == 1791482322.0680528


@pytest.mark.parametrize("output", ["secret/daemon-key\n", "rolebinding/devsy\n", "role/custom\n",
                                    "configmap/custom\n", "serviceaccount/worker\n", "SECRET invalid json",
                                    "configmap/kube-root-ca.crt\n\nserviceaccount/default\n",
                                    "configmap/kube-root-ca.crt \n", subprocess.TimeoutExpired("SECRET", 5)])
def test_auxiliary_resources_or_malformed_metadata_block_without_emitting_secrets(proof, output):
    proof.outputs["auxiliary_resources"] = output
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert str(error.value) == proof.module.SAFE_ERROR
    assert error.value.phase == "auxiliary_resources"


def test_empty_auxiliary_inventory_is_allowed(proof):
    proof.outputs["auxiliary_resources"] = ""
    assert proof.check()["kind"] == "absent"


def test_old_auxiliary_objects_are_preserved_without_emitting_data(proof):
    proof.outputs["auxiliary_resources"] += "Secret old-pull-secret 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z\nConfigMap old-systemd-ready 00000000-0000-4000-8000-000000000004 2026-09-09T00:00:00Z\n"
    result = proof.check()
    assert result["preexisting_auxiliary_count"] == 2
    assert result["recovery_cutoff"] == 1791482322.0680528
    assert "old-pull-secret" not in json.dumps(result)


@pytest.mark.parametrize("row", [
    "Secret partial 00000000-0000-4000-8000-000000000003 2026-10-09T00:00:00Z",
    "Secret partial 00000000-0000-4000-8000-000000000003 <none>",
    "Secret partial 00000000-0000-4000-8000-000000000003 2026-09-09",
    "Secret partial <none> 2026-09-09T00:00:00Z",
    "Secret partial invalid-uid 2026-09-09T00:00:00Z",
    "Secret <none> 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z",
    "Unknown partial 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z",
    "Secret partial 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z unexpected",
])
def test_new_or_unverifiable_auxiliary_object_blocks_recovery(proof, row):
    proof.outputs["auxiliary_resources"] = row + "\n"
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert error.value.phase == "auxiliary_resources"


@pytest.mark.parametrize("cutoff", [None, "1791482322.0680528", False, 0, -1, float("nan"), float("inf"), 1e20])
def test_old_objects_require_valid_numeric_immutable_cutoff(proof, cutoff):
    proof.scope["recovery_cutoff"] = cutoff
    proof.outputs["auxiliary_resources"] = "Secret old-pull-secret 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z\n"
    with pytest.raises(proof.module.ReconciliationError):
        proof.check()


@pytest.mark.parametrize("cutoff,created", [(1.0, "1970-01-01T00:00:01Z"),
                                            (1.0000001, "1970-01-01T00:00:01.0000001Z")])
def test_equal_creation_and_cutoff_timestamps_are_not_preexisting(proof, cutoff, created):
    proof.scope["recovery_cutoff"] = cutoff
    proof.outputs["auxiliary_resources"] = f"Secret partial 00000000-0000-4000-8000-000000000003 {created}\n"
    with pytest.raises(proof.module.ReconciliationError):
        proof.check()


def test_renewed_grant_cannot_reclassify_operation_remnants_as_preexisting(proof):
    proof.scope["recovery_cutoff"] = 1.0
    proof.scope["issued_at"] = 3.0
    proof.outputs["auxiliary_resources"] = "Secret partial 00000000-0000-4000-8000-000000000003 1970-01-01T00:00:02Z\n"
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert error.value.phase == "auxiliary_resources"


def test_missing_immutable_cutoff_never_falls_back_to_current_grant(proof):
    del proof.scope["recovery_cutoff"]
    proof.outputs["auxiliary_resources"] = "Secret old-pull-secret 00000000-0000-4000-8000-000000000003 2026-09-09T00:00:00Z\n"
    with pytest.raises(proof.module.ReconciliationError):
        proof.check()


@pytest.mark.parametrize("key,value", [
    ("inventory", [{"id": "cas-worker-01"}]),
    ("inventory", {"error": "SECRET"}),
    ("inventory", [None]),
    ("inventory", [{"id": ""}]),
    ("resources", {"items": [{"metadata": {"name": "partial-pod"}}]}),
    ("resources", {"kind": "Status", "message": "SECRET"}),
    ("resources", {"items": [], "error": "SECRET"}),
    ("namespace", {"metadata": {"uid": ""}}),
    ("volumes", {"items": [{"metadata": {"name": "partial-pv"}, "spec": {"claimRef": {"namespace": "devsy"}}}]}),
    ("volumes", {"items": [{"metadata": {"name": "partial-pv", "labels": {"devsy.sh/workspace": "partial"}}, "spec": {}}]}),
    ("volumes", {"items": [None]}),
    ("volumes", {"items": [{}]}),
    ("volumes", {"items": [{"metadata": {}, "spec": {}}]}),
    ("volumes", {"items": [{"metadata": {"name": "partial-pv"}, "spec": {"claimRef": {"name": "unresolved"}}}]}),
    ("resources", subprocess.TimeoutExpired("SECRET", 5)),
])
def test_partial_or_unreadable_evidence_fails_closed_without_diagnostics_leak(proof, key, value):
    proof.outputs[key] = value
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert "SECRET" not in str(error.value)
    assert str(error.value) == proof.module.SAFE_ERROR
    assert error.value.phase == key


@pytest.mark.parametrize("change", ["unbound", "multiple", "drift", "wrong_name", "wrong_provider"])
def test_configuration_is_bound_before_queries(proof, change):
    if change == "unbound":
        proof.scope["bindings"] = {}
    elif change == "multiple":
        proof.env["KUBECONFIG"] = str(proof.kube) + ":/other"
    elif change == "drift":
        proof.kube.write_text("changed")
    elif change == "wrong_name":
        proof.scope["allowed_new_names"] = []
    else:
        proof.scope["provider"] = "docker"
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert not proof.calls
    assert error.value.phase == "configuration"


def test_configuration_drift_during_query_invalidates_evidence(proof):
    def drift():
        proof.kube.write_text("changed during query")
        return {"items": []}
    proof.outputs["volumes"] = drift
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert error.value.phase == "recheck"


@pytest.mark.parametrize("argv", [
    ["python", "/scripts/devsy_bridge.py", "--scoped-child", "scope.json"],
    ["/fixture/devsy", "--context", "default", "workspace", "up", "git:source"],
    ["/fixture/devsy", "workspace", "create", "cas-worker-01"],
    ["/fixture/devsy", "workspace", "start", "cas-worker-01"],
])
def test_live_lifecycle_process_prevents_absence_admission(proof, argv):
    process = proof.proc / "123"
    process.mkdir()
    (process / "cmdline").write_bytes(b"\0".join(value.encode() for value in argv))
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert not proof.calls
    assert error.value.phase == "processes"


def test_new_process_during_queries_invalidates_evidence(proof):
    def new_process():
        process = proof.proc / "123"
        process.mkdir()
        (process / "cmdline").write_bytes(b"devsy\0workspace\0up\0cas-worker-01\0")
        return {"items": []}
    proof.outputs["volumes"] = new_process
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert error.value.phase == "recheck"


@pytest.mark.parametrize("status", ["pending", "running"])
def test_matching_pending_native_task_prevents_admission(proof, status):
    tasks = Path(proof.env["DEVSY_HOME"]) / "state/tasks"
    tasks.mkdir(parents=True)
    (tasks / "task.json").write_text(json.dumps({"id": "fixture-task", "command": "up", "status": status,
                                               "workspaceId": "cas-worker-01", "startedAt": "2026-10-09T14:35:00Z",
                                               "updatedAt": "2026-10-09T14:35:00Z"}))
    with pytest.raises(proof.module.ReconciliationError) as error:
        proof.check()
    assert error.value.phase == "tasks"


def test_unrelated_tasks_and_other_namespace_volumes_do_not_block(proof):
    tasks = Path(proof.env["DEVSY_HOME"]) / "state/tasks"
    tasks.mkdir(parents=True)
    (tasks / "task.json").write_text(json.dumps({"status": "running", "workspace": "dakota"}))
    proof.outputs["volumes"] = {"items": [{"metadata": {"name": "dakota-pv", "labels": {"devsy.sh/workspace": "dakota"}},
                                              "spec": {"claimRef": {"namespace": "dakota"}}}]}
    assert proof.check()["kind"] == "absent"
