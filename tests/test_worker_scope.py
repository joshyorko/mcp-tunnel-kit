"""Approved scope uses synthetic effects; no Kubernetes resources are created."""

import importlib.util
import json
from pathlib import Path
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT / "scripts/worker_scope.py"
    assert path.exists(), "Approved scoped lifecycle implementation is missing"
    spec = importlib.util.spec_from_file_location("worker_scope_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manager(tmp_path, invoke=None):
    module = load()
    import hashlib

    scope = json.loads((ROOT / "docs/devsy-worker-scope.proposed.json").read_text())
    scope.update(
        enabled=True,
        expires_at=time.time() + 3600,
        capability_sha256=hashlib.sha256(b"fixture-owner-secret").hexdigest(),
        bindings={},
    )
    config = tmp_path / "scope.json"
    config.write_text(json.dumps(scope))
    config.chmod(0o600)
    rows = {}
    calls = []

    def execute(operation, name, approved):
        calls.append((operation, name))
        if invoke:
            invoke(operation, name, approved)
        rows[name] = {
            "id": name,
            "uid": "fixture-uid",
            "context": "default",
            "provider": {
                "name": "kubernetes",
                "options": {
                    "KUBERNETES_CONTEXT": {"value": "ror"},
                    "KUBERNETES_NAMESPACE": {"value": "devsy"},
                },
            },
            "source": {"gitRepository": approved["repository"]},
        }

    instance = module.WorkerScope(
        config, tmp_path / "jobs", lambda: set(rows), lambda n: rows[n], execute
    )
    return module, instance, calls


def test_anonymous_wrong_credential_and_offscope_inputs_never_submit(tmp_path):
    module, scope, calls = manager(tmp_path)
    for credential in [None, "Bearer wrong"]:
        with pytest.raises(module.ScopeError):
            scope.call(
                "workspace_create_scoped",
                {"name": "cas-worker-01", "request_id": "request-1"},
                credential,
            )
    for body in [
        {"name": "codex-action-server", "request_id": "request-1"},
        {
            "name": "cas-worker-01",
            "request_id": "request-1",
            "source": "https://evil.invalid",
        },
        {"name": "cas-worker-01", "request_id": "request-1", "force": True},
    ]:
        with pytest.raises(module.ScopeError):
            scope.call("workspace_create_scoped", body, "Bearer fixture-owner-secret")
    assert calls == []


def test_short_submission_and_duplicate_return_one_durable_job(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def block(*args):
        entered.set()
        assert release.wait(3)

    _, scope, calls = manager(tmp_path, block)
    first = scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    assert first["status"] == "accepted"
    assert entered.wait(3)
    second = scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "retry-with-new-id"},
        "Bearer fixture-owner-secret",
    )
    assert first["operation_id"] == second["operation_id"]
    release.set()
    scope.wait()
    status = scope.call(
        "workspace_status_scoped",
        {"name": "cas-worker-01"},
        "Bearer fixture-owner-secret",
    )
    assert status["status"] == "completed"
    assert status["workspace_uid"] == "fixture-uid"
    assert calls == [("create", "cas-worker-01")]


def test_recovered_unfinished_job_is_unknown_never_restarted(tmp_path):
    _, scope, calls = manager(tmp_path)
    scope.state.mkdir(mode=0o700)
    (scope.state / "cas-worker-01.json").write_text(
        json.dumps(
            {
                "name": "cas-worker-01",
                "operation_id": "prior",
                "status": "running",
                "operation": "create",
            }
        )
    )
    (scope.state / "cas-worker-01.json").chmod(0o600)
    result = scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "new"},
        "Bearer fixture-owner-secret",
    )
    assert result["status"] == "outcome_unknown"
    assert calls == []


def test_start_requires_owned_uid_and_rejects_replacement(tmp_path):
    module, scope, calls = manager(tmp_path)
    with pytest.raises(module.ScopeError):
        scope.call(
            "workspace_start_scoped",
            {"name": "cas-worker-01", "request_id": "start-1"},
            "Bearer fixture-owner-secret",
        )
    assert calls == []
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "create-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    original = scope.metadata
    scope.metadata = lambda n: {**original(n), "uid": "replacement"}
    with pytest.raises(module.ScopeError):
        scope.call(
            "workspace_start_scoped",
            {"name": "cas-worker-01", "request_id": "start-1"},
            "Bearer fixture-owner-secret",
        )
    assert calls == [("create", "cas-worker-01")]


def test_expired_capability_and_configuration_drift_fail_closed(tmp_path):
    module, scope, calls = manager(tmp_path)
    data = json.loads(scope.config.read_text())
    data["expires_at"] = time.time() - 1
    scope.config.write_text(json.dumps(data))
    with pytest.raises(module.ScopeError):
        scope.call(
            "workspace_create_scoped",
            {"name": "cas-worker-01", "request_id": "request-1"},
            "Bearer fixture-owner-secret",
        )
    assert calls == []


def test_persistent_capability_has_no_expiry_but_can_be_revoked(tmp_path):
    module, scope, calls = manager(tmp_path)
    data = json.loads(scope.config.read_text())
    data["expires_at"] = None
    scope.config.write_text(json.dumps(data))
    result = scope.call(
        "workspace_status_scoped",
        {"name": "cas-worker-01"},
        "Bearer fixture-owner-secret",
    )
    assert result["status"] == "not_submitted"
    data["enabled"] = False
    scope.config.write_text(json.dumps(data))
    with pytest.raises(module.ScopeError):
        scope.call(
            "workspace_create_scoped",
            {"name": "cas-worker-01", "request_id": "revoked"},
            "Bearer fixture-owner-secret",
        )
    assert calls == []
