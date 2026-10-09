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
        result = None
        if invoke:
            result = invoke(operation, name, approved)
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
        return result

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
    running = scope.read("cas-worker-01")
    assert running["status"] == "running"
    assert isinstance(running["started_at"], (int, float))
    assert "finished_at" not in running
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
    assert status["finished_at"] >= status["started_at"]
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
    assert result["retry_safe"] is False
    assert result["error_code"] == "lifecycle_outcome_unknown"
    assert result["diagnostics"]["phase"] == "worker_lost"
    assert calls == []


@pytest.mark.parametrize(
    "invoked,expected",
    [(True, "outcome_unknown"), (None, "outcome_unknown"), (False, "failed")],
)
def test_nonzero_invocation_retains_safe_diagnostics_without_replay(
    tmp_path, invoked, expected
):
    diagnostics = {
        "phase": "devsy_exit",
        "exit_code": 1,
        "devsy_invoked": invoked,
        "stderr_code": "devsy_command_failed",
        "stderr": "fixture-secret-raw-stderr",
    }
    _, scope, calls = manager(tmp_path, lambda *args: diagnostics)
    scope.metadata = lambda name: pytest.fail(
        "Nonzero invocation must not verify metadata"
    )
    accepted = scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    record = scope.read("cas-worker-01")
    assert record["status"] == expected
    assert record["diagnostics"] == {
        k: v for k, v in diagnostics.items() if k != "stderr"
    }
    assert record["retry_safe"] is False
    assert record["finished_at"] >= record["started_at"]
    assert "fixture-secret" not in json.dumps(record)
    repeated = scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-2"},
        "Bearer fixture-owner-secret",
    )
    assert repeated["operation_id"] == accepted["operation_id"]
    assert calls == [("create", "cas-worker-01")]


def test_invocation_exception_records_only_class_without_secret(tmp_path):
    def fail(*args):
        raise RuntimeError("fixture-secret-exception")

    _, scope, _ = manager(tmp_path, fail)
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    record = scope.read("cas-worker-01")
    assert record["status"] == "outcome_unknown"
    assert record["exception_type"] == "RuntimeError"
    assert record["diagnostics"]["phase"] == "invoke"
    assert record["diagnostics"]["devsy_invoked"] is None
    assert record["finished_at"] >= record["started_at"]
    assert "fixture-secret" not in json.dumps(record)


def test_start_cannot_bypass_unreconciled_outcome_with_known_uid(tmp_path):
    _, scope, calls = manager(tmp_path)
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "create-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    record = scope.read("cas-worker-01")
    record.update(status="outcome_unknown", operation="start", request_id="start-1")
    scope.write("cas-worker-01", record)
    repeated = scope.call(
        "workspace_start_scoped",
        {"name": "cas-worker-01", "request_id": "start-2"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    assert repeated["operation_id"] == record["operation_id"]
    assert repeated["status"] == "outcome_unknown"
    assert calls == [("create", "cas-worker-01")]


def test_approved_execution_context_is_durable_before_invocation(tmp_path):
    observed = []

    def capture(*args):
        observed.append(scope.read("cas-worker-01"))

    _, scope, _ = manager(tmp_path, capture)
    approved = json.loads(scope.config.read_text())
    approved["binary"] = "/fixture/bin/devsy"
    approved["extra_secret"] = "fixture-secret-not-for-receipts"
    scope.config.write_text(json.dumps(approved))
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    expected = {
        key: approved[key]
        for key in (
            "context", "provider", "kubernetes_context", "namespace",
            "repository", "revision", "recipe", "binary",
        )
    }
    assert observed[0]["execution_context"] == expected
    record = scope.read("cas-worker-01")
    assert record["execution_context"] == expected
    assert expected["revision"] == "bf0b3823e033b9b5abd86904e0a565d6b3586206"
    assert expected["context"] == "default"
    serialized = json.dumps(record)
    for forbidden in ("capability_sha256", "bindings", "fixture-secret", "extra_secret"):
        assert forbidden not in serialized


def test_failed_verification_keeps_successful_exit_diagnostics(tmp_path):
    diagnostics = {"phase": "devsy_exit", "exit_code": 0, "devsy_invoked": True}
    _, scope, _ = manager(tmp_path, lambda *args: diagnostics)

    def fail(name):
        raise KeyError("fixture-secret-metadata")

    scope.metadata = fail
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    record = scope.read("cas-worker-01")
    assert record["status"] == "outcome_unknown"
    assert record["diagnostics"]["exit_code"] == 0
    assert record["diagnostics"]["devsy_invoked"] is True
    assert record["exception_type"] == "KeyError"
    assert "fixture-secret" not in json.dumps(record)


def test_revalidation_failure_before_invocation_is_known_failed(tmp_path):
    module, scope, calls = manager(tmp_path)
    load_scope = scope.load

    def revoked_after_admission():
        if threading.current_thread() is not threading.main_thread():
            raise module.ScopeError("fixture-secret-revoked")
        return load_scope()

    scope.load = revoked_after_admission
    scope.call(
        "workspace_create_scoped",
        {"name": "cas-worker-01", "request_id": "request-1"},
        "Bearer fixture-owner-secret",
    )
    scope.wait()
    record = scope.read("cas-worker-01")
    assert record["status"] == "failed"
    assert record["error_code"] == "lifecycle_failed"
    assert record["diagnostics"]["devsy_invoked"] is False
    assert record["exception_type"] == "ScopeError"
    assert record["finished_at"] >= record["started_at"]
    assert record["retry_safe"] is False
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
