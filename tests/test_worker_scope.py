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
        execution = approved.get("execution_context", {})
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
            "source": {"gitRepository": approved["repository"],
                       "gitCommit": execution.get("revision")},
            "devContainerPath": execution.get("recipe", approved["recipe"]),
        }
        return result

    def resolve(approved):
        recipe = b'{"name":"remote worker"}\n'
        return {**snapshot("b" * 40), "recipe_snapshot": recipe}

    instance = module.WorkerScope(
        config, tmp_path / "jobs", lambda: set(rows), lambda n: rows[n], execute,
        source_resolver=resolve,
    )
    return module, instance, calls


def snapshot(revision):
    import hashlib

    recipe = b'{"name":"remote worker"}\n'
    return {
        "repository": "https://github.com/joshyorko/codex-action-server.git",
        "source_ref": "refs/heads/main",
        "revision": revision,
        "recipe": ".devcontainer/remote-worker/devcontainer.json",
        "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
        "recipe_snapshot": recipe,
    }


def test_pending_duplicate_reuses_the_first_resolved_main_snapshot(tmp_path):
    entered, release = threading.Event(), threading.Event()
    resolutions = []

    def resolve(_scope):
        resolutions.append("a" * 40)
        return snapshot("a" * 40)

    def block(*_args):
        entered.set()
        assert release.wait(3)

    module = load()
    scope_data = json.loads((ROOT / "docs/devsy-worker-scope.proposed.json").read_text())
    import hashlib
    scope_data.update(enabled=True, expires_at=time.time() + 3600,
                      capability_sha256=hashlib.sha256(b"fixture-owner-secret").hexdigest(),
                      bindings={})
    config = tmp_path / "scope.json"
    config.write_text(json.dumps(scope_data))
    config.chmod(0o600)
    jobs = tmp_path / "jobs"
    scope = module.WorkerScope(config, jobs, lambda: set(), lambda _name: {}, block,
                               source_resolver=resolve)

    first = scope.call("workspace_create_scoped", {"name": NAME, "request_id": "pending"},
                       "Bearer fixture-owner-secret")
    assert entered.wait(3)
    duplicate = scope.call("workspace_create_scoped", {"name": NAME, "request_id": "pending"},
                           "Bearer fixture-owner-secret")
    release.set()
    scope.wait()

    assert first["execution_context"]["revision"] == "a" * 40
    assert duplicate["execution_context"] == first["execution_context"]
    assert resolutions == ["a" * 40]


def test_main_advance_does_not_re_resolve_existing_start_or_ownership(tmp_path):
    current = ["a" * 40]
    resolutions = []
    rows = {}

    def resolve(_scope):
        resolutions.append(current[0])
        return snapshot(current[0])

    def invoke(_operation, name, job_scope):
        execution = job_scope["execution_context"]
        rows[name] = {
            "id": name, "uid": "fixture-uid", "context": "default",
            "provider": {"name": "kubernetes", "options": {
                "KUBERNETES_CONTEXT": {"value": "ror"},
                "KUBERNETES_NAMESPACE": {"value": "devsy"},
                "KUBERNETES_CONFIG": {"value": str(kubeconfig)},
            }},
            "source": {"gitRepository": execution["repository"],
                       "gitCommit": execution["revision"]},
            "devContainerPath": execution["recipe"],
        }

    module = load()
    import hashlib
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_bytes(b"kube")
    kubeconfig.chmod(0o600)
    scope_data = json.loads((ROOT / "docs/devsy-worker-scope.proposed.json").read_text())
    scope_data.update(enabled=True, expires_at=time.time() + 3600,
                      capability_sha256=hashlib.sha256(b"fixture-owner-secret").hexdigest(),
                      bindings={str(kubeconfig): hashlib.sha256(b"kube").hexdigest()})
    config = tmp_path / "scope.json"
    config.write_text(json.dumps(scope_data))
    config.chmod(0o600)
    scope = module.WorkerScope(config, tmp_path / "jobs", lambda: set(rows),
                               lambda name: rows[name], invoke, source_resolver=resolve)
    credential = "Bearer fixture-owner-secret"
    scope.call("workspace_create_scoped", {"name": NAME, "request_id": "create-a"}, credential)
    scope.wait()
    current[0] = "b" * 40

    selection = scope.owned_workspace(NAME, "fixture-uid", credential)
    status = scope.call("workspace_status_scoped", {"name": NAME}, credential)
    started = scope.call("workspace_start_scoped", {"name": NAME, "request_id": "start-a"}, credential)
    scope.wait()

    assert selection["revision"] == "a" * 40
    assert status["execution_context"]["revision"] == "a" * 40
    assert started["execution_context"]["revision"] == "a" * 40
    assert resolutions == ["a" * 40]


def test_failed_main_resolution_does_not_persist_or_invoke_a_job(tmp_path):
    module = load()
    import hashlib
    scope_data = json.loads((ROOT / "docs/devsy-worker-scope.proposed.json").read_text())
    scope_data.update(enabled=True, expires_at=time.time() + 3600,
                      capability_sha256=hashlib.sha256(b"fixture-owner-secret").hexdigest(),
                      bindings={})
    config = tmp_path / "scope.json"
    config.write_text(json.dumps(scope_data))
    config.chmod(0o600)
    calls = []

    def fail(_scope):
        raise RuntimeError("private network detail")

    scope = module.WorkerScope(config, tmp_path / "jobs", lambda: set(), lambda _name: {},
                               lambda *args: calls.append(args), source_resolver=fail)

    with pytest.raises(module.ScopeError):
        scope.call("workspace_create_scoped", {"name": NAME, "request_id": "fetch-failed"},
                   "Bearer fixture-owner-secret")

    assert scope.read(NAME) is None
    assert calls == []


NAME = "cas-worker-01"


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
        "context": approved["context"], "provider": approved["provider"],
        "kubernetes_context": approved["kubernetes_context"],
        "namespace": approved["namespace"], "binary": approved["binary"],
        "repository": approved["repository"], "source_ref": "refs/heads/main",
        "revision": "b" * 40, "recipe": approved["recipe"],
        "recipe_sha256": snapshot("b" * 40)["recipe_sha256"],
    }
    assert observed[0]["execution_context"] == expected
    record = scope.read("cas-worker-01")
    assert record["execution_context"] == expected
    assert expected["revision"] == "b" * 40
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


def test_legacy_migration_preserves_unknown_and_requires_proof(tmp_path):
    import importlib.util
    import hashlib
    module, instance, _ = manager(tmp_path)
    spec = importlib.util.spec_from_file_location('receipt_migration_test', ROOT / 'scripts/creation_receipts.py')
    receipts_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(receipts_module)
    receipts = receipts_module.Receipts(tmp_path / 'receipts', 'fixture')
    receipts.private_root()
    key, fingerprint = receipts.key({'name': 'rcc-worker-01', 'source': 'git:https://github.com/joshyorko/rcc.git'})
    original = {'name': 'rcc-worker-01', 'operation_id': '31a1221b-12d4-4693-aa12-461084cf42b7', 'fingerprint': fingerprint, 'status': 'outcome_unknown'}
    receipts.write(receipts.state / (key + '.json'), original)
    kwargs = dict(receipts=receipts, name='rcc-worker-01', operation_id=original['operation_id'], fingerprint=fingerprint,
                  source='git:https://github.com/joshyorko/rcc.git', workspace_uid='default-rc-a74cc',
                  created_at=time.time()-60, credential='Bearer fixture-owner-secret')
    with pytest.raises(module.ScopeError):
        instance.migrate_legacy_creation(**{**kwargs, 'fingerprint': '0'*64})
    assert instance.read('rcc-worker-01') is None
    instance.absence = lambda *args: {'kind': 'blocked'}
    failed = instance.migrate_legacy_creation(**kwargs)
    assert failed['status'] == 'outcome_unknown' and not failed['new_request_allowed']
    assert failed['legacy_receipt'] == original
    instance.absence = lambda *args: {'kind': 'absent', 'namespace_uid': 'ns-id', 'namespace': 'devsy',
        'kubernetes_context': 'ror', 'observed_at': time.time(), 'workspace_absent': True,
        'provider_resources_absent': True, 'lifecycle_processes_absent': True}
    result = instance.migrate_legacy_creation(**kwargs)
    assert result['status'] == 'failed' and result['new_request_allowed']
    migrated = receipts.read(receipts.state / (key + '.json'))
    assert migrated['original_receipt'] == original and migrated['status'] == 'reconciled_scoped'
    assert not instance.archived_request('rcc-worker-01', result['request_id'])['new_request_allowed']


@pytest.mark.parametrize("status", ["running", "accepted", "outcome_unknown"])
def test_second_worker_waits_for_first_pending_creation(tmp_path, status):
    module, instance, _ = manager(tmp_path)
    instance.root()
    instance.write('cas-worker-01', {'status': status})
    with pytest.raises(module.ScopeError, match='pending creation limit'):
        instance.call('workspace_create_scoped', {'name': 'rcc-worker-01', 'request_id': 'fresh'}, 'Bearer fixture-owner-secret')
    assert instance.read('rcc-worker-01') is None
