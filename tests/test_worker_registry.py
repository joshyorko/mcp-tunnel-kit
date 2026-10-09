"""Dynamic target publication is private, atomic, and never changes static targets."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import stat

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def registry(tmp_path):
    module_path = ROOT / "scripts/worker_registry.py"
    assert module_path.exists(), "Guarded target publisher is missing"
    spec = importlib.util.spec_from_file_location("worker_registry", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    path = root / "targets.json"
    static = tmp_path / "static.json"
    static.write_text(json.dumps({"targets": {"devsy": {"workspace": "protected"}}}))
    static.chmod(0o600)
    return module, path, static


def selection(uid="default-cas-123"):
    return {"context": "default", "provider": "kubernetes", "workspace": "cas-worker-01",
            "workspace_uid": uid, "namespace": "devsy", "kubernetes_context": "ror",
            "kubeconfig": "/operator/kubeconfig", "repository": "https://github.com/joshyorko/codex-action-server.git",
            "revision": "bf0b3823e033b9b5abd86904e0a565d6b3586206",
            "recipe": ".devcontainer/remote-worker/devcontainer.json", "credential": "never-persist"}


def publish(registry, name="cas-worker-01", uid="default-cas-123", operation="operation-1"):
    module, path, static = registry
    return module.publish(path, static, name, selection(uid), operation)


def test_new_registry_is_private_and_contains_only_pinned_target_metadata(registry):
    module, path, static = registry
    original = static.read_bytes()
    result = publish(registry)
    actual = json.loads(path.read_text())
    assert actual["version"] == 1
    assert actual["targets"] == {"cas-worker-01": {"transport": "devsy-kubernetes", "context": "default",
        "provider": "kubernetes", "workspace": "cas-worker-01", "workspace_uid": "default-cas-123",
        "kubernetes_context": "ror", "namespace": "devsy", "kubeconfig": "/operator/kubeconfig",
        "repository": "https://github.com/joshyorko/codex-action-server.git",
        "revision": "bf0b3823e033b9b5abd86904e0a565d6b3586206",
        "recipe": ".devcontainer/remote-worker/devcontainer.json",
        "user": "vscode", "codex_bin": "/home/vscode/.local/bin/codex"}}
    assert actual["owners"] == {"cas-worker-01": {"operation_id": "operation-1", "workspace_uid": "default-cas-123"}}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert static.read_bytes() == original
    assert "never-persist" not in path.read_text()
    assert result["workspace_uid"] == "default-cas-123"


def test_same_operation_and_identity_is_idempotent(registry):
    publish(registry)
    original = registry[1].read_bytes()
    publish(registry)
    assert registry[1].read_bytes() == original


def test_same_operation_cannot_switch_workspace_uid(registry):
    publish(registry)
    original = registry[1].read_bytes()
    with pytest.raises(registry[0].RegistryError):
        publish(registry, uid="different-uid")
    assert registry[1].read_bytes() == original


@pytest.mark.parametrize("field,value", [("kubernetes_context", "another-cluster"), ("namespace", "another-namespace"),
                                         ("kubeconfig", "/operator/other-config"), ("revision", "a" * 40),
                                         ("repository", "https://github.com/unapproved/repo.git"),
                                         ("recipe", ".devcontainer/other.json")])
def test_same_operation_cannot_change_any_approved_binding(registry, field, value):
    publish(registry)
    module, path, static = registry
    original = path.read_bytes()
    selected = selection()
    selected[field] = value
    with pytest.raises(module.RegistryError):
        module.publish(path, static, "cas-worker-01", selected, "operation-1")
    assert path.read_bytes() == original


@pytest.mark.parametrize("field", ["kubernetes_context", "namespace", "kubeconfig", "repository", "revision", "recipe"])
def test_incomplete_verified_scope_cannot_be_published(registry, field):
    module, path, static = registry
    selected = selection()
    del selected[field]
    with pytest.raises(module.RegistryError):
        module.publish(path, static, "cas-worker-01", selected, "operation-1")
    assert not path.exists()


@pytest.mark.parametrize("field,value", [("kubernetes_context", "bad\ncontext"), ("kubeconfig", "relative/config"),
                                         ("kubeconfig", "/operator/../config"), ("kubeconfig", "/bad\nconfig"),
                                         ("repository", "https://credential@example.com/repo"),
                                         ("revision", "main"), ("revision", "a" * 39),
                                         ("recipe", "../devcontainer.json"), ("recipe", "/absolute/recipe")])
def test_invalid_scope_bindings_are_refused(registry, field, value):
    module, path, static = registry
    selected = selection()
    selected[field] = value
    with pytest.raises(module.RegistryError):
        module.publish(path, static, "cas-worker-01", selected, "operation-1")
    assert not path.exists()


def test_archived_operation_cannot_rebind_a_replacement(registry):
    publish(registry)
    publish(registry, uid="new-uid", operation="operation-2")
    original = registry[1].read_bytes()
    with pytest.raises(registry[0].RegistryError):
        publish(registry, uid="another-uid", operation="operation-1")
    assert registry[1].read_bytes() == original


def test_operation_cannot_publish_a_second_target_identity(registry):
    publish(registry)
    original = registry[1].read_bytes()
    with pytest.raises(registry[0].RegistryError):
        publish(registry, name="another-target", uid="another-uid")
    assert registry[1].read_bytes() == original


def test_static_file_cannot_also_be_the_dynamic_destination(registry):
    publish(registry)
    module, path, static = registry
    original = path.read_bytes()
    with pytest.raises(module.RegistryError):
        module.publish(path, path, "new-target", selection(), "new-operation")
    assert path.read_bytes() == original


def test_new_operation_replaces_only_owned_target_and_retains_provenance(registry):
    publish(registry)
    publish(registry, name="unrelated", uid="unrelated-uid", operation="other-operation")
    before = json.loads(registry[1].read_text())
    publish(registry, uid="new-uid", operation="operation-2")
    after = json.loads(registry[1].read_text())
    assert after["targets"]["unrelated"] == before["targets"]["unrelated"]
    assert after["owners"]["unrelated"] == before["owners"]["unrelated"]
    assert after["owners"]["cas-worker-01"] == {"operation_id": "operation-2", "workspace_uid": "new-uid"}
    receipt = after["history"][-1]
    assert receipt["target_name"] == "cas-worker-01"
    assert receipt["target"] == before["targets"]["cas-worker-01"]
    assert receipt["owner"] == before["owners"]["cas-worker-01"]
    assert receipt["replaced_by_operation_id"] == "operation-2"


def test_static_name_collision_never_creates_or_overwrites_registry(registry):
    module, path, static = registry
    with pytest.raises(module.RegistryError):
        publish(registry, name="devsy")
    assert not path.exists()
    publish(registry)
    original = path.read_bytes()
    with pytest.raises(module.RegistryError):
        publish(registry, name="devsy")
    assert path.read_bytes() == original


def test_unowned_existing_target_cannot_be_rebound(registry):
    publish(registry)
    module, path, static = registry
    value = json.loads(path.read_text())
    del value["owners"]["cas-worker-01"]
    path.write_text(json.dumps(value))
    original = path.read_bytes()
    with pytest.raises(module.RegistryError):
        publish(registry, operation="new-operation")
    assert path.read_bytes() == original


@pytest.mark.parametrize("change", ["symlink_file", "symlink_parent", "symlink_lock", "file_mode", "parent_mode", "static_symlink", "static_mode"])
def test_unsafe_paths_are_refused_without_mutating_targets(registry, change):
    module, path, static = registry
    publish(registry)
    original = path.read_bytes()
    if change == "symlink_file":
        saved = path.with_suffix(".saved")
        path.rename(saved)
        path.symlink_to(saved)
    elif change == "symlink_parent":
        saved = path.parent.with_name("saved")
        path.parent.rename(saved)
        path.parent.symlink_to(saved, target_is_directory=True)
    elif change == "symlink_lock":
        lock = path.parent / ("." + path.name + ".lock")
        lock.unlink()
        lock.symlink_to(static)
    elif change == "file_mode":
        path.chmod(0o644)
    elif change == "parent_mode":
        path.parent.chmod(0o755)
    elif change == "static_symlink":
        saved = static.with_suffix(".saved")
        static.rename(saved)
        static.symlink_to(saved)
    else:
        static.chmod(0o644)
    with pytest.raises(module.RegistryError):
        publish(registry, uid="new-uid", operation="operation-2")
    assert path.read_bytes() == original


@pytest.mark.parametrize("text", ["not-json", "[]", '{"version":2,"targets":{}}',
                                 '{"version":1,"targets":[],"owners":{}}',
                                 '{"version":1,"targets":{},"owners":{"missing":{}}}',
                                 '{"version":1,"version":2,"targets":{}}'])
def test_malformed_registry_fails_closed_without_replacement(registry, text):
    module, path, static = registry
    path.write_text(text)
    path.chmod(0o600)
    with pytest.raises(module.RegistryError):
        publish(registry)
    assert path.read_text() == text


@pytest.mark.parametrize("field,value", [("workspace_uid", "../../escape"), ("context", "x\nsecret"),
                                         ("provider", "docker"), ("workspace", ""), ("namespace", "bad/name")])
def test_unverified_selection_fields_are_refused(registry, field, value):
    module, path, static = registry
    selected = selection()
    selected[field] = value
    with pytest.raises(module.RegistryError):
        module.publish(path, static, "cas-worker-01", selected, "operation-1")
    assert not path.exists()


@pytest.mark.parametrize("name,operation", [("../escape", "op"), ("bad target", "op"), ("x" * 129, "op"),
                                           ("safe", "bad\noperation"), ("safe", "")])
def test_invalid_target_or_operation_identity_is_refused(registry, name, operation):
    with pytest.raises(registry[0].RegistryError):
        publish(registry, name=name, operation=operation)
    assert not registry[1].exists()


def test_concurrent_publications_retain_both_targets(registry):
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(publish, registry, name=name, uid=name + "-uid", operation=name + "-op")
                   for name in ("worker-a", "worker-b")]
        for future in futures:
            future.result()
    assert set(json.loads(registry[1].read_text())["targets"]) == {"worker-a", "worker-b"}


def test_failed_atomic_replace_preserves_previous_registry_and_cleans_temp(registry, monkeypatch):
    publish(registry)
    module, path, static = registry
    original = path.read_bytes()
    files = set(path.parent.iterdir())
    def fail(*args, **kwargs):
        raise OSError("private SECRET")
    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(module.RegistryError) as error:
        publish(registry, uid="new-uid", operation="operation-2")
    assert "SECRET" not in str(error.value)
    assert path.read_bytes() == original
    assert set(path.parent.iterdir()) == files


def test_replacement_history_is_bounded(registry):
    for index in range(40):
        publish(registry, uid=f"uid-{index}", operation=f"op-{index}")
    result = json.loads(registry[1].read_text())
    assert len(result["history"]) == 32
    assert result["history"][-1]["owner"]["operation_id"] == "op-38"


def test_image_registry_preserves_exact_digest_provenance(registry):
    module, path, static = registry
    value = {**selection(), 'recipe': 'Containerfile.worker', 'source_kind': 'image',
             'image_ref': 'ghcr.io/joshyorko/codex-action-server', 'image_digest': 'sha256:'+'a'*64}
    module.publish(path, static, 'cas-worker-01', value, 'image-operation')
    target = json.loads(path.read_text())['targets']['cas-worker-01']
    assert target['image_ref'] == value['image_ref'] and target['image_digest'] == value['image_digest']
    with pytest.raises(module.RegistryError):
        module.publish(path, static, 'cas-worker-01', {**value, 'image_digest': 'latest'}, 'image-operation')
