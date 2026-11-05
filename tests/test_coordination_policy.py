"""Managed CAS policy opt-in is private, bounded and independently replaceable."""

import copy
import importlib
import json
import os
from pathlib import Path
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_control_plane as deploy
import instance_profile
import kamal_model
import local_kamal
import vm_deploy_host as host
from test_kamal_model import manifest, profile


def policy():
    return {"pairs": [{
        "sender": {"target": "dakota-nvidia", "cwd": "/tmp/cas-live", "thread_id": "root-a"},
        "recipient": {"target": "dakota-nvidia", "cwd": "/tmp/cas-live", "thread_id": "root-b"},
    }]}


def private_policy(tmp_path, value=None):
    directory = tmp_path / "policy"
    directory.mkdir(mode=0o700)
    path = directory / "policy.json"
    path.write_text(json.dumps(policy() if value is None else value))
    path.chmod(0o600)
    return path


def test_optional_profile_optin_round_trips_without_changing_existing_fields():
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    original = copy.deepcopy(value)
    value["vm"]["cas_coordination_policy_dir"] = value["vm"]["state_dir"] + "/cas-coordination"
    assert instance_profile.decode(instance_profile.encode(value)) == value
    value["vm"].pop("cas_coordination_policy_dir")
    assert value == original


@pytest.mark.parametrize("directory", ["relative", "/tmp/../policy", "/tmp/policy:rw", True, "", None])
def test_owner_profile_rejects_unsafe_optin_directory(directory):
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    value["vm"]["cas_coordination_policy_dir"] = directory
    with pytest.raises(ValueError):
        instance_profile.validate(value)


def test_render_optin_changes_only_cas_fixed_policy_mount_and_environment():
    original = json.loads(kamal_model.render(profile(), manifest()))
    selected = profile()
    selected["cas_coordination_policy_dir"] = selected["state_dir"] + "/cas-coordination"
    enabled = json.loads(kamal_model.render(selected, manifest()))
    cas = enabled["accessories"]["cas"]
    assert cas["env"]["clear"].pop("CODEX_ACTION_COORDINATION_POLICY") == "/run/cas-coordination/policy.json"
    assert cas["volumes"].pop() == selected["cas_coordination_policy_dir"] + ":/run/cas-coordination:ro"
    assert enabled == original
    assert "CODEX_ACTION_COORDINATION_POLICY" not in original["accessories"]["cas"]["env"]["clear"]


@pytest.mark.parametrize("kind", ["missing", "symlink", "directory-link", "world-readable", "directory-readable", "wrong-owner", "oversized", "fifo"])
def test_private_policy_rejects_unsafe_files_before_reading(tmp_path, kind):
    module = importlib.import_module("coordination_policy")
    path = private_policy(tmp_path)
    owner = os.geteuid()
    if kind == "missing":
        path.unlink()
    elif kind == "symlink":
        target = path.with_name("actual.json")
        path.rename(target)
        path.symlink_to(target)
    elif kind == "directory-link":
        link = tmp_path / "link"
        link.symlink_to(path.parent, target_is_directory=True)
        path = link / "policy.json"
    elif kind == "world-readable":
        path.chmod(0o644)
    elif kind == "directory-readable":
        path.parent.chmod(0o755)
    elif kind == "wrong-owner":
        owner += 1
    elif kind == "oversized":
        path.write_bytes(b" " * 65537)
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    with pytest.raises(ValueError):
        module.read_file(path, owner=owner)


@pytest.mark.parametrize("raw", [
    b'{"pairs":[],"pairs":[]}', b'{"pairs":[],"extra":true}',
    b'{"pairs":{}}', b'{"pairs":[{}]}', b'{"pairs":[NaN]}',
    json.dumps({"pairs": [policy()["pairs"][0]] * 65}).encode(),
])
def test_policy_parser_refuses_duplicate_keys_malformed_or_unbounded_shape(raw):
    module = importlib.import_module("coordination_policy")
    with pytest.raises(ValueError):
        module.parse(raw)


@pytest.mark.parametrize("mutation", [
    lambda p: p["pairs"][0]["sender"].update(extra="no"),
    lambda p: p["pairs"][0]["recipient"].update(target="other-target"),
    lambda p: p["pairs"][0]["recipient"].update(cwd="relative"),
    lambda p: p["pairs"][0]["recipient"].update(thread_id="root-a"),
])
def test_policy_parser_refuses_unsafe_or_untyped_peer_identity(mutation):
    module = importlib.import_module("coordination_policy")
    value = policy()
    mutation(value)
    with pytest.raises(ValueError):
        module.parse(json.dumps(value).encode())


def test_atomic_policy_replacement_keeps_directory_and_new_reads_see_new_pairs(tmp_path):
    module = importlib.import_module("coordination_policy")
    directory = tmp_path / "policy"
    owner = os.geteuid()
    result = module.install(directory, b'{"pairs":[]}', owner=owner)
    inode = directory.stat().st_ino
    with (directory / "policy.json").open("rb") as previous:
        replacement = module.install(directory, json.dumps(policy()).encode(), owner=owner)
        assert json.loads(previous.read()) == {"pairs": []}
    assert directory.stat().st_ino == inode
    assert json.loads(module.read_file(directory / "policy.json", owner=owner)) == policy()
    assert result["pairs"] == 0 and replacement["pairs"] == 1
    assert result["sha256"] != replacement["sha256"]
    assert (directory / "policy.json").stat().st_mode & 0o777 == 0o600


def test_controller_override_preserves_private_profile_and_remote_transport_identity(monkeypatch):
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    original = copy.deepcopy(value)
    monkeypatch.setattr(deploy, "INSTANCE", value)
    selected = value["vm"]["state_dir"] + "/cas-coordination"
    deploy.coordination_policy_override(selected)
    assert deploy.INSTANCE["vm"]["cas_coordination_policy_dir"] == selected
    assert value == original
    projected = copy.deepcopy(deploy.INSTANCE)
    projected["vm"].pop("cas_coordination_policy_dir")
    assert projected == original
    assert deploy.profile()["cas_coordination_policy_dir"] == selected


def test_managed_install_uses_validated_private_payload_and_fixed_remote_destination(tmp_path, monkeypatch):
    path = private_policy(tmp_path)
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    value["vm"]["cas_coordination_policy_dir"] = value["vm"]["state_dir"] + "/cas-coordination"
    monkeypatch.setattr(deploy, "INSTANCE", value)
    calls = []
    def remote(action, data):
        calls.append((action, data))
        assert action == "coordination-policy-install"
        assert set(data) == {"policy_json"}
        return {"installed": True, "pairs": 1, "sha256": "a" * 64}
    monkeypatch.setattr(deploy, "remote", remote)
    assert deploy.install_coordination_policy(path)["installed"] is True
    assert len(calls) == 1
    assert json.loads(calls[0][1]["policy_json"]) == policy()


def test_protected_workflow_passes_only_typed_directory_override():
    workflow = (ROOT / ".github/workflows/deploy-control-plane.yml").read_text()
    assert "cas_coordination_policy_dir:" in workflow
    assert "CAS_COORDINATION_POLICY_DIR: ${{ inputs.cas_coordination_policy_dir }}" in workflow
    assert 'args+=(--cas-coordination-policy-dir "$CAS_COORDINATION_POLICY_DIR")' in workflow


def test_read_only_policy_is_valid_but_existing_symlink_cannot_be_replaced(tmp_path):
    module = importlib.import_module("coordination_policy")
    path = private_policy(tmp_path)
    path.chmod(0o400)
    assert json.loads(module.read_file(path, owner=os.geteuid())) == policy()
    target = path.with_name("other.json")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ValueError):
        module.install(path.parent, b'{"pairs":[]}', owner=os.geteuid())
    assert json.loads(target.read_bytes()) == policy()


def test_vm_preflight_checks_opted_in_policy_before_other_mounts(monkeypatch, tmp_path):
    selected = str(tmp_path / "missing")
    monkeypatch.setattr(host, "COORDINATION_POLICY_DIR", selected)
    with pytest.raises(ValueError, match="coordination policy"):
        host.validate_profile()


def test_managed_cli_only_installs_policy_under_existing_trust_and_lock(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(deploy, "configure_local", lambda path: calls.append("configure"))
    monkeypatch.setattr(deploy, "coordination_policy_override", lambda directory: calls.append(("select", directory)))
    monkeypatch.setattr(deploy, "trusted_context", lambda *_a, **_k: calls.append("trust"))
    monkeypatch.setattr(deploy, "lock", lambda: nullcontext())
    monkeypatch.setattr(deploy, "install_coordination_policy", lambda path: calls.append(("install", path)) or {"installed": True})
    assert local_kamal.main(["coordination-policy", "install", "--file", str(tmp_path / "policy.json"),
                             "--directory", "/private/policy"]) == 0
    assert calls == ["configure", ("select", "/private/policy"), "trust", ("install", tmp_path / "policy.json")]
    assert json.loads(capsys.readouterr().out) == {"installed": True}


@pytest.mark.parametrize("selected", [None, "/private/other"])
def test_later_deployment_cannot_omit_or_change_recorded_optin(monkeypatch, selected):
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    if selected is not None:
        value["vm"]["cas_coordination_policy_dir"] = selected
    monkeypatch.setattr(deploy, "INSTANCE", value)
    with pytest.raises(ValueError, match="must be preserved"):
        deploy.require_coordination_policy({"cas_coordination_policy_dir": "/private/original"})


def test_rollback_render_restores_prior_policy_without_rewriting_current_profile(tmp_path, monkeypatch):
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    value["vm"]["cas_coordination_policy_dir"] = "/private/new-policy"
    monkeypatch.setattr(deploy, "INSTANCE", value)
    monkeypatch.setattr(deploy, "HOST", value["deploy_host"]["alias"])
    monkeypatch.setattr(deploy, "VMROOT", value["vm"]["repo_dir"])
    prior = {"manifest": manifest()}
    rendered = json.loads(deploy.generation_configuration(tmp_path, prior).read_text())
    assert "CODEX_ACTION_COORDINATION_POLICY" not in rendered["accessories"]["cas"]["env"]["clear"]
    assert value["vm"]["cas_coordination_policy_dir"] == "/private/new-policy"


def test_upgrade_without_recorded_policy_directory_refuses_before_any_service_change(tmp_path, monkeypatch):
    from test_deploy_control_plane import cas_promotion_fixture
    _old, images, evidence = cas_promotion_fixture()
    repo = tmp_path / "repo"
    (repo / "config").mkdir(parents=True)
    (repo / "config/deploy-images.json").write_text(json.dumps(images))
    (repo / "config/cas-promotion.json").write_text(json.dumps(evidence))
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    current = {"authority": "kamal", "cas_coordination_policy_dir": "/private/previous"}
    calls = []
    def remote(action, data=None):
        calls.append(action)
        if action == "current": return current
        if action in ("snapshot", "profile", "network-check"): return {}
        raise AssertionError("Unexpected mutation: " + action)
    monkeypatch.setattr(deploy, "ROOT", repo)
    monkeypatch.setattr(deploy, "INSTANCE", value)
    monkeypatch.setattr(deploy, "trusted_context", lambda *_a, **_k: None)
    monkeypatch.setattr(deploy, "lock", lambda: nullcontext())
    monkeypatch.setattr(deploy, "remote", remote)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    with pytest.raises(ValueError, match="must be preserved"):
        deploy.execute(SimpleNamespace(local=False, operation="cas", approve_full_stack=False))
    assert calls == ["snapshot", "profile", "network-check", "current"]
