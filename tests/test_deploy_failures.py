"""Regression tests for deployment failure isolation and rollback."""

import json
import os
import sqlite3
import sys
import tarfile
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import call, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compose_control as c
import deploy_control_plane as d
import vm_deploy_host as h


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


def args(operation, *, approve=False):
    return type("Args", (), {
        "local": False,
        "operation": operation,
        "cas_digest": "",
        "cas_revision": "",
        "approve_full_stack": approve,
    })()


def test_cas_failure_restores_only_cas_and_uses_cas_backup():
    before = generation()
    current = dict(before)
    after = dict(before)
    calls = []
    smoke_count = 0

    def remote(action, data=None):
        nonlocal smoke_count
        calls.append((action, data))
        if action == "snapshot":
            return before if calls.count(("snapshot", None)) == 1 else after
        if action == "current":
            return current
        if action in {"backup-cas", "profile", "network-check", "wait", "set-current"}:
            return {}
        if action in {"image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "smoke":
            smoke_count += 1
            if smoke_count == 1:
                raise RuntimeError("new CAS smoke failed")
            return {"status": "PASS"}
        raise AssertionError(f"Unexpected VM action: {action}")

    kamal_calls = []
    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), \
         patch.object(d, "kamal", side_effect=lambda config, operation, name: kamal_calls.append((operation, name))), \
         patch.object(d, "sync_source") as sync_source, \
         patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(RuntimeError, match="previous generation restored"):
            d.execute(args("cas"))

    assert ("backup-cas", None) in calls
    assert ("backup", None) not in calls
    assert kamal_calls == [("reboot", "cas"), ("reboot", "cas")]
    assert not {"compose-stop", "compose-start", "devsy-start"} & {action for action, _ in calls}
    sync_source.assert_not_called()


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_source_sync_failure_is_inside_protected_deployment_path(rollback_fails):
    before = generation()
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "snapshot":
            return before
        if action == "current":
            return before
        if action in {"network-check", "image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        return {}

    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), \
         patch.object(d, "sync_source", side_effect=RuntimeError("secret-source-detail")), \
         patch.object(d, "restore", side_effect=RuntimeError("secret-rollback-detail") if rollback_fails else None) as restore, patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(RuntimeError, match="Deployment failed at source-sync") as error:
            d.execute(args("deploy", approve=True))

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
         patch.object(d, "sync_source"), patch.object(d, "restore"), \
         patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        with pytest.raises(ValueError, match="foreign network conflict"):
            d.execute(args("adopt", approve=True))

    assert "compose-stop" not in calls


def test_adoption_network_check_precedes_compose_stop():
    before = generation(authority="compose")
    after = generation(authority="kamal")
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "snapshot":
            return before if calls.count("snapshot") == 1 else after
        if action == "current":
            return before
        if action in {"image-check", "images"}:
            return {"image_ids": {"cas": "image-cas", "schema_proxy": "image-schema-proxy",
                                  "executor": "image-executor", "tunnel": "image-tunnel"}}
        if action == "smoke":
            return {"status": "PASS"}
        return {}

    with patch.object(d, "trusted_context"), patch.object(d, "lock", return_value=nullcontext()), \
         patch.object(d, "remote", side_effect=remote), patch.object(d, "sync_source"), \
         patch.object(d, "kamal"), patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
        d.execute(args("adopt", approve=True))

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
    assert "cas-targets.json" in members
    assert any(name.startswith("databases/") for name in members)
    assert not any("executor" in name or "tunnel" in name for name in members)


def test_remove_network_leaves_foreign_network_untouched(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "STORE", tmp_path / "store")
    h.STORE.mkdir()
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
    monkeypatch.setattr(sys, "argv", ["vm_deploy_host.py", "remove-network"])

    old_umask = os.umask(0o077)
    try:
        h.main()
    finally:
        os.umask(old_umask)

    assert not any(command[:3] == ["docker", "network", "rm"] for command in docker_calls)


def test_explicit_rollback_recovers_unhealthy_generation_without_healthy_precondition():
    previous=generation(authority='kamal');calls=[]
    def remote(action,data=None):
        calls.append(action)
        if action in ('current','rollback-target'):return previous
        if action=='status':return {'inventory':{'executor':{'state':'running'},'cas':{'state':'exited'}},'healthy':False}
        if action=='snapshot':raise AssertionError('Broken deployment cannot satisfy healthy snapshot')
        return {}
    with patch.object(d,'trusted_context'),patch.object(d,'lock',return_value=nullcontext()),patch.object(d,'remote',side_effect=remote),patch.object(d,'prove_images',return_value={}),patch.object(d,'restore',return_value=previous) as restore,patch.dict(os.environ,{'GITHUB_SHA':'b'*40}):
        result=d.execute(args('rollback',approve=True))
    assert result['identity_preserved'] is True
    restore.assert_called_once()
    assert 'snapshot' not in calls and 'rollback-commit' in calls
