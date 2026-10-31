"""Isolated native fleet drift fixtures. These tests never open a socket."""
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def helper():
    path = ROOT / "scripts/native_drift.py"
    spec = importlib.util.spec_from_file_location("native_drift", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixtures(tmp_path):
    module = helper()
    native = tmp_path / "native-ssh"
    native.mkdir(mode=0o700)
    (native / "identity").write_text("fixture identity\n")
    (native / "identity").chmod(0o600)
    (native / "ssh_config.native").write_text(
        "Host dakota-cpu-native\n"
        "  HostName 100.118.115.62\n  Port 22222\n  User operator\n"
        "  IdentityFile /run/codex-ssh/identity\n  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking yes\n  UserKnownHostsFile /run/codex-ssh/known_hosts\n"
        "  GlobalKnownHostsFile /dev/null\n  BatchMode yes\n  ForwardAgent no\n"
        "  PreferredAuthentications publickey\n\n"
        "Host dakota-nvidia-native\n"
        "  HostName 100.108.115.63\n  Port 22223\n  User operator\n"
        "  IdentityFile /run/codex-ssh/identity\n  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking yes\n  UserKnownHostsFile /run/codex-ssh/known_hosts\n"
        "  GlobalKnownHostsFile /dev/null\n  BatchMode yes\n  ForwardAgent no\n"
        "  PreferredAuthentications publickey\n"
    )
    (native / "ssh_config.native").chmod(0o600)
    (native / "known_hosts.native").write_text(
        "[100.118.115.62]:22222 ssh-ed25519 " + "A" * 44 + " cpu\n"
        "[100.108.115.63]:22223 ssh-ed25519 " + "B" * 44 + " nvidia\n"
    )
    (native / "known_hosts.native").chmod(0o600)
    targets = {"targets": {
        name: {"transport": "ssh", "destination": name + "-native",
               "codex_bin": "/home/operator/.local/bin/codex",
               "socket_path": "/home/operator/.codex/app-server-control/app-server-control.sock",
               "ssh_config": "/run/codex-ssh/ssh_config",
               "known_hosts": "/run/codex-ssh/known_hosts"}
        for name in module.TARGETS
    }}
    return module, native, targets


def test_cli_updated_while_daemon_is_stale_and_cpu_nvidia_are_independent(tmp_path):
    module, native, targets = fixtures(tmp_path)
    calls = []

    def run(command, **kwargs):
        assert command[1:3] == ["-F", "/dev/null"]
        assert "StrictHostKeyChecking=yes" in command
        assert "ForwardAgent=no" in command
        assert "ProxyCommand=none" in command
        assert "ProxyJump=none" in command
        assert "SSH_AUTH_SOCK" not in kwargs["env"]
        calls.append(command)
        endpoint = command[-2]
        remote_command = command[-1]
        if remote_command.endswith(" --version"):
            version = "codex-cli 0.172.0\n" if "100.118.115.62" in endpoint else "codex-cli 0.171.0\n"
            return SimpleNamespace(returncode=0, stdout=version, stderr="")
        if "100.118.115.62" in endpoint:
            return SimpleNamespace(returncode=0,
                stdout=json.dumps({"status": "running", "version": "0.171.0",
                                   "socketPath": targets["targets"]["dakota-cpu"]["socket_path"]}), stderr="")
        return SimpleNamespace(returncode=0,
            stdout=json.dumps({"status": "running", "version": "0.171.0",
                               "socketPath": targets["targets"]["dakota-nvidia"]["socket_path"]}), stderr="")

    result = module.reconcile(targets, native, runner=run)
    assert result["mutated"] is False
    assert result["targets"]["dakota-cpu"]["installed_cli"]["version"] == "0.172.0"
    assert result["targets"]["dakota-cpu"]["running_daemon"]["version"] == "0.171.0"
    assert result["targets"]["dakota-cpu"]["version_drift"] == "cli_daemon_drift"
    assert result["targets"]["dakota-nvidia"]["version_drift"] == "in_sync"
    assert len(calls) == 4
    assert all("app-server daemon version" in call[-1] or call[-1].endswith(" --version") for call in calls)


def test_offline_nvidia_does_not_hide_cpu_result(tmp_path):
    module, native, targets = fixtures(tmp_path)

    def run(command, **_kwargs):
        endpoint, remote_command = command[-2], command[-1]
        if "100.108.115.63" in endpoint:
            raise subprocess.TimeoutExpired(command, timeout=25)
        if remote_command.endswith(" --version"):
            return SimpleNamespace(returncode=0, stdout="codex 0.170.0\n", stderr="")
        return SimpleNamespace(returncode=0,
            stdout=json.dumps({"status": "running", "version": "0.170.0"}), stderr="")

    result = module.reconcile(targets, native, runner=run)
    assert result["targets"]["dakota-cpu"]["installed_cli"]["status"] == "available"
    assert result["targets"]["dakota-cpu"]["running_daemon"]["status"] == "running"
    assert result["targets"]["dakota-nvidia"]["installed_cli"]["status"] == "unavailable"
    assert result["targets"]["dakota-nvidia"]["connection"] == "partial_or_unavailable"


def test_forced_command_refusal_is_reported_without_fallback_or_mutation(tmp_path):
    module, native, targets = fixtures(tmp_path)
    commands = []

    def run(command, **_kwargs):
        commands.append(command[-1])
        return SimpleNamespace(returncode=126, stdout="", stderr="command is not allowed")

    result = module.reconcile(targets, native, runner=run)
    assert result["mutated"] is False
    assert result["targets"]["dakota-cpu"]["installed_cli"]["status"] == "unavailable"
    assert len(commands) == 4
    assert set(commands) == {
        "/home/operator/.local/bin/codex --version",
        "/home/operator/.local/bin/codex app-server daemon version",
    }


def test_bad_endpoint_policy_blocks_one_target_without_stopping_the_other(tmp_path):
    module, native, targets = fixtures(tmp_path)
    config = native / "ssh_config.native"
    raw = config.read_text().replace("ForwardAgent no\n", "ForwardAgent yes\n", 1)
    config.write_text(raw)
    config.chmod(0o600)
    calls = []

    def run(command, **_kwargs):
        calls.append(command[-2])
        return SimpleNamespace(returncode=0, stdout="codex 0.171.0\n", stderr="")

    result = module.reconcile(targets, native, runner=run)
    assert result["targets"]["dakota-cpu"]["connection"] == "blocked_or_unavailable"
    assert result["targets"]["dakota-nvidia"]["installed_cli"]["version"] == "0.171.0"
    assert calls == ["operator@100.108.115.63", "operator@100.108.115.63"]


def test_missing_target_is_reported_independently_and_methods_stay_unknown(tmp_path):
    module, native, targets = fixtures(tmp_path)
    del targets["targets"]["dakota-nvidia"]

    def run(command, **_kwargs):
        if command[-1].endswith(" --version"):
            return SimpleNamespace(returncode=0, stdout="codex 0.171.0\n", stderr="")
        return SimpleNamespace(returncode=0, stdout='{"status":"running","version":"0.170.0"}', stderr="")

    result = module.reconcile(targets, native, runner=run)
    assert result["targets"]["dakota-nvidia"]["connection"] == "not_registered"
    assert result["targets"]["dakota-cpu"]["version_drift"] == "cli_daemon_drift"
    assert result["targets"]["dakota-cpu"]["active_sessions"] == "not_checked"
    assert result["targets"]["dakota-cpu"]["native_upgrade"]["mutated"] is False


@pytest.mark.parametrize("active_sessions", ["active", "unknown", None])
def test_active_or_unknown_sessions_never_open_the_native_upgrade_gate(active_sessions):
    module = helper()
    result = module.native_upgrade_gate(approval=True, active_sessions=active_sessions,
                                        artifact_verified=True, rollback_ready=True,
                                        installer_available=False)
    assert result["status"] == "blocked"
    assert "separately_approved_native_lifecycle_not_implemented" in result["blockers"]
    if active_sessions != "idle":
        assert "native_session_state_not_proven_idle" in result["blockers"]
    assert result["mutated"] is False
