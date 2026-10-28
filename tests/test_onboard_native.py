import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

import onboard_native as onboard


class Runner:
    def __init__(self, states):
        self.states = iter(states)
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[1:3] == ["status", "--json"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(next(self.states)), "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_logged_out_noninteractive_never_prompts(monkeypatch):
    runner = Runner([{"BackendState": "NeedsLogin"}])
    monkeypatch.setattr(onboard.shutil, "which", lambda name: "/usr/bin/" + name)
    with pytest.raises(onboard.OnboardingError, match="tailscale login"):
        onboard.ensure_tailnet(non_interactive=True, run=runner)
    assert len(runner.calls) == 1


def test_login_then_up_preserves_existing_preferences(monkeypatch):
    runner = Runner([
        {"BackendState": "NeedsLogin"},
        {"BackendState": "Stopped"},
        {"BackendState": "Running", "TailscaleIPs": ["100.118.115.62"]},
    ])
    monkeypatch.setattr(onboard.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(onboard.sys.stdin, "isatty", lambda: True)
    assert onboard.ensure_tailnet(run=runner) == "100.118.115.62"
    assert [args for args, _ in runner.calls if "sudo" in args[0]] == [
        ["sudo", "/usr/bin/tailscale", "login"],
        ["sudo", "/usr/bin/tailscale", "up"],
    ]


def test_missing_tailscale_has_actionable_blocker(monkeypatch):
    monkeypatch.setattr(onboard.shutil, "which", lambda _: None)
    with pytest.raises(onboard.OnboardingError, match="tailscale.com/download/linux"):
        onboard.ensure_tailnet(non_interactive=True)


def test_daemon_detection_requires_real_socket(tmp_path):
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\nexit 0\n")
    codex.chmod(0o700)
    sock = tmp_path / "daemon.sock"
    sock.write_text("not a socket")
    with pytest.raises(onboard.OnboardingError, match="socket"):
        onboard.discover_daemon(codex_bin=codex, socket_path=sock)


def test_daemon_detection_preserves_stable_symlink(tmp_path):
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\nprintf '%s\\n' '{\"status\":\"running\"}'\n")
    codex.chmod(0o700)
    actual = tmp_path / "actual.sock"
    stable = tmp_path / "stable.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(actual))
        stable.symlink_to(actual)
        binary, sock = onboard.discover_daemon(codex_bin=codex, socket_path=stable)
        assert binary == codex
        assert sock == stable


def test_private_files_refuse_symlinks_and_conflicts(tmp_path):
    target = tmp_path / "owned"
    target.write_text("owned")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(onboard.OnboardingError, match="private"):
        onboard.write_matching(link, "owned")
    with pytest.raises(onboard.OnboardingError, match="different"):
        onboard.write_matching(target, "replacement")
    assert target.read_text() == "owned"


def test_matching_json_adopts_existing_format(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text('{"b": 2, "a": 1}\n')
    path.chmod(0o600)
    assert onboard.write_matching(path, '{"a":1,"b":2}', json_content=True) is False
    assert path.read_text() == '{"b": 2, "a": 1}\n'


def test_native_acceptance_requires_both_fields():
    with pytest.raises(onboard.OnboardingError, match="together"):
        onboard.native_tuple("/repo", None)
    assert onboard.native_tuple("/repo", "thread") == {
        "target": "local", "cwd": "/repo", "thread_id": "thread"
    }


def test_endpoint_adoption_does_not_rotate_keys_or_restart(tmp_path, monkeypatch):
    state = tmp_path / "endpoint"
    state.mkdir(mode=0o700)
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\nexit 0\n")
    codex.chmod(0o700)
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    info = {"address": "100.75.96.78", "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3XkXt3FHtPryBmNqu2ClRbQHz1Gs026ndWhIN6Mhph comment"}
    calls = []
    def run(args, **kw):
        calls.append(args)
        if args[0] == "systemctl":
            return subprocess.CompletedProcess(args, 0, "active\n", "")
        return subprocess.run(args, **kw)
    monkeypatch.setattr(onboard, "user_unit_dir", lambda: unit_dir)
    monkeypatch.setattr(onboard.shutil, "which", lambda name: "/usr/sbin/sshd" if name == "sshd" else "/usr/bin/" + name)
    first = onboard.prepare_endpoint(state, codex, tmp_path / "socket", "100.118.115.62", 22222, info, run=run)
    key = (state / "ssh_host_ed25519_key").read_bytes()
    calls.clear()
    second = onboard.prepare_endpoint(state, codex, tmp_path / "socket", "100.118.115.62", 22222, info, run=run)
    assert first == second
    assert (state / "ssh_host_ed25519_key").read_bytes() == key
    assert not any(args[0] == "ssh-keygen" and "-q" in args for args in calls)
    assert not any(args[0] == "systemctl" and any(a in args for a in ["daemon-reload", "enable", "start", "restart"]) for args in calls)


def test_acceptance_settings_reused_and_explicit_pair_wins(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    native = {"target": "local", "cwd": "/old", "thread_id": "old"}
    onboard.save_acceptance(state, native)
    assert onboard.load_acceptance(state, None) == native
    replacement = {"target": "local", "cwd": "/new", "thread_id": "new"}
    assert onboard.load_acceptance(state, replacement) == replacement


def test_acceptance_settings_reject_symlink(tmp_path):
    path = tmp_path / "onboarding-settings.json"
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(onboard.OnboardingError, match="private"):
        onboard.load_acceptance(tmp_path, None)


def test_atomic_receipt_rerun_recovers_after_unrelated_stale_temp(tmp_path):
    stale = tmp_path / ".onboarding-receipt.tmp"
    stale.write_text("interrupted")
    destination = tmp_path / "onboarding-receipt.json"
    onboard.write_private_json(destination, {"status": "ready"})
    onboard.write_private_json(destination, {"status": "ready", "again": True})
    assert json.loads(destination.read_text())["again"] is True
    assert stale.read_text() == "interrupted"
    assert stat_mode(destination) == 0o600


def stat_mode(path):
    return path.stat().st_mode & 0o777


def test_daemon_rejects_reported_different_socket(tmp_path):
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\nprintf '%s\\n' '{\"status\":\"running\",\"socketPath\":\"/other.sock\"}'\n")
    codex.chmod(0o700)
    with socket.socket(socket.AF_UNIX) as listener:
        sock = tmp_path / "daemon.sock"
        listener.bind(str(sock))
        with pytest.raises(onboard.OnboardingError, match="different socket"):
            onboard.discover_daemon(codex_bin=codex, socket_path=sock)


def test_prepare_only_exports_descriptor_without_registration(tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    class Connection:
        def info(self):
            return {"address": "100.75.96.78", "public_key": "ssh-ed25519 key", "controller_fingerprint": "SHA256:controller"}
        def register(self, *args, **kwargs):
            pytest.fail("prepare-only must not register centrally")
    import sys
    import types
    monkeypatch.setitem(sys.modules, "native_onboarding_controller", types.SimpleNamespace(connect=lambda *a: Connection()))
    monkeypatch.setattr(onboard, "ensure_tailnet", lambda **kw: "100.118.115.62")
    monkeypatch.setattr(onboard, "discover_daemon", lambda **kw: (Path("/codex"), Path("/socket")))
    monkeypatch.setattr(onboard, "prepare_endpoint", lambda *a: "ssh-ed25519 key")
    assert onboard.main(["--name", "dakota-cpu", "--state-dir", str(state), "--prepare-only", "--non-interactive"]) == 0
    descriptor = json.loads((state / "native-target.json").read_text())
    assert descriptor["name"] == "dakota-cpu"
    assert not (state / "onboarding-receipt.json").exists()


def test_noninteractive_install_never_escalates(monkeypatch):
    monkeypatch.setattr(onboard.shutil, "which", lambda _: None)
    with pytest.raises(onboard.OnboardingError, match="interactive"):
        onboard.install_dependencies(non_interactive=True)
