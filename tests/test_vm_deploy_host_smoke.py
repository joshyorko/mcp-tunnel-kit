"""Host smoke checks keep Devsy preflight independent of native thread identity."""

import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import vm_deploy_host as host


DAKOTA_CWD = "/srv/dakota/worktree/mcp-tunnel-kit"
VM_CWD = "/srv/control-plane/mcp-tunnel-kit"
THREAD_ID = "12345678-1234-5678-9abc-def012345678"


class FakeSession:
    def __init__(self, *, expected_cwd=DAKOTA_CWD, expected_thread=THREAD_ID,
                 read_error=None, active_flags=None, unknown_active_flags=False,
                 native_state_authoritative=True, thread_status="notLoaded",
                 connection_target="local", latest_turn=None):
        self.expected_cwd = expected_cwd
        self.expected_thread = expected_thread
        self.read_error = read_error
        self.active_flags = active_flags or []
        self.unknown_active_flags = unknown_active_flags
        self.native_state_authoritative = native_state_authoritative
        self.thread_status = thread_status
        self.connection_target = connection_target
        self.latest_turn = latest_turn
        self.calls = []

    def call(self, _method, request):
        code = request["arguments"]["code"]
        match = re.fullmatch(r"return await tools\.codex\.([a-z_]+)\((.*)\);", code)
        assert match, "smoke must call the named Codex tool with a JSON argument"
        name, raw_arguments = match.groups()
        arguments = json.loads(raw_arguments)
        self.calls.append((name, arguments))
        payload = arguments.get("payload", {})
        if name == "get_thread_snapshot":
            if self.read_error:
                content = {"result": None, "error": self.read_error}
            else:
                content = {
                    "result": {
                        "operation": "server/diagnostics",
                        "connection": {"target": self.connection_target},
                        "result": {
                            "target": "local", "cwd": self.expected_cwd,
                            "thread_id": self.expected_thread,
                            "source": "native-app-server", "thread_status": self.thread_status,
                            "active_flags": self.active_flags,
                            "unknown_active_flags": self.unknown_active_flags,
                            "native_state_authoritative": self.native_state_authoritative,
                            "latest_turn": self.latest_turn,
                        },
                    },
                    "error": None,
                }
        else:
            raise AssertionError(f"unexpected Codex tool: {name}")
        return {"structuredContent": {
            "status": "completed",
            "execution": {"ok": True, "value": {"structuredContent": content}},
        }}


def configured_host(tmp_path, monkeypatch, *, session):
    state = tmp_path / "state"
    profile = {
        "schema_version": 1,
        "deploy_host": {"alias": "control-plane-vm", "address": "203.0.113.10",
                        "user": "operator", "host_key_fingerprint": "SHA256:" + "A" * 43},
        "vm": {
            "repo_dir": VM_CWD,
            "state_dir": str(state),
            "network": {"name": "mcp-control-plane", "subnet": "198.18.0.0/24",
                        "gateway": "198.18.0.1"},
            "native_ssh_dir": str(state / "native-ssh"),
            "devsy": {"config_source": str(state / "devsy/config.yaml"),
                      "context_dir": str(state / "devsy/contexts/default"),
                      "kubeconfig_source": str(state / "ror/operator-kubeconfig"),
                      "context": "default"},
        },
    }
    host.configure_profile(profile)
    fake = SimpleNamespace(
        executor_session=lambda: (object(), session),
        verify_compact=lambda _session: None,
        execution=lambda result: result["structuredContent"],
        read_devsy=lambda _session, _profile: None,
    )
    monkeypatch.setitem(sys.modules, "compose_control", fake)
    monkeypatch.setattr(host, "private", lambda _path: b'{"profile":"fixture"}')
    return fake


def test_smoke_reads_explicit_dakota_tuple_and_not_vm_checkout(tmp_path, monkeypatch):
    session = FakeSession()
    configured_host(tmp_path, monkeypatch, session=session)

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": True})

    assert result["native_read"]["status"] == "PASS"
    assert result["devsy_reads"] == "PASS"
    exact_read = next(args["payload"] for name, args in session.calls
                      if name == "get_thread_snapshot")
    assert exact_read == {"target": "local", "cwd": DAKOTA_CWD,
                          "thread_id": THREAD_ID}
    assert all(VM_CWD not in json.dumps(args) for _, args in session.calls)


def test_non_strict_smoke_reports_redacted_thread_mismatch_after_devsy_reads(
        tmp_path, monkeypatch):
    session = FakeSession(expected_cwd=DAKOTA_CWD)
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": VM_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert devsy_reads == ["checked"]
    assert result["native_read"] == {
        "status": "FAIL", "error_code": "NATIVE_THREAD_IDENTITY_MISMATCH",
    }
    assert "home/" not in json.dumps(result)
    assert any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_non_strict_smoke_redacts_structured_thread_error(tmp_path, monkeypatch):
    session = FakeSession(read_error=(
        "Stored thread id/cwd does not match the requested workstream"))
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert devsy_reads == ["checked"]
    assert result["native_read"] == {
        "status": "FAIL", "error_code": "THREAD_WORKSTREAM_MISMATCH",
    }
    assert "Stored thread" not in json.dumps(result)
    assert any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_native_snapshot_rejects_active_unknown_or_unverified_state(tmp_path, monkeypatch):
    for index, session in enumerate((
            FakeSession(active_flags=["turn"]),
            FakeSession(unknown_active_flags=True),
            FakeSession(native_state_authoritative=False),
            FakeSession(thread_status="unknown"),
            FakeSession(connection_target="other"))):
        fake = configured_host(tmp_path / str(index), monkeypatch, session=session)
        fake.read_devsy = lambda _session, _profile: None
        result = host.smoke({"native_codex": {
            "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
        }, "require_native": False})
        assert result["native_read"]["status"] == "FAIL"


def test_native_snapshot_accepts_idle_only_with_completed_latest_turn(
        tmp_path, monkeypatch):
    session = FakeSession(
        thread_status="idle",
        latest_turn={"id": "12345678-1234-5678-9abc-def012345678",
                     "status": "completed", "error_code": None},
    )
    fake = configured_host(tmp_path, monkeypatch, session=session)
    fake.read_devsy = lambda _session, _profile: None

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": True})

    assert result["native_read"] == {"status": "PASS", "target": "local"}


def test_native_snapshot_rejects_idle_with_missing_or_noncompleted_latest_turn(
        tmp_path, monkeypatch):
    invalid_snapshots = (
        (None, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "inProgress",
          "error_code": None}, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "malformed", "status": "completed", "error_code": None}, [], False,
         "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": "unexpected"}, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": None}, ["turn"], False, "NATIVE_THREAD_ACTIVITY_UNKNOWN"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": None}, [], True, "NATIVE_THREAD_ACTIVITY_UNKNOWN"),
    )
    for index, (latest_turn, active_flags, unknown_active_flags, error_code) in enumerate(
            invalid_snapshots):
        session = FakeSession(thread_status="idle", latest_turn=latest_turn,
                              active_flags=active_flags,
                              unknown_active_flags=unknown_active_flags)
        fake = configured_host(tmp_path / str(index), monkeypatch, session=session)
        fake.read_devsy = lambda _session, _profile: None

        result = host.smoke({"native_codex": {
            "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
        }, "require_native": False})

        assert result["native_read"] == {
            "status": "FAIL", "error_code": error_code,
        }


def test_native_snapshot_rejects_active_even_without_active_flags(
        tmp_path, monkeypatch):
    session = FakeSession(
        thread_status="active",
        latest_turn={"id": "12345678-1234-5678-9abc-def012345678",
                     "status": "inProgress", "error_code": None},
    )
    fake = configured_host(tmp_path, monkeypatch, session=session)
    fake.read_devsy = lambda _session, _profile: None

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert result["native_read"] == {
        "status": "FAIL", "error_code": "NATIVE_THREAD_STATE_UNVERIFIED",
    }


def test_strict_smoke_fails_closed_when_native_tuple_is_missing(tmp_path, monkeypatch):
    session = FakeSession()
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    try:
        host.smoke({"require_native": True})
    except ValueError as exc:
        assert str(exc) == "qualified Dakota native read is required"
    else:
        raise AssertionError("strict smoke accepted an unconfigured native tuple")

    assert devsy_reads == ["checked"]
    assert not any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_host_devsy_bootstrap_adapter_uses_validated_vm_paths(tmp_path, monkeypatch):
    import grp
    import pwd
    configured_host(tmp_path, monkeypatch, session=FakeSession())
    policy = json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text())
    template = (ROOT / "config/codex-control-plane-devsy.service.in").read_text()
    starter = "#!/usr/bin/env python3\n"

    bootstrap = host._devsy_bootstrap({
        "policy": policy, "unit_template": template, "starter_source": starter,
    })

    assert bootstrap.profile["repo_dir"] == VM_CWD
    assert bootstrap.profile["state_dir"] == str(host.STATE)
    assert bootstrap.profile["uid"] == os.getuid()
    assert bootstrap.profile["service_user"] == pwd.getpwuid(os.getuid()).pw_name
    assert bootstrap.profile["service_group"] == grp.getgrgid(os.getgid()).gr_name


def test_devsy_start_restarts_without_rewriting_managed_starter(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    starter = state / "start-host-devsy.py"
    starter.write_text("approved managed starter\n")
    starter.chmod(0o700)
    calls = []
    monkeypatch.setattr(host, "STATE", state)
    monkeypatch.setattr(host, "run", lambda args, **_kwargs: calls.append(args))

    result = host.devsy_start()

    assert result == {"devsy": "PASS"}
    assert starter.read_text() == "approved managed starter\n"
    assert calls == [["sudo", "-n", "systemctl", "restart", "codex-control-plane-devsy"]]
